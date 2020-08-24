{-# LANGUAGE TupleSections #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import HarborSecV.CmdOptions
import HarborSecV.Models
import Data.Aeson
import Data.Aeson.Types
import Data.Aeson.Encode.Pretty (encodePretty)
import Network.HTTP.Client (path, HttpExceptionContent(..))
import Network.HTTP.Client.TLS
import Network.HTTP.Simple
import Network.HTTP.Types (urlEncode)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy.Char8 as CL
import Text.Read (readEither)
import Data.List
import Data.Time (UTCTime)
import Data.Time.Clock (getCurrentTime)
import Data.Function ((&))
import Data.Foldable (traverse_)
import Data.Either.Combinators ( maybeToRight )
import Control.Concurrent
import Control.Concurrent.Chan
import System.FilePath ((</>))
import System.IO (openFile, stdout, IOMode(..), hPutStr)
import Control.Exception
import Control.Monad (guard, when, forever, forM_, replicateM_, replicateM)
import Control.Monad.Except
import Control.Monad.Reader

type Application m = ReaderT AppEnv (ExceptT HarborSecVException m)

runApplication :: AppEnv -> Application m a -> m (Either HarborSecVException a)
runApplication env r = runExceptT $ runReaderT r env

main :: IO ()
main = do
  (opts, o) <- getOptions
  appRunResult <- runReaderT createEnv opts >>= flip runApplication application
  case appRunResult of
    Left e -> do
      putStrLn "Error occured:"
      throw e
    _      -> return ()

application :: Application IO ()
application = do
  verbose <- asks (optVerbose . cmdOptions)
  timestamp <- asks envTimestamp
  projectsIDs <- asks (optProjectIDs . cmdOptions)
  output <- asks envOutput
  serialize <- asks envSerialize
  env <- ask
  listOfReposLists <- liftIO $ mapM ((sequence <$>) . runApplication env . getRepos) projectsIDs
  let reposList = concat listOfReposLists
  listOfImages <- createRepoWorkers reposList
  when verbose (liftIO $ putStrLn $ "Writing data to " ++ show output)
  logs <- imagesToLogs timestamp listOfImages
  traverse_ (\hlog -> liftIO $ BL.hPutStr output (serialize hlog) >> BL.hPutStr output "\n") logs

createRepoWorkers :: [Either HarborSecVException Repository] -> Application IO [Either HarborSecVException Image]
createRepoWorkers exceptRepos = do
  env <- ask
  verbose <- asks (optVerbose . cmdOptions)
  threads <- asks (optThreads . cmdOptions)
  inputChan <- liftIO newChan
  outputChan <- liftIO newChan
  when verbose (liftIO $ putStrLn $ "Creating " ++ show threads ++ " worker threads")
  liftIO $ forM_ [1..threads] (\n -> forkIO (void $ runApplication env (newWorker inputChan outputChan)))
  liftIO $ forM_ exceptRepos (writeChan inputChan)
  replicateM (length exceptRepos) (liftIO $ readChan outputChan)

newWorker :: Chan (Either HarborSecVException Repository) -> Chan (Either HarborSecVException Image) -> Application IO ()
newWorker repoChan imageChan = forever $ do
  exceptRepo <- liftIO (readChan repoChan)
  env <- ask
  liftIO $ runApplication env (liftEither exceptRepo >>= getLatestImage >>= getImageCVEs) >>= writeChan imageChan

getLatestImage :: Repository -> Application IO Image
getLatestImage repository = do
  baseRequest <- asks envBaseRequest
  verbose <- asks (optVerbose . cmdOptions)
  let reqPath = C.unpack (path baseRequest) </> "repositories"
        </> (repository & repositoryName & C.pack & urlEncode False & C.unpack) </> "tags"
  let tagsReq = setRequestPath (C.pack reqPath) baseRequest
  lift $ do
    resp <- makeRequestWithExcept tagsReq
    timestamp <- liftIO getCurrentTime
    let respStatus = getResponseStatusCode resp
    when verbose (liftIO $ putStrLn ("Request tags in repository " ++ show (repository & repositoryName) ++
      " ended with status " ++ show respStatus))
    when (respStatus /= 200) (throwError $ HarborSecVException timestamp tagsReq (TagsFetchException respStatus))
    let respBody = getResponseBody resp
    tags <- decodeJsonWithExcept timestamp tagsReq respBody
    let sorted = sortBy (\a b -> compare (tagCreated b) (tagCreated a)) tags
    firstTag <- liftEither $ maybeToRight (HarborSecVException timestamp tagsReq TagsNotFoundException) (find (const True) sorted)
    return $ Image { imageTag = firstTag, imageRepository = repository, imageCVEs = mempty }

getImageCVEs :: Image -> Application IO Image
getImageCVEs image = do
  verbose <- asks (optVerbose . cmdOptions)
  baseRequest <- asks envBaseRequest
  let repository = imageRepository image
  let tag = image & imageTag & tagName
  let reqPath = C.unpack (path baseRequest)
        </> "repositories" </> (repository & repositoryName & C.pack & urlEncode False & C.unpack)
        </> "tags" </> tag </> "vulnerability/details"
  let cvesReq = setRequestPath (C.pack reqPath) baseRequest
  lift $ do
    resp <- makeRequestWithExcept cvesReq
    timestamp <- liftIO getCurrentTime
    let respStatus = getResponseStatusCode resp
    when verbose (liftIO $ putStrLn ("Request image vulnerabilities " ++ show (repository & repositoryName) ++
      " ended with status " ++ show respStatus))
    when (respStatus /= 200) (throwError $ HarborSecVException timestamp cvesReq (CVEsFetchException respStatus))
    let respBody = getResponseBody resp
    cVEs <- decodeJsonWithExcept timestamp cvesReq respBody
    return $ image { imageCVEs = cVEs }

getRepos :: ProjectID -> Application IO [Repository]
getRepos projectID = do
  verbose <- asks (optVerbose . cmdOptions)
  (repos, reposTotal) <- getReposPage' projectID 1
  when verbose (liftIO $ putStrLn ("Found " ++ show (length repos) ++ "/" ++ show reposTotal ++
    " repositories in project ID " ++ show projectID))
  return repos where
    getReposPage' :: ProjectID -> Page -> Application IO ([Repository], Int)
    getReposPage' projectID page = do
      baseRequest <- asks envBaseRequest
      verbose <- asks (optVerbose . cmdOptions)
      let reposReq = buildReposPageReq page (buildReposReq projectID baseRequest)
      (repos, total) <- lift $ do
        timestamp <- liftIO getCurrentTime
        resp <- makeRequestWithExcept reposReq
        let respStatus = getResponseStatusCode resp
        when verbose (liftIO $ putStrLn ("Request repos page " ++ show page ++ " for project " ++
                                    show projectID ++ " ended with status " ++ show respStatus))
        when (respStatus /= 200) (throwError $ HarborSecVException timestamp reposReq (ReposFetchException respStatus))
        let respBody = getResponseBody resp
        let totalReposStr = concatMap C.unpack (getResponseHeader "x-total-count" resp)
        total <- withExceptT (\_ -> HarborSecVException timestamp reposReq ReposParseTotalException) (liftEither $ readEither totalReposStr)
        repos <- decodeJsonWithExcept timestamp reposReq respBody
        return (repos, total)
      if total <= page * resultPerPage then liftEither $ Right (repos, total)
        else do
          (restRepos, _) <- getReposPage' projectID (page + 1)
          return (repos ++ restRepos, total)

imagesToLogs :: UTCTime -> [Either HarborSecVException Image] -> Application IO [LogEntry]
imagesToLogs timestamp exceptImages = do
  severity <- asks (optSeverity . cmdOptions)
  return $ do
    exceptImage <- exceptImages
    case exceptImage of
      Left e -> return $ LogException e
      Right image -> do
        cve <- imageCVEs image
        guard $ ((== Just True) . ((>= severity) <$>) . cveSeverity) cve
        return $ LogResult $ Vulnerability { vulnCVE = cve, vulnRepository = imageRepository image,
          vulnTag = imageTag image, vulnTimestamp = timestamp }

buildReposReq :: ProjectID -> Request -> Request
buildReposReq projectId request = setRequestQueryString [
    ("project_id", Just $ C.pack $ show projectId),
    ("page_size", Just $ C.pack $ show resultPerPage) ] $
  setRequestPath ((C.pack . flip (</>) "repositories" . C.unpack . path) request) request

buildReposPageReq :: Page -> Request -> Request
buildReposPageReq page = addToRequestQueryString [("page", Just $ C.pack $ show page)]

makeRequestWithExcept :: Request -> ExceptT HarborSecVException IO (Response BL.ByteString)
makeRequestWithExcept request = do
  timestamp <- liftIO getCurrentTime
  eitherResp <- liftIO $ try (httpLBS request)
  withExceptT (HarborSecVExtException timestamp) (liftEither eitherResp)

decodeJsonWithExcept :: FromJSON a => UTCTime -> Request -> CL.ByteString -> ExceptT HarborSecVException IO a
decodeJsonWithExcept timestamp request body = withExceptT (HarborSecVException timestamp request . JsonDecodeException) (liftEither $ eitherDecode body)

createEnv :: ReaderT CmdOptions IO AppEnv
createEnv = do
  opts <- ask
  verbose <- asks optVerbose
  when verbose (liftIO $ print opts)
  baseReq <- buildBaseReq
  when verbose (liftIO $ print baseReq)
  (output, serialize) <-
    case optOutput opts of
        (Just filePath) -> (, encode) <$> liftIO (openFile filePath AppendMode)
        _               -> return (stdout, encodePretty)
  timestamp <- liftIO getCurrentTime
  return $ AppEnv { envBaseRequest = baseReq, envOutput = output, envSerialize = serialize,
    envTimestamp = timestamp, cmdOptions = opts }
  where
    buildBaseReq :: ReaderT CmdOptions IO Request
    buildBaseReq = do
      Just apiURL <- asks optEndpoint
      Just user <- asks optUser
      Just password <- asks optPassword
      requestManager <- newTlsManager
      parsedReq <- parseRequest apiURL
      return $ addRequestHeader "Content-Type" "application/json; charset=utf-8" $
        setRequestBasicAuth (C.pack user) (C.pack password) $
        setRequestManager requestManager parsedReq

resultPerPage :: Int
resultPerPage = 100
