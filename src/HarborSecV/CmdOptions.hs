module HarborSecV.CmdOptions
    ( CmdOptions (..),
      getOptions
    ) where

import System.Environment
import GHC.IO.Handle.Text (hPutStrLn, hPutStr)
import GHC.IO.Handle.FD (stderr)
import System.Exit

import System.Console.GetOpt
import Control.Monad.Except
import Data.Either
import Data.Maybe
import Control.Monad

data CmdOptions = CmdOptions
  { optVerbose     :: Bool
  , optShowHelp    :: Bool
  , optEndpoint    :: Maybe String
  , optUser        :: Maybe String
  , optPassword    :: Maybe String
  , optProjectIDs  :: [Int]
  , optOutput      :: Maybe FilePath
  , optThreads     :: Int
  , optSeverity    :: Int
  } deriving Show

defaultCmdOptions = CmdOptions
  { optVerbose     = False
  , optShowHelp    = False
  , optThreads     = 10
  , optProjectIDs  = []
  , optOutput      = Nothing
  , optUser        = Nothing 
  , optPassword    = Nothing
  , optEndpoint    = Nothing
  , optSeverity    = 1
  }

options :: [OptDescr (CmdOptions -> Except String CmdOptions)]
options =
  [ Option ['v']     ["verbose"]
      (NoArg (\ opts -> return opts { optVerbose = True }))
      "chatty output"
  , Option ['h','?'] ["help"]
      (NoArg (\ opts -> return opts { optShowHelp = True }))
      "show help"
  , Option ['o']     ["output"]
      (ReqArg (\o opts -> return opts { optOutput = Just o }) "OUTPUT_FILE")
      "output filename, e.g results.json"
  , Option ['e']     ["endpoint"]
      (ReqArg (\o opts -> return opts { optEndpoint = Just o }) "ENDPOINT_URL")
      "endpoint URL, e.g https://harbor.com"
  , Option []        ["user"]
      (ReqArg (\o opts -> return opts { optUser = Just o }) "USER")
      "harbor user"
  , Option []        ["password"]
      (ReqArg (\o opts -> return opts { optPassword = Just o }) "PASSWORD")
      "harbor password"
  , Option ['p']     ["project"]
      (ReqArg (\o opts -> case reads o of
          [(v, "")] -> return opts { optProjectIDs = v : optProjectIDs opts }
          _  -> throwError $ "Unable to parse projectid number '" ++ show o ++ "'\n") "PROJECT_ID")
      "project id, e.g -p 7 -p 42"
  , Option []        ["threads"]
      (ReqArg (\o opts -> case reads o of
          [(v, "")] -> return opts { optThreads = v}
          _  -> throwError "Unable to parse threads number\n") "THREADS_NUM")
      "threads number to use, e.g --threads 15"
  , Option ['s']     ["severity"]
      (ReqArg (\o opts -> case reads o of
          [(v, "")] -> return opts { optSeverity = v}
          _  -> throwError $ "Unable to parse severity (int) '" ++ show o ++ "\n") "SEVERITY")
      "minimum severity, e.g -s 1 (default 0)"
  ]

getOptions :: IO (CmdOptions, [String])
getOptions = do
  argv <- getArgs
  let (o,n,errs) = getOpt Permute options argv
  unless (null errs) (showUsageErr $ concat errs)
  case runExcept $ foldl (>>=) (pure defaultCmdOptions) o of
    (Right opts) -> do
        when (optShowHelp opts) (showHelp >> exitSuccess)
        when (isNothing $ optEndpoint opts) (showUsageErr "Endpoint field is required")
        when (isNothing $ optUser opts) (showUsageErr "User field is required")
        when (isNothing $ optPassword opts) (showUsageErr "Password field is required")
        when (null $ optProjectIDs opts) (showUsageErr "At least one project id must be specified") 
        return (opts, n)
    (Left err) -> showUsageErr err

showUsageErr err = do
  hPutStrLn stderr err
  showHelp
  exitFailure

showHelp :: IO ()
showHelp = putStr (usageInfo header options)
  where header = "Usage: harborsecv [OPTIONS] -e ENDPOINT -p PROJECT_ID --user USER --password PASSWORD"
