{-# LANGUAGE DeriveGeneric  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}

module HarborSecV.Models
    ( Repository (..),
      Tag (..),
      Image (..),
      CVE (..),
      Vulnerability (..),
      HarborSecVException (..),
      AppException (..),
      AppEnv (..),
      LogEntry (..),
      Page,
      ProjectID,
      HttpStatus,
      TimeStamp
    ) where

import HarborSecV.CmdOptions
import Data.Aeson.Types
import Data.Time
import Data.Time.Format.ISO8601
import Data.List (find)
import Data.Maybe (isJust)
import GHC.Generics
import Control.Exception
import Network.HTTP.Simple
import Network.HTTP.Client (HttpExceptionContent(..), method, path, host, queryString, requestHeaders)
import System.IO (Handle)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as B
import qualified Data.HashMap.Lazy as HML
import Data.CaseInsensitive (original)
import qualified Data.HashMap.Strict as HM

data Repository
  = Repository {
    repositoryName :: String,
    repositoryTagsCount :: Int
  } deriving (Show, Generic)

data Tag
  = Tag {
    tagName :: String,
    tagCreated :: LocalTime
  } deriving (Show, Generic)

data Image
  = Image { imageTag :: Tag,
    imageRepository :: Repository,
    imageCVEs :: [CVE]
  } deriving (Show, Generic)

data CVE
  = CVE {
    cveID :: String,
    cveSeverity :: Maybe Int,
    cvePackage :: Maybe String,
    cveVersion :: Maybe String,
    cveDescription :: Maybe String,
    cveLink :: Maybe String
  } deriving (Show, Generic)

data Vulnerability
  = Vulnerability {
    vulnCVE :: CVE,
    vulnRepository :: Repository,
    vulnTag :: Tag,
    vulnTimestamp :: UTCTime
  } deriving (Show, Generic)

data HarborSecVException
  = HarborSecVException UTCTime Request AppException
  | HarborSecVExtException UTCTime HttpException
  deriving (Show, Generic)

data AppException
  = JsonDecodeException { jsonDecodeExceptionReason :: String }
  | ReposFetchException { httpStatus :: HttpStatus }
  | TagsFetchException { httpStatus :: HttpStatus }
  | CVEsFetchException { httpStatus :: HttpStatus }
  | TagsNotFoundException
  | ReposParseTotalException
  deriving (Show, Generic, ToJSON)

instance Exception HarborSecVException

data AppEnv
  = AppEnv {
    envBaseRequest :: Request,
    envTimestamp :: UTCTime,
    envOutput :: Handle,
    envSerialize :: LogEntry -> BL.ByteString,
    cmdOptions :: CmdOptions
  }

data LogEntry
  = LogException HarborSecVException
  | LogResult Vulnerability
  deriving (Show, Generic)

type Page = Int
type ProjectID = Int
type HttpStatus = Int
type TimeStamp = UTCTime

instance ToJSON HttpException where
  toJSON (InvalidUrlException url reason) = object [
        "exceptiontype" .= ("InvalidUrlException" :: String),
        "url"  .= url,
        "reason" .= reason
      ]
  toJSON (HttpExceptionRequest request content) = object [
        "exceptiontype" .= ("HttpExceptionRequest" :: String),
        "request" .= toJSON request,
        "details"  .= show content
      ]

instance ToJSON Request where
  toJSON r = object [
      "method" .= bsToText (method r),
      "host" .= bsToText (host r),
      "path" .= bsToText (path r),
      "query" .= bsToText (queryString r),
      "headers" .= headers
    ] where
      stripHeaders = ["Authorization", "Cookie"]
      headers = HM.fromList $ map (\(k, v) -> if isJust $ find (== k) stripHeaders
        then (bsToText $ original k, "<REDACTED>" :: T.Text)
        else (bsToText (original k), bsToText v)) (requestHeaders r)

bsToText :: B.ByteString -> T.Text
bsToText bs = case TE.decodeUtf8' bs of
  (Left _) -> T.pack $ show bs
  (Right v) -> v

instance ToJSON LogEntry where
  toJSON (LogResult r) = toJSON r
  toJSON (LogException e) = toJSON e

instance ToJSON HarborSecVException where
  toJSON (HarborSecVException timestamp request appExc) = object [
        "@timestamp" .= iso8601Show timestamp,
        "harborsecv" .= object [
          "exception" .= mergeObjects requestObject exceptionObject
        ]
      ] where exceptionObject = toJSON appExc
              requestObject = object [
                "request" .= toJSON request,
                "exceptiontype" .= ("HarborSecVException" :: String)]
  toJSON (HarborSecVExtException timestamp httpException) = object [
        "@timestamp" .= iso8601Show timestamp,
        "harborsecv" .= object [
          "exception" .= toJSON httpException
        ]
      ]

instance FromJSON Tag where
  parseJSON = withObject "Tag" $ \obj -> do
    tag <- obj .: "name"
    zonedTime <- obj .: "created"
    return $ Tag {tagName = tag, tagCreated = zonedTimeToLocalTime zonedTime}

instance ToJSON Tag where
  toJSON Tag { tagName = tagName, tagCreated = tagCreated} =
    object [
      "name" .= tagName,
      "created" .= tagCreated
    ]

instance FromJSON Repository where
  parseJSON = withObject "Repository" $ \obj -> do
    name <- obj .: "name"
    tagsCount <- obj .: "tags_count"
    return (Repository { repositoryName = name, repositoryTagsCount = tagsCount })

instance ToJSON Repository where
  toJSON Repository { repositoryName = repositoryName } =
    object [
      "name" .= repositoryName
    ]

instance FromJSON CVE where
  parseJSON = withObject "CVE" $ \obj -> do
    vID <- obj .: "id"
    vSev <- obj .:? "severity"
    vPkg <- obj .:? "package"
    vVer <- obj .:? "version"
    vDesc <- obj .:? "description"
    vLink <- obj .:? "link"
    return $ CVE { cveID = vID, cveDescription = vDesc, cvePackage = vPkg,
                   cveLink = vLink, cveSeverity = vSev, cveVersion = vVer }

instance ToJSON CVE where
  toJSON CVE { cveID = cveID, cveSeverity = cveSeverity, cvePackage = cvePackage,
               cveDescription = cveDescription, cveLink = cveLink, cveVersion = cveVersion } =
    object [ "id" .= cveID,
             "description" .= cveDescription,
             "severity" .= cveSeverity,
             "package" .= cvePackage,
             "version" .= cveVersion,
             "link" .= cveLink
           ]

instance ToJSON Image where
  toJSON Image { imageRepository = imageRepository, imageTag = imageTag,
                 imageCVEs = imageCVEs} =
    object [
      "repository" .= toJSON imageRepository,
      "tag" .= toJSON imageTag,
      "cves" .= toJSON imageCVEs
    ]

instance ToJSON Vulnerability where
  toJSON Vulnerability { vulnRepository = vulnRepository, vulnTag = vulnTag,
                         vulnCVE = vulnCVE, vulnTimestamp = vulnTimestamp } =
    object [
      "@timestamp" .= iso8601Show vulnTimestamp,
      "harborsecv" .= object [
          "repository" .= toJSON vulnRepository,
          "tag" .= toJSON vulnTag,
          "cve" .= toJSON vulnCVE
        ]
    ]

mergeObjects :: Value -> Value -> Value
mergeObjects (Object x) (Object y) = Object $ HML.union x y
