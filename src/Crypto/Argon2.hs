{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.Argon2 (hashEncoded, hash, verifyEncoded, HashOptions(..), Argon2Variant(..), defaultHashOptions, EncodedPassword, Salt, ClearTextPassword) where

import Control.Exception
import Data.Typeable
import Foreign
import Foreign.C
import Numeric.Natural
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as T
import qualified Data.Text as T
import qualified Crypto.Argon2.FFI as FFI

data Argon2Variant = Argon2i | Argon2d

data HashOptions =
  HashOptions {hashIterations :: !Word32
              ,hashMemory :: !Word32
              ,hashParallelism :: !Word32
              ,hashVariant :: !Argon2Variant}

newtype EncodedPassword = EncodedPassword T.Text
  deriving(Show, Eq)
newtype Salt = Salt BS.ByteString
  deriving(Show, Eq)
newtype ClearTextPassword = ClearTextPassword BS.ByteString
  deriving(Show, Eq)

defaultHashOptions :: HashOptions
defaultHashOptions =
  HashOptions {hashIterations = 3
              ,hashMemory = 2 ^ 12
              ,hashParallelism = 1
              ,hashVariant = Argon2i}

hashEncoded :: HashOptions       -- ^ Options pertaining to how expensive the hash is to calculate
            -> ClearTextPassword -- ^ The password to hash
            -> Salt              -- ^ The salt to use when hashing
            -> EncodedPassword   -- ^ The encoded password hash
hashEncoded options (ClearTextPassword password) (Salt salt) =
  EncodedPassword $ unsafePerformIO (hashEncoded' options password salt FFI.argon2i_hash_encoded FFI.argon2d_hash_encoded)

hash :: HashOptions       -- ^ Options pertaining to how expensive the hash is to calculate
     -> ClearTextPassword -- ^ The password to hash
     -> Salt              -- ^ The salt to use when hashing
     -> BS.ByteString     -- ^ The un-encoded password hash
hash options (ClearTextPassword password) (Salt salt) =
  unsafePerformIO (hash' options password salt FFI.argon2i_hash_raw FFI.argon2d_hash_raw)

variant :: a -> a -> Argon2Variant -> a
variant a _ Argon2i = a
variant _ b Argon2d = b
{-# INLINE variant #-}

type Argon2Encode = Word32 -> Word32 -> Word32 -> CString -> Word64 -> CString -> Word64 -> Word64 -> CString -> Word64 -> IO Int32
type Argon2Raw    = Word32 -> Word32 -> Word32 -> CString -> Word64 -> CString -> Word64 -> CString -> Word64 -> IO Int32

data Argon2Exception
  = Argon2PasswordLengthOutOfRange Word64 Word64 Word64
  | Argon2SaltLengthOutOfRange Word64 Word64 Word64
  | Argon2MemoryUseOutOfRange Word32 Word32 Word32
  | Argon2IterationCountOutOfRange Word32 Word32 Word32
  | Argon2ParallelismOutOfRange Word32 Word32 Word32
  | Argon2Exception Int32
  deriving (Typeable, Show)

instance Exception Argon2Exception

handleSuccessCode :: Int32
                  -> CString
                  -> Word64
                  -> Word64
                  -> Word32
                  -> Word32
                  -> Word32
                  -> IO BS.ByteString
handleSuccessCode res out saltLen passwordLen hashIterations hashMemory hashParallelism =
  case res of
    a
      | a `elem` [FFI.ARGON2_OK] -> BS.packCString out
      | a `elem` [FFI.ARGON2_SALT_TOO_SHORT,FFI.ARGON2_SALT_TOO_LONG] ->
        throwIO (Argon2SaltLengthOutOfRange saltLen
                                            FFI.ARGON2_MIN_SALT_LENGTH
                                            FFI.ARGON2_MAX_SALT_LENGTH)
      | a `elem` [FFI.ARGON2_PWD_TOO_SHORT,FFI.ARGON2_PWD_TOO_LONG] ->
        throwIO (Argon2PasswordLengthOutOfRange passwordLen
                                                FFI.ARGON2_MIN_PWD_LENGTH
                                                FFI.ARGON2_MAX_PWD_LENGTH)
      | a `elem` [FFI.ARGON2_TIME_TOO_SMALL,FFI.ARGON2_TIME_TOO_LARGE] ->
        throwIO (Argon2IterationCountOutOfRange hashIterations
                                                FFI.ARGON2_MIN_TIME
                                                FFI.ARGON2_MAX_TIME)
      | a `elem` [FFI.ARGON2_MEMORY_TOO_LITTLE,FFI.ARGON2_MEMORY_TOO_MUCH] ->
        throwIO (Argon2MemoryUseOutOfRange
                   hashMemory
                   (max FFI.ARGON2_MIN_MEMORY (8 * hashParallelism))
                   FFI.ARGON2_MAX_MEMORY)
      | a `elem` [FFI.ARGON2_LANES_TOO_FEW,FFI.ARGON2_LANES_TOO_MANY] ->
        throwIO (Argon2ParallelismOutOfRange hashParallelism
                                             FFI.ARGON2_MIN_LANES
                                             FFI.ARGON2_MAX_LANES)
      | otherwise -> throwIO (Argon2Exception a)

hashEncoded' :: HashOptions
             -> BS.ByteString
             -> BS.ByteString
             -> Argon2Encode
             -> Argon2Encode
             -> IO T.Text
hashEncoded' HashOptions{..} password salt argon2i argon2d =
  do out <- mallocBytes 512
     res <-
       BS.useAsCString password $
       \password' ->
         BS.useAsCString salt $
         \salt' ->
           argon2 hashIterations
                  hashMemory
                  hashParallelism
                  password'
                  passwordLen
                  salt'
                  saltLen
                  64
                  out
                  512
     fmap T.decodeUtf8 $ handleSuccessCode res out saltLen passwordLen hashIterations hashMemory hashParallelism
     where
       argon2 = variant argon2i argon2d hashVariant
       saltLen = fromIntegral (BS.length salt)
       passwordLen = fromIntegral (BS.length password)

hash' :: HashOptions
      -> BS.ByteString
      -> BS.ByteString
      -> Argon2Raw
      -> Argon2Raw
      -> IO BS.ByteString
hash' HashOptions{..} password salt argon2i argon2d =
  do out <- mallocBytes 512
     res <-
       BS.useAsCString password $
       \password' ->
         BS.useAsCString salt $
         \salt' ->
           argon2 hashIterations
                  hashMemory
                  hashParallelism
                  password'
                  passwordLen
                  salt'
                  saltLen
                  out
                  512
     handleSuccessCode res out saltLen passwordLen hashIterations hashMemory hashParallelism
     where
       argon2 = variant argon2i argon2d hashVariant
       saltLen = fromIntegral (BS.length salt)
       passwordLen = fromIntegral (BS.length password)

type Argon2Verify  = CString -> CString -> Word64 -> IO Int32

verifyEncoded :: HashOptions       -- ^ Options pertaining to how expensive the hash is to calculate
              -> EncodedPassword   -- ^ The encodedArgonHash
              -> ClearTextPassword -- ^ The password to hash
              -> Bool
verifyEncoded HashOptions{..} (EncodedPassword encodedArgonHash) (ClearTextPassword password) =
  unsafePerformIO $ do
    res <- BS.useAsCString password $
        \password' ->
          BS.useAsCString (T.encodeUtf8 encodedArgonHash) $
          \encodedArgonHash' ->
            argon2 encodedArgonHash' password' passwordLen
    case res of
        FFI.ARGON2_OK -> return True
        _             -> return False
  where
    argon2 = variant FFI.argon2i_verify FFI.argon2d_verify hashVariant
    passwordLen = fromIntegral (BS.length password)
