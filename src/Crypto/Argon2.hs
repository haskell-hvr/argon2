{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE RecordWildCards #-}

{-|

"Crypto.Argon2" provides bindings to the
<https://github.com/P-H-C/phc-winner-argon2 reference implementation> of Argon2,
the password-hashing function that won the
<https://password-hashing.net/ Password Hashing Competition (PHC)>. 

The main entry points to this module are 'hashEncoded', which produces a
crypt-like ASCII output; and 'hash' which produces a 'BS.ByteString' (a stream
of bytes). Argon2 is a configurable hash function, and can be configured by
supplying a particular set of 'HashOptions' - 'defaultHashOptions' should provide
a good starting point. See 'HashOptions' for more documentation on the particular
parameters that can be adjusted.

For access directly to the C interface, see "Crypto.Argon2.FFI".

-}
module Crypto.Argon2
       ( -- * Computing hashes
         hashEncoded, hash,
         -- * Verification
         verify,
         -- * Configuring hashing
         HashOptions(..), Argon2Variant(..), defaultHashOptions,
         -- * Exceptions
         Argon2Exception(..))
       where

import GHC.Generics (Generic)
import Control.Exception
import Data.Typeable
import Foreign
import Foreign.C
import Numeric.Natural
import System.IO.Unsafe (unsafePerformIO)
import qualified Crypto.Argon2.FFI as FFI
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

-- | Which variant of Argon2 to use. You should choose the variant that is most
-- applicable to your intention to hash inputs.
data Argon2Variant
  = Argon2i  -- ^ Argon2i uses data-independent memory access, which is preferred
             -- for password hashing and password-based key derivation. Argon2i
             -- is slower as it makes more passes over the memory to protect from
             -- tradeoff attacks.
  | Argon2d -- ^ Argon2d is faster and uses data-depending memory access, which
            -- makes it suitable for cryptocurrencies and applications with no
            -- threats from side-channel timing attacks.
  deriving (Eq,Ord,Read,Show,Bounded,Generic,Typeable,Enum)

-- | Parameters that can be adjusted to change the runtime performance of the
-- hashing.
data HashOptions =
  HashOptions {hashIterations :: !Word32 -- ^ The time cost, which defines the amount of computation realized and therefore the execution time, given in number of iterations.
                                         --
                                         -- 'FFI.ARGON2_MIN_TIME' <= 'hashIterations' <= 'FFI.ARGON2_MAX_TIME'
              ,hashMemory :: !Word32 -- ^ The memory cost, which defines the memory usage, given in kibibytes.
                                     --
                                     -- max 'FFI.ARGON2_MIN_MEMORY' (8 * 'hashParallelism') <= 'hashMemory' <= 'FFI.ARGON2_MAX_MEMORY'
              ,hashParallelism :: !Word32 -- ^ A parallelism degree, which defines the number of parallel threads.
                                          --
                                          -- 'FFI.ARGON2_MIN_LANES' <= 'hashParallelism' <= 'FFI.ARGON2_MAX_LANES' && 'FFI.ARGON_MIN_THREADS' <= 'hashParallelism' <= 'FFI.ARGON2_MAX_THREADS'
              ,hashVariant :: !Argon2Variant -- ^ Which version of Argon2 to use.
              }
  deriving (Eq,Ord,Read,Show,Bounded,Generic,Typeable)

-- | A set of default 'HashOptions', taken from the @argon2@ executable.
--
-- @
-- 'defaultHashOptions' :: 'HashOptions'
-- 'defaultHashOptions' =
--   'HashOptions' {'hashIterations' = 1
--               ,'hashMemory' = 2 ^ 17
--               ,'hashParallelism' = 4
--               ,'hashVariant' = 'Argon2i'}
-- @
defaultHashOptions :: HashOptions
defaultHashOptions =
  HashOptions {hashIterations = 1
              ,hashMemory = 2 ^ 17
              ,hashParallelism = 4
              ,hashVariant = Argon2i}

-- | Encode a password with a given salt and 'HashOptions' and produce a textual
-- encoding of the result.
hashEncoded :: HashOptions -- ^ Options pertaining to how expensive the hash is to calculate.
            -> BS.ByteString -- ^ The password to hash. Must be less than 4294967295 bytes.
            -> BS.ByteString -- ^ The salt to use when hashing. Must be less than 4294967295 bytes.
            -> T.Text -- ^ The encoded password hash.
hashEncoded options password salt =
  unsafePerformIO
    (hashEncoded' options password salt FFI.argon2i_hash_encoded FFI.argon2d_hash_encoded)

-- | Encode a password with a given salt and 'HashOptions' and produce a stream
-- of bytes.
hash :: HashOptions -- ^ Options pertaining to how expensive the hash is to calculate.
     -> BS.ByteString -- ^ The password to hash. Must be less than 4294967295 bytes.
     -> BS.ByteString -- ^ The salt to use when hashing. Must be less than 4294967295 bytes.
     -> BS.ByteString -- ^ The un-encoded password hash.
hash options password salt =
  unsafePerformIO (hash' options password salt FFI.argon2i_hash_raw FFI.argon2d_hash_raw)

variant :: a -> a -> Argon2Variant -> a
variant a _ Argon2i = a
variant _ b Argon2d = b
{-# INLINE variant #-}

-- | Not all 'HashOptions' can necessarily be used to compute hashes. If you
-- supply invalid 'HashOptions' (or hashing otherwise fails) a 'Argon2Exception'
-- will be throw.
data Argon2Exception
  = -- | The length of the supplied password is outside the range supported by @libargon2@.
    Argon2PasswordLengthOutOfRange !CSize -- ^ The erroneous length.
  | -- | The length of the supplied salt is outside the range supported by @libargon2@.
    Argon2SaltLengthOutOfRange !CSize -- ^ The erroneous length.
  | -- | Either too much or too little memory was requested via 'hashMemory'.
    Argon2MemoryUseOutOfRange !Word32 -- ^ The erroneous 'hashMemory' value.
  | -- | Either too few or too many iterations were requested via 'hashIterations'.
    Argon2IterationCountOutOfRange !Word32 -- ^ The erroneous 'hashIterations' value.
  | -- | Either too much or too little parallelism was requested via 'hasParallelism'.
    Argon2ParallelismOutOfRange !Word32 -- ^ The erroneous 'hashParallelism' value.
  | -- | An unexpected exception was throw. Please <https://github.com/ocharles/argon2/issues report this as a bug>!
    Argon2Exception !Int32 -- ^ The =libargon2= error code.
  deriving (Typeable, Show)

instance Exception Argon2Exception

type Argon2Encoded = Word32 -> Word32 -> Word32 -> CString -> CSize -> CString -> CSize -> CSize -> CString -> CSize -> IO Int32

hashEncoded' :: HashOptions
             -> BS.ByteString
             -> BS.ByteString
             -> Argon2Encoded
             -> Argon2Encoded
             -> IO T.Text
hashEncoded' options@HashOptions{..} password salt argon2i argon2d =
  do let saltLen = fromIntegral (BS.length salt)
         passwordLen = fromIntegral (BS.length password)
     outLen <- fmap fromIntegral $ FFI.argon2_encodedlen
                                              hashIterations
                                              hashMemory
                                              hashParallelism
                                              saltLen
                                              hashlen
     out <- mallocBytes outLen
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
                  (fromIntegral saltLen)
                  (fromIntegral hashlen)
                  out
                  (fromIntegral outLen)
     handleSuccessCode res options password salt
     fmap T.decodeUtf8 (BS.packCString out)
  where argon2 = variant argon2i argon2d hashVariant
        hashlen = 64

type Argon2Unencoded = Word32 -> Word32 -> Word32 -> CString -> CSize -> CString -> CSize -> CString -> CSize -> IO Int32

hash' :: HashOptions
      -> BS.ByteString
      -> BS.ByteString
      -> Argon2Unencoded
      -> Argon2Unencoded
      -> IO BS.ByteString
hash' options@HashOptions{..} password salt argon2i argon2d =
  do let saltLen = fromIntegral (BS.length salt)
         passwordLen = fromIntegral (BS.length password)
         outLen = 512
     out <- mallocBytes outLen
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
                  (fromIntegral outLen)
     handleSuccessCode res options password salt
     BS.packCStringLen (out, outLen)
  where argon2 = variant argon2i argon2d hashVariant

handleSuccessCode :: Int32
                  -> HashOptions
                  -> BS.ByteString
                  -> BS.ByteString
                  -> IO ()
handleSuccessCode res HashOptions{..} password salt =
  let saltLen = fromIntegral (BS.length salt)
      passwordLen = fromIntegral (BS.length password)
  in case res of
       a
         | a `elem` [FFI.ARGON2_OK] -> return ()
         | a `elem` [FFI.ARGON2_SALT_TOO_SHORT,FFI.ARGON2_SALT_TOO_LONG] ->
           throwIO (Argon2SaltLengthOutOfRange saltLen)
         | a `elem` [FFI.ARGON2_PWD_TOO_SHORT,FFI.ARGON2_PWD_TOO_LONG] ->
           throwIO (Argon2PasswordLengthOutOfRange passwordLen)
         | a `elem` [FFI.ARGON2_TIME_TOO_SMALL,FFI.ARGON2_TIME_TOO_LARGE] ->
           throwIO (Argon2IterationCountOutOfRange hashIterations)
         | a `elem` [FFI.ARGON2_MEMORY_TOO_LITTLE,FFI.ARGON2_MEMORY_TOO_MUCH] ->
           throwIO (Argon2MemoryUseOutOfRange hashMemory)
         | a `elem`
             [FFI.ARGON2_LANES_TOO_FEW
             ,FFI.ARGON2_LANES_TOO_MANY
             ,FFI.ARGON2_THREADS_TOO_FEW
             ,FFI.ARGON2_THREADS_TOO_MANY] ->
           throwIO (Argon2ParallelismOutOfRange hashParallelism)
         | otherwise -> throwIO (Argon2Exception a)

-- | Verify that a given password could result in a given hash output.
-- Automatically determines the correct 'HashOptions' based on the
-- encoded hash (as produced by 'hashEncoded').
verify
  :: T.Text -> BS.ByteString -> Bool
verify encoded password =
  unsafePerformIO
    (BS.useAsCString password $
     \pwd ->
       BS.useAsCString (T.encodeUtf8 encoded) $
       \enc ->
         do res <-
              (variant FFI.argon2i_verify FFI.argon2d_verify v) enc
                                                                pwd
                                                                (fromIntegral (BS.length password))
            return (res == FFI.ARGON2_OK))
    where v | T.pack "$argon2i" `T.isPrefixOf` encoded = Argon2i
            | otherwise = Argon2d
