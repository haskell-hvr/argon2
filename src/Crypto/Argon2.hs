{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE Trustworthy        #-}

{-|

Module      : Crypto.Argon2
License     : BSD3
Maintainer  : hvr@gnu.org

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
      hashEncoded
    , hash
      -- * Verification
    , verifyEncoded
      -- * Configuring hashing
    , HashOptions(..)
    , Argon2Variant(..)
    , Argon2Version(..)
    , defaultHashOptions
      -- * Status codes
    , Argon2Status(..)
    ) where

import           Control.Exception
import qualified Crypto.Argon2.FFI as FFI
import qualified Data.ByteString   as BS
import qualified Data.Text.Short   as TS
import           Data.Typeable
import           Foreign
import           Foreign.C
import           GHC.Generics      (Generic)
import           System.IO.Unsafe  (unsafePerformIO)

-- | Which variant of Argon2 to use. You should choose the variant that is most
-- applicable to your intention to hash inputs.
data Argon2Variant
  = Argon2i  -- ^ Argon2i uses data-independent memory access, which is preferred
             -- for password hashing and password-based key derivation. Argon2i
             -- is slower as it makes more passes over the memory to protect from
             -- tradeoff attacks.
  | Argon2d  -- ^ Argon2d is faster and uses data-depending memory access, which
             -- makes it suitable for cryptocurrencies and applications with no
             -- threats from side-channel timing attacks.
  | Argon2id -- ^ Argon2id works as Argon2i for the first half of the first iteration
             -- over the memory, and as Argon2d for the rest, thus providing both
             -- side-channel attack protection and brute-force cost savings due to
             -- time-memory tradeoffs.
  deriving (Eq,Ord,Read,Show,Bounded,Generic,Typeable,Enum)

toArgon2Type :: Argon2Variant -> FFI.Argon2_type
toArgon2Type Argon2i  = FFI.Argon2_i
toArgon2Type Argon2d  = FFI.Argon2_d
toArgon2Type Argon2id = FFI.Argon2_id

-- | Version of the Argon2 algorithm.
data Argon2Version
  = Argon2Version10 -- ^ Version 1.0 (deprecated)
  | Argon2Version13 -- ^ Version 1.3 (See [this announcment](https://www.ietf.org/mail-archive/web/cfrg/current/msg07948.html) for more details)
  deriving (Eq,Ord,Read,Show,Bounded,Generic,Typeable,Enum)

toArgon2Ver :: Argon2Version -> FFI.Argon2_version
toArgon2Ver Argon2Version10 = FFI.ARGON2_VERSION_10
toArgon2Ver Argon2Version13 = FFI.ARGON2_VERSION_13

-- | Parameters that can be adjusted to change the runtime performance of the
-- hashing. See also 'defaultHashOptions'.
data HashOptions =
  HashOptions { hashIterations  :: !Word32 -- ^ The time cost, which defines the amount of computation realized and therefore the execution time, given in number of iterations.
                                         --
                                         -- 'FFI.ARGON2_MIN_TIME' <= 'hashIterations' <= 'FFI.ARGON2_MAX_TIME'

              , hashMemory      :: !Word32 -- ^ The memory cost, which defines the memory usage, given in [kibibytes](https://en.wikipedia.org/wiki/Kibibyte).
                                     --
                                     -- max 'FFI.ARGON2_MIN_MEMORY' (8 * 'hashParallelism') <= 'hashMemory' <= 'FFI.ARGON2_MAX_MEMORY'

              , hashParallelism :: !Word32 -- ^ A parallelism degree, which defines the number of parallel threads.
                                          --
                                          -- 'FFI.ARGON2_MIN_LANES' <= 'hashParallelism' <= 'FFI.ARGON2_MAX_LANES' && 'FFI.ARGON_MIN_THREADS' <= 'hashParallelism' <= 'FFI.ARGON2_MAX_THREADS'

              , hashVariant     :: !Argon2Variant -- ^ Which variant of Argon2 to use.

              , hashVersion     :: !Argon2Version -- ^ Which version of Argon2 to use for generating hashes.

              , hashLength      :: !Word32        -- ^ Desired length of hash expressed in octets.
              }
  deriving (Eq,Ord,Read,Show,Bounded,Generic,Typeable)

-- | A set of default 'HashOptions', taken from the @argon2@ executable.
--
-- @
-- 'defaultHashOptions' :: 'HashOptions'
-- 'defaultHashOptions' =
--   'HashOptions' { 'hashIterations'  = 3
--               , 'hashMemory'      = 2 ^ 12 -- 4 MiB
--               , 'hashParallelism' = 1
--               , 'hashVariant'     = 'Argon2i'
--               , 'hashVersion'     = 'Argon2Version13'
--               , 'hashLength'      = 2 ^ 5 -- 32 bytes
--               }
-- @
--
-- For more information on how to select these parameters for your application, see section 6.4 of the [Argon2 specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
--
defaultHashOptions :: HashOptions
defaultHashOptions = HashOptions
    { hashIterations  = 3
    , hashMemory      = 2 ^ (12 :: Int) -- 4 MiB
    , hashParallelism = 1
    , hashVariant     = Argon2i
    , hashVersion     = Argon2Version13
    , hashLength      = 32
    }

-- | Encode a password with a given salt and 'HashOptions' and produce a textual
-- encoding according to the [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) of the result.
--
-- Use 'verifyEncoded' to verify.
hashEncoded :: HashOptions   -- ^ Options pertaining to how expensive the hash is to calculate.
            -> BS.ByteString -- ^ The password to hash. Must be less than 4294967295 bytes.
            -> BS.ByteString -- ^ The salt to use when hashing. Must be less than 4294967295 bytes.
            -> Either Argon2Status TS.ShortText  -- ^ The encoded password hash (or error code in case of failure).
hashEncoded options password salt = unsafePerformIO $ try $ hashEncoded' options password salt

-- | Encode a password with a given salt and 'HashOptions' and produce a binary stream
-- of bytes (of size 'hashLength').
hash :: HashOptions -- ^ Options pertaining to how expensive the hash is to calculate.
     -> BS.ByteString -- ^ The password to hash. Must be less than 4294967295 bytes.
     -> BS.ByteString -- ^ The salt to use when hashing. Must be less than 4294967295 bytes.
     -> Either Argon2Status BS.ByteString -- ^ The un-encoded password hash (or error code in case of failure).
hash options password salt = unsafePerformIO $ try $ hash' options password salt

-- | Returned status code for Argon2 functions.
--
-- Not all 'HashOptions' can necessarily be used to compute hashes. If
-- you supply unsupported or invalid 'HashOptions' (or hashing
-- otherwise fails) an 'Argon2Status' value will be returned to
-- describe the failure.
--
-- Note that this enumeration contains some status codes which are not
-- expected to be returned by the operation provided by the Haskell
-- API.
data Argon2Status
    = Argon2Ok                            -- ^ OK (operation succeeded)
    | Argon2OutputPtrNull                 -- ^ Output pointer is @NULL@
    | Argon2OutputTooShort                -- ^ Output is too short
    | Argon2OutputTooLong                 -- ^ Output is too long
    | Argon2PwdTooShort                   -- ^ Password is too short
    | Argon2PwdTooLong                    -- ^ Password is too long
    | Argon2SaltTooShort                  -- ^ Salt is too short
    | Argon2SaltTooLong                   -- ^ Salt is too long
    | Argon2AdTooShort                    -- ^ Associated data is too short
    | Argon2AdTooLong                     -- ^ Associated data is too long
    | Argon2SecretTooShort                -- ^ Secret is too short
    | Argon2SecretTooLong                 -- ^ Secret is too long
    | Argon2TimeTooSmall                  -- ^ Time cost is too small
    | Argon2TimeTooLarge                  -- ^ Time cost is too large
    | Argon2MemoryTooLittle               -- ^ Memory cost is too small
    | Argon2MemoryTooMuch                 -- ^ Memory cost is too large
    | Argon2LanesTooFew                   -- ^ Too few lanes
    | Argon2LanesTooMany                  -- ^ Too many lanes
    | Argon2PwdPtrMismatch                -- ^ Password pointer is @NULL@, but password length is not 0
    | Argon2SaltPtrMismatch               -- ^ Salt pointer is @NULL@, but salt length is not 0
    | Argon2SecretPtrMismatch             -- ^ Secret pointer is @NULL@, but secret length is not 0
    | Argon2AdPtrMismatch                 -- ^ Associated data pointer is @NULL@, but ad length is not 0
    | Argon2MemoryAllocationError         -- ^ Memory allocation error
    | Argon2FreeMemoryCbkNull             -- ^ The free memory callback is @NULL@
    | Argon2AllocateMemoryCbkNull         -- ^ The allocate memory callback is @NULL@
    | Argon2IncorrectParameter            -- ^ Argon2_Context context is @NULL@
    | Argon2IncorrectType                 -- ^ There is no such version of Argon2
    | Argon2OutPtrMismatch                -- ^ Output pointer mismatch
    | Argon2ThreadsTooFew                 -- ^ Not enough threads
    | Argon2ThreadsTooMany                -- ^ Too many threads
    | Argon2MissingArgs                   -- ^ Missing arguments
    | Argon2EncodingFail                  -- ^ Encoding failed
    | Argon2DecodingFail                  -- ^ Decoding failed
    | Argon2ThreadFail                    -- ^ Threading failure
    | Argon2DecodingLengthFail            -- ^ Some of encoded parameters are too long or too short
    | Argon2VerifyMismatch                -- ^ The password does not match the supplied hash

    | Argon2InternalError                 -- ^ Internal error or unrecognised status code
    deriving (Typeable,Eq,Ord,Read,Show,Enum,Bounded)

instance Exception Argon2Status

toArgon2Status :: CInt -> Argon2Status
toArgon2Status = \case
    FFI.ARGON2_OK                         -> Argon2Ok
    FFI.ARGON2_OUTPUT_PTR_NULL            -> Argon2OutputPtrNull
    FFI.ARGON2_OUTPUT_TOO_SHORT           -> Argon2OutputTooShort
    FFI.ARGON2_OUTPUT_TOO_LONG            -> Argon2OutputTooLong
    FFI.ARGON2_PWD_TOO_SHORT              -> Argon2PwdTooShort
    FFI.ARGON2_PWD_TOO_LONG               -> Argon2PwdTooLong
    FFI.ARGON2_SALT_TOO_SHORT             -> Argon2SaltTooShort
    FFI.ARGON2_SALT_TOO_LONG              -> Argon2SaltTooLong
    FFI.ARGON2_AD_TOO_SHORT               -> Argon2AdTooShort
    FFI.ARGON2_AD_TOO_LONG                -> Argon2AdTooLong
    FFI.ARGON2_SECRET_TOO_SHORT           -> Argon2SecretTooShort
    FFI.ARGON2_SECRET_TOO_LONG            -> Argon2SecretTooLong
    FFI.ARGON2_TIME_TOO_SMALL             -> Argon2TimeTooSmall
    FFI.ARGON2_TIME_TOO_LARGE             -> Argon2TimeTooLarge
    FFI.ARGON2_MEMORY_TOO_LITTLE          -> Argon2MemoryTooLittle
    FFI.ARGON2_MEMORY_TOO_MUCH            -> Argon2MemoryTooMuch
    FFI.ARGON2_LANES_TOO_FEW              -> Argon2LanesTooFew
    FFI.ARGON2_LANES_TOO_MANY             -> Argon2LanesTooMany
    FFI.ARGON2_PWD_PTR_MISMATCH           -> Argon2PwdPtrMismatch
    FFI.ARGON2_SALT_PTR_MISMATCH          -> Argon2SaltPtrMismatch
    FFI.ARGON2_SECRET_PTR_MISMATCH        -> Argon2SecretPtrMismatch
    FFI.ARGON2_AD_PTR_MISMATCH            -> Argon2AdPtrMismatch
    FFI.ARGON2_MEMORY_ALLOCATION_ERROR    -> Argon2MemoryAllocationError
    FFI.ARGON2_FREE_MEMORY_CBK_NULL       -> Argon2FreeMemoryCbkNull
    FFI.ARGON2_ALLOCATE_MEMORY_CBK_NULL   -> Argon2AllocateMemoryCbkNull
    FFI.ARGON2_INCORRECT_PARAMETER        -> Argon2IncorrectParameter
    FFI.ARGON2_INCORRECT_TYPE             -> Argon2IncorrectType
    FFI.ARGON2_OUT_PTR_MISMATCH           -> Argon2OutPtrMismatch
    FFI.ARGON2_THREADS_TOO_FEW            -> Argon2ThreadsTooFew
    FFI.ARGON2_THREADS_TOO_MANY           -> Argon2ThreadsTooMany
    FFI.ARGON2_MISSING_ARGS               -> Argon2MissingArgs
    FFI.ARGON2_ENCODING_FAIL              -> Argon2EncodingFail
    FFI.ARGON2_DECODING_FAIL              -> Argon2DecodingFail
    FFI.ARGON2_THREAD_FAIL                -> Argon2ThreadFail
    FFI.ARGON2_DECODING_LENGTH_FAIL       -> Argon2DecodingLengthFail
    FFI.ARGON2_VERIFY_MISMATCH            -> Argon2VerifyMismatch
    _                                     -> Argon2InternalError -- should never happen


hashEncoded' :: HashOptions
             -> BS.ByteString
             -> BS.ByteString
             -> IO TS.ShortText
hashEncoded' HashOptions{..} password salt = do
    outLen <- FFI.argon2_encodedlen
                  hashIterations
                  hashMemory
                  hashParallelism
                  saltLen
                  hashLength
                  (toArgon2Type hashVariant)

    allocaBytes (fromIntegral outLen) $ \out -> do
        res <- BS.useAsCString password $ \password' ->
               BS.useAsCString salt $ \salt' ->
               FFI.argon2_hash
                   hashIterations
                   hashMemory
                   hashParallelism
                   password'
                   passwordLen
                   salt'
                   (fromIntegral saltLen)
                   nullPtr
                   (fromIntegral hashLength)
                   out
                   outLen
                   (toArgon2Type hashVariant)
                   (toArgon2Ver hashVersion)

        handleSuccessCode res
        res' <- TS.fromByteString <$> BS.packCString out
        case res' of
          Nothing -> throwIO Argon2InternalError
          Just t  -> evaluate t

  where
    saltLen     = fromIntegral (BS.length salt)
    passwordLen = fromIntegral (BS.length password)


hash' :: HashOptions
      -> BS.ByteString
      -> BS.ByteString
      -> IO BS.ByteString
hash' HashOptions{..} password salt =
    allocaBytes (fromIntegral hashLength) $ \out -> do
        res <- BS.useAsCString password $ \password' ->
               BS.useAsCString salt $ \salt' ->
               FFI.argon2_hash
                   hashIterations
                   hashMemory
                   hashParallelism
                   password'
                   passwordLen
                   salt'
                   saltLen
                   out
                   (fromIntegral hashLength)
                   nullPtr
                   0
                   (toArgon2Type hashVariant)
                   (toArgon2Ver hashVersion)

        handleSuccessCode res
        evaluate =<< BS.packCStringLen (out, fromIntegral hashLength)
  where
    saltLen     = fromIntegral (BS.length salt)
    passwordLen = fromIntegral (BS.length password)

handleSuccessCode :: CInt -> IO ()
handleSuccessCode res = case toArgon2Status res of
                          Argon2Ok -> return ()
                          nok      -> throwIO nok

-- | Verify that a given password could result in a given hash output.
-- Automatically determines the correct 'HashOptions' based on the
-- encoded hash (using the [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) as produced by 'hashEncoded').
--
-- Returns 'Argon2Ok' on succesful verification. If decoding is
-- succesful but the password mismatches, 'Argon2VerifyMismatch' is
-- returned; if decoding fails, the respective 'Argon2Status' code is
-- returned.
verifyEncoded :: TS.ShortText -> BS.ByteString -> Argon2Status
verifyEncoded encoded password
  -- c.f. https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
  | "$argon2id$" `TS.isPrefixOf` encoded = unsafePerformIO $ go FFI.Argon2_id
  | "$argon2i$"  `TS.isPrefixOf` encoded = unsafePerformIO $ go FFI.Argon2_i
  | "$argon2d$"  `TS.isPrefixOf` encoded = unsafePerformIO $ go FFI.Argon2_d
  | otherwise                            = Argon2DecodingFail
  where
    go v = BS.useAsCString password $ \pwd ->
             BS.useAsCString (TS.toByteString encoded) $ \enc ->
               toArgon2Status <$> FFI.argon2_verify enc pwd (fromIntegral (BS.length password)) v
