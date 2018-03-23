{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE Trustworthy        #-}

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
      hashEncoded
    , hash
      -- * Verification
    , verifyEncoded
      -- * Configuring hashing
    , HashOptions(..)
    , Argon2Variant(..)
    , Argon2Version(..)
    , defaultHashOptions
      -- * Exceptions
    , Argon2Exception(..)
    ) where

import           Control.Exception
import qualified Crypto.Argon2.FFI as FFI
import qualified Data.ByteString   as BS
import qualified Data.Text.Short   as TS
import           Data.Typeable
import           Foreign
import           Foreign.C
import           GHC.Generics      (Generic)
import           Numeric.Natural
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

-- | Version of the Argon2 algorithm.
data Argon2Version
  = Argon2Version10 -- ^ Version 1.0 (deprecated)
  | Argon2Version13 -- ^ Version 1.3 (See [this announcment](https://www.ietf.org/mail-archive/web/cfrg/current/msg07948.html) for more details)
  deriving (Eq,Ord,Read,Show,Bounded,Generic,Typeable,Enum)

-- | Parameters that can be adjusted to change the runtime performance of the
-- hashing.
data HashOptions =
  HashOptions { hashIterations  :: !Word32 -- ^ The time cost, which defines the amount of computation realized and therefore the execution time, given in number of iterations.
                                         --
                                         -- 'FFI.ARGON2_MIN_TIME' <= 'hashIterations' <= 'FFI.ARGON2_MAX_TIME'
              , hashMemory      :: !Word32 -- ^ The memory cost, which defines the memory usage, given in kibibytes.
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
--   'HashOptions' { 'hashIterations' = 3
--               , 'hashMemory' = 2 ^ 12 -- 4 MiB
--               , 'hashParallelism' = 1
--               , 'hashVariant' = 'Argon2i'
--               , 'hashVersion' = 'Argon2V13'
--               , 'hashLength'  = 2 ^ 5 -- 32 bytes
--               }
-- @
defaultHashOptions :: HashOptions
defaultHashOptions = HashOptions
    { hashIterations  = 3
    , hashMemory      = 2 ^ 12 -- 4 MiB
    , hashParallelism = 1
    , hashVariant     = Argon2i
    , hashVersion     = Argon2Version13
    , hashLength      = 32
    }

-- | Encode a password with a given salt and 'HashOptions' and produce a textual
-- encoding of the result.
hashEncoded :: HashOptions   -- ^ Options pertaining to how expensive the hash is to calculate.
            -> BS.ByteString -- ^ The password to hash. Must be less than 4294967295 bytes.
            -> BS.ByteString -- ^ The salt to use when hashing. Must be less than 4294967295 bytes.
            -> TS.ShortText  -- ^ The encoded password hash.
hashEncoded options password salt = unsafePerformIO $ hashEncoded' options password salt

-- | Encode a password with a given salt and 'HashOptions' and produce a stream
-- of bytes.
hash :: HashOptions -- ^ Options pertaining to how expensive the hash is to calculate.
     -> BS.ByteString -- ^ The password to hash. Must be less than 4294967295 bytes.
     -> BS.ByteString -- ^ The salt to use when hashing. Must be less than 4294967295 bytes.
     -> BS.ByteString -- ^ The un-encoded password hash.
hash options password salt = unsafePerformIO $ hash' options password salt

variant :: a -> a -> a -> Argon2Variant -> a
variant a _ _ Argon2i  = a
variant _ b _ Argon2d  = b
variant _ _ c Argon2id = c
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
    Argon2Exception !CInt -- ^ The @libargon2@ error code.
  deriving (Typeable, Show)

instance Exception Argon2Exception

type Argon2Encoded = Word32 -> Word32 -> Word32 -> CString -> CSize -> CString -> CSize -> CSize -> CString -> CSize -> IO Int32

hashEncoded' :: HashOptions
             -> BS.ByteString
             -> BS.ByteString
             -> IO TS.ShortText
hashEncoded' options@HashOptions{..} password salt = do
    outLen <- FFI.argon2_encodedlen
                  hashIterations
                  hashMemory
                  hashParallelism
                  saltLen
                  hashLength
                  argon2type

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
                   argon2type
                   argon2ver

        handleSuccessCode res options password salt
        res' <- TS.fromByteString <$> BS.packCString out
        case res' of
          Nothing -> fail "Argon2.hashEncoded: the impossible happened"
          Just t  -> return t

  where
    saltLen     = fromIntegral (BS.length salt)
    passwordLen = fromIntegral (BS.length password)
    argon2type  = variant FFI.Argon2_i FFI.Argon2_d FFI.Argon2_id hashVariant
    argon2ver   = case hashVersion of
                    Argon2Version10 -> FFI.ARGON2_VERSION_10
                    Argon2Version13 -> FFI.ARGON2_VERSION_13

type Argon2Unencoded = Word32 -> Word32 -> Word32 -> CString -> CSize -> CString -> CSize -> CString -> CSize -> IO Int32

hash' :: HashOptions
      -> BS.ByteString
      -> BS.ByteString
      -> IO BS.ByteString
hash' options@HashOptions{..} password salt =
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
                   (fromIntegral saltLen)
                   out
                   (fromIntegral hashLength)
                   nullPtr
                   0
                   argon2type
                   argon2ver

        handleSuccessCode res options password salt
        BS.packCStringLen (out, fromIntegral hashLength)
  where
    saltLen     = fromIntegral (BS.length salt)
    passwordLen = fromIntegral (BS.length password)
    argon2type  = variant FFI.Argon2_i FFI.Argon2_d FFI.Argon2_id hashVariant
    argon2ver   = case hashVersion of
                    Argon2Version10 -> FFI.ARGON2_VERSION_10
                    Argon2Version13 -> FFI.ARGON2_VERSION_13

handleSuccessCode :: CInt
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
         | a `elem` [FFI.ARGON2_LANES_TOO_FEW,FFI.ARGON2_LANES_TOO_MANY
                    ,FFI.ARGON2_THREADS_TOO_FEW,FFI.ARGON2_THREADS_TOO_MANY] ->
           throwIO (Argon2ParallelismOutOfRange hashParallelism)
         | otherwise -> throwIO (Argon2Exception a)

-- | Verify that a given password could result in a given hash output.
-- Automatically determines the correct 'HashOptions' based on the
-- encoded hash (as produced by 'hashEncoded').
verifyEncoded :: TS.ShortText -> BS.ByteString -> Bool
verifyEncoded encoded password
  -- c.f. https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
  | "$argon2id$" `TS.isPrefixOf` encoded = unsafePerformIO $ go FFI.Argon2_id
  | "$argon2i$"  `TS.isPrefixOf` encoded = unsafePerformIO $ go FFI.Argon2_i
  | "$argon2d$"  `TS.isPrefixOf` encoded = unsafePerformIO $ go FFI.Argon2_d
  | otherwise                                  = False
  where
    go v = BS.useAsCString password $ \pwd ->
           BS.useAsCString (TS.toByteString encoded) $ \enc -> do
               res <- FFI.argon2_verify enc pwd (fromIntegral (BS.length password)) v
               return $! res == FFI.ARGON2_OK
