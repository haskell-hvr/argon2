{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE Unsafe #-}

-- |
-- Module      : Crypto.Argon2.FFI
-- License     : BSD3
-- Maintainer  : hvr@gnu.org
--
-- This module provides low-level access to parts of the C API
--
-- Prefer the "Crypto.Argon2" API when possible.
module Crypto.Argon2.FFI where

#include <argon2.h>
#include <stdint.h>

import Foreign
import Foreign.C


#if !defined(USE_SYSTEM_ARGON2)
# error USE_SYSTEM_ARGON2 undefined
#endif

-- * @libargon2@ functions

-- | Compute Argon2 hash
--
-- > int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
-- >                 const uint32_t parallelism, const void *pwd,
-- >                 const size_t pwdlen, const void *salt,
-- >                 const size_t saltlen, void *hash,
-- >                 const size_t hashlen, char *encoded,
-- >                 const size_t encodedlen, argon2_type type,
-- >                 const uint32_t version);
--
-- === __Parameters__
--
--  [t_cost] Number of iterations
--  [m_cost] Sets memory usage to m_cost kibibytes
--  [parallelism] Number of threads and compute lanes
--  [pwd] Pointer to password
--  [pwdlen] Password size in bytes
--  [salt] Pointer to salt
--  [saltlen] Salt size in bytes
--  [hash] Buffer where to write the raw hash
--  [hashlen] Desired length of the hash in bytes
--  [encoded] Buffer where to write the encoded hash
--  [encodedlen] Size of the buffer (thus max size of the encoded hash)
--  [type] Variant of Argon2 hash
--  [version] Version of Argon2 specification
--
foreign import ccall safe
#if USE_SYSTEM_ARGON2
    "argon2.h argon2_hash"
#else
    "argon2.h hs_argon2__argon2_hash"
#endif
    argon2_hash
    :: Word32 {- t_cost -}
    -> Word32 {- m_cost -}
    -> Word32 {- parallelism -}
    -> Ptr a -> CSize {- pwd  + pwdlen -}
    -> Ptr b -> CSize {- salt + saltlen -}
    -> Ptr c -> CSize {- hash + hashlen -}
    -> CString -> CSize {- encoded + encodedlen -}
    -> Argon2_type
    -> Argon2_version
    -> IO CInt

-- | Verify encoded hash
--
-- > int argon2_verify(const char *encoded, const void *pwd,
-- >                   const size_t pwdlen, argon2_type type);
--
-- === __Parameters__
--
--  [encoded] Pointer to zero-terminated encoded hash
--  [pwd] Pointer to password
--  [pwdlen] Password size in bytes
--  [type] Variant of Argon2 hash
--
foreign import ccall safe
#if USE_SYSTEM_ARGON2
    "argon2.h argon2_verify"
#else
    "argon2.h hs_argon2__argon2_verify"
#endif
    argon2_verify
    :: CString -> Ptr a -> CSize -> Argon2_type -> IO CInt

-- | Compute size of encoded hash
--
-- > size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
-- >                          uint32_t saltlen, uint32_t hashlen, argon2_type type);
--
-- === __Parameters__
--
--  [t_cost] Number of iterations
--  [m_cost] Sets memory usage to m_cost kibibytes
--  [parallelism] Number of threads and compute lanes
--  [salt] Pointer to salt
--  [saltlen] Salt size in bytes
--  [hashlen] Desired length of the hash in bytes
--  [type] Variant of Argon2 hash
--
foreign import ccall unsafe
#if USE_SYSTEM_ARGON2
    "argon2.h argon2_encodedlen"
#else
    "argon2.h hs_argon2__argon2_encodedlen"
#endif
    argon2_encodedlen
    :: Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> Argon2_type -> CSize

-- * @libargon2@ API typedefs

-- ** @argon2_type@

type Argon2_type = (#type argon2_type)
pattern Argon2_d  = (#const Argon2_d)
pattern Argon2_i  = (#const Argon2_i)
pattern Argon2_id = (#const Argon2_id)

-- ** @argon2_version@

type Argon2_version = Word32 -- NB, not (#type argon2_version)
pattern ARGON2_VERSION_10 = (#const ARGON2_VERSION_10)
pattern ARGON2_VERSION_13 = (#const ARGON2_VERSION_13)
pattern ARGON2_VERSION_NUMBER = (#const ARGON2_VERSION_NUMBER)

-- ** @argon2_error_codes@

-- argon2_error_codes
pattern ARGON2_OK                       = (#const ARGON2_OK)
pattern ARGON2_OUTPUT_PTR_NULL          = (#const ARGON2_OUTPUT_PTR_NULL)
pattern ARGON2_OUTPUT_TOO_SHORT         = (#const ARGON2_OUTPUT_TOO_SHORT)
pattern ARGON2_OUTPUT_TOO_LONG          = (#const ARGON2_OUTPUT_TOO_LONG)
pattern ARGON2_PWD_TOO_SHORT            = (#const ARGON2_PWD_TOO_SHORT)
pattern ARGON2_PWD_TOO_LONG             = (#const ARGON2_PWD_TOO_LONG)
pattern ARGON2_SALT_TOO_SHORT           = (#const ARGON2_SALT_TOO_SHORT)
pattern ARGON2_SALT_TOO_LONG            = (#const ARGON2_SALT_TOO_LONG)
pattern ARGON2_AD_TOO_SHORT             = (#const ARGON2_AD_TOO_SHORT)
pattern ARGON2_AD_TOO_LONG              = (#const ARGON2_AD_TOO_LONG)
pattern ARGON2_SECRET_TOO_SHORT         = (#const ARGON2_SECRET_TOO_SHORT)
pattern ARGON2_SECRET_TOO_LONG          = (#const ARGON2_SECRET_TOO_LONG)
pattern ARGON2_TIME_TOO_SMALL           = (#const ARGON2_TIME_TOO_SMALL)
pattern ARGON2_TIME_TOO_LARGE           = (#const ARGON2_TIME_TOO_LARGE)
pattern ARGON2_MEMORY_TOO_LITTLE        = (#const ARGON2_MEMORY_TOO_LITTLE)
pattern ARGON2_MEMORY_TOO_MUCH          = (#const ARGON2_MEMORY_TOO_MUCH)
pattern ARGON2_LANES_TOO_FEW            = (#const ARGON2_LANES_TOO_FEW)
pattern ARGON2_LANES_TOO_MANY           = (#const ARGON2_LANES_TOO_MANY)
pattern ARGON2_PWD_PTR_MISMATCH         = (#const ARGON2_PWD_PTR_MISMATCH)
pattern ARGON2_SALT_PTR_MISMATCH        = (#const ARGON2_SALT_PTR_MISMATCH)
pattern ARGON2_SECRET_PTR_MISMATCH      = (#const ARGON2_SECRET_PTR_MISMATCH)
pattern ARGON2_AD_PTR_MISMATCH          = (#const ARGON2_AD_PTR_MISMATCH)
pattern ARGON2_MEMORY_ALLOCATION_ERROR  = (#const ARGON2_MEMORY_ALLOCATION_ERROR)
pattern ARGON2_FREE_MEMORY_CBK_NULL     = (#const ARGON2_FREE_MEMORY_CBK_NULL)
pattern ARGON2_ALLOCATE_MEMORY_CBK_NULL = (#const ARGON2_ALLOCATE_MEMORY_CBK_NULL)
pattern ARGON2_INCORRECT_PARAMETER      = (#const ARGON2_INCORRECT_PARAMETER)
pattern ARGON2_INCORRECT_TYPE           = (#const ARGON2_INCORRECT_TYPE)
pattern ARGON2_OUT_PTR_MISMATCH         = (#const ARGON2_OUT_PTR_MISMATCH)
pattern ARGON2_THREADS_TOO_FEW          = (#const ARGON2_THREADS_TOO_FEW)
pattern ARGON2_THREADS_TOO_MANY         = (#const ARGON2_THREADS_TOO_MANY)
pattern ARGON2_MISSING_ARGS             = (#const ARGON2_MISSING_ARGS)
pattern ARGON2_ENCODING_FAIL            = (#const ARGON2_ENCODING_FAIL)
pattern ARGON2_DECODING_FAIL            = (#const ARGON2_DECODING_FAIL)
pattern ARGON2_THREAD_FAIL              = (#const ARGON2_THREAD_FAIL)
pattern ARGON2_DECODING_LENGTH_FAIL     = (#const ARGON2_DECODING_LENGTH_FAIL)
pattern ARGON2_VERIFY_MISMATCH          = (#const ARGON2_VERIFY_MISMATCH)

-- * @libargon2@ limits & constants

pattern ARGON2_MIN_LANES = (#const ARGON2_MIN_LANES)
pattern ARGON2_MAX_LANES = (#const ARGON2_MAX_LANES)

pattern ARGON2_MIN_THREADS = (#const ARGON2_MIN_THREADS)
pattern ARGON2_MAX_THREADS = (#const ARGON2_MAX_THREADS)

pattern ARGON2_SYNC_POINTS = (#const ARGON2_SYNC_POINTS)

pattern ARGON2_MIN_OUTLEN = (#const ARGON2_MIN_OUTLEN)
pattern ARGON2_MAX_OUTLEN = (#const ARGON2_MAX_OUTLEN)

pattern ARGON2_MIN_MEMORY = (#const ARGON2_MIN_MEMORY)

pattern ARGON2_MAX_MEMORY_BITS = (#const ARGON2_MAX_MEMORY_BITS)
pattern ARGON2_MAX_MEMORY = (#const ARGON2_MAX_MEMORY)

pattern ARGON2_MIN_TIME = (#const ARGON2_MIN_TIME)
pattern ARGON2_MAX_TIME = (#const ARGON2_MAX_TIME)

pattern ARGON2_MIN_PWD_LENGTH = (#const ARGON2_MIN_PWD_LENGTH)
pattern ARGON2_MAX_PWD_LENGTH = (#const ARGON2_MAX_PWD_LENGTH)

pattern ARGON2_MIN_AD_LENGTH = (#const ARGON2_MIN_AD_LENGTH)
pattern ARGON2_MAX_AD_LENGTH = (#const ARGON2_MAX_AD_LENGTH)

pattern ARGON2_MIN_SALT_LENGTH = (#const ARGON2_MIN_SALT_LENGTH)
pattern ARGON2_MAX_SALT_LENGTH = (#const ARGON2_MAX_SALT_LENGTH)

pattern ARGON2_MIN_SECRET = (#const ARGON2_MIN_SECRET)
pattern ARGON2_MAX_SECRET = (#const ARGON2_MAX_SECRET)

{-

/* Global flag to determine if we are wiping internal memory buffers. This flag
 * is defined in core.c and deafults to 1 (wipe internal memory). */
extern int FLAG_clear_internal_memory;

pattern ARGON2_FLAG_CLEAR_PASSWORD = (#const ARGON2_FLAG_CLEAR_PASSWORD)
pattern ARGON2_FLAG_CLEAR_SECRET   = (#const ARGON2_FLAG_CLEAR_SECRET)
pattern ARGON2_DEFAULT_FLAGS       = (#const ARGON2_DEFAULT_FLAGS)

-}

