{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE PatternSynonyms #-}

module Crypto.Argon2.FFI where

#include <argon2.h>
#include <stdint.h>

import Foreign
import Foreign.C

foreign import ccall unsafe "argon2.h argon2i_hash_encoded" argon2i_hash_encoded :: (#type const uint32_t) -> (#type const uint32_t) -> (#type const uint32_t) -> Ptr a -> (#type const size_t) -> Ptr b -> (# type const size_t) -> (#type const size_t) -> CString -> (#type const size_t) -> IO (#type int)

foreign import ccall unsafe "argon2.h argon2i_hash_raw" argon2i_hash_raw :: (#type const uint32_t) -> (#type const uint32_t) -> (#type const uint32_t) -> Ptr a -> (#type const size_t) -> Ptr b -> (#type size_t) -> Ptr c -> (#type const size_t) -> IO (#type int)

foreign import ccall unsafe "argon2.h argon2d_hash_encoded" argon2d_hash_encoded :: (#type const uint32_t) -> (#type const uint32_t) -> (#type const uint32_t) -> Ptr a -> (#type const size_t) -> Ptr b -> (# type const size_t) -> (#type const size_t) -> CString -> (#type const size_t) -> IO (#type int)

foreign import ccall unsafe "argon2.h argon2d_hash_raw" argon2d_hash_raw :: (#type const uint32_t) -> (#type const uint32_t) -> (#type const uint32_t) -> Ptr a -> (#type const size_t) -> Ptr b -> (#type size_t) -> Ptr c -> (#type const size_t) -> IO (#type int)

foreign import ccall unsafe "argon2.h argon2i_verify" argon2i_verify :: CString -> Ptr a -> (#type const size_t) -> IO (#type int)

foreign import ccall unsafe "argon2.h argon2d_verify" argon2d_verify :: CString -> Ptr a -> (#type const size_t) -> IO (#type int)

pattern ARGON2_OK = (#const ARGON2_OK)
pattern ARGON2_OUTPUT_PTR_NULL = (#const ARGON2_OUTPUT_PTR_NULL)
pattern ARGON2_OUTPUT_TOO_SHORT = (#const ARGON2_OUTPUT_TOO_SHORT)
pattern ARGON2_OUTPUT_TOO_LONG = (#const ARGON2_OUTPUT_TOO_LONG)
pattern ARGON2_PWD_TOO_SHORT = (#const ARGON2_PWD_TOO_SHORT)
pattern ARGON2_PWD_TOO_LONG = (#const ARGON2_PWD_TOO_LONG)
pattern ARGON2_SALT_TOO_SHORT = (#const ARGON2_SALT_TOO_SHORT)
pattern ARGON2_SALT_TOO_LONG = (#const ARGON2_SALT_TOO_LONG)
pattern ARGON2_AD_TOO_SHORT = (#const ARGON2_AD_TOO_SHORT)
pattern ARGON2_AD_TOO_LONG = (#const ARGON2_AD_TOO_LONG)
pattern ARGON2_SECRET_TOO_SHORT = (#const ARGON2_SECRET_TOO_SHORT)
pattern ARGON2_SECRET_TOO_LONG = (#const ARGON2_SECRET_TOO_LONG)
pattern ARGON2_TIME_TOO_SMALL = (#const ARGON2_TIME_TOO_SMALL)
pattern ARGON2_TIME_TOO_LARGE = (#const ARGON2_TIME_TOO_LARGE)
pattern ARGON2_MEMORY_TOO_LITTLE = (#const ARGON2_MEMORY_TOO_LITTLE)
pattern ARGON2_MEMORY_TOO_MUCH = (#const ARGON2_MEMORY_TOO_MUCH)
pattern ARGON2_LANES_TOO_FEW = (#const ARGON2_LANES_TOO_FEW)
pattern ARGON2_LANES_TOO_MANY = (#const ARGON2_LANES_TOO_MANY)
pattern ARGON2_PWD_PTR_MISMATCH = (#const ARGON2_PWD_PTR_MISMATCH)
pattern ARGON2_SALT_PTR_MISMATCH = (#const ARGON2_SALT_PTR_MISMATCH)
pattern ARGON2_SECRET_PTR_MISMATCH = (#const ARGON2_SECRET_PTR_MISMATCH)
pattern ARGON2_AD_PTR_MISMATCH = (#const ARGON2_AD_PTR_MISMATCH)
pattern ARGON2_MEMORY_ALLOCATION_ERROR = (#const ARGON2_MEMORY_ALLOCATION_ERROR)
pattern ARGON2_FREE_MEMORY_CBK_NULL = (#const ARGON2_FREE_MEMORY_CBK_NULL)
pattern ARGON2_ALLOCATE_MEMORY_CBK_NULL = (#const ARGON2_ALLOCATE_MEMORY_CBK_NULL)
pattern ARGON2_INCORRECT_PARAMETER = (#const ARGON2_INCORRECT_PARAMETER)
pattern ARGON2_INCORRECT_TYPE = (#const ARGON2_INCORRECT_TYPE)
pattern ARGON2_OUT_PTR_MISMATCH = (#const ARGON2_OUT_PTR_MISMATCH)
pattern ARGON2_THREADS_TOO_FEW = (#const ARGON2_THREADS_TOO_FEW)
pattern ARGON2_THREADS_TOO_MANY = (#const ARGON2_THREADS_TOO_MANY)
pattern ARGON2_MISSING_ARGS = (#const ARGON2_MISSING_ARGS)
pattern ARGON2_ENCODING_FAIL = (#const ARGON2_ENCODING_FAIL)
pattern ARGON2_DECODING_FAIL = (#const ARGON2_DECODING_FAIL)

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

pattern ARGON2_FLAG_CLEAR_PASSWORD = (#const ARGON2_FLAG_CLEAR_PASSWORD)
pattern ARGON2_FLAG_CLEAR_SECRET = (#const ARGON2_FLAG_CLEAR_SECRET)
pattern ARGON2_FLAG_CLEAR_MEMORY = (#const ARGON2_FLAG_CLEAR_MEMORY)
pattern ARGON2_DEFAULT_FLAGS = (#const ARGON2_DEFAULT_FLAGS)
