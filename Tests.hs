{-# LANGUAGE OverloadedStrings #-}

import Crypto.Argon2
import Test.QuickCheck
import Test.Tasty
import Data.Ix
import Test.Tasty.QuickCheck
import qualified Crypto.Argon2.FFI as FFI
import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as T
import Data.Bits (shiftL)

arbitraryVariant :: Gen Argon2Variant
arbitraryVariant = arbitraryBoundedEnum

-- The hard-coded constants correspond to `decode_string`, but see
-- https://github.com/P-H-C/phc-winner-argon2/issues/77
arbitraryHashOptions :: Gen HashOptions
arbitraryHashOptions =
  do p <-
       arbitraryWithin (max (max FFI.ARGON2_MIN_LANES FFI.ARGON2_MIN_THREADS) 1)
                       (min (min FFI.ARGON2_MAX_LANES FFI.ARGON2_MAX_THREADS) 254)
     HashOptions <$>
       arbitraryWithin FFI.ARGON2_MIN_TIME
                       (min FFI.ARGON2_MAX_TIME (2 ^ 32 - 1)) <*>
       arbitraryWithin
         (max (max FFI.ARGON2_MIN_MEMORY (8 * p))
              (shiftL p 3))
         FFI.ARGON2_MAX_MEMORY <*>
       pure p <*>
       arbitraryVariant

arbitraryWithin lower upper = arbitrary `suchThat` (inRange (lower,upper))

arbitraryBytes :: Gen BS.ByteString
arbitraryBytes = fmap BS.pack arbitrary

arbitraryPassword :: Gen BS.ByteString
arbitraryPassword = arbitraryBytes `suchThat`
                             (\pwd ->
                                (FFI.ARGON2_MIN_PWD_LENGTH
                                ,FFI.ARGON2_MAX_PWD_LENGTH) `inRange`
                                BS.length pwd)

arbitrarySalt =
  arbitraryBytes `suchThat`
  (\salt ->
     (FFI.ARGON2_MIN_SALT_LENGTH,FFI.ARGON2_MAX_SALT_LENGTH) `inRange`
     BS.length salt)

main :: IO ()
main =
  defaultMain
    (testGroup "Properties"
               [testProperty
                  "Round trip"
                  (forAll arbitraryHashOptions $
                   \hashOptions ->
                     forAll arbitraryPassword $
                     \password ->
                       forAll arbitrarySalt $
                       \salt ->
                         verify (hashEncoded hashOptions password salt) password)])
