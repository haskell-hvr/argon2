{-# LANGUAGE OverloadedStrings #-}

import           Crypto.Argon2
import qualified Crypto.Argon2.FFI     as FFI
import           Data.Bits             (shiftL)
import qualified Data.ByteString       as BS
import           Data.Ix
import           Test.QuickCheck
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck

arbitraryVariant :: Gen Argon2Variant
arbitraryVariant = arbitraryBoundedEnum

arbitraryVersion :: Gen Argon2Version
arbitraryVersion = arbitraryBoundedEnum

arbitraryHashOptions :: Gen HashOptions
arbitraryHashOptions =
  do p <- arbitraryWithin 1 4
     HashOptions <$> arbitraryWithin FFI.ARGON2_MIN_TIME (min FFI.ARGON2_MAX_TIME 65536)
                 <*> arbitraryWithin (FFI.ARGON2_MIN_MEMORY*p) (FFI.ARGON2_MIN_MEMORY*p*4)  -- arbitraryWithin (max (max FFI.ARGON2_MIN_MEMORY (8 * p)) (shiftL p 3)) (min FFI.ARGON2_MAX_MEMORY 512)
                 <*> pure p
                 <*> arbitraryVariant
                 <*> arbitraryVersion
                 <*> arbitraryWithin FFI.ARGON2_MIN_OUTLEN (min FFI.ARGON2_MAX_OUTLEN 65536)

arbitraryWithin lower upper = arbitrary `suchThat` (inRange (lower,upper))

arbitraryBytes :: Gen BS.ByteString
arbitraryBytes = BS.pack <$> arbitrary

arbitraryPassword :: Gen BS.ByteString
arbitraryPassword = arbitraryBytes `suchThat`
                    (\pwd -> (FFI.ARGON2_MIN_PWD_LENGTH,FFI.ARGON2_MAX_PWD_LENGTH) `inRange` BS.length pwd)

arbitrarySalt = arbitraryBytes `suchThat`
                (\salt -> (FFI.ARGON2_MIN_SALT_LENGTH,FFI.ARGON2_MAX_SALT_LENGTH) `inRange` BS.length salt)

main :: IO ()
main = defaultMain $ testGroup "Tests" [unitTests,props]
  where
    props = testGroup "Properties"
       [ testProperty "Round trip"
                  (forAll arbitraryHashOptions $ \hashOptions ->
                   forAll arbitraryPassword $ \password ->
                   forAll arbitrarySalt $ \salt ->
                         verifyEncoded (hashEncoded hashOptions password salt) password)

       , testProperty "Unencoded hashing"
                  (forAll arbitraryHashOptions $ \hashOptions ->
                   forAll arbitraryPassword $ \password ->
                   forAll arbitrarySalt $ \salt ->
                          hash hashOptions password salt /= password)

       , testProperty "defaultHashOptions"
                  (forAll arbitraryVariant $ \variant ->
                  (forAll arbitraryPassword $ \password ->
                   forAll arbitrarySalt $ \salt ->
                          verifyEncoded (hashEncoded
                                    (defaultHashOptions {hashVariant = variant})
                                    password
                                    salt)
                                 password))
       ]


    unitTests = testGroup "KATs"
       [ testGroup "argon2 README" $
         let opts = defaultHashOptions { hashVariant     = Argon2i
                                       , hashMemory      = 2^16
                                       , hashIterations  = 2
                                       , hashParallelism = 4
                                       , hashLength      = 24
                                       , hashVersion     = Argon2Version13
                                       }
         in [ testCase "hashEncoded" $
              hashEncoded opts "password" "somesalt" @?= "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
            , testCase "verifyEncoded" $
              verifyEncoded "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" "password" @?= True
            , testCase "verifyEncoded 2" $
              verifyEncoded "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" "passvord" @?= False
            , testCase "verifyEncoded 3" $
              verifyEncoded "$argon2d$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" "password" @?= False
            , testCase "verifyEncoded 4" $
              verifyEncoded "$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" "password" @?= False
            , testCase "hash" $
              hash opts "password" "somesalt" @?= "\x45\xD7\xAC\x72\xE7\x6F\x24\x2B\x20\xB7\x7B\x9B\xF9\xBF\x9D\x59\x15\x89\x4E\x66\x9A\x24\xE6\xC6"
            ]
       ]
