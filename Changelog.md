# 1.2.0

- Updated embedded phc-winner-argon2, so that hashes are generated
  using version 1.3 of the argon2 specification.
  
  Note that that hashes generated using this version are different than
  hashes generated using previous versions, so anything that compares them
  or relies on them being stable may be broken by this update. 
  However, Crypto.Argon2.verify will continue to be able to verify
  hashes produced by previous versions.

- Use CSize for portability instead of Word64, fixing build on 32 bit
  systems. This changed the constructors of Argon2Exception, an API change.

- Bug fix: Crypto.Argon2.hash returned a ByteString truncated at the first
  NULL.

- Added use-system-library build flag.

- Build against `base-4.9`

# 1.1.0

- First stable release. Same API as 1.0.0, but now features documentation and
  expected type class instances for data types.

- QuickCheck properties added:

  1. verify (hashEncoded options password salt) password == True
  2. hash options password salt /= password

- `hash` now uses the underlying "raw" hash routines, rather than the encoded
  routines. This was a bug in 1.0.0. Thanks to @jorgen for this fix.

- `verify` added, in order to correctly verify that a password matches an 
  encoded password.

- `defaultHashOptions` are now more expensive.

# 1.0.0

- Initial release
