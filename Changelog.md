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

# 1.0.0

- Initial release
