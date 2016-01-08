{ mkDerivation, base, stdenv }:
mkDerivation {
  pname = "argon2";
  version = "1.0.0";
  src = ./.;
  libraryHaskellDepends = [ base ];
  homepage = "https://github.com/ocharles/argon2.git";
  description = "Haskell bindings to libargon2 - the reference implementation of the Argon2 password-hashing function";
  license = stdenv.lib.licenses.bsd3;
}
