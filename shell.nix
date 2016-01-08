{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let

  inherit (nixpkgs) pkgs;

  f = { mkDerivation, base, bytestring, exceptions, stdenv, text
      , transformers
      }:
      mkDerivation {
        pname = "argon2";
        version = "1.0.0";
        src = ./.;
        libraryHaskellDepends = [
          base bytestring exceptions text transformers
        ];
        homepage = "https://github.com/ocharles/argon2.git";
        description = "Haskell bindings to libargon2 - the reference implementation of the Argon2 password-hashing function";
        license = stdenv.lib.licenses.bsd3;
      };

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  drv = haskellPackages.callPackage f {};

in

  if pkgs.lib.inNixShell then drv.env else drv
