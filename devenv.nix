# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ pkgs, ... }:

let
  openssl3 = pkgs.callPackage ./nix/openssl-3.nix { };
  openssl4 = pkgs.callPackage ./nix/openssl-4.nix { };
  boringssl = pkgs.callPackage ./nix/boringssl.nix { };
in
{
  packages = [
    pkgs.go_1_26
    pkgs.go-task
    pkgs.cmake
    pkgs.ninja
    pkgs.clang
    (pkgs.writeShellScriptBin "openssl-3" ''
      exec ${openssl3}/bin/openssl "$@"
    '')
    (pkgs.writeShellScriptBin "openssl-4" ''
      exec ${openssl4}/bin/openssl "$@"
    '')
    (pkgs.writeShellScriptBin "bssl-shim" ''
      exec ${boringssl}/bin/bssl_shim "$@"
    '')
  ];

  env = {
    DTLS_INTEROP_OPENSSL3_BIN = "${openssl3}/bin/openssl";
    DTLS_INTEROP_OPENSSL4_BIN = "${openssl4}/bin/openssl";
    DTLS_INTEROP_BSSL_SHIM_BIN = "${boringssl}/bin/bssl_shim";
  };

  enterTest = ''
    go test ./...
  '';
}
