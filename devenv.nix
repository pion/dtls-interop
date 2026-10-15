# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ config, lib, pkgs, ... }:

let
  openssl3 = pkgs.callPackage ./nix/openssl-3.nix { };
  openssl4 = pkgs.callPackage ./nix/openssl-4.nix { };
  boringssl = pkgs.callPackage ./nix/boringssl.nix { };
  wolfssl = pkgs.callPackage ./nix/wolfssl.nix { };
  anvil = pkgs.callPackage ./nix/tls-anvil.nix { };
  selected = runner: config.interop.runner == "all" || config.interop.runner == runner;
in
{
  options.interop.runner = lib.mkOption {
    type = lib.types.enum [ "all" "pion-v3" "pion-v4" "openssl3" "openssl4" "boringssl" "wolfssl" "mbedtls" "anvil" ];
    default = "all";
    description = "Peer tools to include in the interoperability shell.";
  };

  config = {
    packages = [ pkgs.go_1_26 pkgs.go-task ]
      ++ lib.optionals (config.interop.runner == "all") [ pkgs.cmake pkgs.ninja pkgs.clang ]
      ++ lib.optional (selected "mbedtls") pkgs.mbedtls
      ++ lib.optional (selected "openssl3") (pkgs.writeShellScriptBin "openssl-3" ''
        exec ${openssl3}/bin/openssl "$@"
      '')
      ++ lib.optional (selected "openssl4") (pkgs.writeShellScriptBin "openssl-4" ''
        exec ${openssl4}/bin/openssl "$@"
      '')
      ++ lib.optional (selected "boringssl") (pkgs.writeShellScriptBin "bssl-shim" ''
        exec ${boringssl}/bin/bssl_shim "$@"
      '')
      ++ lib.optional (selected "wolfssl") wolfssl
      ++ lib.optional (selected "anvil") anvil;

    env = lib.optionalAttrs (selected "mbedtls") {
      DTLS_INTEROP_MBEDTLS_SERVER_BIN = "${pkgs.mbedtls}/bin/ssl_server2";
    } // lib.optionalAttrs (selected "openssl3") {
      DTLS_INTEROP_OPENSSL3_BIN = "${openssl3}/bin/openssl";
    } // lib.optionalAttrs (selected "openssl4") {
      DTLS_INTEROP_OPENSSL4_BIN = "${openssl4}/bin/openssl";
    } // lib.optionalAttrs (selected "boringssl") {
      DTLS_INTEROP_BSSL_SHIM_BIN = "${boringssl}/bin/bssl_shim";
    } // lib.optionalAttrs (selected "wolfssl") {
      DTLS_INTEROP_WOLFSSL_SERVER_BIN = "${wolfssl}/bin/wolfssl-dtls13-server";
      DTLS_INTEROP_WOLFSSL_CLIENT_BIN = "${wolfssl}/bin/wolfssl-dtls13-client";
    } // lib.optionalAttrs (selected "anvil") {
      DTLS_INTEROP_ANVIL_BIN = "${anvil}/bin/tls-anvil";
    };

    enterTest = ''
      go test ./...
    '';
  };
}
