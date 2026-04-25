# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{
  description = "Reproducible development shell for Pion DTLS interoperability tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (import nixpkgs {
            inherit system;
          })
        );
    in
    {
      devShells = forAllSystems (
        pkgs:
        let
          go = pkgs.go_1_24 or pkgs.go;
          peerPackages =
            with pkgs;
            [
              openssl
            ]
            ++ lib.optionals stdenv.isLinux [
              boringssl
            ];
        in
        {
          default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                cacert
                git
                go
                go-task
                pkg-config
              ]
              ++ peerPackages;

            OPENSSL_CONF = ./openssl/openssl.cnf;
            RUNNER = "host";

            shellHook = ''
              export INTEROP_NIX_SHELL=1
            '';
          };
        }
      );
    };
}
