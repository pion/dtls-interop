# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ lib, stdenv, fetchzip, cmake, makeWrapper, patchelf }:

stdenv.mkDerivation {
  pname = "wolfssl";
  version = "5.9.2";

  src = fetchzip {
    url = "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.2-stable.tar.gz";
    hash = "sha256-BKzmTkNWpBhYNBuMdzeL4XDZI/rXO1NrLkfwmwFcNng=";
  };

  nativeBuildInputs = [ cmake makeWrapper patchelf ];

  cmakeFlags = [
    "-DWOLFSSL_DTLS=YES"
    "-DWOLFSSL_DTLS13=YES"
    "-DWOLFSSL_DTLS_CID=YES"
    "-DWOLFSSL_EXAMPLES=YES"
    "-DWOLFSSL_CRYPT_TESTS=NO"
  ];

  postInstall = ''
    install -Dm755 examples/server/server "$out/libexec/wolfssl-dtls13-server"
    install -Dm755 examples/client/client "$out/libexec/wolfssl-dtls13-client"
    install -d "$out/share/wolfssl"
    cp -r "$NIX_BUILD_TOP/$sourceRoot/certs" "$out/share/wolfssl/certs"
    patchelf --set-rpath "$out/lib" "$out/libexec/wolfssl-dtls13-server"
    patchelf --set-rpath "$out/lib" "$out/libexec/wolfssl-dtls13-client"
    makeWrapper "$out/libexec/wolfssl-dtls13-server" "$out/bin/wolfssl-dtls13-server" \
      --chdir "$out/share/wolfssl"
    makeWrapper "$out/libexec/wolfssl-dtls13-client" "$out/bin/wolfssl-dtls13-client" \
      --chdir "$out/share/wolfssl"
  '';

  meta = {
    description = "TLS/SSL library";
    homepage = "https://www.wolfssl.com/";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.unix;
  };
}
