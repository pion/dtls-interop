# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ lib, stdenv, fetchzip, cmake }:

stdenv.mkDerivation {
  pname = "wolfssl";
  version = "5.9.2";

  src = fetchzip {
    url = "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.2-stable.tar.gz";
    hash = "sha256-BKzmTkNWpBhYNBuMdzeL4XDZI/rXO1NrLkfwmwFcNng=";
  };

  nativeBuildInputs = [ cmake ];

  cmakeFlags = [
    "-DWOLFSSL_DTLS=YES"
    "-DWOLFSSL_DTLS13=YES"
    "-DWOLFSSL_DTLS_CID=YES"
    "-DWOLFSSL_EXAMPLES=NO"
    "-DWOLFSSL_CRYPT_TESTS=NO"
  ];

  meta = {
    description = "TLS/SSL library";
    homepage = "https://www.wolfssl.com/";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.unix;
  };
}
