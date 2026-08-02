# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ stdenv, fetchurl, patchelf, perl }:

stdenv.mkDerivation (finalAttrs: {
  pname = "openssl-4";
  version = "4.0.1";

  src = fetchurl {
    url = "https://github.com/openssl/openssl/releases/download/openssl-${finalAttrs.version}/openssl-${finalAttrs.version}.tar.gz";
    hash = "sha256-LbPzoNbqS1nh8JSs4sjNU23/uHzcOQhMWvoeb3833Qk=";
  };

  nativeBuildInputs = [ patchelf perl ];

  configurePhase = ''
    runHook preConfigure
    patchShebangs ./Configure
    ./Configure linux-x86_64 shared --prefix=$out --openssldir=$out/ssl
    runHook postConfigure
  '';

  buildPhase = "make -j$NIX_BUILD_CORES";
  installPhase = "make install_sw";

  postFixup = ''
    patchelf --add-rpath '$ORIGIN/../lib' "$out/bin/openssl"
  '';

  doCheck = false;
})
