# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ stdenv, fetchFromGitHub, cmake, ninja, clang, perl, go }:

stdenv.mkDerivation {
  pname = "boringssl";
  version = "0.20260730.0";

  src = fetchFromGitHub {
    owner = "google";
    repo = "boringssl";
    rev = "79a292fdae25c074f19e6ec53a9b0c465051be91";
    hash = "sha256-k+dw4zjDQRqMgCMU8m1FgOgeQLpRb4f/dTEahFLdRWs=";
  };

  nativeBuildInputs = [ cmake ninja clang perl go ];

  configurePhase = ''
    runHook preConfigure
    cmake -S . -B build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=${clang}/bin/clang \
      -DCMAKE_CXX_COMPILER=${clang}/bin/clang++
    runHook postConfigure
  '';

  buildPhase = "ninja -C build bssl_shim";

  installPhase = ''
    install -Dm755 build/ssl/test/bssl_shim $out/bin/bssl_shim
  '';
}
