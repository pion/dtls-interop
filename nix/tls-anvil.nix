# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

{ lib, stdenvNoCC, fetchurl, fetchFromGitHub, runCommand, maven, unzip, jdk_headless, graalvmPackages, makeWrapper }:

let
  # Reuse the release's dependency jars while compiling Anvil from pinned branche.
  dependencies = fetchurl {
    url = "https://github.com/tls-attacker/TLS-Anvil/releases/download/v1.5.3/TLS-Anvil-v1.5.3.zip";
    hash = "sha256-JhioQZom6B9yZJQ38vULA1YJ0j3vO2LycAh96ZMRNB8=";
  };

  scannerDependencies = runCommand "tls-scanner-dependencies-7.8.2" {
    nativeBuildInputs = [ maven ];
    JAVA_HOME = jdk_headless;
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-4YIv0bREzbyyAtlo9VE6Z+CVSO0wduSxfWLtM9mFvNM=";
  } ''
    cat > pom.xml <<'EOF'
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion>
      <groupId>ly.pion</groupId><artifactId>scanner-dependencies</artifactId><version>1</version>
      <dependencies>
        <dependency>
          <groupId>de.rub.nds.tls.scanner</groupId><artifactId>tls-client-scanner</artifactId><version>7.8.2</version>
        </dependency>
        <dependency>
          <groupId>de.rub.nds.tls.scanner</groupId><artifactId>tls-server-scanner</artifactId><version>7.8.2</version>
        </dependency>
      </dependencies>
    </project>
    EOF
    mvn -B -Dmaven.repo.local="$TMPDIR/m2" \
      org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
      -DincludeScope=runtime -DoutputDirectory="$out"
  '';

  tlsScannerSrc = fetchFromGitHub {
    owner = "JoTurk";
    repo = "TLS-Scanner";
    rev = "1385dbec1c24413d377b68df241627fce821728f"; # jo/dtls-13
    hash = "sha256-q43VXIw0THpjQWHafsUqsyjpeB3BW1ygKLKI9PpFVe8=";
  };

  # ChaCha20 record-number encryption and ACK handling.
  # https://github.com/tls-attacker/TLS-Attacker/pull/250
  # https://github.com/tls-attacker/TLS-Attacker/pull/251
  tlsAttackerSrc = fetchFromGitHub {
    owner = "JoTurk";
    repo = "TLS-Attacker";
    rev = "2840b754e13a949a90502fb9d8033c6c86acf363";
    hash = "sha256-xxMKZxJ5kSYacm+YMnhwTK5bPrbayZhmGco4pdb/0Kg=";
  };

  # Cache dependencies and Scanner independently of Anvil and its runtime.
  compiledDependencies = runCommand "tls-anvil-dependencies" {
    nativeBuildInputs = [ unzip jdk_headless ];
  } ''
    unzip -q ${dependencies} -d dependencies
    cp -r dependencies/apps/lib .
    chmod -R u+w lib
    rm lib/tls-test-framework-*.jar
    for dependency in ${scannerDependencies}/*.jar; do
      name=$(basename "$dependency" | sed 's/-[0-9].*//')
      rm -f lib/"$name"-[0-9]*.jar
      cp "$dependency" lib/
    done

    # Compile Scanner from the branch and include Attacker's DTLS 1.3 fixes.
    find ${tlsScannerSrc}/TLS-{Scanner-Core,Client-Scanner,Server-Scanner}/src/main/java \
      -name '*.java' > scanner-sources
    tlsCorePackage=${tlsAttackerSrc}/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core
    javac -proc:none -cp 'lib/*' -d dependency-classes \
      "$tlsCorePackage/constants/Dtls13MaskConstans.java" \
      "$tlsCorePackage/crypto/cipher/ChaCha20Poly1305Cipher.java" \
      "$tlsCorePackage/workflow/container/ActionHelperUtil.java" \
      @scanner-sources
    jar --create --file dependency-fixes.jar -C dependency-classes .

    mkdir -p $out
    cp -r lib dependency-fixes.jar $out/
  '';

  application = stdenvNoCC.mkDerivation {
    pname = "tls-anvil";
    version = "1.5.3-unstable-2026-10-15";

    src = fetchFromGitHub {
      owner = "JoTurk";
      repo = "TLS-Anvil";
      rev = "1fc71886b6173b9a3d3a2090dacea2193bfb87a0"; # jo/dtls-13
      hash = "sha256-zlS9JK97IZT5PqZoRHWNOVvS1KMhu5wNSqohfDZd++Y=";
    };

    nativeBuildInputs = [ jdk_headless ];

    # Adapt Anvil's older API calls to Scanner's TLS-Attacker dependency.
    postPatch = ''
      substituteInPlace \
        TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/FeatureExtractionResult.java \
        TLS-Testsuite/src/main/java/de/rub/nds/tlstest/suite/tests/{client,server}/tls13/rfc8446/KeyShare.java \
        --replace-fail 'isCurve' 'isEcGroup'
      substituteInPlace \
        TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/model/derivationParameter/CertificateDerivation.java \
        --replace-fail 'setCertificateChainConfig((List<X509CertificateConfig>) getSelectedValue())' \
          'setCertificateChainConfigs(List.of((List<X509CertificateConfig>) getSelectedValue()))'
    '';

    buildPhase = ''
      runHook preBuild
      cp -r ${compiledDependencies}/lib .
      cp ${compiledDependencies}/dependency-fixes.jar .

      find TLS-Test-Framework/src/main/java TLS-Testsuite/src/main/java -name '*.java' > sources
      javac -proc:none -cp 'dependency-fixes.jar:lib/*' -d classes @sources
      jar --create --file TLS-Anvil.jar -C classes . -C TLS-Testsuite/src/main/resources .
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/share/tls-anvil
      cp TLS-Anvil.jar $out/share/tls-anvil/
      runHook postInstall
    '';
  };
in
stdenvNoCC.mkDerivation {
  inherit (application) pname version;
  dontUnpack = true;
  nativeBuildInputs = [ makeWrapper ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    makeWrapper ${graalvmPackages.graalvm-ce}/bin/java $out/bin/tls-anvil \
      --add-flags "-cp ${compiledDependencies}/dependency-fixes.jar:${application}/share/tls-anvil/TLS-Anvil.jar:${compiledDependencies}/lib/* de.rub.nds.tlstest.suite.Main"
    runHook postInstall
  '';

  passthru = { inherit application compiledDependencies; };

  meta = {
    description = "TLS-Anvil with native DTLS 1.2 and 1.3 tests";
    homepage = "https://github.com/JoTurk/TLS-Anvil/tree/jo/dtls-13";
    license = [ lib.licenses.asl20 lib.licenses.mit ];
    mainProgram = "tls-anvil";
  };
}
