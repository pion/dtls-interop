<h1 align="center">Pion DTLS Interop</h1>

<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-dtls-gray.svg?longCache=true&colorB=brightgreen" alt="Pion dtls-interop"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="Join us on Discord"></a>
  <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

Interoperability tests for [pion/dtls](https://github.com/pion/dtls).
The aim is to test every DTLS 1.2 and 1.3 feature supported by Pion, first against itself,
then against other DTLS implementations.

## How it works

The suite connects Pion clients and servers to peers and runs shared test cases
against each implementation. Cases that a peer does not support or that its
adapter has not implemented are skipped.

The following implementations have test runners:

| Implementation | Runner |
| --- | --- |
| Pion DTLS v4 | `pion-v4` |
| Pion DTLS v3 | `pion-v3` |
| BoringSSL | `boringssl` |
| OpenSSL 3 | `openssl3` |
| wolfSSL | `wolfssl` |
| Mbed TLS | `mbedtls` |

## Run locally

With Nix and Devenv installed, enter the development environment to get Go,
Task, and the peer implementations:

```sh
devenv shell
task interop
```

`task interop` runs all implementations using the Pion version in [go.mod](go.mod).
Use `RUNNER` to select one:

```sh
task interop RUNNER=pion-v4
task interop RUNNER=boringssl
```

### Select the Pion version

Pass a branch, tag, or commit to clone it into `.cache/pion-dtls/<ref>` and test
that checkout. An existing cached checkout is reused:

```sh
task interop -- main
task interop -- v4.0.0
task interop -- ee71667c005d4ae1745490f2c6ef87555d898c68
```

You can also pass a relative or absolute path to a local pion/dtls v4 checkout,
including uncommitted changes:

```sh
task interop -- ../dtls
task interop RUNNER=pion-v4 -- /path/to/dtls
```

The runner uses a temporary Go workspace to test the selected checkout.

## Development environment

[devenv.nix](devenv.nix) defines the tools and peer binaries. Inside `devenv shell`,
you can check the bundled OpenSSL versions and BoringSSL shim:

```sh
openssl-3 version
openssl-4 version
bssl-shim -is-handshaker-supported
```

## Community and license

Join the [Pion Discord](https://discord.gg/PngbdqpFbt) for discussion and see the
[contributing guide](https://github.com/pion/webrtc/wiki/Contributing) to get
involved.

MIT licensed. See [LICENSE](LICENSE).
