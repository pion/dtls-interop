<h1 align="center">
  <br>
  Pion DTLS-interop
  <br>
</h1>
<h4 align="center">Pion/DTLS interoperability runner tool for testing pion/dtls against other implementations</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-dtls-gray.svg?longCache=true&colorB=brightgreen" alt="Pion dtls-interop"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a>  <br>
  <a href="https://goreportcard.com/report/github.com/pion/dtls-interop"><img src="https://goreportcard.com/badge/github.com/pion/dtls-interop" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

Pion's DTLS interoperability runner is an automated test framework that verifies real-world DTLS compatibility by running live handshakes and data flows between Pion and other DTLS implementations, ensuring protocol correctness and cross-implementation reliability.

## Development environment

The repo is developed with Nix/Devenv for the best dev experince we recommend using Devenv,
to install all the tools and dependencies, Simply run `devenv shell`:

```sh
devenv shell
openssl-3 version
openssl-4 version
bssl-shim -is-handshaker-supported
```

Supported Implementations:

- [ ] - OpenSSl:
  - [ ] - v4 with 1.2.
  - [ ] - v3 with 1.2.
- [ ] - BoringSSL
  - [ ] - 1.2
  - [ ] - 1.3
  - [ ] - dual mode

### Contributing
Check out the [contributing wiki](https://github.com/pion/webrtc/wiki/Contributing) to join the group of amazing people making this project possible

### License
MIT License - see [LICENSE](LICENSE) for full text
