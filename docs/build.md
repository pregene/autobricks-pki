# Building from source

Autobricks PKI Server 1.0 builds on Linux and provides `abpkid` and `abpki-cli`. Run commands from the repository root.

Client-only builds also support macOS arm64/x86_64; see [macOS client packages](macos-client.md#building-packages).

## Prerequisites

Install Bash, Python 3, `flock`, a Rust toolchain supporting edition 2024, a C compiler, `pkg-config`, `dpkg-dev`, and distribution OpenSSL development libraries. Regression checks also require the OpenSSL command-line client.

## Build binaries

```sh
./scripts/build/run.sh ./scripts/build/release.sh
```

The command stages `bin/abpkid` and `bin/abpki-cli`. Intermediate build files reside in `target/`. Binaries require the corresponding system OpenSSL shared libraries at runtime.

The build runner increments `VERSION` before a build attempt, including attempts that later fail. Versions use `1.0.NNN` with at least three digits and no wrapping. Both binaries report that version:

```sh
./bin/abpkid --version
./bin/abpki-cli --version
```

## Check a source build

```sh
./scripts/check/panic-gate.sh
```

The gate checks formatting, runs Clippy and runs the regression suite. Its compiling commands allocate their own build versions. Isolated checks use temporary fixtures; they do not install packages or write to production WORM storage.

For installed-service checks and the distinction between installed and isolated results, see [checking a build and installation](../tests/PERFORMANCE.md).

## Build installation packages

See [PACKAGE.md](../PACKAGE.md) for host builds, the Ubuntu 22.04/24.04 amd64/arm64 matrix, package filenames and checksum verification. Package output is stored in `build/`.

[Install packages](../INSTALL.md) · [Runtime configuration](runtime.md)
