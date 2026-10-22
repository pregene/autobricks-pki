# Building from source

Autobricks PKI Server 1.0 builds on Linux and provides `abpkid` and `abpki-cli`. Run commands from the repository root.

Development builds and tests support macOS. Deployment server packages are
produced only for Ubuntu. Client-only installation archives support macOS
arm64/x86_64; see [macOS client packages](macos-client.md#building-packages).

## Prerequisites

Install a Rust toolchain supporting edition 2024, a C compiler, `pkg-config`,
and OpenSSL development libraries. The sibling `autobricks-certificate`
checkout is required by the source dependency.

## Build binaries

```sh
cargo build --release --locked
```

Build output resides in `target/release/`. Binaries require the corresponding
system OpenSSL shared libraries and the packaged Autobricks dynamic libraries
at runtime. Both binaries report the version in `VERSION`:

```sh
./target/release/abpkid --version
./target/release/abpki-cli --version
```

## Build installation packages

See [PACKAGE.md](../PACKAGE.md) for the published Ubuntu and macOS package
matrix, filenames, contents, and checksum verification.

[Install packages](../INSTALL.md) · [Runtime configuration](runtime.md)
