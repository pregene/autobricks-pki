# Building installation packages

Autobricks PKI Server 1.0 provides Linux Debian packages built from the source checkout. Run the commands below from the repository root.

## Package types

| Package | Contents |
| --- | --- |
| `autobricks-pki` | Server, local client, both services, configuration tools and documentation |
| `autobricks-pki-cli` | Local client service, CLI, configuration tools and documentation |

The packages are mutually exclusive because they own the same client files. Install the server package on a PKI server host, or the client-only package on a host connecting to an existing server.

## Build on the current host

Use a Linux amd64 or arm64 host with Bash, Python 3, `flock`, a Rust toolchain supporting edition 2024, a C compiler, `pkg-config`, `dpkg-dev`, and distribution OpenSSL development libraries (`libssl-dev`).

```sh
./scripts/build/run.sh ./scripts/package/build.sh
```

The command builds both binaries and creates both package types for the host OS/version and architecture. Binaries are staged in `bin/`; packages are written to `build/`:

```text
autobricks-pki-VERSION-OS-OS_VERSION-ARCH.deb
autobricks-pki-cli-VERSION-OS-OS_VERSION-ARCH.deb
```

The build runner allocates a new `1.0.NNN` version before each build attempt, including an attempt that later fails. Use the generated filenames rather than renaming packages for a different platform.

To package binaries already staged in `bin/`:

```sh
./scripts/package/build.sh --existing-binaries
```

Both binaries must report the version in `VERSION`. This command does not compile or allocate another version.

## Ubuntu package matrix

Use Docker Engine on an amd64 host with permission to run Docker and network access for build dependencies:

```sh
./scripts/build/run.sh ./scripts/package/docker/build.sh
```

| Ubuntu | Architectures | Package types |
| --- | --- | --- |
| 22.04 | amd64, arm64 | Server plus client; client only |
| 24.04 | amd64, arm64 | Server plus client; client only |

The command produces eight packages under one version, using Rust 1.98.1 and locked Cargo dependencies. ARM64 packages are cross-compiled. Each target uses its distribution OpenSSL libraries. All four targets must succeed before the packages are copied into `build/`.

Packages are checked for name, version, architecture, binary contents and required libraries. amd64 binaries also run version/help checks. ARM64 runtime and package installation require a matching target host; the build does not install the packages on the build host.

## Verify package checksums

The matrix build writes `build/SHA256SUMS-VERSION.txt`. Replace `<version>` with the generated version:

```sh
cd build
sha256sum -c SHA256SUMS-<version>.txt
```

Use the package matching the destination OS/version and architecture. See [installation and removal](INSTALL.md) for prerequisites, configuration inputs and installation commands.

[Binary builds](docs/build.md) · [File layout](FILES.md)
