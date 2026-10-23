# Installation packages

Autobricks PKI Server 1.1.135 is distributed as architecture-specific release
assets. Verify every downloaded file against the checksum manifest published in
the same release.

## Ubuntu packages

| Ubuntu | Architecture | Server package | Client package |
| --- | --- | --- | --- |
| 22.04 | amd64 | `autobricks-pki-1.1.135-ubuntu-22.04-amd64.deb` | `autobricks-pki-cli-1.1.135-ubuntu-22.04-amd64.deb` |
| 22.04 | arm64 | `autobricks-pki-1.1.135-ubuntu-22.04-arm64.deb` | `autobricks-pki-cli-1.1.135-ubuntu-22.04-arm64.deb` |
| 24.04 | amd64 | `autobricks-pki-1.1.135-ubuntu-24.04-amd64.deb` | `autobricks-pki-cli-1.1.135-ubuntu-24.04-amd64.deb` |
| 24.04 | arm64 | `autobricks-pki-1.1.135-ubuntu-24.04-arm64.deb` | `autobricks-pki-cli-1.1.135-ubuntu-24.04-arm64.deb` |

The server package contains `abpkid`, `abpki-cli`, and the Certificate, COMM,
IPC, Transport, and Service dynamic libraries. The client package contains
`abpki-cli` and the same five dynamic libraries but does not contain `abpkid`.

## macOS client packages

Client archives are provided for macOS arm64 and x86_64:

- `autobricks-pki-cli-1.1.135-macos-arm64.tar.gz`
- `autobricks-pki-cli-1.1.135-macos-x86_64.tar.gz`

Each archive contains `abpki-cli`, the five matching dynamic libraries,
installation and removal commands, launchd configuration, and license notices.
It contains no server executable.

See [installation and removal](INSTALL.md) and the
[macOS client guide](docs/macos-client.md) for installation instructions.
