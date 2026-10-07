# macOS client

Autobricks PKI Server 1.0 provides a client for macOS 11 or later on Apple Silicon (arm64) and Intel (x86_64). The PKI server runs on Linux.

The CLI sends requests through a local Unix socket. A launchd service validates the remote server using macOS system trust and forwards requests over TLS. No client certificate enrollment is required. Certificate access tokens remain in the invoking user's private `~/.abpki` directory.

## Installation

Download the archive matching `uname -m` and `macos-SHA256SUMS` from the release. Verify the checksum entry for that archive before extracting it. The server hostname must resolve on the Mac and match the server certificate; both configured TCP ports must be reachable.

Extract the archive, then run:

```sh
sudo ./install.sh
```

Enter the server hostname, management TLS port (default 5545), and public HTTPS port (default 5546). Installation retrieves the Root CA through public HTTPS `/root`. First-use retrieval does not independently authenticate a previously unknown server. Confirm its SHA-256 fingerprint through a trusted channel before accepting enrollment in the System keychain. Subsequent connections verify the server certificate and hostname using OS trust.

The same settings can be supplied as arguments; Root trust confirmation remains interactive:

```sh
sudo ./install.sh pki.autobricks.internal 5545 5546
abpki-cli list-ca
abpki-cli --help
```

The service uses `/Library/Application Support/Autobricks PKI/client.json` and `/var/run/autobricks-pki-client/client.sock`. Members of the macOS `staff` group can call the socket. The launchd label is `com.autobricks.pki.client`; service logs use `/var/log/autobricks-pki-client.log`.

## Usage

Use the CLI from your normal operating-system account:

```sh
abpki-cli list-ca
abpki-cli list all
abpki-cli create --help
abpki-cli create < request.json
abpki-cli info <fingerprint>
abpki-cli check <fingerprint>
abpki-cli download <fingerprint> web01
abpki-cli renew <fingerprint>
abpki-cli revoke <fingerprint> --pass
```

Replace placeholders with actual fingerprints. Select an issuer from `list-ca` and prepare `request.json` using `create --help`. Creation saves its access token in your protected `~/.abpki` directory. Ordinary renewal and download use that token; `revoke --pass` prompts for the server administrator password with terminal echo disabled. Keep downloaded private-key archives private.

Inspect the service with `sudo launchctl print system/com.autobricks.pki.client`. See [CLI commands](cli.md), [certificate creation](../LEAF-CREATE.md) and [renewal](../LEAF-RENEW.md).

## Removal

```sh
sudo ./uninstall.sh
```

Removal stops the service and removes its executable, configuration, socket and enrolled Root trust. User credential records, downloaded certificates and service logs remain.

## Building packages

Install Rust with `aarch64-apple-darwin` and `x86_64-apple-darwin` targets. On macOS, install the Xcode command line tools. On Linux, provide Zig, cargo-zigbuild and an extracted macOS SDK through `SDKROOT`.

```sh
scripts/build/run.sh --keep-version scripts/package/macos.sh
```

The command produces two architecture-specific installation archives and `macos-SHA256SUMS` under `build/`, using the current project version. Archives are unsigned and are installed from a terminal.
