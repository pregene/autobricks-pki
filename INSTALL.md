# Package installation and removal

Autobricks PKI Server 1.0 provides two Linux Debian packages with curses installation screens. The package being installed determines the screen; there is no package selection inside the installer.

| Package | Contents |
| --- | --- |
| `autobricks-pki` | Server and local client, both binaries and services |
| `autobricks-pki-cli` | Local client service and CLI only |

The packages are mutually exclusive because both own the client files. The server package includes the client without requiring the client-only package.

## Prerequisites

The server host requires Autobricks DNS, Autobricks TrueLog, and the TrueLog client. Their services must be active. TrueLog must mount `/mnt/worm-storage` with retention of at least 365 days. The installer grants the server account access to DNS, TrueLog client, and WORM writer groups.

Client-only installation requires a reachable PKI server, not a local DNS or TrueLog service. Installation requires an interactive terminal at least 80 columns by 25 rows. Noninteractive package configuration reports an error instead of assuming connection settings.

## Build and install

```sh
./scripts/build/run.sh ./scripts/package/build.sh
```

The build produces both `autobricks-pki-VERSION-OS-OS_VERSION-ARCH.deb` and `autobricks-pki-cli-VERSION-OS-OS_VERSION-ARCH.deb` under `build/`, and stages binaries under `bin/`. Package construction requires `dpkg-dev`, distribution `libssl-dev`, Python 3, and the Rust toolchain. Distribution OpenSSL supplies the packaged library dependencies.

Install one package, using its exact generated filename:

```sh
sudo apt install ./build/autobricks-pki-<version>-<os>-<os-version>-<architecture>.deb
```

Or, for a client-only host:

```sh
sudo apt install ./build/autobricks-pki-cli-<version>-<os>-<os-version>-<architecture>.deb
```

The installer collects the inputs listed below. Tab moves between fields, Left/Right and Home/End move the text cursor, and Install starts provisioning. Validation errors remain on the settings screen. Backend failures display an error and do not report installation success. TLS and Root download connections retry temporary connection failures for up to 30 seconds while endpoints start. Certificate-verification failures stop immediately. Failed connection messages include the host and port and remain visible in dpkg output after the screen closes.

## Installation inputs

| Package | Input | Default or requirement |
| --- | --- | --- |
| Server | Base domain | `autobricks.internal`; at most 24 ASCII characters |
| Server | DNS registration IP | Required reachable IPv4 or IPv6 address |
| Server | Bind address | `0.0.0.0` |
| Client only | Server address | Required DNS name or IP matching the server certificate |
| Both | Management TLS port | `5545` |
| Both | Public HTTPS port | `5546`; must differ from the management port |

The included client uses the server installation settings without separate connection questions. Client-only installation does not create a CA hierarchy or request server WORM settings.

## Server and included client

The installer collects base domain, DNS registration IP, bind address, management TLS port, and public HTTPS port. It generates a random 16-character ADMIN password, writes it as `ABPKI_ADMIN_PASSWORD` in root-owned mode-0600 `/etc/autobricks-pki/abpkid.env`, and displays it on completion. SQLite retains the salted administrator password hash for server-side verification. Client-only installation does not generate this password.

The server creates its Root CA, six default Intermediate CAs, and TLS certificate. Intermediate validity is `min(398, TrueLog retention days - 7)` days. DNS registration and audit submission use the installed Autobricks services.

The included client uses the server registration IP, which is present in the server certificate IP SAN, and the configured ports. It enrolls the initialized local Root CA without another settings screen. A wildcard bind address is never used as a destination.

## Installation WORM namespace

Fresh server installation reserves `/mnt/worm-storage/<installation-timestamp>/pki/` using UTC Unix seconds. It saves `ABPKI_INSTALLED_AT` and `ABPKI_WORM` in `abpkid.env`. Existing timestamp directories are not reused. Restarts, upgrades, and reinstall after remove reuse the saved namespace. Fresh installation after purge reserves another namespace without deleting retained archives.

Live SQLite remains at `/var/lib/autobricks-pki/abpki.sqlite`, outside WORM. PKI does not change TrueLog retention, backing storage, or mount ownership.

## Client installation and operating-system trust

Client-only installation collects server address, management TLS port (5545), and HTTPS port (5546). It retrieves the Root CA through HTTPS `GET /root`, checks that it is a CA, and validates its certificate chain and current validity. First-use retrieval bootstraps the private Root; it does not independently authenticate a previously unknown server.

Before saving trust, the installer verifies both TLS endpoints against the retrieved Root and checks server identity. It writes the owned Root certificate to `/usr/local/share/ca-certificates/autobricks-pki-client.crt`, runs `update-ca-certificates`, and verifies a connection using OS trust. Reconfiguration does not silently replace the enrolled server identity or Root.

The daemon reads `/etc/autobricks-pki-client/client.json` and the OS trust bundle `/etc/ssl/certs/ca-certificates.crt`. No client certificate or mTLS pairing is required. `abpki-cli.service` runs `abpki-cli daemon --config /etc/autobricks-pki-client/client.json`; user commands communicate through `/run/autobricks-pki-client/client.sock`.

The service account and socket group are `autobricks-pki-cli`. The installer adds the invoking `SUDO_USER` to that group and grants socket ACL access for immediate use. Other local callers need membership in that group. Socket access does not grant certificate revocation permission.

The CLI stores certificate tokens as mode-0600 files at `~/.abpki/<fingerprint>` under a mode-0700 directory. It sends tokens and per-operation administrator passwords through socket request fields. `revoke --pass` prompts on the caller's terminal with echo disabled; `--pass PASSWORD` accepts an explicit value. No per-command credentials are read from daemon environment variables.

## Reconfiguration and upgrade

Upgrades load existing settings into the same installation screen. CA identity, WORM namespace, and ADMIN password are retained. The client preserves its enrolled server identity and Root. Listener port changes on a combined installation update the included client ports.

Retry incomplete configuration with the applicable package name:

```sh
sudo dpkg --configure autobricks-pki
sudo dpkg --configure autobricks-pki-cli
```

An initialized hierarchy is reused if external delivery failed; the server retries queued delivery. Retained artifacts in the same configured namespace without their database require recovery rather than overwrite.

## Remove and purge

`apt remove` stops services and removes package files but preserves configuration and mutable state. `apt purge` additionally removes package-owned configuration, server SQLite and secrets, service accounts, and the owned client Root trust entry. Trust removal checks the enrolled file checksum and refreshes OS trust.

Server purge deletes DNS records only if they still match the addresses recorded by that PKI instance. Externally changed records stop purge for resolution. WORM certificate/key archives and TrueLog audit logs remain governed by retention. Shared DNS and TrueLog installations are preserved. Retained encrypted key files require a protected copy of their SQLite encryption secret for recovery.

Caller-owned `~/.abpki/` credentials are outside package-managed system state and are not removed from user home directories by package purge.

```sh
sudo apt remove autobricks-pki
sudo apt purge autobricks-pki
# Client-only host:
sudo apt remove autobricks-pki-cli
sudo apt purge autobricks-pki-cli
```

## Service operation

```sh
sudo systemctl status abpkid.service
sudo systemctl status abpki-cli.service
abpki-cli list-ca
```

`abpkid.service` exists only in the server package. Both packages include `abpki-cli.service`.

[Building packages](PACKAGE.md) · [File layout](FILES.md) · [Runtime configuration](docs/runtime.md)
