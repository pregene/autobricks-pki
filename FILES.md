# Service files and directories

Autobricks PKI Server 1.0 separates executable files, service configuration, mutable SQLite state, and WORM artifacts. The layout below is a reference for Linux systemd deployment. The repository supplies the binaries; service registration and directory provisioning are operator-managed. `abpkid` does not install a systemd unit or create its parent directories.

## Repository build outputs

| Path | Contents |
| --- | --- |
| `bin/abpkid` | Server binary for local testing |
| `bin/abpki-cli` | Client binary for local testing |
| `build/` | Installation package output directory |

Both repository directories are ignored by Git. Service installation paths are separate from these local build outputs.

## Service deployment layout

| Path | Contents and responsibility | Ownership and permissions |
| --- | --- | --- |
| `/usr/local/bin/abpkid` | Server executable; started with `serve` | Root-owned, executable (`0755`) |
| `/usr/local/bin/abpki-cli` | Connecting client executable | Root-owned, executable (`0755`) |
| `/etc/systemd/system/abpkid.service` | Operator-provided systemd unit | Root-owned (`0644`) |
| `/etc/autobricks-pki/` | Service configuration directory | Root-owned (`0750`) |
| `/etc/autobricks-pki/abpkid.env` | Environment settings supplied to the process by systemd | Root-owned (`0600`) |
| `/var/lib/autobricks-pki/` | Mutable PKI state directory | Owned by the service's operating-system account (`0700`) |
| `/var/lib/autobricks-pki/abpki.sqlite` | Certificates, private keys, revocation state, password hash, key encryption password, token hashes, and pending delivery records | Owned by the service account (`0600`) |
| `/var/lib/autobricks-pki/abpki.sqlite-journal` | SQLite rollback journal created and removed during database transactions | Managed by SQLite in the protected state directory |
| `/mnt/worm-storage/pki/` | Certificate and private-key archive directory on the TrueLog-provided WORM mount | Service account needs directory traversal and file creation/append access |
| `/run/autobricks-dns/autobricks-dns.sock` | External DNS control socket | Managed by Autobricks DNS; service account needs explicit socket access |

The operating-system service account is a filesystem/process identity. The PKI application has no user accounts or user-management database.

Initialization and normal service execution use the same state paths and compatible filesystem ownership. Binary replacement does not replace the SQLite database or WORM artifacts.

## Path configuration

The reference service environment contains:

```ini
ABPKI_DATABASE=/var/lib/autobricks-pki/abpki.sqlite
ABPKI_WORM=/mnt/worm-storage/pki
ABPKI_ORIGIN=https://pki.example.internal
ABPKI_BIND=0.0.0.0
ABPKI_TLS_PORT=5545
ABPKI_HTTPS_PORT=5546
AUTOBRICKS_DNS_SOCKET=/run/autobricks-dns/autobricks-dns.sock
```

The DNS registration IP is supplied once through `abpkid init 192.0.2.10 example.internal`. `ABPKI_BIND` controls listening only; it is not a DNS registration address. Management uses TLS port 5545; public Root CA, CRL, and OCSP endpoints use HTTPS port 5546. Published HTTPS URLs use `ABPKI_HTTPS_PORT`.

`abpkid` reads environment variables, not the environment file directly. The service manager supplies the file's values to the process. The administrator password is an initialization input; normal `serve` operation reads its stored hash from SQLite and does not require the plaintext password in the service environment file.

Set an absolute `ABPKI_DATABASE` path for the service. Without it, the binary uses `abpki.sqlite` relative to its working directory. `ABPKI_WORM` defaults to `/mnt/worm-storage/pki`, and the DNS socket defaults to the path shown above.

The SQLite parent directory and WORM artifact directory must exist before `init` or `serve`. Autobricks DNS and Autobricks TrueLog must be installed first, and the WORM filesystem must be mounted before PKI starts. Keep the PKI artifact directory separate from TrueLog-managed log files. Files are accessed through the mount, never through its backing storage directory.

## SQLite state

The service database path is `/var/lib/autobricks-pki/abpki.sqlite`, configured with `ABPKI_DATABASE`. Mutable database files and immutable archives occupy separate storage locations:

```text
/var/lib/autobricks-pki/              # Mutable local storage
    abpki.sqlite                    # Operational database
    abpki.sqlite-journal            # Temporary SQLite rollback journal

/mnt/worm-storage/pki/               # WORM certificate archives
    root/
    intermediate/
    certificate/
```

The reference service configuration sets the absolute database path above. If `ABPKI_DATABASE` is omitted, the executable uses `abpki.sqlite` in its working directory.

The operational database and all of its working files stay on mutable storage outside WORM. The implementation uses SQLite `DELETE` journal mode, so transaction working data uses the rollback journal rather than normal WAL/SHM files. SQLite manages journal recovery; service restarts reuse the existing database.

| Database table | Contents |
| --- | --- |
| `settings` | Salted administrator password hash, private-key encryption password, base domain, and current service TLS certificate identifier |
| `certificates` | Root, Intermediate, and leaf certificates; Encrypted PKCS#8 private keys; validity; revocation timestamps; issuance profiles; access-token hashes |
| `crls` | Signed CRL PEM, update deadline, and CRL number for issuer generations |
| `outbox` | Certificate, audit, and DNS delivery records with completion state |

Operational private keys use encrypted PKCS#8 PEM in SQLite. Root CA, Intermediate CA, and leaf private keys also have matching encrypted PEM archive copies on WORM; the encryption password is managed in SQLite. Its TLS certificate and key are loaded from the database. The database file is created with mode `0600`; an existing file with group or other access is rejected. The parent directory's permissions are set by the operator, not repaired automatically by the daemon.

## WORM artifacts

Certificate artifacts use the following paths relative to `ABPKI_WORM`:

```text
/mnt/worm-storage/pki/
    root/
        <CN>.pem
        <CN>.key.pem
    intermediate/
        <YYYY-MM-DD>/
            <certificate-fingerprint>/
                <CN>.pem
                <CN>.key.pem
    certificate/
        <YYYY-MM-DD>/
            <certificate-fingerprint>/
                <CN>.pem
                <CN>.key.pem
```

The Root CA public certificate is stored under `root/`. Intermediate CA public certificates use `intermediate/`; leaf certificates use `certificate/`. Each Root CA, Intermediate CA, and leaf certificate is accompanied by its matching encrypted PKCS#8 private-key PEM as `<CN>.key.pem`.

`YYYY-MM-DD` is the UTC issuance date captured when the archive is queued, independent of custom certificate validity dates and delivery retry time. Fingerprint directories separate multiple certificates with the same CN and issuance date. CN filename components retain ASCII letters, digits, dots, hyphens, and underscores; other UTF-8 bytes are percent-encoded to prevent path traversal. The certificate subject itself is unchanged.

Archive subdirectories use mode `0700`; certificate and key files use `0600`. Existing subdirectories and files with broader permissions are rejected. Delivery retries accept matching bytes and append only a missing suffix. Conflicting content and symlink paths are rejected. WORM retention is enforced by the filesystem; PKI does not rotate or delete artifacts. Existing archived files are not moved or renamed.

Download archives are constructed in memory. CRLs remain in SQLite and are served through HTTPS. OCSP responses are generated for requests without a persistent response directory.

## Logs and runtime files

Audit events are submitted through `/usr/bin/ab-truelog-cli write --service abpkid --data <event-json>`. TrueLog creates and manages its own appendable WORM log files, including rotation, retention integration, and checksum chains. PKI does not create audit JSON files or append to TrueLog-managed files. With TrueLog 0.3.55 and its standard mount, the daily log path is `/mnt/worm-storage/abpkid/truelog-YYYY-MM-DD.log`; the receiving TrueLog server controls its location and date. See the [TrueLog client interface](https://github.com/pregene/autobricks-log/blob/main/TRUELOG.md#write-records-through-the-client). Process startup and error messages use standard output and standard error; a systemd unit can capture these in the journal. `abpkid` does not create a separate `/var/log/autobricks-pki` directory, PID file, or PKI Unix socket.

The DNS control socket belongs to Autobricks DNS. PKI connects to it without creating, replacing, or deleting it. TrueLog owns the lifecycle of its WORM mount.

## Client download files

Downloads are saved on the machine running `abpki-cli`:

| Command | Output location and contents |
| --- | --- |
| `root` | `root.crt` in the client's current working directory; Root CA PEM |
| `chain <issuer>` | `trust-chain` in the client's current working directory; Intermediate and Root PEM blocks |
| `download <fingerprint> <target>` | `<target>.tar.gz` at the supplied target path |

The archive contains exactly `certificate.pem`, `private-key.pem`, and `trust-chain`. The server constructs it in memory without a download staging directory. The client creates output files with mode `0600` and refuses to overwrite existing files. Target parent directories must already exist. Access tokens are returned to the caller; the CLI does not create a token-storage directory.

## Backup artifacts

SQLite backup copies may be placed on WORM as separate artifacts. A database backup includes encrypted private keys, their encryption password, and credential hashes and requires corresponding access restrictions. The server does not currently create automatic backups or manage a backup directory. The live database and rollback journal remain outside WORM even when backup artifacts are archived there.

```mermaid
flowchart TD
    Unit[systemd service] --> Binary[/usr/local/bin/abpkid]
    Config[/etc/autobricks-pki/abpkid.env] -->|Environment| Binary
    Binary -->|Mutable state and keys| DB[/var/lib/autobricks-pki/abpki.sqlite]
    DB --> Journal[SQLite rollback journal]
    Binary -->|Certificates and private keys| WORM[/mnt/worm-storage/pki/]
    Binary -->|Audit events| CLI[ab-truelog-cli]
    CLI --> TrueLog[Autobricks TrueLog]
    TrueLog --> Audit[TrueLog-managed WORM logs]
    Binary -->|Record registration| DNS[Autobricks DNS control socket]
    Binary -->|stdout and stderr| Logs[Service journal]
    Binary -->|TLS and HTTPS downloads| Client[abpki-cli output files]
```

[Runtime configuration](docs/runtime.md) · [Storage](docs/storage.md) · [Key storage](docs/key-storage.md)
