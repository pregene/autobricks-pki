# Storage

Autobricks PKI Server 1.0 uses SQLite on mutable storage and the Autobricks TrueLog-provided WORM mount for retained artifacts. The live database and its journal remain outside WORM.

## Storage roles

| Data | Location |
| --- | --- |
| Certificate, encrypted Root/Intermediate/leaf private key, and signed CRL PEM | Files under `ABPKI_WORM` |
| Certificate identities, lifecycle state, issuer relationships and artifact paths | SQLite |
| Private-key encryption secret, administrator hash and certificate token hashes | Protected SQLite settings and records |
| Audit log contents | TrueLog-managed WORM files |
| Pending DNS, audit and CRL delivery | SQLite |

Certificate and key PEM contents are not duplicated in SQLite. See [stored certificate information](../DDL.md) and [file locations](../FILES.md).

## Issuance and delivery

The certificate and encrypted key must be stored on WORM before issuance succeeds. A WORM write failure prevents successful issuance. A later DNS or TrueLog failure leaves delivery pending without reversing an issued certificate.

An interrupted operation can leave retained files that do not correspond to a completed certificate record. WORM retention still applies; service recovery does not remove these files or bypass the mount.

## Audit delivery

PKI submits events through `ab-truelog-cli` using service `abpkid`. TrueLog manages log files, checksums and retention. PKI does not create a separate audit log file.

Failed submission is retried. A lost acknowledgement can follow a successful TrueLog write, so retrying can produce another log entry. PKI does not provide exactly-once audit delivery or a separate audit-history query interface.

## Removal and recovery

Revocation retains certificate and key files. Package removal retains service data; purge removes package-owned mutable data and secrets while WORM retention remains in force. Recovering encrypted key files requires the corresponding protected encryption secret.

[Key storage](key-storage.md) · [Installation and removal](../INSTALL.md)
