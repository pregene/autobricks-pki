# Storage

Autobricks PKI Server 1.0 uses SQLite on mutable storage and the Autobricks TrueLog-provided WORM mount for immutable artifacts. The live database and its journal remain outside WORM.

## Storage roles

| Data | Storage |
| --- | --- |
| Certificate PEM and encrypted Root/Intermediate/leaf private-key PEM | Original files under `ABPKI_WORM`, normally `/mnt/worm-storage/<installation-timestamp>/pki`. |
| Certificate and CRL metadata, state, file paths, CA-to-leaf relationships, and access-token hashes | SQLite. |
| Private-key encryption password and administrator password hash | SQLite settings. |
| Audit log contents | TrueLog-managed WORM files. |
| Queryable audit history and TrueLog confirmation checksums | SQLite audit design. |
| Pending audit, DNS delivery, and CRL publication | SQLite outbox. |
| SQLite backup artifacts | WORM can retain backup files. |

Certificate and key bytes are not duplicated in SQLite under this storage contract. Read them through the WORM mount for signing, TLS, chain construction, and downloads. The `intermediate_leaf` table provides indexed numeric CA-to-leaf membership. See [DDL](../DDL.md).

## Issuance boundary

Generate the certificate and key, encrypt the key, and write and synchronize both WORM files. Only then commit the metadata, relative file paths, CA-to-leaf relation, and audit/DNS outbox operations. A WORM failure prevents successful issuance. A later DNS or TrueLog failure leaves its delivery pending without reversing a committed certificate.

WORM and SQLite do not share an atomic transaction. A failed metadata transaction can leave immutable unreferenced files; retention still applies. Do not overwrite, delete, or access backing SOURCE storage to simulate rollback. Relative path and filesystem permission checks protect subsequent reads.

## Audit delivery

PKI submits events through `ab-truelog-cli` using service `abpkid`. TrueLog manages log files, rotation, checksums, and retention. PKI validates the returned receipt and marks the outbox entry complete; it does not create a separate audit log file. A lost response can follow a committed write; stable event identifiers correlate retries but do not provide exactly-once remote delivery.

## Runtime coverage

Certificate, encrypted-key, and signed CRL source files reside on WORM. SQLite stores their paths and metadata, including numeric CA-to-leaf relations. Persistent audit rows with TrueLog checksums remain a schema contract; the runtime does not yet populate that history. See [audit history](../DDL.md#audit-history-schema).

[File layouts](../FILES.md) · [Key storage](key-storage.md) · [SQLite schema](../DDL.md)
