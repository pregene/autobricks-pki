# Stored certificate information

Autobricks PKI Server 1.0 retains certificate identities, lifecycle state, issuer relationships and delivery state in SQLite. The database is configured by `ABPKI_DATABASE`; the installed default is `/var/lib/autobricks-pki/abpki.sqlite`.

The live database and its working files stay on mutable storage. Certificate, encrypted private-key and CRL PEM files reside on WORM. Database access is restricted to the service account with mode `0600`.

## Certificate records

| Information | Meaning |
| --- | --- |
| Index | Numeric identifier displayed in certificate lists |
| Fingerprint | Lowercase SHA-256 of the certificate DER; identifies one generation |
| Common Name | Certificate subject CN; retained across renewal |
| Certificate type | Root CA, Intermediate CA or leaf |
| Issuer and serial | Issuing certificate and contiguous uppercase hexadecimal serial |
| Validity | Signed start and expiration timestamps, stored as UTC Unix seconds |
| State | VALID, SUPERSEDED or REVOKED |
| Supersession and revocation times | UTC Unix seconds for the corresponding transitions |
| Issuance profile | Field values retained for leaf renewal |
| Predecessor | Previous certificate generation replaced through renewal |
| Artifact locations | Relative certificate and encrypted-key paths under `ABPKI_WORM` |

Intermediate CA records remain associated with the leaves they issued. Renewal creates a new certificate generation; it does not change the issuer relationship of an existing certificate.

## Certificate lifecycle state

| State | Meaning |
| --- | --- |
| `VALID` | Current generation; ordinary leaf renewal returns without issuing a replacement |
| `SUPERSEDED` | Renewal handover period; ordinary authorized leaf renewal can issue a replacement |
| `REVOKED` | Revoked certificate; renewal is rejected |

Signed validity remains independent of local state. A SUPERSEDED certificate is not immediately revoked and can still return GOOD from `check` or OCSP. Leaf retirement occurs seven days after transition; Intermediate CA retirement occurs after 48 days. Downloading or renewing does not extend these deadlines.

## Service settings and credentials

The service retains the installation domain, WORM retention-derived CA lifetime, service TLS certificate selection, administrator password hash, private-key encryption secret and certificate token hashes. Lists and status queries do not expose these credentials.

Certificate files alone do not contain the private-key encryption secret. Preserve access to the corresponding protected service data when recovering encrypted archives.

## CRLs and pending delivery

CRL records identify the published signed file, issuer, CRL number and update deadline. Linked Intermediate CA generations share revocation history and increasing CRL numbers.

Pending DNS registration, TrueLog submission and CRL publication remain recorded for retry. Failure of external delivery does not reverse an already committed certificate operation. A lost TrueLog acknowledgement may lead to repeated submission; delivery is not guaranteed to be exactly once.

## Audit records

TrueLog owns audit log files and retention. PKI submits events through `ab-truelog-cli` using service `abpkid`. There is no separate PKI audit-history query interface or SQLite receipt-history feature.

## Retention and removal

Revocation does not delete certificate records, keys or WORM artifacts. Removing the package preserves service data; purging removes package-owned mutable data and secrets while WORM retention remains in force. See [installation and removal](INSTALL.md).

[File layout](FILES.md) · [Storage](docs/storage.md) · [Creation](LEAF-CREATE.md) · [Renewal](LEAF-RENEW.md) · [Operation results](ERROR.md)
