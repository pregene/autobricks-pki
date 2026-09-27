# Leaf certificate revocation

Autobricks PKI Server 1.0 revokes a specific leaf certificate by fingerprint. Revocation requires the single administrator password. Possession of a certificate, its private key, or its download token does not authorize the standalone revocation command. The [renewal handover](LEAF-RENEW.md#download-completion-and-automatic-revocation) separately authorizes server-controlled automatic revocation of the recorded predecessor after replacement download confirmation. The service has no user accounts or per-user revocation roles.

Revocation records distrust of the certificate; it does not delete certificate records, private keys, WORM artifacts, or TrueLog audit records.

## Request interface

```sh
abpki-cli revoke <fingerprint> --pass
```

`--pass` without a value prompts for the password on the CLI's terminal with echo disabled. `--pass PASSWORD` accepts a value directly. The CLI sends `method=POST`, `path=/api/revoke`, the target fingerprint in the JSON body, and the password in `credential` through the local Unix socket. The daemon forwards this operation over TLS using its installed connection settings. The running service does not read the caller's environment or prompt for a password.

The JSON payload is:

```json
{"fingerprint":"<leaf-certificate-sha256-fingerprint>"}
```

The operation accepts a leaf fingerprint rather than CN, because renewal generations share a CN. There is no revocation reason, scheduled revocation, temporary hold, or reversal parameter in this interface.

## Revocation processing

1. Verify the administrator password against the salted PBKDF2 hash in SQLite.
2. Start a SQLite `BEGIN IMMEDIATE` transaction and find the certificate. Reject an unknown fingerprint or a Root/Intermediate CA target.
3. If the leaf is already revoked, return success without changing its original revocation timestamp or creating another revocation event.
4. Set `revoked_at` to the current Unix UTC timestamp.
5. Regenerate signed CRLs for Intermediate CA generations sharing the issuer CN. Each CRL receives an incremented CRL number and a fixed seven-day validity period.
6. Queue the `certificate-revoked` audit event and commit the revocation state, CRLs, and outbox entry atomically in SQLite.
7. Attempt pending external delivery and return `{"status":"REVOKED"}`. TrueLog submission is retried from the outbox if delivery fails.

```mermaid
sequenceDiagram
    participant Admin as abpki-cli
    participant Local as Local client daemon
    participant PKI as abpkid
    participant DB as SQLite
    participant Log as TrueLog
    Admin->>Local: Socket revoke request with fingerprint and password
    Local->>PKI: Forward operation and credential through TLS
    PKI->>DB: Verify password; begin transaction
    PKI->>DB: Find leaf and check revocation state
    alt First revocation
        PKI->>DB: Set revoked_at
        PKI->>PKI: Generate signed CRLs
        PKI->>DB: Store CRLs and audit outbox entry
    end
    PKI->>DB: Commit
    PKI->>Log: Attempt pending audit submission
    PKI-->>Local: REVOKED
    Local-->>Admin: Result through Unix socket
```

## Certificate status and operational effects

| Component | Effect |
| --- | --- |
| SQLite | Retains the leaf and records its revocation timestamp. |
| CRL | Updated CRLs become available immediately after commit through public HTTPS. Previously cached CRLs remain subject to client refresh behavior. |
| OCSP and `check` | Queries observe the committed revoked status. |
| Renewal | The revoked fingerprint cannot be renewed. |
| Other renewal generations | Remain independent; revoking one fingerprint does not revoke every certificate sharing its CN. |
| DNS | Records remain registered. Revocation does not delete DNS records. |
| Downloads | The existing token remains usable for archive download; revocation does not erase or invalidate the stored download credential. |
| Active connections | PKI does not terminate connections in consuming applications. Their certificate validation and revocation policies determine enforcement. |
| Audit | TrueLog receives `certificate-revoked` with the fingerprint and timestamp. Passwords and private keys are excluded. |

Revocation can target an expired leaf. New issuance still cannot reuse its reserved CN. There is no unrevocation operation.

## Failure and retry behavior

Invalid credentials, unknown targets, and CA targets are rejected. Failure to persist the revocation or generate/store the CRLs rolls back the transaction, including its audit outbox entry.

Audit delivery failure does not undo committed revocation. The current success response does not include an audit-delivery flag. Repeating an authorized request for an already revoked certificate is safe and returns `REVOKED`, including after a lost response.

[Creation](LEAF-CREATE.md) · [Renewal](LEAF-RENEW.md) · [CRLs](CRL.md) · [OCSP](OCSP.md) · [SQLite schema](DDL.md)

[Operation results and audit error codes](ERROR.md)
