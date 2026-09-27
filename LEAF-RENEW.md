# Leaf certificate renewal

Autobricks PKI Server 1.0 renews a leaf by issuing a new certificate and a new private key with the existing identity and profile. The CLI reads the existing certificate's access token from the calling user's protected credential record and supplies it through the Unix socket request. Renewal requires no user account or administrator password and does not grant revocation permission.

Leaf holders monitor expiration, request renewal, download the replacement, and deploy it to their services. Intermediate CA renewal is performed internally by `abpkid`.

## Renewal handover state

Accepted renewal changes the old certificate's local `valid` state to `SUPERSEDED`. The replacement is issued as `VALID`. The old certificate remains temporarily usable while the holder downloads the replacement certificate and its matching key and trust chain. A failed or interrupted download does not itself revoke the old certificate. Expiration and explicit administrator revocation still apply.

This handover state is separate from the X.509 CRL revocation reason of the same name. It does not set `revoked_at`, produce a CRL revocation entry, or make OCSP report `REVOKED`. See [certificate lifecycle state](DDL.md#certificate-lifecycle-state).

The handover state and download confirmation are storage and protocol contracts; the current runtime processing below does not yet implement these transitions.

## Download completion and automatic revocation

1. The renewal operation records the old certificate's numeric key in the replacement's `previous_certificate_idx`. The old certificate becomes `SUPERSEDED` and the new certificate is `VALID`. The relationship is persisted with issuance, independently of TrueLog delivery.
2. The holder downloads the replacement archive using its fingerprint and access token. The CLI writes the entire archive and successfully synchronizes the local file before confirming completion.
3. The CLI sends completion confirmation through the Unix socket with the replacement fingerprint and its saved token; the daemon forwards it through management TLS. This is part of the download workflow, not a separate user command. The current protocol has no completion operation; its handler and CLI submission are required for this contract.
4. The server loads the replacement and its recorded predecessor. It does not accept an arbitrary old fingerprint supplied by the caller. Initial-issuance downloads with no predecessor require no automatic revocation.
5. In one SQLite transaction, the server changes the predecessor from `SUPERSEDED` to `REVOKED`, records the revocation time, and queues CRL publication and the revocation audit event. OCSP then reports the old certificate as `REVOKED`. The replacement remains `VALID`.
6. After commit, the server attempts immediate CRL publication and acknowledges completion. CRL or TrueLog delivery failure leaves work pending without undoing revocation.

If writing or synchronizing the archive fails, the CLI does not confirm. If confirmation is lost, retry confirmation with the same replacement identity and token; do not create another replacement. If the first confirmation already committed, return success without a second revocation event. Confirmation must support retry using the already saved archive without overwriting it. The old certificate remains `SUPERSEDED` while confirmation is absent, subject to expiration, administrator revocation, and the mandatory seven-day deadline of an associated Intermediate CA handover.

Downloading successfully is the revocation trigger; application installation or TLS reload is not an additional prerequisite. A certificate holder must therefore account for the old certificate becoming revoked as soon as download confirmation commits.

This automatic transition applies only to the recorded predecessor and is authorized by the authenticated renewal/download workflow. It does not permit a holder to invoke administrator-only revocation against other certificates. A missing or inconsistent predecessor is a server-state error; do not guess from CN.

```mermaid
sequenceDiagram
    participant CLI as abpki-cli
    participant Local as Local client daemon
    participant PKI as abpkid
    participant DB as SQLite
    CLI->>Local: Socket download request with fingerprint and saved token
    Local->>PKI: Forward through TLS
    PKI-->>Local: Certificate archive
    Local-->>CLI: Archive through Unix socket
    CLI->>CLI: Save complete archive and synchronize file
    CLI->>Local: Socket completion confirmation with fingerprint and token
    Local->>PKI: Forward through TLS
    PKI->>DB: Resolve predecessor from replacement row
    PKI->>DB: Revoke predecessor, update CRLs, queue audit; commit
    PKI-->>Local: Completion acknowledged
    Local-->>CLI: Confirmation through Unix socket
```

## Issuer handover deadline

If the old issuer is itself `SUPERSEDED`, the leaf participates in [Intermediate CA handover](INTERMEDIATE.md#intermediate-ca-renewal-handover). The replacement must use the new `VALID` CA. Download confirmation retires the old leaf and contributes to retiring its old CA. At the CA's fixed seven-day deadline, every outstanding old leaf is revoked even if replacement download never completed. A failed download does not extend that deadline.

## Eligibility and request

Renewal is accepted only when the existing leaf is not revoked, its validity has started, and:

```text
0 < not_after - current_time <= 7 * 86400 seconds
```

Exactly seven days remaining is eligible; expiration itself is not. `check` reports revocation status, not remaining lifetime: `GOOD` alone does not establish renewal eligibility or complete certificate validity. Use the certificate's validity timestamps as well.

```sh
abpki-cli renew <existing-fingerprint>
```

The CLI sends a Unix socket message with `method=POST`, `path=/api/renew`, the fingerprint in the JSON body, and the locally stored access token in `credential`. The client daemon forwards that message through management TLS using its installed server address and port. No per-command environment variables are used. The management API accepts only the fingerprint in the request body:

```json
{"fingerprint":"<existing-leaf-fingerprint>"}
```

Renewal preserves the existing certificate's full validity duration, not its remaining lifetime:

```text
original_duration = old.not_after - old.not_before
new.not_before = renewal_time_utc
new.not_after = new.not_before + original_duration
```

A seven-day certificate renews for seven days; a 47-day certificate renews for 47 days. Custom durations are preserved exactly in seconds, without rounding. The renewal request has no duration or profile-edit parameters; the server obtains the duration from the existing certificate. A different lifetime requires a separate issuance request subject to normal CN uniqueness rules; renewal does not bypass those rules to change the lifetime.

## Renewal processing

1. Load the existing certificate and verify the access token against its stored SHA-256 digest. CA certificates cannot use this operation.
2. Reject a revoked certificate or one outside the renewal window.
3. Load the stored leaf profile and the original issuer. Select the Intermediate CA generation with the same issuer CN and the greatest `not_after`.
4. Set the new validity start to the current time and its end to that start plus the existing certificate's full duration. Reject an interval outside the selected issuer's validity; no automatic shortening occurs.
5. Start a SQLite transaction and validate the preserved profile. Generate a new P-256 key, random serial number, signed certificate, fingerprint, and access token. Renewal bypasses the new-issuance CN uniqueness rejection.
6. Write the replacement certificate and encrypted key to WORM. Store their paths, metadata, profile, token hash, and CA-to-leaf relation in SQLite. Queue a `certificate-created` audit event and server DNS registration; commit the transaction.
7. Return `certificate`, `download_token`, and `integrations_pending`, using the same result format as creation. The background worker delivers queued audit and DNS operations.

| Property | Renewal behavior |
| --- | --- |
| CN and certificate kind | Preserved. |
| DNS, IP, purpose, and access-policy SANs | Preserved from the existing profile. Renewal does not accept profile edits. |
| Issuer | Same Intermediate CA CN; its selected certificate generation may change. |
| Key, serial, fingerprint, access token | Newly generated. |
| Validity | Starts at renewal time and preserves the existing full duration exactly; reject if it exceeds the issuer boundary. |
| CRL and OCSP URLs | Generated from the service distribution configuration and selected issuer. |
| Old certificate | Temporarily `SUPERSEDED`; automatically `REVOKED` when replacement download is confirmed. |
| Renewal linkage | The replacement references its predecessor by `previous_certificate_idx`; this field is part of the specified schema, not the current runtime. |

```mermaid
sequenceDiagram
    participant Holder as Leaf holder
    participant Local as Local client daemon
    participant PKI as abpkid
    participant DB as SQLite
    participant WORM as WORM mount
    participant External as TrueLog / DNS
    Holder->>Local: Socket renew request with fingerprint and saved token
    Local->>PKI: Forward through TLS
    PKI->>DB: Load certificate, profile, and issuer generations
    PKI->>PKI: Check token, revocation, renewal window, issuer bounds
    PKI->>PKI: Generate new key and certificate
    PKI->>WORM: Write certificate and encrypted key
    PKI->>DB: Store replacement metadata, paths, relation, and outbox; commit
    PKI->>External: Background worker delivers audit and DNS operations
    PKI-->>Local: New certificate, new token, delivery state
    Local-->>Holder: Result through Unix socket; CLI saves new token
    Holder->>Local: Socket download request with new fingerprint and saved token
    Local->>PKI: Forward through TLS
    PKI-->>Local: Certificate archive
    Local-->>Holder: Archive through Unix socket
    Holder->>Holder: Validate and deploy replacement
```

## Deployment and retained generations

The CLI saves the new fingerprint/token association on receiving the renewal response. The holder downloads using the new fingerprint; the CLI supplies the saved token through the socket, validates the replacement's identity and trust chain, then installs the new certificate, matching private key, and trust chain together. The application reloads its TLS configuration and the holder checks successful operation before retiring its local old key material.

The current runtime retains the old certificate until expiry or administrator revocation; the handover contract above introduces its explicit temporary `SUPERSEDED` state. Renewal does not overwrite WORM artifacts: the new fingerprint creates a separate archive directory. TrueLog manages the issuance audit record; the current event is `certificate-created`, without a separate renewal event or predecessor field.

## Failure and retry behavior

Invalid tokens, revoked/expired certificates, requests outside the renewal window, or issuer-boundary violations are rejected. A transaction failure leaves no replacement certificate or queued operations. An external delivery failure after commit leaves a valid replacement in SQLite and pending work in the outbox; it does not require another renewal.

Renewal requests have no idempotency identifier or single-successor constraint. Repeating a request against the old certificate during its eligible window can issue another replacement with a different key and token. The old token is not consumed. After a lost response, certificate listing can show new records but cannot recover their tokens. Repeated renewal is therefore distinct from retrying external delivery.

[Creation and download](LEAF-CREATE.md) · [Revocation](LEAF-REVOKE.md) · [Validity](VALIDATION.md) · [SQLite schema](DDL.md)

[Operation results and audit error codes](ERROR.md)
