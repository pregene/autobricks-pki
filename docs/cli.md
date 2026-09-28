# Command-line client

`abpki-cli` submits requests to the local `abpki-client` service through a Unix domain socket. The service connects to `abpkid` over management TLS (default port 5545), using settings saved during client installation. No client certificate or client private key is used for this TLS connection.

`abpki-cli.service` runs the local daemon with `/etc/autobricks-pki-client/client.json`. CLI operations use `/run/autobricks-pki-client/client.sock`; only the daemon opens remote TLS connections. Both package types include this service.

[Executable usage and request examples](runtime.md)

## Commands

| Command | Function |
| --- | --- |
| `abpki-cli create-ca ... --pass {password}` | Not implemented in 1.0; reserved for 1.1. |
| `abpki-cli revoke ... --pass` | Revoke a certificate; requires the administrator password. |
| `abpki-cli chain ...` | Download the Intermediate CA and Root CA certificates as `trust-chain`. |
| `abpki-cli root ...` | Download the Root CA certificate as `root.crt`. |
| `abpki-cli renew <fingerprint> [--pass [PASSWORD]]` | Poll a leaf with its saved token; --pass marks a CA or leaf SUPERSEDED without issuance. |
| `abpki-cli create ...` | Create a server or client certificate for its intended use. |
| `abpki-cli check ...` | Query certificate status: `GOOD`, `REVOKED`, or `UNKNOWN`. |
| `abpki-cli info <fingerprint>` | Display X.509 certificate information. |
| `abpki-cli list-ca [valid|revoked|renew|all]` | List Intermediate CA metadata by state; defaults to `valid`. |
| `abpki-cli list [valid|revoked|renew|all]` | List leaf metadata by state; defaults to `valid`. |
| `abpki-cli download {fingerprint} {target}` | Download the certificate, its private key, and its trust chain as `{target}.tar.gz`, identified by the certificate fingerprint. |

Certificate creation is available to any connected client. URI SAN values are encoded within the documented input limits. The consuming server or client interprets purpose and access-policy claims. See the [field input reference](../LEAF-CREATE.md#certificate-field-support). Additional Intermediate CA creation returns `501 Not Implemented` in 1.0. Certificate revocation requires the administrator password. `abpkid` enforces these permissions when processing requests.

## Validity and renewal

Leaf certificates default to 47 days; Intermediate CAs use the installation-derived `min(398, TrueLog retention days - 7)` default and maximum. Leaves enter SUPERSEDED when seven days remain or their issuer is replaced; CA renewal starts at 48 days. ADMIN `renew --pass` can mark a certificate SUPERSEDED earlier. Normal leaf `renew` returns a no-op for VALID or issues a new VALID certificate for SUPERSEDED, preserving its original duration. Old leaves retire after seven days and old CAs after 48 days, independently of renewal/download completion.

[Step-by-step leaf renewal and response examples](../LEAF-RENEW.md) · [Intermediate CA operator procedure](../INTERMEDIATE.md#operator-procedure) · [Validity and renewal rules](../VALIDATION.md)

## Certificate status

`check` reports one of the certificate status values `GOOD`, `REVOKED`, or `UNKNOWN` returned by the service.

## Download encoding

All downloaded certificates, private keys, and trust chains use PEM encoding, including files contained in `.tar.gz` archives.

## Root CA certificate download

`GET https://<dns record name>:5546/root` returns the Root CA certificate in PEM with `Content-Type: application/x-pem-file`. No administrator password or client certificate is required.

`abpki-cli root` uses this endpoint on the client configuration's `https_port` (default 5546) and saves the PEM certificate as `root.crt`.

## CA chain download

`abpki-cli chain ...` downloads the Intermediate CA certificate and its Root CA certificate together as PEM certificate blocks in a file named `trust-chain`.

## Certificate download

`fingerprint` identifies the certificate to download. `target` supplies the output base path. The output is a gzip-compressed tar archive named `{target}.tar.gz` containing exactly three PEM files:

| Archive member | Contents |
| --- | --- |
| Certificate | The server or client certificate identified by `fingerprint` |
| Private key | The private key matching that certificate |
| Trust chain | The Intermediate CA and Root CA certificates together in one PEM file |

For example, a target of `certificates/server` produces `certificates/server.tar.gz`.

```mermaid
sequenceDiagram
    participant CLI as abpki-cli
    participant Local as abpki-client
    participant Server as abpkid
    participant File as Local filesystem
    CLI->>Local: Request certificate through Unix socket
    Local->>Server: Request certificate over TLS
    Server-->>Local: Certificate archive
    Local-->>CLI: Archive through Unix socket
    CLI->>File: Save as target.tar.gz
```

Private-key downloads and normal leaf renewal require the certificate-specific access token returned by issuance. The CLI saves issuance tokens in caller-owned credential records and includes the selected token in the Unix socket request for these commands. The service has no application user accounts; `revoke` and `renew --pass` receive the single administrator password through the Unix socket credential field which is verified on the server. Bare `--pass` prompts in the calling CLI; per-command credentials are not service environment variables.

[Common Names, DNS naming, and uniqueness](../COMMON-NAME.md)

## Certificate list filters

| Leaf command | Intermediate CA command | Included state |
| --- | --- | --- |
| `abpki-cli list` or `abpki-cli list valid` | `abpki-cli list-ca` or `abpki-cli list-ca valid` | `VALID` |
| `abpki-cli list revoked` | `abpki-cli list-ca revoked` | `REVOKED` |
| `abpki-cli list renew` | `abpki-cli list-ca renew` | `SUPERSEDED`: renewal handover pending |
| `abpki-cli list all` | `abpki-cli list-ca all` | All states |

The `renew` list selector displays stored SUPERSEDED rows. Scheduled readiness, CA replacement, and explicit ADMIN transitions populate this state. `list-ca all` includes every Intermediate CA generation, regardless of state.

Each page contains at most 256 entries matching the selected filter. Every page preserves the selected filter and the initial maximum-index boundary. Lists contain metadata only.
