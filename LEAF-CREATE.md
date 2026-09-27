# Leaf certificate creation

Autobricks PKI Server 1.0 issues `server`, `client`, and `server-and-client` certificates through an Intermediate CA. Any connected client can request issuance without an account, administrator password, or client certificate. The local `abpki-client` service verifies the server certificate and hostname using the OS trust store populated with the PKI Root CA during client installation.

This document specifies the creation flow with WORM as the source store and numeric CA-to-leaf relationships. Current runtime code still duplicates PEM contents in SQLite; the storage and audit flow below is not fully implemented.

## Request interface

`abpki-cli create --help` displays a JSON example directly. To use `abpki-cli create < request.json`, save the JSON object below as `request.json` and edit its issuer, CN, IP, and access policies. The installed field reference is `/usr/share/doc/autobricks-pki/LEAF-CREATE.md`.

`abpki-cli create` reads JSON from standard input and submits it to `abpki-client` through its local Unix socket. `abpki-client` sends the `/api/create` POST operation through management TLS (default port 5545). This path is a management protocol selector, not a public HTTPS endpoint.

Before this command, the local client installation configures `server = "192.0.2.10"`, `port = 5545`, and the public HTTPS port `5546`. Installation retrieves `/root`, registers the Root CA in OS trust, and saves the endpoint settings. The daemon loads those settings and OS trust. The CLI command below only sends the issuance request through the local Unix socket; it does not establish a remote TLS connection itself. See [client installation settings](docs/runtime.md#installation-settings).

```sh
abpki-cli create <<'JSON'
{
  "issuer": "www.autobricks.internal",
  "profile": {
    "kind": "server",
    "common_name": "web01",
    "ip_addresses": ["192.0.2.20"],
    "uri_sans": [
      "urn:autobricks:purpose:www",
      "urn:autobricks:allowed-source-cidr:192.0.2.0/24",
      "urn:autobricks:api-server:r:198.51.100.10/32"
    ]
  }
}
JSON
```

| Field | Requirement and processing |
| --- | --- |
| `issuer` | Required Intermediate CA CN or SHA-256 fingerprint. A CN selects the current `VALID` generation; a fingerprint selects an exact generation, which must also be `VALID` and within its validity interval. `SUPERSEDED` and `REVOKED` issuers cannot issue new leaves. |
| `profile.kind` | Required: `server`, `client`, or `server-and-client`. |
| `profile.common_name` | Required: 1–24 ASCII letters, digits, or hyphens, without leading or trailing hyphens; normalized to lowercase. |
| `profile.dns_names` | Optional array. For server-capable certificates, omit it or supply exactly the generated `<intermediate>-<cn>.<baseDomain>` name. |
| `profile.ip_addresses` | Optional array for client-only certificates. Server-capable certificates require at least one address, with at most one IPv4 and one IPv6 address. These become IP SANs and DNS A/AAAA records. |
| `profile.uri_sans` | Optional array for client-only certificates. Server-capable certificates require exactly one supported `urn:autobricks:purpose:<purpose>` entry. More than one purpose entry is rejected, including repeated identical values. Access-policy URNs use the formats in the certificate field catalog. |
| `profile.validity` | Optional object with `not_before` and `not_after` as Unix UTC seconds. Omission uses the current time and 47 days. The entire interval must fit within the selected issuer's validity. |

`uri_sans` is a JSON array. Separate quoted URI strings with commas, as in the example above; each string becomes a separate URI SAN. Do not combine several URIs inside one comma-separated string. The single purpose value must be in the supported catalog. Other array elements describe access policies, not additional certificate purposes. Purpose entries and access-policy entries can share the array, subject to their individual validation rules; the current validator permits at most one `urn:autobricks:allowed-source-cidr:` entry.

Unknown request/profile fields are rejected. Leaf subjects contain CN; this request does not accept arbitrary subject attributes, a CSR, or a caller-provided private key. See [certificate fields and purposes](CERTITFICATE.md) for the broader certificate field catalog.

Purpose and CIDR access URNs describe certificate claims. Open issuance does not verify that a requester owns the supplied addresses or is entitled to the requested access claims. A consuming service applies its own authorization policy; the presence of these claims alone does not establish administrator approval.

## Issuance processing

1. Resolve the Intermediate CA, verify that it is `VALID` and currently usable, and normalize the leaf CN. For a server-capable profile, generate the DNS name and insert it into DNS SAN.
2. Validate the profile, purpose/access URNs, DNS registration data, and validity interval. An interval exceeding the issuer boundary is rejected rather than shortened automatically.
3. Load the issuer certificate and encrypted private key from their WORM paths. Verify the certificate fingerprint and key correspondence, then decrypt the key in memory using the password from SQLite.
4. Start a SQLite `BEGIN IMMEDIATE` transaction and recheck the issuer state and CN/DNS uniqueness before issuance. Reject an existing leaf CN across issuers and leaf kinds, including expired or revoked records. Use targeted indexed lookups; do not load all certificate PEMs or decrypt unrelated keys to check uniqueness.
5. Generate a new P-256 private key and a random positive serial number. Sign an X.509 v3 certificate using the selected Intermediate CA and SHA-256. Generate the certificate access token and its hash.
6. Write the certificate PEM and encrypted PKCS#8 private-key PEM to WORM and synchronize the files. WORM failure prevents issuance success.
7. Insert certificate metadata and WORM paths into SQLite with `valid=VALID`, `superseded_at=NULL`, `revoked_at=NULL`, and `previous_certificate_idx=NULL`. Retain the issuance profile and token hash; do not store PEM contents or the plaintext token.
8. Insert `intermediate_leaf(intermediate_idx, leaf_idx)` using the actual issuer and new leaf row IDs. Queue the `CREATE` audit event with result `200` and any server DNS registrations in the same transaction. Commit.
9. Submit pending audit work through `ab-truelog-cli` and register DNS through Autobricks DNS. Confirmed TrueLog results populate `audit` as specified in [DDL.md](DDL.md#audit-history-schema). Return the certificate, access token, and delivery state.

The transaction serializes issuer-state and uniqueness checks with metadata insertion. WORM files cannot be rolled back with SQLite; an interrupted issuance can leave retained, unreferenced files. Those files do not represent a successfully committed certificate.

| Certificate extension | Value |
| --- | --- |
| Basic Constraints | Critical, CA=false. |
| Key Usage | Critical, digitalSignature. |
| Extended Key Usage | serverAuth, clientAuth, or both according to `kind`. |
| Subject Alternative Name | DNS, IP, and URI entries from the validated profile. |
| Subject/Authority Key Identifier | Identifies the leaf key and issuing CA key. |
| CRL Distribution Points | Public HTTPS `/crl/<intermediate-fingerprint>`. |
| Authority Information Access | Public HTTPS `/ocsp/`. |

```mermaid
sequenceDiagram
    participant Client as abpki-cli
    participant Local as abpki-client
    participant PKI as abpkid
    participant DB as SQLite
    participant WORM as WORM mount
    participant Log as TrueLog
    participant DNS as Autobricks DNS
    Client->>Local: create(profile, issuer) through Unix socket
    Local->>PKI: create using installed TLS configuration
    PKI->>DB: Begin; check CN and DNS uniqueness
    PKI->>PKI: Validate, generate key, sign certificate
    PKI->>WORM: Write certificate and encrypted key; synchronize
    PKI->>DB: Store metadata, paths, token hash, CA-leaf relation, outbox; commit
    PKI->>Log: Submit CREATE event with result 200
    opt Server-capable certificate
        PKI->>DNS: Register A/AAAA records
    end
    PKI-->>Local: certificate, download_token, integrations_pending
    Local-->>Client: Result through Unix socket
    Client->>Client: Save fingerprint and token in caller-owned credential record
```

## Result and artifact delivery

The JSON result contains `certificate`, `download_token`, and `integrations_pending`. The certificate result identifies the fingerprint, CN, issuer, serial, validity, and lifecycle state. Any certificate PEM returned in the response is read from WORM; it is not a SQLite column. The result excludes private keys, token hashes, and the stored profile. The CLI saves the returned fingerprint/token association in the calling user's protected local credential record before reporting completion. Normal output omits the token. Listing and status operations cannot recover it. See [per-operation socket data](docs/runtime.md#per-operation-data-through-the-unix-socket).

`integrations_pending=true` means reconciliation encountered a pending external delivery failure, potentially including an earlier queued operation. Certificate issuance has already committed. The server retries pending work during maintenance; the client must not create another certificate merely to retry DNS or audit delivery. WORM certificate and key files must already be stored before issuance success.

WORM artifacts use the UTC creation date and certificate fingerprint:

```text
/mnt/worm-storage/<installation-timestamp>/pki/certificate/<YYYY-MM-DD>/<fingerprint>/<CN>.pem
/mnt/worm-storage/<installation-timestamp>/pki/certificate/<YYYY-MM-DD>/<fingerprint>/<CN>.key.pem
```

Stored key PEM is encrypted. TrueLog owns audit file creation and retention. Client-only issuance does not register DNS records.

Use the returned fingerprint to download the deployment archive. The CLI reads the associated token from its local credential record and includes it in the Unix socket request:

```sh
abpki-cli download <fingerprint> web01
```

`web01.tar.gz` contains exactly `certificate.pem`, `private-key.pem`, and `trust-chain`. All contents are PEM; the downloaded leaf key is decrypted. Local output files use mode `0600` and existing output files are not overwritten.

## Failure and retry behavior

Validation or transactional failure rolls back SQLite metadata, relationships, and queued operations. WORM files already written remain subject to retention. DNS or audit delivery failure after commit retains the issued certificate and pending operations. Missing or unreadable issuer files, failed WORM writes, signing failure, and database faults produce a server error rather than a successful issuance. A lost issuance response can leave a committed certificate whose token the client never received; the interface has no issuance request identifier or token recovery operation. Repeating `create` with the same CN is rejected by uniqueness checks.

[SQLite schema](DDL.md) · [Naming](COMMON-NAME.md) · [Revocation](LEAF-REVOKE.md) · [Renewal](LEAF-RENEW.md)

[Operation results and audit error codes](ERROR.md)
