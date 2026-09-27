# Runtime configuration

Autobricks PKI Server 1.0 runs on Linux. Install Autobricks DNS and Autobricks TrueLog first. The PKI process requires access to the DNS control socket and a dedicated directory on the TrueLog-provided WORM mount.

Install and configure `autobricks-truelog-cli` on the PKI host, with the PKI service account authorized to access its client socket. TrueLog manages audit storage; PKI does not specify an audit filename.

[Service files, directory ownership, and permissions](../FILES.md)

## Server configuration

| Environment variable | Function | Default |
| --- | --- | --- |
| `ABPKI_DATABASE` | SQLite database file on mutable storage | `abpki.sqlite` |
| `ABPKI_WORM` | Existing directory on the WORM mount for certificates and private-key archives | `/mnt/worm-storage/pki` |
| `ABPKI_TRUELOG_CLI` | TrueLog client executable for audit submission as service `abpkid` | `/usr/bin/ab-truelog-cli` |
| `ABPKI_ORIGIN` | Public HTTPS origin using the registered DNS name; published URLs use `ABPKI_HTTPS_PORT` | `https://pki.<baseDomain>` from initialization or SQLite |
| `ABPKI_BIND` | Listen IP address shared by both listeners, without a port | `0.0.0.0` |
| `ABPKI_TLS_PORT` | Certificate management TLS port | `5545` |
| `ABPKI_HTTPS_PORT` | Public HTTPS port | `5546` |
| `AUTOBRICKS_DNS_SOCKET` | Autobricks DNS Unix control socket | `/run/autobricks-dns/autobricks-dns.sock` |
| `ABPKI_ADMIN_PASSWORD` | Single administrator password used by `init` | Required for initialization |

The SQLite parent directory and WORM artifact directory must already exist. Protect the SQLite directory from other operating-system users. The database requires mode `0600`. `ABPKI_WORM` must designate actual WORM storage; the filesystem supplies immutability and retention enforcement.

## Initialization and service operation

```sh
export ABPKI_DATABASE=/var/lib/autobricks-pki/abpki.sqlite
export ABPKI_WORM=/mnt/worm-storage/pki
export ABPKI_ORIGIN=https://pki.example.internal
export ABPKI_BIND=0.0.0.0
export ABPKI_TLS_PORT=5545
export ABPKI_HTTPS_PORT=5546

read -rsp 'Administrator password: ' ABPKI_ADMIN_PASSWORD
export ABPKI_ADMIN_PASSWORD
abpkid init 192.0.2.10 example.internal
unset ABPKI_ADMIN_PASSWORD

abpkid root > root-trust.pem
abpkid serve
```

`init REGISTRATION_IP [BASE_DOMAIN]` prompts for `baseDomain` when the argument is omitted. Press Enter to use `autobricks.internal`; unattended installation supplies the domain argument explicitly. `baseDomain` is limited to 24 ASCII characters, including dots. The domain is stored in SQLite. Root and Intermediate CA names and subjects are described in [CA initialization](../INTERMEDIATE.md#installation-domain-and-ca-subjects).

`init` takes the DNS registration address as an installation argument, separate from the listener bind address. Wildcard and multicast registration addresses are rejected. Normal service operation does not require this argument.

`init` requires a password of at least 12 bytes and creates the Root CA, six Intermediate CAs, empty signed CRLs, and the PKI service's TLS certificate. It queues DNS registration for the service hostname and certificate/key delivery to WORM and audit submission through TrueLog. Reinitializing an existing hierarchy is rejected.

If external delivery fails after initialization commits, the CA hierarchy remains in SQLite. `serve` retries pending delivery; reinitialization does not replace the hierarchy. The local `root` command exports only the public Root CA certificate as PEM. Distribute this trust anchor through a trusted channel before connecting with `abpki-cli`.

The service checks CA renewal, its own TLS certificate renewal, CRL refresh, and pending delivery every 30 seconds. New TLS connections use the current service certificate. Other deployed leaf certificates remain the responsibility of their holders. HTTPS retrieval refreshes an expired CRL before returning it.

## Client connection

```sh
export ABPKI_SERVER=tls://pki.example.internal:5545
export ABPKI_HTTPS_PORT=5546
export ABPKI_TRUST_FILE=/path/to/root-trust.pem
abpki-cli list-ca
abpki-cli root
abpki-cli chain www.example.internal
```

Certificate management uses TLS port 5545. The `root` command uses HTTPS on the same hostname with `ABPKI_HTTPS_PORT` (default 5546).

The client validates the server certificate against `ABPKI_TRUST_FILE` and checks the requested hostname. It sends no client certificate. Download commands create new output files and refuse to overwrite existing files.

## Certificate creation

`create` reads a JSON request from standard input. `issuer` accepts an Intermediate CA CN or its SHA-256 fingerprint. The CN selects its newest certificate generation. `kind` is `server`, `client`, or `server-and-client`.

```sh
abpki-cli create <<'JSON'
{
  "issuer": "www.example.internal",
  "profile": {
    "kind": "server",
    "common_name": "web01",
    "ip_addresses": ["192.0.2.20"],
    "uri_sans": ["urn:autobricks:purpose:www"]
  }
}
JSON
```

Omitting `validity` uses the current UTC time and a 47-day lifetime. A custom `validity` object contains `not_before` and `not_after` as Unix timestamps in seconds, subject to the issuer boundary. Server profiles require a supported purpose URI and at least one address for automatic DNS registration. Leaf CNs contain 1–24 ASCII letters, digits, or hyphens, without leading or trailing hyphens, and are normalized to lowercase. New leaf issuance rejects existing CNs across all issuers and certificate kinds; renewal preserves the existing CN. Server DNS names are generated as `<intermediate>-<cn>.<baseDomain>` and inserted into DNS SAN. Omit `dns_names` or supply exactly that generated name. Autobricks DNS receives the corresponding A/AAAA records. Existing external records with different addresses remain delivery conflicts. See [CN and DNS rules](../COMMON-NAME.md).

Client-only profiles do not trigger DNS registration. Leaf certificate subjects currently contain the Common Name; additional identity information is supplied through DNS, IP, and URI SANs. Issued leaf certificates include AIA OCSP and CRL Distribution Points URLs derived from `ABPKI_ORIGIN`.

The JSON response contains `certificate`, `download_token`, and `integrations_pending`. Store the token securely; list and status endpoints never return it or private keys. A pending integration is retried from SQLite and does not require issuing another certificate.

```sh
export ABPKI_ACCESS_TOKEN='<token returned by create>'
abpki-cli download <fingerprint> server
abpki-cli check <fingerprint>
abpki-cli renew <fingerprint>
```

`download` creates `server.tar.gz` containing `certificate.pem`, `private-key.pem`, and `trust-chain`, all PEM-encoded. `renew` requires the existing certificate's token and the final seven-day renewal window. Its response contains a replacement certificate and a new token. Renewal does not grant revocation permission.

## Administrator operations

There are no user accounts or user management. One administrator password authorizes Intermediate CA creation and leaf revocation. Intermediate names accept at most 16 ASCII letters, digits, or hyphens, excluding the optional `.<baseDomain>` suffix.

```sh
read -rsp 'Administrator password: ' ABPKI_ADMIN_PASSWORD
export ABPKI_ADMIN_PASSWORD
printf '%s\n' '{"cn":"custom-ca","days":398}' | abpki-cli create-ca --pass
abpki-cli revoke <fingerprint> --pass
unset ABPKI_ADMIN_PASSWORD
```

`--pass PASSWORD` also accepts the password directly. With `--pass` and no value, the CLI reads `ABPKI_ADMIN_PASSWORD`. Revocation and the updated signed CRL commit in the same SQLite transaction. OCSP queries read the committed certificate status.

## Public HTTPS interfaces (5546)

| Method | Path | Function |
| --- | --- | --- |
| GET | `/` | Product and build version |
| GET | `/crl/<cn-or-intermediate-fingerprint>` | Signed issuer CRL in PEM |
| POST | `/ocsp/` | RFC 6960 DER request and response |
| GET | `/root` | Root CA PEM |

The public listener exposes only the product information, Root CA, CRL, and OCSP endpoints. It does not expose management operations. HTTP/1.0 and HTTP/1.1 are supported, including chunked request bodies. Headers are limited to 16 KiB and bodies to 1 MiB. OCSP uses standard binary DER bodies and media types.

## Management TLS interface (5545)

| Operation | Path selector | Function |
| --- | --- | --- |
| GET | `/api/chain/<issuer>` | Intermediate and Root PEM chain |
| GET | `/api/list-ca` | Intermediate CA records without private keys |
| GET | `/api/list` | Leaf records without private keys |
| GET | `/api/check/<fingerprint>` | GOOD, REVOKED, or UNKNOWN revocation status |
| GET | `/api/download/<fingerprint>` | Token-protected three-file archive |
| POST | `/api/create` | JSON certificate creation request |
| POST | `/api/create-ca` | Administrator-protected CA creation |
| POST | `/api/revoke` | Administrator-protected leaf revocation |
| POST | `/api/renew` | Token-protected leaf renewal |

Management uses one newline-terminated JSON request and response per TLS connection. Requests contain `method` (`GET` or `POST`), `path`, `content_type`, optional `credential`, and `body` as an array of bytes. POST payload bytes contain JSON with content type `application/json`. Administrator passwords and certificate access tokens occupy the encrypted `credential` field. Responses contain `status`, `content_type`, and `body` as an array of bytes. Request frames are limited to 1 MiB and response frames to 16 MiB, including the terminating newline.

Both listeners validate requests independently and close connections after one response. Both use the service TLS certificate without requiring client certificates. The combined connection limit is 32, with a 15-second connection deadline. Certificate fingerprints are lowercase hexadecimal SHA-256 digests of the complete DER certificate.

[CLI functions](cli.md) · [Key storage](key-storage.md) · [CRL](../CRL.md) · [OCSP](../OCSP.md)
