# AUTH support

Autobricks PKI does not implement or own an AUTH service. The Autobricks Auth
service owns the separate Auth SQLite database, its schema, ALLOW contracts,
the writable in-memory Snapshot, and every data mutation. The
`autobricks-auth` dynamic library loaded by PKI is a read-only decision
consumer.

PKI provides optional AUTH protocol support. When enabled, `abpkid` validates
the PKI-owned certificate information in an AUTH request and delegates only the
exact SERVER-to-CLIENT access decision to `autobricks-auth`. The wire format
uses the VCCMS RFC 6960-derived AUTH profile.

## Ownership boundary

| Responsibility | Owner |
| --- | --- |
| Parse the AUTH-over-OCSP request profile | PKI |
| Resolve CLIENT and SERVER `CertID` values | PKI |
| Determine current certificate status | PKI |
| Convert resolved certificates to SHA-256 fingerprints | PKI |
| Create and maintain the Auth SQLite database and schema | Autobricks Auth service |
| Receive `ab-auth-cli add` and `del` operations | Autobricks Auth service |
| Persist ALLOW contract mutations and maintain the writable Snapshot | Autobricks Auth service |
| Connect PKI checks to the running Auth service | Autobricks Auth library |
| Decide the exact SERVER/CLIENT pair | Autobricks Auth |
| Combine certificate status and the pair decision | PKI |
| Encode the AUTH protocol response | PKI |

PKI must not create, migrate, repair, or write the Auth database. It must not
duplicate the Auth Cache configuration, ALLOW Snapshot, or pair lookup logic.
Autobricks Auth must not own PKI certificate status, issuer resolution, CRL,
OCSP, TLS, or HTTP routing.

## Service and PKI runtime roles

Autobricks Auth runs as a service before PKI uses AUTH support. Service startup
creates or opens the Auth SQLite database, prepares its schema, loads all ALLOW
records into the writable Snapshot, and owns the persistence Queue.

`ab-auth-cli` sends contract-management operations to the running Autobricks
Auth service. The service, not PKI, handles these operations:

```text
ab-auth-cli add <server-fingerprint> <client-fingerprint> [...]
ab-auth-cli del <server-fingerprint> [<client-fingerprint>]
```

PKI is a separate process. When AUTH support is enabled, PKI loads the
Autobricks Auth dynamic library as a lightweight check client and calls only
the pair-check operation. In this mode:

- the Auth database and schema must already exist;
- database or schema creation is forbidden;
- database, Queue, and ALLOW contract writes are forbidden;
- `ab_auth_add` and `ab_auth_del` are forbidden;
- PKI does not run the Auth service or accept `ab-auth-cli` management calls;
- the library sends `ab_auth_check` to the running Auth service over its
  configured local IPC connection; and
- missing or unavailable Auth state fails closed and can never produce ALLOW.

More than one process on the same machine may load its own Autobricks Auth
dynamic-library instance. Snapshot and Cache consistency among those instances
is an Autobricks Auth responsibility. PKI does not implement or control that
synchronization. The PKI-facing contract is only that an Auth check returns the
current authorization decision maintained by Autobricks Auth.

## PKI configuration

`pki.json` controls whether PKI exposes AUTH protocol support:

```jsonc
{
  "auth_support": true
}
```

Packaged services may set the equivalent `ABPKI_AUTH_SUPPORT=true` environment
value in `/etc/autobricks/pki/abpkid.env`. The installer writes `false` by
default and preserves an existing valid setting during reconfiguration.

Autobricks Auth has its own installed configuration. PKI does not copy or
interpret Auth-owned Connection, Cache, SQLite, Queue, or IPC fields.

Configuration behavior established so far:

- `auth_support: false` means PKI does not initialize or use
  `autobricks-auth` and does not provide AUTH protocol support.
- `auth_support: true` means PKI requires the Auth library and running Auth
  service during `serve` startup.
- PKI configuration does not contain an Auth library path. Dynamic-library
  discovery uses the installed locations, with `AUTOBRICKS_AUTH_LIBRARY` as an
  explicit test/development override.
- Auth data remains separate from the PKI operational database.

## Autobricks Auth module contract

The current Autobricks Auth 0.2 C ABI is an opaque-handle function interface.
It is not a callback-table interface. PKI prepares an internal dynamic-call
adapter, but every adapter operation is gated by `auth_support`.

When `auth_support` is `false`, PKI must not:

- load the Autobricks Auth dynamic library;
- resolve or invoke an `ab_auth_*` symbol;
- validate or initialize the nested `auth` object;
- open or create the Auth SQLite database or Queue;
- start the Auth Cache PRELOAD Snapshot; or
- call Auth during `/ocsp/`, certificate management, or another PKI path.

The source may contain the adapter implementation so one binary supports both
configurations, but the disabled runtime path must remain unreachable.

When `auth_support` is `true`, the intended PKI module lifecycle is:

1. Load the platform Autobricks Auth dynamic library.
2. Resolve `ab_auth_abi_version` and require ABI version `3`.
3. Call the no-argument `ab_auth_initialize()` entry point.
4. Retain the resulting lightweight IPC client handle.
5. Retain the returned opaque Auth handle for the PKI service lifetime.
6. For a GOOD CLIENT/SERVER pair, call
   `ab_auth_check(handle, server_fingerprint, client_fingerprint)`.
7. On shutdown, call `ab_auth_uninitialize(handle)` exactly once before
   unloading the library.

PKI uses these Auth functions:

| Function | PKI use |
| --- | --- |
| `ab_auth_abi_version` | Verify the loaded ABI before initialization |
| `ab_auth_initialize` | Connect a lightweight client to the configured Auth service |
| `ab_auth_check` | Check one exact SERVER/CLIENT fingerprint pair |
| `ab_auth_last_error` | Read a diagnostic after a failed Auth call |
| `ab_auth_uninitialize` | Flush and release the retained Auth handle |

`ab_auth_validate` is available for configuration-only validation without
opening runtime state. `ab_auth_add` and `ab_auth_del` belong to the service
management path and PKI must never invoke them.

Autobricks Auth 0.2.8 `ab_auth_initialize` reads only the IPC object from the
installed Auth configuration. It does not open the Auth database or initialize
Cache, Queue, or TrueLog state in the PKI process.

`ab_auth_check` returns `AB_AUTH_ALLOW` (`1`), `AB_AUTH_DENY` (`0`), or
`AB_AUTH_ERROR` (`-1`). PKI maps ALLOW only after both certificates are GOOD.
An Auth ERROR is never ALLOW and follows the fail-closed AUTH response rule.

The Auth service configuration contains these top-level members:

- `ipc`
- `truelog_cli`
- `connection`
- `caches`

The dynamic library reads the `ipc` member itself from the installed Auth
configuration. PKI neither receives nor passes that configuration object.

If enabled Auth initialization fails, `abpkid serve` fails startup. An Auth
check error is never converted to ALLOW.

## Endpoint

| Method | URL | Request content type | Response content type |
| --- | --- | --- | --- |
| POST | `https://pki.<baseDomain>:<https-port>/auth/` | `application/ocsp-request` | `application/ocsp-response` |

`<baseDomain>` is the PKI installation base domain. `<https-port>` is the
configured public HTTPS listener port; the default is `5546`. The trailing
slash in `/auth/` is part of the endpoint.

The endpoint exists only when `auth_support` is enabled. It is a decision query
only. It does not add or delete authorization contracts and does not issue,
renew, or revoke certificates.

## Request profile

The POST body is one unsigned, DER-encoded RFC 6960 `OCSPRequest`. It contains
exactly two request entries in this fixed order:

1. `requestList[0]`: CLIENT certificate `CertID`
2. `requestList[1]`: SERVER certificate `CertID`

Each `CertID` retains the standard OCSP fields:

```asn1
CertID ::= SEQUENCE {
    hashAlgorithm   AlgorithmIdentifier,
    issuerNameHash  OCTET STRING,
    issuerKeyHash   OCTET STRING,
    serialNumber    CertificateSerialNumber
}
```

The CLIENT and SERVER certificates themselves are not included in the POST
body. The caller constructs each `CertID` from the applicable issuer
certificate and leaf certificate. The issuer certificate is used locally and
is not transmitted.

The AUTH request profile requires:

- canonical DER encoding;
- exactly two `Request` entries in CLIENT-then-SERVER order;
- no `optionalSignature`;
- no `requestExtensions`; and
- no `singleRequestExtensions` on either entry.

JSON, certificate PEM, certificate DER, Base64 wrappers, form fields, and raw
fingerprint pairs are not AUTH POST bodies.

## Certificate resolution

`abpkid` resolves both `CertID` values against PKI-managed certificate state.
It verifies the issuer binding and serial number, then obtains the normalized
SHA-256 fingerprints used by Autobricks Auth.

Before an ALLOW decision is possible:

- `requestList[0]` must resolve to a client-capable leaf certificate;
- `requestList[1]` must resolve to a server-capable leaf certificate;
- both certificates must have current GOOD status; and
- the exact `(SERVER fingerprint, CLIENT fingerprint)` pair must exist in the
  current Autobricks Auth ALLOW Snapshot.

Common Names, Subjects, DNS names, IP addresses, users, groups, and roles are
not authorization keys.

## Response profile

The response body contains exactly one of these ASCII decision tokens:

| Certificate status | Access mapping | Response body |
| --- | --- | --- |
| Both certificates are GOOD | Pair exists | `GOOD:ALLOW` |
| Both certificates are GOOD | Pair does not exist | `GOOD:DENY` |
| Either certificate is REVOKED | Not evaluated as ALLOW | `REVOKED:DENY` |
| Either certificate cannot be resolved or is not currently valid | Not evaluated as ALLOW | `UNKNOWN:DENY` |

`REVOKED` takes precedence over `UNKNOWN`. `ALLOW` is possible only with
`GOOD:ALLOW`; every other result is DENY.

The response uses `Content-Type: application/ocsp-response` for compatibility
with the AUTH profile, but its body is the registered ASCII AUTH decision
token, not an RFC 6960 DER `OCSPResponse`.

Responses are not cacheable. A malformed request, unexpected response token,
HTTP error, timeout, connection failure, unavailable Auth library or Snapshot,
or internal lookup failure must be treated as `UNKNOWN:DENY` by the caller.
No failure may be converted to ALLOW.

## Example

```http
POST /auth/ HTTP/1.1
Host: pki.autobricks.internal:5546
Content-Type: application/ocsp-request
Content-Length: <decimal-der-length>

<OCSPRequest DER: CLIENT CertID, SERVER CertID>
```

```http
HTTP/1.1 200 OK
Content-Type: application/ocsp-response
Cache-Control: no-store

GOOD:ALLOW
```

AUTH does not replace certificate-chain, hostname, CRL, or OCSP validation
performed by the connecting parties. It adds the exact SERVER-to-CLIENT access
decision after PKI certificate-status resolution.

[Certificate services](docs/certificate-services.md) · [CRL distribution](CRL.md) · [OCSP service](OCSP.md)
