# Operation results and errors

Autobricks PKI Server 1.0 reports whether a request completed separately from certificate status. A successful status query may report GOOD, REVOKED or UNKNOWN. A successful revocation reports REVOKED.

## Management responses

| Status | When it is returned | User action |
| --- | --- | --- |
| `200 OK` | The operation completed, including a renewal poll that did not issue a replacement | Read the command-specific result |
| `400 Bad Request` | A request was rejected because of input, credentials, certificate state, issuer availability or a service failure | Check the request and credential, then service availability; do not assume this code identifies only malformed input |
| `404 Not Found` | An unknown route, or an unknown certificate requested with `info` | Check the endpoint or fingerprint |
| `409 Conflict` | An authorized renewal targets a revoked certificate | No replacement is issued |
| `501 Not Implemented` | Additional Intermediate CA creation in version 1.0 | Use the default installation hierarchy |

A missing issuer or download target and invalid credentials can return `400`; they do not have separate guaranteed `403`, `404` or `500` classifications. `check` returns `200` with `status=UNKNOWN` for an unknown fingerprint.

A rejected request normally contains this JSON body:

```json
{"error":"Request rejected; check parameters, permissions, validity, and service availability."}
```

The CLI reports unsuccessful requests with a nonzero exit status. Management responses use `status`, `content_type` and body bytes; see [the management interface](docs/runtime.md#management-tls-interface-5545).

## Creation

Creation accepts the [documented profile fields and input limits](LEAF-CREATE.md). Existing CN/DNS rules and issuer validity limits apply. PKI encodes supplied extension values without evaluating their application policy meaning.

Success returns the certificate identity, download token and delivery state. The CLI saves the token privately. `integrations_pending=true` means external delivery remains pending; it does not mean certificate issuance should be repeated.

An unknown or unusable issuer, reserved CN/DNS name, invalid input representation, or an issuance failure rejects the request. WORM certificate and key files must be written before issuance can succeed.

## Revocation

Standalone revocation requires the administrator password. It accepts a leaf fingerprint, not a CA. Repeating an authorized revocation of an already revoked leaf succeeds without changing its original revocation time.

Revocation becomes effective before CRL publication and audit delivery. A CRL publication failure leaves retry work pending and does not undo revocation. See [revocation](LEAF-REVOKE.md).

## Renewal

| Certificate state | Authorized ordinary leaf renewal |
| --- | --- |
| VALID | `result=200`, `renewed=false`; no replacement |
| SUPERSEDED | `result=200`, `renewed=true`; a new VALID certificate |
| REVOKED | `result=409`, `renewed=false`; no replacement |

ADMIN renewal marks a currently usable certificate SUPERSEDED without issuing a replacement. Repeated requests retain the first transition time. Invalid credentials, expired or not-yet-valid targets, and an interval outside issuer validity are rejected.

Leaf retirement occurs seven days after SUPERSEDED; Intermediate CA retirement occurs after 48 days. Renewal and download do not revoke the predecessor immediately or extend its deadline. See [renewal responses](LEAF-RENEW.md#renewal-responses).

## OCSP responses

OCSP uses binary DER response bodies, not the management JSON result format. A successful protocol response carries GOOD, REVOKED or UNKNOWN. Protocol errors such as MALFORMED_REQUEST or UNAUTHORIZED are distinct from signed certificate status.

The endpoint requires POST with `Content-Type: application/ocsp-request`. Unsupported methods return `405 Method Not Allowed`; unsupported media types return `415 Unsupported Media Type`. An HTTP success alone does not establish certificate validity. See [OCSP](OCSP.md).

## Retrying operations

| Situation | Action |
| --- | --- |
| Creation succeeded but external delivery is pending | Keep the returned identity and token; PKI retries delivery |
| Renewal succeeded but download failed | Retry download using the new fingerprint and its token |
| Invalid input or credentials | Correct them before retrying |
| Connection lost after sending a mutation | Determine the outcome before repeating the operation |
| Service unavailable | Restore connectivity/service availability, then check certificate state |

A lost response can follow committed issuance. Repeating creation does not recover a lost token and can be rejected because the CN is already reserved. Repeating renewal of the old fingerprint can issue another replacement. Authorized standalone revocation can be repeated safely.

[Creation](LEAF-CREATE.md) · [Revocation](LEAF-REVOKE.md) · [Renewal](LEAF-RENEW.md)
