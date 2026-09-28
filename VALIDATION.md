# Certificate validity and renewal

## Default validity

| Certificate type | Default validity | Renewal responsibility |
| --- | --- | --- |
| Root CA | No defined expiration | Root CA management |
| Intermediate CA | `min(398, TrueLog retention days - 7)` days | Internal renewal by `abpkid` |
| Server certificate | 47 days | Periodic checks and renewal by the certificate holder |
| Client certificate | 47 days | Periodic checks and renewal by the certificate holder |

Intermediate CA validity may be shortened at creation but cannot exceed its installation-derived maximum. Leaf validity periods can be changed at creation. Server and client certificates are leaf certificates. Their validity must remain within the issuing Intermediate CA certificate's validity, including when a custom duration is requested.

## Installation retention boundary

During installation initialization, `abpkid init` reads `AB_WORM_RETAIN_DAYS` from the installed TrueLog configuration (`/etc/default/autobricks-log` by default). It calculates:

```text
intermediate_max_days = min(398, truelog_retention_days - 7)
```

A 365-day retention setting yields 358 days. This value is calculated from installation settings, not fixed at 358. The seven-day margin is measured in elapsed 24-hour days. Missing, unreadable, invalid, or duplicate retention settings prevent CA initialization; retention must exceed seven days.

SQLite stores the observed retention and resulting limit in `settings.ca_validity_policy`. Initial default CAs, additional CA creation, and internal CA renewal use this limit. Explicit validity requests above the limit are rejected. A later TrueLog setting change does not automatically alter this stored policy or the signed contents of existing certificates.

The setting describes the protection period assigned to newly created WORM files. Existing WORM files keep their original retention deadlines. This policy does not change TrueLog configuration or extend existing files' protection.

## Root CA expiration encoding

The Root CA has no defined expiration under the product policy. X.509 still requires a `notAfter` value. The certificate uses GeneralizedTime `99991231235959Z` (9999-12-31 23:59:59 UTC), the representation specified for an undefined expiration date in [RFC 5280, Section 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5).

This does not remove signature, trust, or other certificate validation requirements.

## Issuer validity boundary

Validity is evaluated using actual UTC timestamps, not duration labels alone. A requested leaf validity interval must satisfy:

```text
intermediate.notBefore <= leaf.notBefore
leaf.notBefore < leaf.notAfter
leaf.notAfter <= intermediate.notAfter
```

An Intermediate CA's validity must likewise fit within its Root CA certificate's encoded validity interval.

For example, if an Intermediate CA has 20 days remaining, a leaf starting now cannot receive the default 47-day lifetime under that issuer certificate. Its requested expiration must fit within those 20 days. A 47-day request that exceeds the issuer boundary fails validity validation; the default does not override the boundary.

The same boundary applies to renewed certificates. Intermediate CA renewal does not change the signed expiration of previously issued leaf certificates.

## Renewal lifecycle

| Certificate | Automatic transition | SUPERSEDED lifetime |
| --- | --- | --- |
| Intermediate CA | 48 days before expiry | 48 days from transition |
| Server/client leaf | 7 days before expiry, or issuer CA replacement | 7 days from transition |

ADMIN `renew --pass` changes a currently valid certificate to SUPERSEDED earlier without issuing its replacement. The server handles pending Intermediate CA replacement automatically. It marks related leaves SUPERSEDED after that replacement. Leaf holders poll `renew`: VALID returns a no-op; SUPERSEDED issues a new VALID certificate; REVOKED returns 409. Tokens authorize ordinary leaf renewal. `check` remains GOOD/REVOKED/UNKNOWN.

## Scheduling and retirement

The server checks leaf readiness and retirement at startup and every 30 seconds, independently of the hourly CA/service TLS renewal run. Hourly attempt times survive restarts. SUPERSEDED Intermediate CAs are renewed internally, including those initiated early by ADMIN. Service TLS is replaced internally when due or when its issuer is renewed.

Leaf retirement occurs at `superseded_at + 604800`; Intermediate CA retirement occurs at `superseded_at + 4147200`. Neither deadline depends on renewal or download completion. Repeated requests do not reset transition times. Due retirement of persisted SUPERSEDED records is processed on restart. A deadline is enforced on the next maintenance pass; downtime never extends signed certificate validity. Revocation commits before CRL and audit delivery. Missing transition timestamps are errors, never replaced with invented dates.

## Duration preservation on renewal

```text
original_duration = old.not_after - old.not_before
new.not_before = issuance_time_utc
new.not_after = new.not_before + original_duration
```

Renewal preserves the original duration exactly in seconds, not the remaining lifetime. A seven-day certificate renews for seven days and a 47-day certificate for 47 days. Intermediate CAs also retain their original duration. Requests cannot override duration or profile. If the new interval exceeds issuer validity, issuance fails without shortening it. The original signed expiration remains effective during SUPERSEDED state.

[Leaf renewal and responses](LEAF-RENEW.md) · [Intermediate CA lifecycle](INTERMEDIATE.md)
