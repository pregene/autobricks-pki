# Leaf certificate creation

Autobricks PKI Server 1.0 issues certificates through an Intermediate CA. `extended_key_usage` selects certificate EKUs; legacy `kind` requests remain accepted. Any connected client can request issuance without an account, administrator password, or client certificate. The local `abpki-client` service verifies the server certificate and hostname using the OS trust store populated with the PKI Root CA during client installation.

This document specifies the creation flow with WORM as the source store and numeric CA-to-leaf relationships. Certificate and key PEM contents reside only on WORM. The audit-history schema below is not yet populated by the runtime.

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
| `profile.kind` | Legacy selector: `server`, `client`, or `server-and-client`. Use either this field or `extended_key_usage`. |
| `profile.extended_key_usage` | Array of EKU names or OIDs. Selects server/client classification for the existing DNS and lifecycle integration. |
| `profile.common_name` | Required: 1–24 ASCII letters, digits, or hyphens, without leading or trailing hyphens; normalized to lowercase. |
| `profile.dns_names` | Optional array. For server-capable certificates, omit it or supply exactly the generated `<intermediate>-<cn>.<baseDomain>` name. |
| `profile.ip_addresses` | Optional array for client-only certificates. Server-capable certificates require at least one address, with at most one IPv4 and one IPv6 address. These become IP SANs and DNS A/AAAA records. |
| `profile.uri_sans` | Optional array, 1–16 supplied ASCII strings, at most 2,048 bytes each. Values, including repetitions, are encoded without checking their application meaning. |
| `profile.validity` | Optional object with `not_before` and `not_after` as Unix UTC seconds. Omission uses the current time and 47 days. The entire interval must fit within the selected issuer's validity. |

`uri_sans` is an array of strings, each encoded as one URI SAN. Contents are preserved as ASCII values within the documented length limit; PKI does not interpret URI purpose or access-policy claims. The consuming application decides what the values mean. Separate values with JSON commas instead of combining them into one string.

Unknown request/profile fields are rejected. The extended profile supports the Subject DN, SAN and extension fields listed below. CSR and caller-provided private-key input remain unavailable. See [certificate fields and purposes](CERTITFICATE.md) for the broader certificate field catalog.

Purpose and CIDR access URNs describe certificate claims. Open issuance does not verify that a requester owns the supplied addresses or is entitled to the requested access claims. A consuming service applies its own authorization policy; the presence of these claims alone does not establish administrator approval.

## Issuance processing

1. Resolve the Intermediate CA, verify that it is `VALID` and currently usable, and normalize the leaf CN. For a server-capable profile, generate the DNS name and insert it into DNS SAN.
2. Validate input sizes, ASN.1 representations, existing DNS registration constraints, and the validity interval. An interval exceeding the issuer boundary is rejected rather than shortened automatically.
3. Load the issuer certificate and encrypted private key from their WORM paths. Verify the certificate fingerprint and key correspondence, then decrypt the key in memory using the password from SQLite.
4. Start a SQLite `BEGIN IMMEDIATE` transaction and recheck the issuer state and CN/DNS uniqueness before issuance. Reject an existing leaf CN across issuers and leaf kinds, including expired or revoked records. Use targeted indexed lookups; do not load all certificate PEMs or decrypt unrelated keys to check uniqueness.
5. Generate a new P-256 private key and a random positive serial number. Sign an X.509 v3 certificate using the selected Intermediate CA and SHA-256. Generate the certificate access token and its hash.
6. Write the certificate PEM and encrypted PKCS#8 private-key PEM to WORM and synchronize the files. WORM failure prevents issuance success.
7. Insert certificate metadata and WORM paths into SQLite with `valid=VALID`, `superseded_at=NULL`, `revoked_at=NULL`, and `previous_certificate_idx=NULL`. Retain the issuance profile and token hash; do not store PEM contents or the plaintext token.
8. Insert `intermediate_leaf(intermediate_idx, leaf_idx)` using the actual issuer and new leaf row IDs. Queue the `CREATE` audit event with result `200` and any server DNS registrations in the same transaction. Commit.
9. Return the certificate, access token, and delivery state. A background worker submits queued audit work through `ab-truelog-cli` and registers DNS through Autobricks DNS. Persistent confirmed audit rows are specified in [DDL.md](DDL.md#audit-history-schema) but are not yet written by the runtime.

The transaction serializes issuer-state and uniqueness checks with metadata insertion. WORM files cannot be rolled back with SQLite; an interrupted issuance can leave retained, unreferenced files. Those files do not represent a successfully committed certificate.

| Certificate extension | Value |
| --- | --- |
| Basic Constraints | Critical, CA=false. |
| Key Usage | Requested bits; default critical digitalSignature. |
| Extended Key Usage | Requested names/OIDs, or the EKUs selected by legacy `kind`. |
| Subject Alternative Name | DNS, IP, URI, email, directoryName, registeredID and otherName values from the profile. |
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

`integrations_pending=true` means external delivery is outstanding, potentially including an earlier queued operation; it does not necessarily indicate a delivery failure. Certificate issuance has already committed. The server retries pending work during maintenance; the client must not create another certificate merely to retry DNS or audit delivery. WORM certificate and key files must already be stored before issuance success.

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

## Certificate field support

The table separates the certificate field from the project field name. Full attribute or extension names belong in the description. Each field appears once; URI contents, Key Usage bits, and Extended Key Usage purposes are values rather than separate fields.

`IMPLEMENTED` includes current input support and internal generation or management. `PLANNED` means support remains to be implemented. `N/A` means unsupported. Descriptions state input limitations. Project names use lowercase snake_case. Internal-only fields do not imply caller control over their values. [Request interface](#request-interface) lists the current create inputs. Existing input names and the designated `unit_name`, `private_oid`, and `csr` names are retained.

The limits below are product input/encoding bounds, not judgments about the meaning or application suitability of supplied values. Text lengths count Unicode scalar values unless marked ASCII bytes. A create request is limited to 65,536 UTF-8 bytes and the final certificate to 32,768 DER bytes. Omit optional fields rather than supplying null. Internally generated and N/A fields are not caller inputs. Existing CN naming and DNS registration constraints still apply.

Certificate identifiers follow [OpenSSL extension configuration](https://docs.openssl.org/3.0/man5/x509v3_config/), [OpenSSL DN configuration](https://docs.openssl.org/3.0/man1/openssl-req/#distinguished-name-and-attribute-section-format), [OpenSSL object definitions](https://github.com/openssl/openssl/blob/openssl-3.0.0/crypto/objects/objects.txt), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1), and [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986.html#section-4).

| Category | Certificate field | Project field | Description | Status |
| --- | --- | --- | --- | --- |
| Subject DN | CN | `common_name` | `commonName`. Current input: 1–24 ASCII bytes, letters/digits/hyphens only, no edge hyphens; normalized to lowercase. A leaf CN is globally unique.  | IMPLEMENTED |
| Subject DN | O | `organization_name` | `organizationName`. Input: one UTF8String, 1–64 Unicode scalar values. | IMPLEMENTED |
| Subject DN | OU | `unit_name` | `organizationalUnitName`. Input: one UTF8String, 1–64 Unicode scalar values. Project field name is unit_name. | IMPLEMENTED |
| Subject DN | C | `country_name` | countryName: exactly 2 PrintableString ASCII bytes; no country-code membership check. | IMPLEMENTED |
| Subject DN | ST | `state_or_province_name` | `stateOrProvinceName`. Input: one UTF8String, 1–128 Unicode scalar values. | IMPLEMENTED |
| Subject DN | L | `locality_name` | `localityName`. Input: one UTF8String, 1–128 Unicode scalar values. | IMPLEMENTED |
| Subject DN | street | `street_address` | `streetAddress`. Input: one UTF8String, 1–128 Unicode scalar values. | IMPLEMENTED |
| Subject DN | postalCode | `postal_code` | Postal code. Input: one UTF8String, 1–40 Unicode scalar values. | IMPLEMENTED |
| Subject DN | serialNumber | `subject_serial_number` | Subject/device serialNumber, distinct from the certificate serial. Input: one PrintableString, 1–64 ASCII bytes. | IMPLEMENTED |
| Subject DN | GN | `given_name` | `givenName`. Input: one UTF8String, 1–64 Unicode scalar values. | IMPLEMENTED |
| Subject DN | SN | `surname` | `surname`. Input: one UTF8String, 1–64 Unicode scalar values. | IMPLEMENTED |
| Subject DN | pseudonym | `pseudonym` | Pseudonym. Input: one UTF8String, 1–128 Unicode scalar values. | IMPLEMENTED |
| Subject DN | UID | `user_id` | `userId`. Input: one UTF8String, 1–64 Unicode scalar values. Does not create a PKI account. | IMPLEMENTED |
| Subject DN | DC | `domain_components` | domainComponent: 1–8 ordered IA5String values, each 1–63 ASCII bytes; input order and repeated values are preserved. | IMPLEMENTED |
| Subject DN | initials | `initials` | Initials. Input: one UTF8String, 1–16 Unicode scalar values. | IMPLEMENTED |
| Subject DN | title | `title` | Position/title. Input: one UTF8String, 1–64 Unicode scalar values. | IMPLEMENTED |
| Subject DN | description | `description` | Subject description. Input: one UTF8String, 1–1,024 Unicode scalar values. | IMPLEMENTED |
| Subject DN | businessCategory | `business_category` | Business classification. Input: one UTF8String, 1–128 Unicode scalar values. | IMPLEMENTED |
| Subject DN | organizationIdentifier | `organization_identifier` | Organization identifier. Input: one UTF8String, 1–64 Unicode scalar values. | IMPLEMENTED |
| Subject DN | dnQualifier | `dn_qualifier` | DN disambiguation. Input: one PrintableString, 1–64 ASCII bytes. | IMPLEMENTED |
| Subject DN | generationQualifier | `generation_qualifier` | Generation suffix. Input: one UTF8String, 1–16 Unicode scalar values. | IMPLEMENTED |
| Subject DN | emailAddress | `subject_email` | Subject emailAddress: one IA5String value, 1–128 ASCII bytes. Mailbox meaning and ownership are not checked. | IMPLEMENTED |
| Request | Certificate kind | `kind` | Legacy selector: server, client, server-and-client (6/6/17 ASCII bytes). Alternative to extended_key_usage; supplying both is ambiguous and rejected. | IMPLEMENTED |
| Issuer DN | issuer | `issuer` | Top-level issuer selects an Intermediate CA by CN or fingerprint. Current generated Intermediate CN has a 1–16-byte name component and baseDomain of at most 24 ASCII bytes; fingerprint is 64 lowercase hexadecimal characters. Actual CA Subject supplies Issuer DN. validates these forms explicitly. | IMPLEMENTED |
| Certificate body | validity | `validity` | Current optional object: not_before and not_after are signed 64-bit Unix-second integers; not_before < not_after, entirely within issuer validity and ASN.1 time encoding range. Omission uses current time plus 47 days. Retains the contract; examples omit this field. | IMPLEMENTED |
| SAN | dNSName | `dns_names` | 1–16 supplied IA5String values, each 1–253 ASCII bytes. Existing server issuance still accepts only the generated DNS name; omission generates it. Client-only values receive length/encoding checks. SAN total at most 64. | IMPLEMENTED |
| SAN | iPAddress | `ip_addresses` | 1–16 supplied IP literals, encoded as 4-byte IPv4 or 16-byte IPv6 addresses. Existing server DNS registration still requires 1–2 addresses, at most one per family. SAN total at most 64. | IMPLEMENTED |
| SAN | uniformResourceIdentifier | `uri_sans` | 1–16 IA5String values, each 1–2,048 ASCII bytes; SAN total at most 64. Contents and repetitions are preserved; no URI scheme, purpose, permission, CIDR-policy or endpoint checks. | IMPLEMENTED |
| SAN | rfc822Name | `email_sans` | 1–16 IA5String values, each 1–254 ASCII bytes; SAN total at most 64. No mailbox syntax, identity or ownership checks. | IMPLEMENTED |
| SAN | directoryName | `directory_name_sans` | Input: 1–16 nonempty DN objects, using the DN field limits; nested CN is 1–64 Unicode scalars and is not a reserved leaf CN. No repeated scalar attributes or multi-valued RDNs. Shared SAN total 64. | IMPLEMENTED |
| SAN | registeredID | `registered_id_sans` | 1–16 numeric OID strings, each 2–20 components and at most 100 ASCII bytes; components at most 2^32−1 with ASN.1 first/second-component rules. Repetitions preserved; SAN total at most 64. | IMPLEMENTED |
| SAN | otherName | `other_name_sans` | 1–16 objects with oid, asn1_type, value. OID at most 100 ASCII bytes/20 components. Typed value at most 4,096 DER bytes; text at most 1,024 Unicode scalars. No OID-specific application meaning checks; SAN total at most 64. | IMPLEMENTED |
| Extension | keyUsage | `key_usage` | 1–9 bit names; default digitalSignature. All nine X.509 bits can be encoded, regardless of algorithm/application suitability. contentCommitment and nonRepudiation name the same bit. Critical defaults to true and may be supplied explicitly. | IMPLEMENTED |
| Extension | extendedKeyUsage | `extended_key_usage` | 1–16 known names or numeric OIDs; each OID at most 100 ASCII bytes/20 components. Values are encoded without checking combinations or application purpose. serverAuth/clientAuth still determine internal TLS classification and DNS integration. | IMPLEMENTED |
| Extension | basicConstraints | `basic_constraints` | Internally generated CA=false for leaf creation, with no caller value override. Root/Intermediate CA generation remains separate. Leaf criticality defaults to true and may be set through critical. | IMPLEMENTED |
| Extension | nameConstraints | `name_constraints` | permitted_subtrees and/or excluded_subtrees: 1–16 entries each, one GeneralName per subtree. Name length/type bounds apply; IP constraints use address/prefix encoded as 8/32 bytes. No subtree applicability or descendant policy enforcement. Critical defaults true. | IMPLEMENTED |
| Extension | subjectKeyIdentifier | `subject_key_identifier` | Internally derived 20-byte key identifier; no caller value input. Its critical flag may be supplied explicitly. | IMPLEMENTED |
| Extension | authorityKeyIdentifier | `authority_key_identifier` | Internally generated from the issuer key identifier; no caller value input. Its critical flag may be supplied explicitly. | IMPLEMENTED |
| Extension | certificatePolicies | `certificate_policies` | 1–16 objects: policy_oid at most 100 ASCII bytes/20 components; optional cps_uri at most 2,048 ASCII bytes; optional user_notice 1–200 Unicode scalars. Encodes supplied policy/qualifier values without validating policy meaning or URL availability. | IMPLEMENTED |
| Extension | policyMappings | `policy_mappings` | 1–16 issuer_domain_policy/subject_domain_policy OID pairs, each OID at most 100 ASCII bytes/20 components. Encodes supplied pairs without policy matching or role checks. Critical defaults true. | IMPLEMENTED |
| Extension | policyConstraints | `policy_constraints` | Object with require_explicit_policy and/or inhibit_policy_mapping. JSON integers in 0..2,147,483,647; encoded as the corresponding context-tagged SkipCerts values. Critical defaults true; no policy evaluation. | IMPLEMENTED |
| Extension | inhibitAnyPolicy | `inhibit_any_policy` | JSON integer in 0..2,147,483,647, encoded as INTEGER. Critical defaults true. PKI does not evaluate the effect on a consuming application. | IMPLEMENTED |
| Extension | crlDistributionPoints | `crl_distribution_points` | Internally generated issuer-fingerprint HTTPS full-CRL URL; no caller value input. Its critical flag may be supplied explicitly. | IMPLEMENTED |
| Extension | freshestCRL | `freshest_crl` | 1–16 IA5String values, each 1–2,048 ASCII bytes, encoded as URI distribution points. No Delta CRL generation or URL availability checks are performed by this field mapping. Critical defaults false. | IMPLEMENTED |
| Extension | authorityInfoAccess | `authority_info_access` | Internally generated deployed OCSP URL using id-ad-ocsp; no caller value input. Its critical flag may be supplied explicitly. | IMPLEMENTED |
| Extension | subjectInfoAccess | `subject_info_access` | 1–16 objects: access_method OID at most 100 ASCII bytes/20 components and uri IA5String at most 2,048 bytes. Encodes values without checking method meaning, certificate role or service availability. | IMPLEMENTED |
| Extension | issuerAltName | `issuer_alt_name` | Object containing GeneralName arrays, 1–16 per supplied array and 64 names total. Same per-name bounds as SAN. Supplied identities are encoded without ownership or issuer-identity assertions. | IMPLEMENTED |
| Extension | subjectDirectoryAttributes | `subject_directory_attributes` | 1–16 attribute objects, each with 1–16 typed values. OID at most 100 ASCII bytes/20 components; value at most 4,096 DER bytes; text at most 1,024 Unicode scalars. Values are DER SET-ordered; no attribute semantics checks. | IMPLEMENTED |
| Extension | tlsfeature | `tls_feature` | 1–16 values: status_request (5), status_request_v2 (17), or a JSON integer 0..65535. Encodes the requested feature integers; does not implement or check TLS stapling. | IMPLEMENTED |
| Extension | noCheck | `ocsp_no_check` | Boolean inclusion switch: true emits ASN.1 NULL (05 00), false omits it. Critical defaults false. No responder-role or OCSP behavior checks. | IMPLEMENTED |
| Extension | qcStatements | `qc_statements` | 1–16 objects: statement_id OID at most 100 ASCII bytes/20 components, optional typed statement_info at most 4,096 DER bytes and text at most 1,024 scalars. Encodes supplied values without asserting qualified-certificate status. | IMPLEMENTED |
| Extension | Private extension OID | `private_oid` | 1–16 objects: OID at most 100 ASCII bytes/20 components; typed value at most 4,096 DER bytes; text at most 1,024 scalars; required Boolean critical. Do not duplicate reserved/generated extension OIDs. Custom extension semantics are the consuming application’s responsibility. | IMPLEMENTED |
| Extension control | critical | `critical` | Nonempty object, at most 32 extension project-name keys with Boolean values. Controls emitted extension flags without enforcing application profiles. Unknown/unemitted extension keys are errors. Private extension flags reside in their own objects. | IMPLEMENTED |
| Certificate body | subjectPublicKeyInfo | `subject_public_key_info` | Internally generated P-256 EC public key and algorithm/curve identifiers; no caller input or selectable key length. Retains P-256 generated-key mode. | IMPLEMENTED |
| CSR | CSR | `csr` | CSR input is not implemented. A CSR is a signed issuance request, not a certificate field. No CSR/private-key storage or download contract is introduced by the field-encoding implementation. | PLANNED |
| CSR | challengePassword | `challenge_password` | Unsupported. No accepted input value or length; not the administrator password. This key is not accepted; CSR import is not implemented. | N/A |
| Certificate body | version | `version` | Internally fixed to X.509 v3 (ASN.1 INTEGER value 2); no caller input. | IMPLEMENTED |
| Certificate body | serialNumber | `serial` | Internally generated positive 159-bit random integer, issuer-unique; current output is 40 uppercase hexadecimal characters without separators. No caller input. Subject serialNumber is a different field. | IMPLEMENTED |
| Certificate body | signature / signatureAlgorithm | `signature_algorithm` | Internally fixed to ECDSA with SHA-256; no caller algorithm string or length input. | IMPLEMENTED |
| Certificate body | signatureValue | `signature_value` | Internally computed ASN.1 ECDSA signature; variable encoded length, not caller text. No caller input. | IMPLEMENTED |
| Management | Fingerprint | `fingerprint` | Internally computed SHA-256 of final DER; exactly 64 lowercase hexadecimal characters, no separators. No create input. | IMPLEMENTED |
| Management | Private-key storage | `key_pem` | Internal PEM private key, encrypted for WORM storage and decrypted only for authorized leaf delivery. No create input or caller-selected text length; limits follow the generated P-256 key encoding. | IMPLEMENTED |
| Management | Access token | `download_token` | Internally generated 32 random bytes represented as 64 lowercase hexadecimal characters. Returned capability, not a create input. | IMPLEMENTED |
| Management | Certificate state and revocation time | `valid`, `superseded_at`, `revoked_at` | Internal lifecycle values VALID/SUPERSEDED/REVOKED (5/10/7 ASCII characters); superseded_at/revoked_at are nullable signed 64-bit Unix seconds. No create input. | IMPLEMENTED |
| Management | Renewal predecessor reference | `previous_certificate_idx` | Internal nullable numeric predecessor reference to a SQLite signed 64-bit integer row ID; no create input. | IMPLEMENTED |
| Management | Certificate and key storage paths | `certificate_path`, `private_key_path` | Internal WORM-relative paths; current escaped CN filename component is limited to 240 bytes. Complete path length is storage-dependent, not a caller field allowance. No create input. | IMPLEMENTED |
| Management | Friendly name, product, environment, owner | `friendly_name`, `product`, `environment`, `owner` | Unsupported metadata fields; no accepted create values or lengths. rejects these keys. | N/A |
| Certificate body / legacy | issuerUniqueID / subjectUniqueID | `issuer_unique_id`, `subject_unique_id` | Unsupported legacy identifiers; no accepted create values or lengths. rejects these keys. | N/A |

## Complete creation JSON example

The profile below supplies the supported DN, SAN and extension inputs together. PKI encodes these values; it does not decide whether their combination is suitable for TLS, CA policy processing, OCSP, a particular certificate ecosystem, or any consuming application. Populating a URL does not implement the service behind it. All names, addresses and OIDs are examples.

The existing installation must have issuer `www.autobricks.internal` and baseDomain `autobricks.internal`. CN `web01` and its generated DNS name must be unused. The example omits `validity`, using 47 days entirely within the issuer's validity. It does not supply generated certificate metadata, a CSR or a private key.

```json
{
  "issuer": "www.autobricks.internal",
  "profile": {
    "common_name": "web01",
    "organization_name": "Example Operations",
    "unit_name": "Infrastructure",
    "country_name": "KR",
    "state_or_province_name": "Seoul",
    "locality_name": "Seoul",
    "street_address": "100 Example Road",
    "postal_code": "00000",
    "subject_serial_number": "DEVICE-WEB01",
    "given_name": "Min",
    "surname": "Kim",
    "pseudonym": "web-operator",
    "user_id": "web-operator-01",
    "domain_components": [
      "autobricks",
      "internal"
    ],
    "initials": "MK",
    "title": "Service Operator",
    "description": "Combined TLS server and client identity for web01",
    "business_category": "Information Technology",
    "organization_identifier": "EXAMPLE-ORG-001",
    "dn_qualifier": "web01-infrastructure",
    "generation_qualifier": "I",
    "subject_email": "operator@example.test",
    "dns_names": [
      "www-web01.autobricks.internal"
    ],
    "ip_addresses": [
      "192.0.2.20",
      "2001:db8::20"
    ],
    "uri_sans": [
      "urn:autobricks:purpose:www",
      "urn:autobricks:allowed-source-cidr:192.0.2.0/24",
      "urn:autobricks:destination-cidr:198.51.100.0/24",
      "urn:autobricks:database-server:r:198.51.100.20/32",
      "urn:autobricks:web-server:r:198.51.100.30/32",
      "urn:autobricks:api-server:w:198.51.100.40/32",
      "urn:autobricks:file-server:rw:198.51.100.50/32",
      "urn:autobricks:resource:r:2001:db8:1::/64",
      "urn:autobricks:gateway:rw:198.51.100.1/32"
    ],
    "email_sans": [
      "operator@example.test"
    ],
    "directory_name_sans": [
      {
        "common_name": "web01",
        "organization_name": "Example Operations",
        "unit_name": "Infrastructure",
        "country_name": "KR"
      }
    ],
    "registered_id_sans": [
      "1.3.6.1.4.1.32473.1.1"
    ],
    "other_name_sans": [
      {
        "oid": "1.3.6.1.4.1.32473.1.2",
        "asn1_type": "UTF8String",
        "value": "DEVICE-WEB01"
      }
    ],
    "key_usage": [
      "digitalSignature"
    ],
    "extended_key_usage": [
      "serverAuth",
      "clientAuth"
    ],
    "certificate_policies": [
      {
        "policy_oid": "1.3.6.1.4.1.32473.2.1",
        "cps_uri": "https://policy.example.test/cps",
        "user_notice": "Example service identity policy"
      }
    ],
    "subject_info_access": [
      {
        "access_method": "1.3.6.1.4.1.32473.3.1",
        "uri": "https://service.example.test/information"
      }
    ],
    "issuer_alt_name": {
      "dns_names": [
        "www.autobricks.internal"
      ]
    },
    "subject_directory_attributes": [
      {
        "oid": "1.3.6.1.4.1.32473.4.1",
        "values": [
          {
            "asn1_type": "UTF8String",
            "value": "infrastructure-device"
          }
        ]
      }
    ],
    "tls_feature": [
      "status_request"
    ],
    "qc_statements": [
      {
        "statement_id": "1.3.6.1.4.1.32473.5.1",
        "statement_info": {
          "asn1_type": "UTF8String",
          "value": "Documentation-only statement"
        }
      }
    ],
    "private_oid": [
      {
        "oid": "1.3.6.1.4.1.32473.6.1",
        "asn1_type": "UTF8String",
        "value": "web01-service-metadata",
        "critical": false
      }
    ],
    "critical": {
      "key_usage": true,
      "extended_key_usage": false,
      "certificate_policies": false,
      "issuer_alt_name": false,
      "subject_info_access": false,
      "subject_directory_attributes": false,
      "tls_feature": false,
      "qc_statements": false,
      "name_constraints": true,
      "policy_mappings": true,
      "policy_constraints": true,
      "inhibit_any_policy": true,
      "freshest_crl": false,
      "ocsp_no_check": false
    },
    "name_constraints": {
      "permitted_subtrees": [
        {
          "dns_names": [
            "autobricks.internal"
          ]
        },
        {
          "ip_addresses": [
            "192.0.2.0/24"
          ]
        },
        {
          "ip_addresses": [
            "2001:db8::/32"
          ]
        }
      ],
      "excluded_subtrees": [
        {
          "dns_names": [
            "restricted.autobricks.internal"
          ]
        }
      ]
    },
    "policy_mappings": [
      {
        "issuer_domain_policy": "1.3.6.1.4.1.32473.2.1",
        "subject_domain_policy": "1.3.6.1.4.1.32473.2.2"
      }
    ],
    "policy_constraints": {
      "require_explicit_policy": 0,
      "inhibit_policy_mapping": 1
    },
    "inhibit_any_policy": 0,
    "freshest_crl": [
      "https://pki.example.test/crl/delta.crl"
    ],
    "ocsp_no_check": true
  }
}
```

### Input representation

Use either `extended_key_usage` or legacy `kind`, not both. Known EKU names map to their numeric OIDs. serverAuth and clientAuth select existing server/client metadata and DNS integration; other EKUs use the internal leaf classification. Saved profiles retain all supplied fields for renewal. Renewal preserves the original duration and profile, generating a new key and the issuer/key-dependent fields.

| Input | Certificate representation |
| --- | --- |
| DN strings | Separate RDNs, in the support-table order. DirectoryString fields use UTF8String; C/subject serial/dnQualifier use PrintableString; DC and Subject email use IA5String. |
| `domain_components` | Repeated DC RDNs in input order. |
| Seven SAN arrays | GeneralName values in one SAN extension; repeated values are preserved. |
| `key_usage` | Named bits in one BIT STRING. An omitted value defaults to digitalSignature. |
| `extended_key_usage` | OIDs in one EKU sequence, retaining the input order. |
| `name_constraints` | Permitted/excluded GeneralSubtrees, one name per subtree; minimum omitted (zero), maximum absent. IP address/prefix supplies the address and mask bytes. |
| `certificate_policies` | Policy OID with optional CPS IA5String and UserNotice explicitText UTF8String. |
| `policy_mappings` | Pairs of issuer-domain and subject-domain policy OIDs. |
| `policy_constraints`, `inhibit_any_policy` | ASN.1 integer fields; no policy evaluation. |
| `freshest_crl` | A distribution point with a fullName URI for each supplied string. |
| `subject_info_access` | AccessDescription method OID plus URI. |
| `issuer_alt_name` | Supplied GeneralName values in the issuerAltName extension. |
| `subject_directory_attributes` | Attribute OIDs and DER-ordered SETs of typed values. |
| `tls_feature` | Sequence of feature integers; names status_request/status_request_v2 map to 5/17. |
| `ocsp_no_check` | True includes a NULL extension value, false omits it. |
| `qc_statements` | Statement OID and optional typed information. |
| `private_oid` | One extension per object, using its OID, encoded typed value and critical flag. |
| `critical` | Boolean flags on the corresponding emitted extensions. Defaults: true for KU, basicConstraints, nameConstraints and the three policy-control extensions; false for other extensions. |

`critical` accepts the configurable extension names above, `subject_alt_name`, and the generated `basic_constraints`, `subject_key_identifier`, `authority_key_identifier`, `authority_info_access`, and `crl_distribution_points`. Private extension flags remain in their own objects. A flag does not create an absent extension.

### Typed values

`other_name_sans` and `private_oid` use `asn1_type` and `value` alongside their OID. Attribute values and statement information use an object containing those same two keys. Values are directly encoded; strings are not interpreted as OpenSSL configuration commands.

| `asn1_type` | JSON `value` and size |
| --- | --- |
| `UTF8String` | String, 1–1,024 Unicode scalar values. |
| `PrintableString` | String, 1–1,024 bytes in the ASN.1 PrintableString alphabet. |
| `IA5String` | String, 1–1,024 ASCII bytes. |
| `INTEGER` | Canonical signed decimal string, signed 64-bit range. |
| `BOOLEAN` | JSON Boolean. |
| `OBJECT IDENTIFIER` | Canonical numeric OID, at most 100 ASCII bytes and 20 components. |
| `OCTET STRING` | Canonical padded Base64 for 1–4,000 bytes. |
| `DER` | Canonical padded Base64 containing one DER value, at most 4,096 bytes and 8 nested constructed levels. |

The encoded typed value is limited to 4,096 DER bytes including tag and length. ASN.1 type, length and structural requirements are checked; PKI does not validate the application-defined meaning of an OID's value. DER SET ordering and equivalent Key Usage bit aliases follow ASN.1 encoding, rather than application policy.

### Request and encoding limits

The maximum create JSON body is 65,536 UTF-8 bytes including whitespace/escapes. Duplicate JSON keys, unknown members, null values, and nesting beyond the supported depth are invalid input representations. Individual collection/string limits appear in each field's Description. The final signed certificate is limited to 32,768 DER bytes before archival.

The service retains its existing CN naming/uniqueness, generated server DNS and DNS registration address-count checks. Input extension contents do not establish verified identity, permission or compliance. CSR remains a separate, unimplemented issuance input; this example preserves server-generated keys and the existing three-file download archive.
