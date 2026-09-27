# Development history

## 1.0.042 — 2026-09-27

- Limited Intermediate CA name components to 16 ASCII characters, excluding the baseDomain suffix, in CA creation and DNS generation.
- Updated naming documentation and verified 16-character acceptance and 17-character rejection for short and domain-qualified CA names.

## 1.0.040 — 2026-09-27

- Limited installation baseDomain input to 24 ASCII characters, including dots, and updated naming and installation documentation.
- Verified acceptance at 24 characters and rejection at 25 characters with the domain validation test.

## 1.0.038 — 2026-09-27

- Added COMMON-NAME.md describing CA/leaf names, CN uniqueness, renewal generations, DNS naming, and TLS SAN identity with RFC references.
- Enforced normalized 1–24-character leaf CNs and rejected duplicate new issuance across issuers and leaf kinds while preserving authorized renewal.
- Generated server DNS SANs and registrations as <intermediate>-<cn>.<baseDomain>, rejecting mismatched SANs and generated-name collisions.
- Retained the separately registered PKI service endpoint with its internal leaf CN pki.
- Passed 27 tests and warning-free static analysis, including CN length boundaries, renewal exceptions, and DNS collision handling.

## 1.0.034 — 2026-09-27

- Added installation-time baseDomain input with autobricks.internal as the interactive default and persisted the domain in SQLite.
- Added domain-based Root and default Intermediate CA Common Names and the KR/Seoul/Autobricks organization subject.
- Derived the default HTTPS hostname from the saved domain and preserved existing CA subjects during renewal.
- Updated installation and CA documentation; passed 26 tests and warning-free static analysis.

## 1.0.030 — 2026-09-27

- Added local bin/ executable staging and build/ package output directories, excluded both from Git, and added a release staging script through the common build runner.

- Added Root and Intermediate CA private-key archives beside their certificate PEM files.
- Encrypted all persisted private keys as AES-256-CBC PKCS#8 PEM, with a random encryption password managed in SQLite settings.
- Reused stored encrypted PEM for WORM delivery and decrypted keys in memory for cryptographic operations and authorized leaf downloads.
- Added schema version 2 migration for legacy plaintext SQLite keys with secure deletion and compaction.
- Passed 24 tests including CA key archive permissions, wrong-password rejection, certificate/key matching, SQLite migration, and missing-password rejection; static analysis passed without warnings.

## 1.0.025 — 2026-09-27

- Separated Intermediate CA PEM archives into intermediate/YYYY-MM-DD/<fingerprint>/<CN>.pem.
- Added the mutable SQLite database and rollback journal to the documented directory layout.
- Verified separate Root, Intermediate, and leaf archive paths with the archive lifecycle test.

## 1.0.023 — 2026-09-27

- Added Root CA certificate archival under root/ and UTC issuance-date/fingerprint directories for Intermediate and leaf certificates.
- Added owner-only leaf private-key PEM archives with escaped CN filenames and conflict-safe append retries.
- Replaced direct audit-file writes with ab-truelog-cli submission using the abpkid service, stable event IDs, and receipt validation.
- Updated service layout, storage, key management, and TrueLog client configuration documentation.
- Passed 23 tests, including mock TrueLog submission/failure handling, archive isolation, key permissions, and path traversal rejection; static analysis passed without warnings.

## 1.0.019 — 2026-09-27

- Separated certificate management TLS on port 5545 from public Root CA, CRL, and OCSP HTTPS on port 5546.
- Added bounded JSON management frames and updated the CLI to use the appropriate listener.
- Split bind address and listener port settings; initialization accepts a separate DNS registration IP argument.
- Updated configuration and service layout documentation.
- Passed 20 tests including listener isolation, management frame validation, binary interoperability, and signed OpenSSL OCSP responses; static analysis passed without warnings.

## 1.0.015 — 2026-09-27

- Added FILES.md covering the systemd deployment layout, configuration paths, SQLite state, WORM artifacts, permissions, and client downloads.

- Added an explicit in-development status to README.

- Added public GET /root PEM downloads and updated abpki-cli root to use the endpoint.
- Verified direct HTTPS Root CA retrieval and CLI root.crt output in the binary interoperability test.

## 1.0.013 — 2026-09-27

- Added Linux Rust binaries abpkid and abpki-cli with build-version propagation through the common build runner.
- Added the HTTPS response writer and TLS configuration, adding bounded HTTP request parsing and OCSP binary POST handling.
- Implemented software Root/Intermediate CA initialization, leaf issuance, purpose and validity checks, renewal, and administrator-protected revocation.
- Added SQLite certificate/private-key storage, a single salted administrator password hash, certificate-specific access tokens, and durable external delivery records without user management.
- Implemented signed seven-day CRLs, immediate revocation updates, signed OCSP status responses, and CA-generation continuity.
- Added Autobricks DNS control-socket registration, direct WORM certificate/audit delivery, PEM downloads, and token-protected three-file archives.
- Added 16 passing policy, HTTP parsing, lifecycle, delivery retry, TLS, initialization, and real binary/OpenSSL OCSP interoperability tests.
- Added runtime configuration documentation and retained applicable MIT, Rust dependency, and OpenSSL legal notices.

## 1.0.000 — 2026-09-27

- Documented automatic registration in autobricks-dns during server certificate issuance.

- Documented installation-time DNS registration through autobricks-dns and use of the registered hostname for HTTPS access, CRL URLs, and OCSP URLs.

- Updated README installation prerequisites to require both Autobricks DNS and Autobricks TrueLog before PKI installation.

- Specified mandatory RFC 6960 POST conformance, binary DER bodies, and OCSP media types.

- Added OCSP HTTPS POST documentation, request-body certificate identification, leaf AIA requirements, and standard certificate status descriptions.

- Documented fixed seven-day CRL validity, scheduled refresh, and immediate CRL publication upon certificate revocation.

- Added HTTPS CRL distribution documentation with Intermediate CA CN/fingerprint lookup and leaf distribution-point requirements.

- Added validity defaults, issuer expiration limits, Root CA expiration encoding, and renewal responsibilities and timing.

- Added default Root CA and six-Intermediate-CA (database, www, vpn, worm, app, truelog) initialization documentation with a server/client issuance diagram.

- Documented mandatory server purpose URI SANs and a 33-token service purpose catalog.

- Defined full-name access policy URNs under urn:autobricks with r/w/rw permissions and CIDR scopes, preserving the existing allowed-source-cidr policy.

- Added a brief OCSP and CRL comparison with RFC references.

- Documented eight VPN access policy categories and distinguished source restrictions from destination scopes.
- Added an RFC reference table and explicit RFC numbers and section references to certificate documentation citations.
- Added Root CA, Intermediate CA, server, and client certificate purpose descriptions and a certificate hierarchy diagram.
- Added the X.509 certificate information reference covering identities, usages, CA constraints, request fields, management records, and PEM outputs with official sources.
- Added extended DN attributes and the Autobricks VPN consumer profile, including source-CIDR URI semantics and validity constraints.

## 1.0.000 — 2026-09-26

- Added English documentation for Autobricks PKI Server 1.0 and Linux-only platform support.
- Documented PKCS#11 key storage through SoftHSM2 and tpm2-pkcs11 with tpm2-tss.
- Added upstream license texts and third-party notices, including file-specific exceptions.
- Updated product references in the project license.
- Added key storage and build flow diagrams in Mermaid.
- Added VERSION and a build runner with serialized version allocation and build status propagation.
- Excluded local agent instructions and the build lock from Git.
- Added CA hierarchy, server/client certificate lifecycle, and TLS access documentation with diagrams.
- Documented open certificate issuance and permission-restricted revocation, with an access table and flow diagram.
- Documented the server binary `abpkid` and the connecting client binary `abpki-cli`.
- Added CLI command documentation for certificate creation, status checks, CA and certificate lists, and fingerprint-based archive downloads.
- Added CLI documentation for Intermediate CA creation, certificate revocation, and renewal, including privileged-operation access requirements.
- Documented the root command for downloading the Root CA certificate as root.crt.
- Documented the chain command for downloading Intermediate CA and Root CA certificates as trust-chain.
- Specified PEM encoding for certificate downloads, including Root CA, trust-chain, and archived certificates.
- Documented the three-file PEM download archive: certificate, matching private key, and trust chain.
- Documented SQLite server storage and added its public-domain notice with the official source reference.
- Documented autobricks-worm storage for audit logs and generated certificates, with a storage diagram.
- Clarified that live SQLite files use mutable storage and SQLite backup artifacts may be stored in autobricks-worm.
- Documented direct certificate and backup file writes through /mnt/worm-storage, including True Log-provided mounts.
- Clarified the relationship between autobricks-worm and the additional True Log functionality in autobricks-truelog.
- Added Autobricks TrueLog as an installation prerequisite and linked its server installation guide.
