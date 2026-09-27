# Development history

## 1.0.072 — 2026-09-27

- Revalidated the installation readiness fix with the distribution OpenSSL panic gate: formatting, production Clippy checks, 33 Rust tests, and 10 installer tests passed.

## 1.0.070 — 2026-09-27

- Added bounded TLS and Root download readiness retries after service startup, preserving immediate certificate-verification failure handling.
- Included connection targets in installation failures and preserved the backend error in dpkg output after closing curses.
- Verified delayed-listener, timeout-target, and certificate-failure behavior with installer regression tests.

## 1.0.069 — 2026-09-27

- Built and inspected both Ubuntu 22.04 amd64 Debian packages, shared screen payloads, maintainer-script syntax, binary help, and distribution OpenSSL linkage.

- Added server-plus-client and client-only Debian package composition with shared curses installation screens and separate package entry points.
- Added the local Rust client daemon, Unix socket requests, installed JSON connection settings, OS trust loading, caller-owned token files, and hidden administrator password prompts.
- Added Root CA enrollment, immediate installer socket access, client service management, and owned trust cleanup.
- Generated and persisted the server installation ADMIN password, preserving it across reconfiguration and displaying it on successful completion.
- Isolated distribution OpenSSL headers to prevent ABI mismatches with libraries when a different OpenSSL installation exists under /usr/local.
- Passed the panic gate with 33 Rust regression tests and seven isolated installer tests using distribution OpenSSL; verified curses backend success/failure and password display.

## 1.0.060 — 2026-09-27

- Removed redundant package-type and automatic client configuration captions from the installation screen.

- Added a visible editing cursor with positional insertion, navigation, and deletion; moved field length hints onto the input row.

- Added a generated 16-character ADMIN password to the server installation completion screen and documented its server configuration storage. The screen test keeps the password in memory only.

- Colored the installation header product name and copyright blue and the full version green.

- Enforced installer field length and character restrictions during input, with bounded controls and inline limits.

- Replaced the screen preview review step with Install, simulated installation progress, and Finish controls.

- Removed package selection from the installer preview; server and client preview commands open their respective settings directly.

- Updated the installation screen preview to read the full product version from VERSION and display the standard product banner.

- Added a curses installation screen preview for combined server/client and client-only flows with in-memory input validation and review, without installation side effects.

- Removed password-entry and credential-handling prescriptions from the package installation specification.

- Added PACKAGE.md describing combined server/client and client-only package composition, installation inputs, trust enrollment, and removal behavior.

- Removed the duplicate examples directory and package copy; retained LEAF-CREATE.md as the request field reference.
- Embedded the create help JSON directly in source without an external example-file build dependency.

## 1.0.059 — 2026-09-27

- Added a server certificate request JSON example, embedded it in create help, and documented how to prepare request.json.
- Included the example and leaf creation reference in the Debian package.

## 1.0.058 — 2026-09-27

- Aligned server and client help banners with the Autobricks product format, displaying the full version once without a parenthesized build label.

## 1.0.057 — 2026-09-27

- Allocated a fresh Unix-timestamp WORM namespace for each installation and persisted its timestamp and archive path in the service environment file.
- Preserved the configured namespace across reconfiguration and upgrades while isolating fresh installations from retained archives after purge.
- Built version 1.0.057 binaries and Debian package and verified the packaged installer and service configuration.
- Required an explicit server WORM directory and updated the service write paths and storage documentation.
- Verified namespace retention, timestamp collision handling, configuration consistency, and reservation failure handling with three isolated installer tests.

## 1.0.056 — 2026-09-27

- Replaced compact server and client help with a product banner, operation descriptions, global options, operation-specific help, and examples.
- Added -h and -V aliases; help is available before runtime configuration, credentials, or network access.
- Built and staged both binaries in bin/ and verified 36 help/version invocations without runtime settings or output files.

## 1.0.055 — 2026-09-27

- Added version 1.1 additional Intermediate CA creation to the README feature roadmap.

- Added the planned HSM 1.3 and TPM 1.4 integration versions to README.

- Added a local panic gate with production Clippy checks and malformed-input regression coverage.
- Replaced build-script and URL-encoding panic paths with error returns, and fixed management frame-limit addition overflow.
- Passed all 33 regression tests, including duration preservation, single-purpose validation, and disabled additional CA creation.
- Built and staged abpkid and abpki-cli version 1.0.055 in bin/.

## 1.0.046 — 2026-09-27

- Disabled additional Intermediate CA creation in version 1.0 with CLI/service Not implemented errors and a management 501 response, retaining installation hierarchy creation and internal renewal.

- Preserved exact certificate duration during leaf, service TLS, and Intermediate CA renewal and defined the renewal request with fingerprint only, without a duration parameter.

- Replaced per-command credential environment examples with Unix socket request credentials, caller-owned token storage, and CLI password input in creation, renewal, revocation, and download documentation.

- Specified client installation Root CA retrieval, OS trust-store registration, verified TLS connection, and persisted endpoint configuration.

- Clarified client installation address/port configuration, TOML connection fields, and separate daemon and Unix socket command responsibilities.

- Documented Unix socket calls to a local PKI client service with installation-managed server and TLS trust configuration, and updated leaf creation and CLI flows.

- Rejected multiple purpose URI SANs and updated issuance examples to combine one purpose with access-policy entries.

- Documented JSON array syntax for multiple URI SAN entries.

- Aligned leaf creation documentation with VALID issuer selection, WORM source storage, numeric CA-to-leaf relations, and confirmed audit delivery.

- Specified an indexed Intermediate-to-leaf relation table and WORM-only certificate/key contents with SQLite metadata and file paths.

- Specified coordinated Intermediate CA and leaf handover, persisted transition timestamps, download-based retirement, and mandatory seven-day revocation with issuer-specific CRL publication requirements.

- Specified automatic predecessor revocation after authenticated replacement download confirmation, including numeric renewal linkage and retry behavior.

- Documented SUPERSEDED as a temporary certificate renewal handover state, distinct from CRL revocation, with existing-certificate use during replacement download.

- Documented the certificate valid field separately from operation results, validity timestamps, and X.509 revocation reasons.

- Documented separator-free hexadecimal fingerprint and serial storage and aligned OCSP audit serial formatting with the existing serial encoder.

- Expanded ERROR.md with per-operation failure conditions, validation precedence, management response mapping, OCSP outcome matrices, and retry and audit persistence boundaries.

- Added ERROR.md defining shared integer operation results and linked audit results, OCSP status mapping, and certificate lifecycle documentation.

- Removed the audit request identifier and mapped audit fields to existing socket, certificate, OCSP, outbox, and TrueLog data sources and runtime interfaces.

- Simplified audit confirmation fields to TrueLog checksums and documented OCSP JSON payloads containing peer IP, queried certificate identity, and response status.

- Documented the audit table contract for certificate creation, revocation, renewal, and OCSP history, including numeric certificate references, TrueLog receipts, and query indexes.

- Added automatically incremented integer primary keys for certificates and CRLs, a required unique certificate fingerprint, and a numeric CRL foreign key to certificates.
- Removed legacy database and plaintext-key migration handling from initialization.

- Added leaf creation, revocation, and renewal specifications covering request fields, authorization, processing, delivery, and retry behavior.

- Added DDL.md documenting the SQLite schema, relationships, settings, encrypted key fields, delivery outbox, and schema initialization.

- Added OS and OS-version fields to hyphen-separated Debian package filenames and updated installation examples.

## 1.0.045 — 2026-09-27

- Added a Debian package builder, debconf installation prompts, and the abpkid systemd service.
- Added installation validation, PKI account provisioning, DNS/TrueLog/WORM group access, CA initialization, and service startup.
- Added remove preservation and purge cleanup of mutable PKI state, package-owned accounts, and unchanged PKI DNS records while retaining WORM and TrueLog archives.
- Accepted the protected writer-group permissions exposed by TrueLog WORM for encrypted certificate-key archives.
- Built the amd64 Debian package using distribution OpenSSL 3 and retained its applicable license notices.

## 1.0.043 — 2026-09-27

- Documented a minimum 365-day TrueLog retention period in README installation prerequisites.

- Added installation-time TrueLog retention configuration reading and persisted the retention-derived Intermediate CA validity policy in SQLite.
- Applied min(398, retention days minus seven) to default CA creation and renewal, and rejected explicit CA durations exceeding that limit.
- Updated validity, installation, and storage documentation.

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
