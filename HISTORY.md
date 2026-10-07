# Development history

## 1.0.127 — 2026-10-07

- Updated shared client guides with platform-specific service, configuration, trust and file locations; added macOS command examples and clarified first-use Root trust verification.

- Added macOS arm64/x86_64 client support with local Unix socket communication, launchd service management, macOS native certificate trust, and terminal installation/removal scripts. The server remains Linux-only.
- Built both client-only installation archives without changing VERSION. Verified Mach-O architecture, embedded version, macOS 11.0 deployment metadata, system library dependencies, archive contents, launchd configuration and SHA-256 checksums. The Linux client also compiled with the default server feature. macOS installation/runtime and the regression suite were not executed.

## 1.0.127 — 2026-09-28

- Separated package-building instructions from installation guidance and aligned certificate, storage and error guides with available functionality. Preserved certificate field names and JSON examples; checked 144 local links, nine JSON blocks and all 18 remaining Mermaid diagrams.

- Quoted absolute-path labels in the service file layout diagram. All 23 documentation Mermaid blocks passed parser validation.

- Escaped message semicolons in the leaf creation and revocation Mermaid sequence diagrams; parser verification reproduced the original errors and accepted the corrected diagrams.

- Built and verified eight release packages for Ubuntu 22.04/24.04 on amd64/arm64, with server-plus-client and client-only variants and SHA-256 checksums. Native version/help and architecture/dependency checks passed; ARM64 runtime and package installation were not tested.

## 1.0.126 — 2026-09-28

- Documented the CA name/policy extension profile example in the Intermediate CA guide.

- Documented field-level length and encoding limits and a complete extended creation example, retaining separate certificate identifiers and project field names.
- Added extended DN, seven SAN forms, Key Usage/EKU, policy, access-information, directory-attribute, TLS-feature, OCSP no-check, QC-statement and private-extension input encoding. Application meaning is left to certificate consumers; input sizes and ASN.1 representations are bounded.
- Preserved supplied extension criticality and full stored profiles across renewal, with non-TLS leaves included in listing and lifecycle queries. Existing key storage and three-file downloads remain unchanged.
- Added nine cumulative certificate read-back regressions covering field values, ASN.1 types, critical flags, all typed encodings, length boundaries, renewal, legacy downloads and index compatibility. Panic gate passed 86 Rust tests and 10 isolated installer tests. Post-deployment validation passed 38 installed-service checks and 43 isolated cumulative regression checks.

## 1.0.117 — 2026-09-28

- Added Docker builds for Ubuntu 22.04 and 24.04 on amd64 and arm64, producing eight server/client package artifacts with native executable and cross-target ELF checks and SHA-256 checksums.

## 1.0.114 — 2026-09-28

- Updated the development status to TESTABLE and added SQLCipher integration to the version 1.2 roadmap.

- Expanded leaf and Intermediate CA renewal guides with user and administrator procedures, response fields, deployment steps, retry handling, duration examples, and retirement timelines.

- Added leaf and Intermediate CA state filters, defaulting to VALID, with indexed pagination and cumulative regression cases.
- Added automatic SUPERSEDED readiness at seven days for leaves and 48 days for Intermediate CAs; ADMIN renewal requests only mark certificates pending.
- Added normal renewal polling responses for VALID, SUPERSEDED, and REVOKED, private token capture only on issuance, and exact original-duration preservation.
- Added unconditional retirement at seven days for leaves and 48 days for Intermediate CAs, with retained transition timestamps, bounded queries, CRL retry, and Root-signed CA revocation CRLs.

- Added 16 cumulative regression cases for state filters and renewal lifecycle behavior, plus installed leaf and CA filter checks.

## 1.0.111 — 2026-09-28

- Cached public OCSP issuer hashes, refreshed renewed CA generations, and removed duplicate request parsing while retaining live revocation lookup.
- Added non-unique indexed DNS lookups, including legacy aliases, without blocking same-name renewal.
- Added 256-row certificate pages and incremental CLI rendering with an initial maximum-index boundary.
- Added ABP1 raw-body framing with legacy-request reply compatibility.
- Passed the cumulative panic gate with 61 Rust tests and 10 installer tests; passed 54 post-test checks on installed 1.0.111, including same-CN/DNS renewal and CA cache refresh.

- Extended post-test.sh with installed server/client version banners, concurrent CLI status/info checks, and eighteen labeled isolated regression cases from prebuilt test executables.

## 1.0.108 — 2026-09-28

- Moved running-server DNS and TrueLog delivery outside the shared service lock, with independent CRL retries.
- Cached server TLS configuration while retaining current certificate checks; reused client trust configuration across up to 16 concurrent relays.
- Added partial outbox indexes and cursor-based batches of 64 pending external operations.
- Coalesced CRL publication across linked CA generations and completed their pending tasks with the publication transaction.
- Added regression cases for TLS cache reuse and replacement, concurrent client relays and capacity recovery, external-delivery lock release and retries, bounded outbox filtering, and coalesced CRL failure recovery. Coverage is mapped to FIXED items 10–14 in tests/PERFORMANCE.md. Passed the panic gate with 55 Rust tests and 10 installer tests; passed all 34 installed CLI checks on 1.0.108.

## 1.0.105 — 2026-09-28

- Replaced runtime-wide certificate loading with fingerprint, issuer/serial, CA selection, and metadata-only queries.
- Restricted OCSP, CRL, TLS, and public-chain key access to required signing material; CRL revocation entries use stored serial metadata.
- Added lookup indexes and FIXED.md to track nine query corrections.
- Added tests/post-test.sh for numbered checks through the installed CLI, covering metadata lists, certificate status and X.509 information, missing certificates, and Root/chain downloads.
- Passed the panic gate with 44 Rust tests and 10 installer tests; passed 34 installed CLI checks on 1.0.105.

## 1.0.102 — 2026-09-27

- Added package assembly from existing version-verified binaries without recompilation.

- Added abpki-cli info FINGERPRINT and its TLS management endpoint to display public X.509 certificate details directly from WORM without private-key access.
- Added operation help and explicit certificate-not-found responses.
- Passed the panic gate with 44 Rust tests and 10 installer tests, including actual CLI info output and private-key-independent certificate inspection.

## 1.0.099 — 2026-09-27

- Stored signed CRLs on WORM and retained only publication paths and metadata in SQLite; CRL downloads read published files without signing or database writes.
- Linked Intermediate CA renewals through predecessor keys and preserved shared CRL numbering and revocations across all linked generations.
- Created initial empty CRLs with number 1 and refreshed expired CRLs through background scheduling.
- Verified no PEM contents exist in any operational SQLite table after issuance, renewal, and revocation.
- Passed the panic gate with 43 Rust tests and 10 installer tests; built both binaries.

## 1.0.088 — 2026-09-27

- Added hourly renewal scheduling with a persisted attempt time and restart deduplication; retained independent CRL refresh and integration retries.
- Committed certificate revocation before CRL signing and retained failed CRL publication for retry without reversing revocation.
- Prevented downloads of known-outdated CRLs when pending regeneration fails.
- Passed the panic gate with 39 Rust tests and 10 installer tests; verified OCSP reports REVOKED while CRL publication fails.

## 1.0.079 — 2026-09-27

- Stored certificate and encrypted private-key files directly on WORM before inserting SQLite paths and metadata; removed certificate-copy outbox delivery.
- Added the CA-to-leaf relation, persisted revocation status, and loaded signing keys from protected WORM paths.
- Added an explicit maintenance batch preserving existing certificates, keys, identifiers, configuration, and trust while replacing the legacy database layout with rollback backups. The runtime performs no schema conversion.
- Passed 36 Rust tests, verified the maintenance batch against temporary data, and built both binaries.

## 1.0.076 — 2026-09-27

- Built server and client binaries with metadata-only lists and remaining-day output in bin/.

## 1.0.075 — 2026-09-27

- Renamed list columns to IssuedAt and remain; remaining days are calculated from expiry with partial days rounded up and expired certificates shown as zero.

## 1.0.074 — 2026-09-27

- Added metadata-only certificate list queries that do not load certificate PEM or decrypt private keys.
- Formatted CLI lists with Index, Common Name, Status, Issued At (UTC), Validity (Days), and full Fingerprint columns.
- Verified metadata projection and list rendering with three focused tests.

## 1.0.072 — 2026-09-27

- Revalidated the installation readiness fix with the distribution OpenSSL panic gate: formatting, production Clippy checks, 33 Rust tests, and 10 installer tests passed.

## 1.0.070 — 2026-09-27

- Added bounded TLS and Root download readiness retries after service startup, preserving immediate certificate-verification failure handling.
- Included connection targets in installation failures and preserved the backend error in dpkg output after closing curses.
- Verified delayed-listener, timeout-target, and certificate-failure behavior with installer regression tests.

## 1.0.069 — 2026-09-27


- Added server-plus-client and client-only Debian package composition with shared curses installation screens and separate package entry points.
- Added the local Rust client daemon, Unix socket requests, installed JSON connection settings, OS trust loading, caller-owned token files, and hidden administrator password prompts.
- Added Root CA enrollment, immediate installer socket access, client service management, and owned trust cleanup.
- Generated and persisted the server installation ADMIN password, preserving it across reconfiguration and displaying it on successful completion.
- Isolated distribution OpenSSL headers to prevent ABI mismatches with libraries when a different OpenSSL installation exists under /usr/local.
- Passed the panic gate with 33 Rust regression tests and seven isolated installer tests using distribution OpenSSL; verified curses backend success/failure and password display.

## 1.0.060 — 2026-09-27

- Added package-specific curses installation screens with bounded input, inline limits, and a visible editing cursor.
- Displayed the full VERSION in green and the product name and copyright in blue.

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


- Documented Unix socket calls to a local PKI client service with installation-managed server and TLS trust configuration, and updated leaf creation and CLI flows.

- Rejected multiple purpose URI SANs and updated issuance examples to combine one purpose with access-policy entries.

- Documented JSON array syntax for multiple URI SAN entries.


- Specified an indexed Intermediate-to-leaf relation table and WORM-only certificate/key contents with SQLite metadata and file paths.



- Documented SUPERSEDED as a temporary certificate renewal handover state, distinct from CRL revocation, with existing-certificate use during replacement download.

- Documented the certificate valid field separately from operation results, validity timestamps, and X.509 revocation reasons.

- Documented separator-free hexadecimal fingerprint and serial storage and aligned OCSP audit serial formatting with the existing serial encoder.






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
