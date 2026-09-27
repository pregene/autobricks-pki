# Autobricks PKI Server 1.0

**Development status: In development.**

Root CA and Intermediate CA management, with purpose-specific server and client certificate issuance, renewal, and revocation for the Autobricks product family.

Implementation language: **Rust**. Supported platform: **Linux only**.

Server binary: `abpkid`.

Client binary: `abpki-cli`, connecting to `abpkid` over TLS.

## Installation prerequisites

**Install Autobricks DNS (`autobricks-dns`) and Autobricks TrueLog (`autobricks-truelog`) before installing Autobricks PKI Server 1.0.**

Both components must be installed before PKI installation begins.
TrueLog provides logging and the underlying WORM filesystem at `/mnt/worm-storage`. Install and configure `autobricks-truelog-cli` on the PKI host for audit event submission. PKI delegates audit file management to TrueLog and DNS registration to Autobricks DNS.

Follow the [Autobricks TrueLog server installation guide](https://github.com/pregene/autobricks-log/blob/main/TRUELOG.md#install-the-true-log-server).

During installation, the PKI service registers its DNS record through `autobricks-dns`. Clients access the service at `https://<dns record name>`. The registered name is the hostname used in the service's CRL and OCSP URLs.

Initial installation creates one Root CA and six Intermediate CAs: `database`, `www`, `vpn`, `worm`, `app`, and `truelog`. Each Intermediate CA issues server and client certificates.

[Default Intermediate CAs](INTERMEDIATE.md)

## Runtime

[Build and tests](docs/build.md) · [Configuration and operation](docs/runtime.md) · [Service files and directories](FILES.md)

## Certificate services

- Root CA and Intermediate CA management
- Intermediate CA creation protected by the administrator password
- Server and client certificate issuance available to any connected client
- Automatic DNS registration through `autobricks-dns` when a server certificate is issued
- Certificate renewal
- Certificate revocation protected by the administrator password
- TLS service access without a required client certificate

[Certificate services](docs/certificate-services.md) · [Certificate fields and purposes](CERTITFICATE.md)

## Command-line client

`abpki-cli` provides `create-ca`, `create`, `check`, `list-ca`, `list`, `download`, `revoke`, `renew`, `root`, and `chain`.
All downloaded certificates, private keys, and trust chains use PEM encoding. Each `{target}.tar.gz` download contains exactly three files: the certificate, its private key, and its trust chain. `GET https://<dns record name>/root` returns the Root CA certificate in PEM. `abpki-cli root` saves it as `root.crt`. The `chain` command downloads the Intermediate CA and Root CA certificates as `trust-chain`.

[CLI commands](docs/cli.md)

## Storage

`abpkid` keeps its live SQLite database on mutable storage outside WORM. `autobricks-worm` provides appendable WORM storage for audit logs and generated certificates, and can also store SQLite backup copies. Certificates, encrypted private-key PEM copies, and backup files can be written directly through `/mnt/worm-storage`, through the WORM mount provided by the required `autobricks-truelog` installation.

[Storage](docs/storage.md) · [SQLite notice](licenses/SQLite-PUBLIC-DOMAIN.md)

## Certificate validity

The Root CA has no defined expiration. Intermediate CAs default to 398 days; server and client certificates default to 47 days. Creation supports custom validity within the issuer boundary. Renewal is available during the final seven days before expiration. `abpkid` renews Intermediate CAs internally; leaf holders check and renew their own certificates.

[Validity and renewal](VALIDATION.md)

## CRL distribution

`abpkid` serves CRLs over HTTPS at `/crl/<cn>` and `/crl/<intermediate-ca-fingerprint>`. Issued leaf certificates include their issuer's HTTPS CRL URL in the CRL Distribution Points extension. CRLs have a non-configurable seven-day validity period and are updated immediately upon certificate revocation.

[CRL distribution](CRL.md)

## OCSP service

`abpkid` accepts HTTPS POST requests at `/ocsp/`, with the target certificate identified in the OCSP request body. Issued and renewed leaf certificates include this URL in AIA. Signed responses carry `GOOD`, `REVOKED`, or `UNKNOWN` certificate status.

[OCSP service](OCSP.md)

## Key storage

Version 1.0 uses software cryptography with P-256 keys and SHA-256 signatures. Encrypted private keys, their encryption password, and the salted administrator password hash are stored in SQLite. The service has no user accounts or user management.

[Key storage](docs/key-storage.md)

## Build version

[VERSION](VERSION) contains the build version in `1.0.NNN` format.
The [build runner](docs/build.md) increments the build number before running a build command.

[Development history](HISTORY.md)

## License

Autobricks code is governed by the [Autobricks PKI Source-Available License 1.0](LICENSE).
Third-party components remain governed by their respective licenses. See [Third-party licenses and notices](THIRD_PARTY_NOTICES.md) for license texts and applicable conditions.

Certificate management uses TLS port `5545`; public Root CA downloads, CRLs, and OCSP use HTTPS port `5546`. `ABPKI_BIND` contains only the listen IP address. The DNS registration IP is supplied separately with `abpkid init <registration-ip> [baseDomain]`. See [runtime configuration](docs/runtime.md).

Initialization prompts for `baseDomain` when omitted, defaulting to `autobricks.internal`. The Root CA CN is `pki.<baseDomain>`; default Intermediate CA CNs are `database`, `www`, `vpn`, `worm`, `app`, and `truelog`, each suffixed with `.<baseDomain>`.

[Common Names, DNS naming, and uniqueness](COMMON-NAME.md)
