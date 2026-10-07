# Third-party components and licenses

## Components

`abpkid` uses SQLite as its database.

The version 1.0 server uses rustls for TLS, OpenSSL for software cryptography, and rusqlite with bundled SQLite for storage. The macOS client uses rustls and native macOS certificate trust without linking OpenSSL or SQLite. [Rust dependency licenses](licenses/RUST_DEPENDENCIES.md) lists the resolved Linux and macOS dependencies and retained legal texts. The HTTP response writer and TLS configuration retain the applicable [MIT permission notice](licenses/HTTPS-MIT.txt). Debian package builds link distribution-managed OpenSSL 3 on Ubuntu 22.04; its [distribution copyright notice](licenses/OpenSSL-3-Ubuntu-copyright.txt) and [Apache-2.0 license](licenses/OpenSSL-3-APACHE-2.0.txt) are retained. The [OpenSSL 1.1.1w license](licenses/OpenSSL-1.1.1w-LICENSE.txt) covers builds using that version. Other build environments must preserve the terms for their actual OpenSSL version.

SoftHSM2, tpm2-pkcs11, and tpm2-tss notices below are retained reference material; these components are not linked or required by the version 1.0 binaries.

The versions below identify the releases covered by the retained license texts. SQLite is covered by its upstream public-domain statement. The component table identifies the retained upstream legal references.

| Component | Covered version | Retained license text | Source |
| --- | --- | --- | --- |
| SoftHSM2 | 2.7.0 | [SoftHSM2-2.7.0-LICENSE.txt](licenses/SoftHSM2-2.7.0-LICENSE.txt) | [Upstream license](https://github.com/softhsm/SoftHSMv2/blob/2.7.0/LICENSE) |
| tpm2-pkcs11 | 1.10.1 | [tpm2-pkcs11-1.10.1-LICENSE.txt](licenses/tpm2-pkcs11-1.10.1-LICENSE.txt) | [Upstream license](https://github.com/tpm2-software/tpm2-pkcs11/blob/1.10.1/LICENSE) |
| tpm2-tss | 4.2.0 | [tpm2-tss-4.2.0-LICENSE.txt](licenses/tpm2-tss-4.2.0-LICENSE.txt) | [Upstream license](https://github.com/tpm2-software/tpm2-tss/blob/4.2.0/LICENSE) |
| SQLite | Upstream public-domain statement | [SQLite public-domain notice](licenses/SQLite-PUBLIC-DOMAIN.md) | [Upstream statement](https://www.sqlite.org/copyright.html) |

## Applicable conditions

SoftHSM2, tpm2-pkcs11, and tpm2-tss use BSD-2-Clause as their primary license. Its terms permit use, modification, and redistribution in source and binary forms. Source redistribution must retain copyright notices, conditions, and disclaimers. Binary redistribution must reproduce them in accompanying documentation or other materials.

Autobricks code is governed by the [Autobricks PKI Source-Available License 1.0](LICENSE). Under Section 18, third-party code remains governed by its own licenses. Autobricks modification restrictions do not apply to that third-party code. The BSD terms above do not require disclosure or relicensing of Autobricks code.

### SQLite

SQLite is public domain, rather than BSD-licensed. Its upstream statement imposes no attribution, source-disclosure, or copyleft requirement on applications using the library. Autobricks code remains under its own license. SQLite bindings, extensions, and separately licensed build files require their own applicable notices.

## File-specific exceptions and copyright notices

- **SoftHSM2:** The retained LICENSE includes copyright notices for .SE, The Internet Infrastructure Foundation and SURFnet bv. Preserve additional notices in any source files distributed.
- **tpm2-pkcs11:** Its LICENSE states that William Roberts retains copyright in `lib/twist.c`, `lib/twist.h`, and `test/unit/test_twist`, which the author relicensed under BSD2. It identifies `src/pkcs11.h` and `.gitignore` as subject to their own file-level terms.
- **tpm2-pkcs11 [src/pkcs11.h](https://github.com/tpm2-software/tpm2-pkcs11/blob/1.10.1/src/pkcs11.h):** This header contains copyright notices for g10 Code GmbH, Andreas Jellinghaus, and Red Hat, Inc., with separate permission and disclaimer text. Preserve those notices when including or redistributing the header.
- **tpm2-tss:** Its [REUSE.toml](https://github.com/tpm2-software/tpm2-tss/blob/4.2.0/REUSE.toml) specifies separate terms, including CC-BY-4.0 for documentation and manuals, and CC0-1.0 and FSFULLR for certain build support files. Do not label the entire distribution solely as BSD-2-Clause.
- **tpm2-pkcs11 / tpm2-tss:** Their top-level LICENSE files do not collect every copyright notice. Preserve copyright notices, SPDX information, and separate licenses for the files actually distributed.

## Distribution scope

These notices cover the primary components and do not constitute a complete dependency manifest for a binary distribution. When creating packages or containers, complete the notices for the versions and files actually included.

The [tpm2-pkcs11 build documentation](https://github.com/tpm2-software/tpm2-pkcs11/blob/1.10.1/docs/BUILDING.md) lists dependencies including OpenSSL, SQLite3, libyaml, and Python packages for `tpm2_ptool`. The [SoftHSM2 documentation](https://github.com/softhsm/SoftHSMv2/blob/2.7.0/README.md) specifies OpenSSL or Botan as its cryptographic library. Include their applicable license notices according to the selected versions, build options, and distribution contents. Preserve copyright and license files supplied by operating system packages.

## External services

Autobricks DNS and Autobricks TrueLog are separately installed runtime services. Their repositories declare GPLv3 licensing. The PKI DNS adapter communicates with the existing Unix-socket protocol; it does not incorporate DNS server source. Direct WORM file I/O does not incorporate TrueLog source. Their package licenses remain applicable to their distribution.
