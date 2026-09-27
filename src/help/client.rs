use super::Operation;

pub(super) const OPERATIONS: &[Operation] = &[
    Operation {
        name: "daemon",
        usage: "daemon --config PATH",
        description: "Run the local Unix socket client service.",
        details: "Read the installed connection settings and OS trust bundle. Invoked by systemd.",
        example: "abpki-cli daemon --config /etc/autobricks-pki-client/client.json",
    },
    Operation {
        name: "create",
        usage: "create",
        description: "Issue a server or client certificate using a JSON request from standard input.",
        details: concat!(
            "Input:\n  JSON containing issuer and profile.\n  Choose issuer from abpki-cli list-ca and replace the sample CN and IP.\n  Server certificates require exactly one purpose URI SAN.\n\nRequest JSON example:\n",
            r#"{
  "issuer": "www.autobricks.internal",
  "profile": {
    "kind": "server",
    "common_name": "web01",
    "ip_addresses": [
      "192.0.2.20"
    ],
    "uri_sans": [
      "urn:autobricks:purpose:www",
      "urn:autobricks:allowed-source-cidr:192.0.2.0/24",
      "urn:autobricks:api-server:r:198.51.100.10/32"
    ]
  }
}
"#,
            "\nPreparation:\n  Save the JSON example as request.json and edit its issuer, CN, IP, and access policies.\n\nField reference:\n  LEAF-CREATE.md (installed: /usr/share/doc/autobricks-pki/LEAF-CREATE.md)\n\nOutput:\n  Issued certificate and integration delivery state as JSON. The download token is saved in the invoking user's private credential directory."
        ),
        example: "abpki-cli create < request.json",
    },
    Operation {
        name: "check",
        usage: "check FINGERPRINT",
        description: "Check certificate revocation status: GOOD, REVOKED, or UNKNOWN.",
        details: "Arguments:\n  FINGERPRINT\n      Certificate SHA-256 fingerprint, 64 lowercase hexadecimal characters without separators.\n\nGOOD is a revocation status, not a complete certificate validity check.",
        example: "abpki-cli check <fingerprint>",
    },
    Operation {
        name: "list-ca",
        usage: "list-ca",
        description: "List issuing Intermediate CA certificates.",
        details: "Output:\n  Intermediate CA certificate records as JSON. Private keys are excluded.",
        example: "abpki-cli list-ca",
    },
    Operation {
        name: "list",
        usage: "list",
        description: "List issued leaf certificates.",
        details: "Output:\n  Leaf certificate records as JSON. Private keys and access tokens are excluded.",
        example: "abpki-cli list",
    },
    Operation {
        name: "download",
        usage: "download FINGERPRINT TARGET",
        description: "Download certificate, private key, and trust chain as TARGET.tar.gz.",
        details: "Arguments:\n  FINGERPRINT\n      Certificate SHA-256 fingerprint without separators.\n  TARGET\n      Output basename; .tar.gz is appended.\n\nArchive contents:\n  certificate.pem\n  private-key.pem\n  trust-chain\n\nAll members contain PEM data. Requires the certificate access token. Existing output files are not overwritten.",
        example: "abpki-cli download <fingerprint> web01",
    },
    Operation {
        name: "revoke",
        usage: "revoke FINGERPRINT --pass [PASSWORD]",
        description: "Revoke a leaf certificate using the administrator password.",
        details: "Arguments:\n  FINGERPRINT\n      Target leaf certificate fingerprint.\n\nOptions:\n  --pass [PASSWORD]\n      Administrator password. Omit its value to enter it at a hidden terminal prompt.\n\nA certificate access token does not authorize this command. Root and Intermediate CA targets are not accepted.",
        example: "abpki-cli revoke <fingerprint> --pass '<administrator-password>'",
    },
    Operation {
        name: "renew",
        usage: "renew FINGERPRINT",
        description: "Renew a leaf certificate while preserving its original validity duration.",
        details: "Arguments:\n  FINGERPRINT\n      Existing leaf certificate fingerprint.\n\nRequires the certificate access token. The certificate must be unrevoked and within its final seven days before expiration.\nA seven-day certificate renews for seven days. There is no duration parameter.",
        example: "abpki-cli renew <fingerprint>",
    },
    Operation {
        name: "root",
        usage: "root",
        description: "Download the public Root CA certificate to root.crt in PEM format.",
        details: "Output:\n  root.crt\n\nUses the public HTTPS endpoint. Existing output files are not overwritten. No private key is included.",
        example: "abpki-cli root",
    },
    Operation {
        name: "chain",
        usage: "chain ISSUER",
        description: "Download an Intermediate CA and Root CA as the PEM file trust-chain.",
        details: "Arguments:\n  ISSUER\n      Intermediate CA CN or SHA-256 fingerprint.\n\nOutput:\n  trust-chain (without a filename extension).\n\nExisting output files are not overwritten. No CA private keys are included.",
        example: "abpki-cli chain www.autobricks.internal",
    },
    Operation {
        name: "create-ca",
        usage: "create-ca",
        description: "Not implemented in version 1.0; additional CA creation is reserved for 1.1.",
        details: "This operation cannot create a CA in version 1.0.\nInstallation still creates the six default Intermediate CAs.",
        example: "abpki-cli create-ca --help",
    },
];

pub(super) const EXAMPLES: &str = "  abpki-cli create --help\n  abpki-cli create < request.json\n  abpki-cli list-ca\n  abpki-cli check <fingerprint>\n  abpki-cli download <fingerprint> web01\n  abpki-cli renew --help";
