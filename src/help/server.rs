use super::Operation;

pub(super) const OPERATIONS: &[Operation] = &[
    Operation {
        name: "init",
        usage: "init REGISTRATION_IP BASE_DOMAIN --ca-subject FILE",
        description: "Initialize the Root CA, eight default Intermediate CAs, and service certificate.",
        details: "Arguments:\n  REGISTRATION_IP\n      Server IP registered with Autobricks DNS.\n  BASE_DOMAIN\n      Base domain, up to 24 ASCII characters.\n  --ca-subject FILE\n      Required JSON file containing the complete Root and Intermediate CA Subject.\n\nInitialization settings:\n  ABPKI_ADMIN_PASSWORD\n      Initial administrator password, at least 12 bytes.\n  retention_days\n      PKI retention policy in the JSON configuration; default: 365.\n\nThe configured SQLite and WORM directories must exist. An existing CA hierarchy is not replaced.",
        example: "abpkid init 192.0.2.10 example.internal --ca-subject /etc/autobricks/pki/ca-subject.json",
    },
    Operation {
        name: "serve",
        usage: "serve",
        description: "Run the PKI service, certificate maintenance, and pending integration delivery.",
        details: "Service settings:\n  ABPKI_BIND\n      Listen IP; default: 0.0.0.0.\n  ABPKI_TLS_PORT\n      Management TLS port; default: 5545.\n  ABPKI_HTTPS_PORT\n      Public HTTPS port; default: 5546.\n  ABPKI_DATABASE, ABPKI_WORM\n      Operational SQLite file and WORM artifact directory.\n  ABPKI_ORIGIN\n      Public HTTPS origin used for certificate distribution URLs.\n  AUTOBRICKS_DNS_SOCKET, ABPKI_TRUELOG_CLI\n      DNS control socket and TrueLog submission executable.\n\nInitialize the hierarchy before starting the service. Incoming TLS connections do not require client certificates.",
        example: "abpkid serve",
    },
    Operation {
        name: "root",
        usage: "root",
        description: "Print the initialized Root CA certificate as PEM.",
        details: "Output:\n  Writes only the public Root CA PEM to standard output.\n  Uses the configured local PKI database and WORM directory.\n  Does not export a private key.",
        example: "abpkid root > root.crt",
    },
];

pub(super) const EXAMPLES: &str = "  abpkid init 192.0.2.10 example.internal --ca-subject /etc/autobricks/pki/ca-subject.json\n  abpkid serve\n  abpkid root > root.crt\n  abpkid serve --help";
