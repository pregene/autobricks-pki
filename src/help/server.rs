use super::Operation;

pub(super) const OPERATIONS: &[Operation] = &[
    Operation {
        name: "init",
        usage: "init REGISTRATION_IP [BASE_DOMAIN]",
        description: "Initialize the Root CA, six default Intermediate CAs, and service certificate.",
        details: "Arguments:\n  REGISTRATION_IP\n      Server IP registered with Autobricks DNS.\n  BASE_DOMAIN\n      Base domain, up to 24 ASCII characters. Prompts when omitted; default: autobricks.internal.\n\nInitialization settings:\n  ABPKI_ADMIN_PASSWORD\n      Initial administrator password, at least 12 bytes.\n  ABPKI_TRUELOG_CONFIG\n      TrueLog retention configuration; default: /etc/default/autobricks-log.\n\nThe configured SQLite and WORM directories must exist. An existing CA hierarchy is not replaced.",
        example: "abpkid init 192.0.2.10 autobricks.internal",
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

pub(super) const EXAMPLES: &str = "  abpkid init 192.0.2.10 autobricks.internal\n  abpkid serve\n  abpkid root > root.crt\n  abpkid serve --help";
