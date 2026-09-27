use crate::Result;
pub const PREFIX: &str = "urn:autobricks:purpose:";
pub const PURPOSES: [&str; 33] = [
    "mariadb",
    "mysql",
    "oracle",
    "db2",
    "postgresql",
    "mongodb",
    "couchebase",
    "www",
    "express",
    "fastapi",
    "caddy",
    "nginx",
    "gateway",
    "file",
    "api",
    "router",
    "vpn",
    "worm",
    "redis",
    "etcd",
    "elasticsearch",
    "rabbitmq",
    "kafka",
    "dns",
    "ldap",
    "keycloak",
    "prometheus",
    "smtp",
    "registry",
    "pki",
    "truelog",
    "kms",
    "proxy",
];
pub fn validate(uris: &[String], server: bool) -> Result<()> {
    let mut present = false;
    for uri in uris {
        if let Some(token) = uri.strip_prefix(PREFIX) {
            if !PURPOSES.contains(&token) {
                return Err("unknown or empty server purpose".into());
            }
            present = true;
        }
    }
    if server && !present {
        return Err("server certificates require a purpose URI SAN".into());
    }
    Ok(())
}
