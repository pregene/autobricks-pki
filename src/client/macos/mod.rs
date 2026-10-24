use crate::Result;
use std::{net::ToSocketAddrs, sync::Arc};

pub const SOCKET: &str = "/var/run/autobricks/pki-client.sock";
pub const CONFIG: &str = "/Library/Application Support/Autobricks PKI/client.json";

fn installed_config() -> std::path::PathBuf {
    std::env::var_os("ABPKI_CLIENT_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| CONFIG.into())
}

fn same_server(previous: &str, current: &str, port: u16) -> bool {
    if previous == current {
        return true;
    }
    let Ok(previous_ip) = previous.parse::<std::net::IpAddr>() else {
        return false;
    };
    (current, port)
        .to_socket_addrs()
        .is_ok_and(|mut addresses| addresses.any(|address| address.ip() == previous_ip))
}

pub fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    tls_config_with_identity(None)
}

pub fn tls_config_with_identity(
    identity: Option<(&[u8], &[u8])>,
) -> Result<Arc<rustls::ClientConfig>> {
    if std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some() {
        return Err(
            "macOS client requires OS trust; remove SSL_CERT_FILE and SSL_CERT_DIR overrides"
                .into(),
        );
    }
    let certificates = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates.certs {
        roots.add(certificate)?;
    }
    if roots.is_empty() {
        return Err(format!(
            "macOS trust store contains no usable certificates: {:?}",
            certificates.errors
        )
        .into());
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let config = match identity {
        Some((certificate, key)) => builder.with_client_auth_cert(
            rustls_pemfile::certs(&mut std::io::BufReader::new(certificate))
                .collect::<std::io::Result<Vec<_>>>()?,
            rustls_pemfile::private_key(&mut std::io::BufReader::new(key))?
                .ok_or("private key is missing")?,
        )?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Validate both remote listeners and print the installation settings as JSON.
pub fn configure(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err("configure requires SERVER TLS_PORT HTTPS_PORT".into());
    }
    let mut config = super::daemon::Config {
        server: args[0].clone(),
        port: args[1].parse()?,
        https_port: args[2].parse()?,
        unix_socket: SOCKET.into(),
        ca: "macos-system-trust".into(),
        certificate: None,
        private_key: None,
    };
    let origin = config.origin()?;
    let installed_config = installed_config();
    if installed_config.exists() {
        let previous: super::daemon::Config =
            serde_json::from_slice(&std::fs::read(installed_config)?)?;
        if !same_server(&previous.server, &config.server, config.port) {
            return Err(
                "existing client server identity cannot be replaced by reinstallation".into(),
            );
        }
        config.certificate = previous.certificate;
        config.private_key = previous.private_key;
    }
    let identity = match (&config.certificate, &config.private_key) {
        (Some(certificate), Some(key)) => Some((std::fs::read(certificate)?, std::fs::read(key)?)),
        _ => None,
    };
    let tls = tls_config_with_identity(
        identity
            .as_ref()
            .map(|(certificate, key)| (certificate.as_slice(), key.as_slice())),
    )?;
    // Root retrieval is intentionally available over verified TLS before the
    // client has enrolled an mTLS identity. list/list-ca are mTLS-only.
    super::management_request_with_config(&origin, tls.clone(), "GET", "/api/root", &[], None)?;
    super::request_with_config(
        &super::public_origin(&origin, config.https_port)?,
        tls,
        "GET",
        "/root",
        &[],
        None,
    )?;
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

/// Recreate volatile runtime storage after a reboot before binding the socket.
pub fn prepare_socket(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let parent = path.parent().ok_or("socket path has no parent")?;
    if parent == std::path::Path::new("/var/run/autobricks") {
        if !parent.exists() {
            std::fs::DirBuilder::new().mode(0o750).create(parent)?;
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o027 != 0 {
            return Err("macOS service socket directory must be root-owned and protected".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_ip_migration_requires_the_same_resolved_server() {
        assert!(super::same_server("127.0.0.1", "localhost", 5545));
        assert!(super::same_server("pki.example", "pki.example", 5545));
        assert!(!super::same_server("192.0.2.1", "localhost", 5545));
        assert!(!super::same_server("old.example", "new.example", 5545));
    }
}
