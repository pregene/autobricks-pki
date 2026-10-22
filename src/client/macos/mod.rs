use crate::Result;
use std::sync::Arc;

pub const SOCKET: &str = "/var/run/autobricks-pki-client/client.sock";
pub const CONFIG: &str = "/Library/Application Support/Autobricks PKI/client.json";

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
    let config = super::daemon::Config {
        server: args[0].clone(),
        port: args[1].parse()?,
        https_port: args[2].parse()?,
        unix_socket: SOCKET.into(),
        ca: "macos-system-trust".into(),
        certificate: None,
        private_key: None,
    };
    let origin = config.origin()?;
    if std::path::Path::new(CONFIG).exists() {
        let previous: super::daemon::Config = serde_json::from_slice(&std::fs::read(CONFIG)?)?;
        if previous.server != config.server {
            return Err(
                "existing client server identity cannot be replaced by reinstallation".into(),
            );
        }
    }
    let tls = tls_config()?;
    super::management_request_with_config(&origin, tls.clone(), "GET", "/api/list-ca", &[], None)?;
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
    if parent == std::path::Path::new("/var/run/autobricks-pki-client") {
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
