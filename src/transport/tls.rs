use crate::Result;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{io::BufReader, sync::Arc};
fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs =
        rustls_pemfile::certs(&mut BufReader::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err("certificate chain is empty".into());
    }
    Ok(certs)
}
pub fn client(trust: &[u8]) -> Result<Arc<ClientConfig>> {
    client_with_identity(trust, None)
}
pub fn client_with_identity(
    trust: &[u8],
    identity: Option<(&[u8], &[u8])>,
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(trust)? {
        roots.add(cert)?;
    }
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
    let config = match identity {
        Some((certificate, key)) => {
            builder.with_client_auth_cert(certificates(certificate)?, private_key(key)?)?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}
fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(pem))?
        .ok_or_else(|| "private key is missing".into())
}
