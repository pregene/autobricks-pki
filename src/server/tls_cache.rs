use crate::{
    Result,
    server::service::{Service, now},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct TlsCache {
    current: Mutex<Option<(String, Arc<rustls::ServerConfig>)>>,
}

impl TlsCache {
    pub fn config(&self, service: &Service) -> Result<Arc<rustls::ServerConfig>> {
        let fingerprint = String::from_utf8(
            service
                .db
                .setting("tls_certificate")?
                .ok_or("PKI is not initialized")?,
        )?;
        // Always check current metadata: cached key material must not bypass revocation/expiry.
        let certificate = service.db.metadata(&fingerprint)?;
        if certificate.revoked_at.is_some() || now() >= certificate.validity.not_after {
            return Err("PKI TLS certificate is revoked or expired".into());
        }
        let mut current = self.current.lock().map_err(|_| "TLS cache lock failed")?;
        if let Some((id, config)) = &*current
            && id == &fingerprint
        {
            return Ok(config.clone());
        }
        let config = service.tls_config()?;
        *current = Some((fingerprint, config.clone()));
        Ok(config)
    }
}
