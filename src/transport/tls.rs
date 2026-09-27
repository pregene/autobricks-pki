use crate::Result;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::CertificateDer};
use std::{
    io::{BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};
fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs =
        rustls_pemfile::certs(&mut BufReader::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err("certificate chain is empty".into());
    }
    Ok(certs)
}
pub fn server(chain: &[u8], key: &[u8]) -> Result<Arc<ServerConfig>> {
    let key =
        rustls_pemfile::private_key(&mut BufReader::new(key))?.ok_or("missing private key")?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates(chain)?, key)?;
    Ok(Arc::new(config))
}
pub fn client(trust: &[u8]) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(trust)? {
        roots.add(cert)?;
    }
    Ok(Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}
pub struct DeadlineStream {
    pub tls: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    deadline: Instant,
}
impl DeadlineStream {
    pub fn new(socket: TcpStream, config: Arc<ServerConfig>) -> Result<Self> {
        Ok(Self {
            tls: rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, socket),
            deadline: Instant::now() + Duration::from_secs(15),
        })
    }
    fn configure(&self) -> std::io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        self.tls.sock.set_read_timeout(Some(remaining))?;
        self.tls.sock.set_write_timeout(Some(remaining))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.configure()?;
        self.tls.read(b)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.configure()?;
        self.tls.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.configure()?;
        self.tls.flush()
    }
}
