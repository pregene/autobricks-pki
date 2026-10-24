use crate::{
    Result,
    transport::management::{self, Message, Reply},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[cfg(not(target_os = "macos"))]
pub const SOCKET: &str = "/var/run/autobricks/pki-client.sock";
#[cfg(not(target_os = "macos"))]
pub const CONFIG: &str = "/etc/autobricks/pki/client.json";
#[cfg(target_os = "macos")]
pub const SOCKET: &str = super::macos::SOCKET;
#[cfg(target_os = "macos")]
pub const CONFIG: &str = super::macos::CONFIG;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: String,
    pub port: u16,
    pub https_port: u16,
    pub unix_socket: String,
    pub ca: String,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
}
impl Config {
    pub fn origin(&self) -> Result<String> {
        if self.port == 0 || self.https_port == 0 || self.port == self.https_port {
            return Err("invalid client connection ports".into());
        }
        if self.certificate.is_some() != self.private_key.is_some() {
            return Err("client certificate and private key must be configured together".into());
        }
        let host = if self.server.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.server)
        } else {
            self.server.clone()
        };
        let origin = format!("https://{host}:{}", self.port);
        super::origin::Distribution::new(&origin)?;
        Ok(origin)
    }
}
pub fn call(socket: &Path, message: &Message) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    management::write_frame(&mut stream, message, management::MAX_REQUEST)?;
    let reply: Reply = management::read_frame(&mut stream, management::MAX_RESPONSE)?;
    if reply.status != "200 OK" {
        return Err(String::from_utf8_lossy(&reply.body).into_owned().into());
    }
    Ok(reply.body)
}
pub fn serve(config_path: &Path) -> Result<()> {
    let config: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    let origin = config.origin()?;
    // Load the OS trust bundle once at service startup; never disable TLS verification.
    #[cfg(not(target_os = "macos"))]
    let tls = {
        let trust = fs::read(&config.ca)?;
        let identity = match (&config.certificate, &config.private_key) {
            (Some(certificate), Some(key)) => Some((fs::read(certificate)?, fs::read(key)?)),
            _ => None,
        };
        crate::transport::tls::client_with_identity(
            &trust,
            identity
                .as_ref()
                .map(|(certificate, key)| (certificate.as_slice(), key.as_slice())),
        )?
    };
    #[cfg(target_os = "macos")]
    let tls = {
        let identity = match (&config.certificate, &config.private_key) {
            (Some(certificate), Some(key)) => Some((fs::read(certificate)?, fs::read(key)?)),
            _ => None,
        };
        super::macos::tls_config_with_identity(
            identity
                .as_ref()
                .map(|(certificate, key)| (certificate.as_slice(), key.as_slice())),
        )?
    };
    let path = Path::new(&config.unix_socket);
    #[cfg(target_os = "macos")]
    super::macos::prepare_socket(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err("client socket path is not a socket".into());
        }
        if UnixStream::connect(path).is_ok() {
            return Err("client socket already in use".into());
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let config = Arc::new(config);
    let origin = Arc::new(origin);
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        if active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 16).then_some(n + 1)
            })
            .is_err()
        {
            // Reject promptly without blocking other callers on an unread local socket.
            continue;
        }
        let guard = Active(active.clone());
        let config = config.clone();
        let origin = origin.clone();
        let tls = tls.clone();
        std::thread::Builder::new()
            .name("abpki-client-relay".into())
            .spawn(move || {
                let _guard = guard;
                let result =
                    match management::read_frame::<Message>(&mut stream, management::MAX_REQUEST) {
                        Ok(message) => relay(message, &config, &origin, tls),
                        Err(error) => Err(error),
                    };
                let reply = match result {
                    Ok(body) => Reply {
                        status: "200 OK".into(),
                        content_type: "application/octet-stream".into(),
                        body,
                    },
                    Err(error) => Reply {
                        status: "502 Bad Gateway".into(),
                        content_type: "text/plain".into(),
                        body: error.to_string().into_bytes(),
                    },
                };
                let _ = management::write_frame(&mut stream, &reply, management::MAX_RESPONSE);
            })?;
    }
    Ok(())
}
fn relay(
    message: Message,
    config: &Config,
    origin: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>> {
    if message.method == "GET" && message.path == "/root" {
        return super::request_with_config(
            &super::public_origin(origin, config.https_port)?,
            tls,
            "GET",
            "/root",
            &[],
            None,
        );
    }
    message.validate()?;
    super::management_request_with_config(
        origin,
        tls,
        &message.method,
        &message.path,
        &message.body,
        message.credential.as_deref(),
    )
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}
