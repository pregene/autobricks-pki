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
    time::Duration,
};

pub const SOCKET: &str = "/run/autobricks-pki-client/client.sock";
pub const CONFIG: &str = "/etc/autobricks-pki-client/client.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: String,
    pub port: u16,
    pub https_port: u16,
    pub unix_socket: String,
    pub ca: String,
}
impl Config {
    pub fn origin(&self) -> Result<String> {
        if self.port == 0 || self.https_port == 0 || self.port == self.https_port {
            return Err("invalid client connection ports".into());
        }
        let host = if self.server.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.server)
        } else {
            self.server.clone()
        };
        let origin = format!("https://{host}:{}", self.port);
        crate::certificate::profile::Distribution::new(&origin)?;
        Ok(origin)
    }
}
pub fn call(socket: &Path, message: &Message) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    management::write_frame(&mut stream, message, crate::transport::request::MAX_BODY)?;
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
    let trust = fs::read(&config.ca)?;
    crate::transport::tls::client(&trust)?;
    let path = Path::new(&config.unix_socket);
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
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let result = relay(&mut stream, &config, &origin, &trust);
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
        // A disconnected local caller must not stop the daemon.
        let _ = management::write_frame(&mut stream, &reply, management::MAX_RESPONSE);
    }
    Ok(())
}
fn relay(stream: &mut UnixStream, config: &Config, origin: &str, trust: &[u8]) -> Result<Vec<u8>> {
    let message: Message = management::read_frame(stream, crate::transport::request::MAX_BODY)?;
    if message.method == "GET" && message.path == "/root" {
        return super::request(
            &super::public_origin(origin, config.https_port)?,
            trust,
            "GET",
            "/root",
            &[],
            None,
        );
    }
    let request = message.into_request()?;
    super::management_request(
        origin,
        trust,
        &request.method,
        &request.path,
        &request.body,
        request
            .headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer ")),
    )
}
