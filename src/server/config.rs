use crate::Result;
use std::{env, path::PathBuf};
pub struct Config {
    pub database: PathBuf,
    pub worm: PathBuf,
    pub dns_socket: PathBuf,
    pub origin: String,
    pub truelog_cli: PathBuf,
    pub listeners: super::listener_config::ListenerConfig,
}
impl Config {
    pub fn environment() -> Result<Self> {
        Ok(Self {
            database: env::var("ABPKI_DATABASE")
                .unwrap_or_else(|_| "abpki.sqlite".into())
                .into(),
            worm: env::var("ABPKI_WORM")
                .unwrap_or_else(|_| "/mnt/worm-storage/pki".into())
                .into(),
            dns_socket: env::var("AUTOBRICKS_DNS_SOCKET")
                .unwrap_or_else(|_| "/run/autobricks-dns/autobricks-dns.sock".into())
                .into(),
            truelog_cli: env::var("ABPKI_TRUELOG_CLI")
                .unwrap_or_else(|_| "/usr/bin/ab-truelog-cli".into())
                .into(),
            origin: env::var("ABPKI_ORIGIN").unwrap_or_default(),
            listeners: super::listener_config::ListenerConfig::parse(
                &env::var("ABPKI_BIND").unwrap_or_else(|_| "0.0.0.0".into()),
                &env::var("ABPKI_TLS_PORT").unwrap_or_else(|_| "5545".into()),
                &env::var("ABPKI_HTTPS_PORT").unwrap_or_else(|_| "5546".into()),
            )?,
        })
    }
}
