use crate::Result;
use serde::Deserialize;
use std::{
    env,
    path::{Path, PathBuf},
};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    auth_support: bool,
    auth_2fa: bool,
    database: Option<PathBuf>,
    worm: Option<PathBuf>,
    dns_socket: Option<PathBuf>,
    origin: Option<String>,
    truelog_cli: Option<PathBuf>,
    retention_days: Option<u32>,
    comm_config: Option<PathBuf>,
}

pub struct Config {
    pub auth_support: bool,
    pub auth_2fa: bool,
    pub database: PathBuf,
    pub worm: PathBuf,
    pub dns_socket: PathBuf,
    pub origin: String,
    pub truelog_cli: PathBuf,
    pub retention_days: u32,
    pub comm_config: Option<PathBuf>,
}

fn required_path(name: &str, file: Option<PathBuf>) -> Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .or(file)
        .ok_or_else(|| format!("missing configuration value: {name}").into())
}
fn boolean(name: &str, file: bool) -> Result<bool> {
    match env::var(name) {
        Ok(value) if matches!(value.as_str(), "1" | "true" | "TRUE") => Ok(true),
        Ok(value) if matches!(value.as_str(), "0" | "false" | "FALSE") => Ok(false),
        Ok(_) => Err(format!("{name} must be true or false").into()),
        Err(env::VarError::NotPresent) => Ok(file),
        Err(error) => Err(error.into()),
    }
}

impl Config {
    pub fn load(config: Option<&Path>) -> Result<Self> {
        let file: FileConfig = match config {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => FileConfig::default(),
        };
        Ok(Self {
            auth_support: boolean("ABPKI_AUTH_SUPPORT", file.auth_support)?,
            auth_2fa: file.auth_2fa,
            database: required_path("ABPKI_DATABASE", file.database)?,
            worm: required_path("ABPKI_WORM", file.worm)?,
            dns_socket: required_path("AUTOBRICKS_DNS_SOCKET", file.dns_socket)?,
            origin: env::var("ABPKI_ORIGIN")
                .ok()
                .or(file.origin)
                .unwrap_or_default(),
            truelog_cli: required_path("ABPKI_TRUELOG_CLI", file.truelog_cli)?,
            retention_days: file.retention_days.unwrap_or(365),
            comm_config: env::var_os("ABPKI_COMM_CONFIG")
                .map(PathBuf::from)
                .or(file.comm_config),
        })
    }
}
