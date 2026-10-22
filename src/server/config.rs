use crate::Result;
use serde::Deserialize;
use std::{
    env,
    path::{Path, PathBuf},
};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    database: Option<PathBuf>,
    worm: Option<PathBuf>,
    dns_socket: Option<PathBuf>,
    origin: Option<String>,
    truelog_cli: Option<PathBuf>,
    truelog_config: Option<PathBuf>,
    comm_config: Option<PathBuf>,
    comm_library: Option<PathBuf>,
}

pub struct Config {
    pub database: PathBuf,
    pub worm: PathBuf,
    pub dns_socket: PathBuf,
    pub origin: String,
    pub truelog_cli: PathBuf,
    pub truelog_config: PathBuf,
    pub comm_config: Option<PathBuf>,
    pub comm_library: Option<PathBuf>,
}

fn required_path(name: &str, file: Option<PathBuf>) -> Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .or(file)
        .ok_or_else(|| format!("missing configuration value: {name}").into())
}

impl Config {
    pub fn load(config: Option<&Path>) -> Result<Self> {
        let file: FileConfig = match config {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => FileConfig::default(),
        };
        Ok(Self {
            database: required_path("ABPKI_DATABASE", file.database)?,
            worm: required_path("ABPKI_WORM", file.worm)?,
            dns_socket: required_path("AUTOBRICKS_DNS_SOCKET", file.dns_socket)?,
            origin: env::var("ABPKI_ORIGIN")
                .ok()
                .or(file.origin)
                .unwrap_or_default(),
            truelog_cli: required_path("ABPKI_TRUELOG_CLI", file.truelog_cli)?,
            truelog_config: required_path("ABPKI_TRUELOG_CONFIG", file.truelog_config)?,
            comm_config: env::var_os("ABPKI_COMM_CONFIG")
                .map(PathBuf::from)
                .or(file.comm_config),
            comm_library: env::var_os("ABPKI_COMM_LIBRARY")
                .map(PathBuf::from)
                .or(file.comm_library),
        })
    }
}
