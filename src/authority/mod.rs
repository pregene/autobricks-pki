use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultIssuer {
    Database,
    Www,
    Vpn,
    Worm,
    App,
    Truelog,
    Auth,
    Cert,
}
pub const DEFAULT_ISSUERS: [DefaultIssuer; 8] = [
    DefaultIssuer::Database,
    DefaultIssuer::Www,
    DefaultIssuer::Vpn,
    DefaultIssuer::Worm,
    DefaultIssuer::App,
    DefaultIssuer::Truelog,
    DefaultIssuer::Auth,
    DefaultIssuer::Cert,
];
impl DefaultIssuer {
    pub fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Www => "www",
            Self::Vpn => "vpn",
            Self::Worm => "worm",
            Self::App => "app",
            Self::Truelog => "truelog",
            Self::Auth => "auth",
            Self::Cert => "cert",
        }
    }
}
pub const ROOT_NOT_AFTER: &str = "99991231235959Z";

mod lifecycle;
mod renewal;

pub mod domain;
pub mod validity;
