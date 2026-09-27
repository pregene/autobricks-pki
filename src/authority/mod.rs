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
}
pub const DEFAULT_ISSUERS: [DefaultIssuer; 6] = [
    DefaultIssuer::Database,
    DefaultIssuer::Www,
    DefaultIssuer::Vpn,
    DefaultIssuer::Worm,
    DefaultIssuer::App,
    DefaultIssuer::Truelog,
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
        }
    }
}
pub const ROOT_NOT_AFTER: &str = "99991231235959Z";

mod lifecycle;

pub mod domain;
pub mod subject;
