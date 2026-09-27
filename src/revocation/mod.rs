pub mod crl;
pub mod ocsp;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Good,
    Revoked,
    Unknown,
}

pub(crate) mod der;

pub(crate) mod issuer_cache;
mod service;
