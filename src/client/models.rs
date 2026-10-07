use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateListEntry {
    pub idx: i64,
    pub cn: String,
    pub fingerprint: String,
    pub valid: String,
    pub issue_at: i64,
    pub remain: i64,
}

pub const PAGE_SIZE: usize = 256;
#[derive(Debug, Deserialize, Serialize)]
pub struct CertificatePage {
    pub entries: Vec<CertificateListEntry>,
    pub next_after: Option<i64>,
    pub through: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListFilter {
    Valid,
    Revoked,
    Renew,
    All,
}

impl ListFilter {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "valid" => Ok(Self::Valid),
            "revoked" => Ok(Self::Revoked),
            "renew" => Ok(Self::Renew),
            "all" => Ok(Self::All),
            _ => Err("invalid list filter; use valid, revoked, renew, or all".into()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Revoked => "revoked",
            Self::Renew => "renew",
            Self::All => "all",
        }
    }

    #[cfg(feature = "server")]
    pub(crate) fn predicate(self) -> &'static str {
        match self {
            Self::Valid => "valid='VALID'",
            Self::Revoked => "valid='REVOKED'",
            Self::Renew => "valid='SUPERSEDED'",
            Self::All => "1=1",
        }
    }
}
