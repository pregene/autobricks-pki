use crate::{Result, storage::database::Database};
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

    fn predicate(self) -> &'static str {
        match self {
            Self::Valid => "valid='VALID'",
            Self::Revoked => "valid='REVOKED'",
            Self::Renew => "valid='SUPERSEDED'",
            Self::All => "1=1",
        }
    }
}

impl Database {
    pub fn list_certificates(&self, intermediate: bool) -> Result<Vec<CertificateListEntry>> {
        let page = self.certificate_page(intermediate, 0, None)?;
        if page.next_after.is_some() {
            return Err("list requires pagination; update the client".into());
        }
        Ok(page.entries)
    }
    pub fn certificate_page(
        &self,
        intermediate: bool,
        after: i64,
        through: Option<i64>,
    ) -> Result<CertificatePage> {
        self.filtered_certificate_page(intermediate, ListFilter::Valid, after, through)
    }

    pub fn filtered_certificate_page(
        &self,
        intermediate: bool,
        filter: ListFilter,
        after: i64,
        through: Option<i64>,
    ) -> Result<CertificatePage> {
        let state = filter.predicate();
        let through = match through {
            Some(upper) => upper,
            None => {
                self.conn
                    .query_row("SELECT COALESCE(MAX(idx),0) FROM certificates", [], |r| {
                        r.get(0)
                    })?
            }
        };
        if after < 0 || through < after {
            return Err("invalid list cursor".into());
        }
        let kinds = if intermediate {
            "kind='intermediate'"
        } else {
            "kind IN ('server','client','server-and-client','leaf')"
        };
        let mut query = self.conn.prepare(&format!(
            "SELECT idx,cn,fingerprint,valid,not_before,MAX(0,(not_after-?1+86399)/86400) FROM certificates WHERE {kinds} AND {state} AND idx>?2 AND idx<=?3 ORDER BY idx LIMIT ?4"))?;
        let mut entries = query
            .query_map(
                rusqlite::params![
                    chrono::Utc::now().timestamp(),
                    after,
                    through,
                    PAGE_SIZE as i64 + 1
                ],
                |row| {
                    Ok(CertificateListEntry {
                        idx: row.get(0)?,
                        cn: row.get(1)?,
                        fingerprint: row.get(2)?,
                        valid: row.get(3)?,
                        issue_at: row.get(4)?,
                        remain: row.get(5)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let next_after = if entries.len() > PAGE_SIZE {
            entries.pop();
            entries.last().map(|entry| entry.idx)
        } else {
            None
        };
        Ok(CertificatePage {
            entries,
            next_after,
            through,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_needs_only_metadata_and_excludes_other_certificate_kinds() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database {
            ocsp_issuers: Default::default(),
            worm: crate::storage::worm::Worm::new(directory.path()).unwrap(),
            conn: rusqlite::Connection::open_in_memory().unwrap(),
        };
        // Deliberately omit PEM and key columns to verify metadata-only reads.
        db.conn
            .execute_batch(
                "CREATE TABLE certificates (
            idx INTEGER, cn TEXT, fingerprint TEXT, kind TEXT,
            valid TEXT, not_before INTEGER, not_after INTEGER);
            INSERT INTO certificates VALUES
            (1, 'root', 'r', 'root', 'VALID', 0, 86400),
            (2, 'app', 'i', 'intermediate', 'VALID', 0, 30931200),
            (3, 'web', 'l', 'server', 'REVOKED', 0, 4060800);",
            )
            .unwrap();
        let ca = db.list_certificates(true).unwrap();
        assert_eq!(ca.len(), 1);
        assert_eq!(ca[0].idx, 2);
        assert_eq!(ca[0].remain, 0);
        assert!(db.list_certificates(false).unwrap().is_empty());
        let leaves = db
            .filtered_certificate_page(false, ListFilter::All, 0, None)
            .unwrap()
            .entries;
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].valid, "REVOKED");
        assert_eq!(leaves[0].remain, 0);
        let json = serde_json::to_value(&leaves[0]).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 6);
        assert!(json.get("pem").is_none());
        assert!(json.get("key_pem").is_none());
    }
}
