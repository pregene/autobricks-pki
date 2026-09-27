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

impl Database {
    /// Read only list metadata; never load certificate or private-key contents.
    pub fn list_certificates(&self, intermediate: bool) -> Result<Vec<CertificateListEntry>> {
        let mut query = self.conn.prepare(
            "SELECT idx, cn, fingerprint,
             valid,
             not_before, MAX(0, (not_after - ?2 + 86399) / 86400)
             FROM certificates
             WHERE (?1 AND kind = 'intermediate')
                OR (NOT ?1 AND kind IN ('server', 'client', 'server-and-client'))
             ORDER BY idx",
        )?;
        Ok(query
            .query_map(
                rusqlite::params![intermediate, chrono::Utc::now().timestamp()],
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
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_needs_only_metadata_and_excludes_other_certificate_kinds() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database {
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
        let leaves = db.list_certificates(false).unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].valid, "REVOKED");
        assert_eq!(leaves[0].remain, 0);
        let json = serde_json::to_value(&leaves[0]).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 6);
        assert!(json.get("pem").is_none());
        assert!(json.get("key_pem").is_none());
    }
}
