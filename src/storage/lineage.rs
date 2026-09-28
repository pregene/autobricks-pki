use crate::{Result, storage::database::Database};

impl Database {
    pub(crate) fn crl_issuers(&self, fingerprint: &str) -> Result<Vec<String>> {
        if self.metadata(fingerprint)?.kind == "root" {
            Ok(vec![fingerprint.to_owned()])
        } else {
            self.ca_lineage(fingerprint)
        }
    }

    /// Resolve renewal generations by predecessor keys, never by a shared CN.
    pub fn ca_lineage(&self, fingerprint: &str) -> Result<Vec<String>> {
        let mut query = self.conn.prepare(
            "WITH RECURSIVE lineage(idx) AS (
                SELECT idx FROM certificates WHERE fingerprint=? AND kind='intermediate'
                UNION
                SELECT c.idx FROM certificates c JOIN lineage l
                ON c.previous_certificate_idx=l.idx
                   OR c.idx=(SELECT previous_certificate_idx FROM certificates WHERE idx=l.idx)
                WHERE c.kind='intermediate'
            ) SELECT fingerprint FROM certificates WHERE idx IN lineage ORDER BY idx",
        )?;
        let generations = query
            .query_map([fingerprint], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if generations.is_empty() {
            return Err("Intermediate CA lineage not found".into());
        }
        Ok(generations)
    }

    pub fn ca_has_successor(&self, fingerprint: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM certificates WHERE kind='intermediate' AND previous_certificate_idx=(SELECT idx FROM certificates WHERE fingerprint=?))",
            [fingerprint], |row| row.get(0))?)
    }
}
