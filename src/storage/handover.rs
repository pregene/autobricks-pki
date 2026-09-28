use crate::{Result, storage::database::Database};
use rusqlite::params;

impl Database {
    pub(crate) fn mark_superseded(&self, fingerprint: &str, timestamp: i64) -> Result<()> {
        self.conn.execute("UPDATE certificates SET valid='SUPERSEDED',superseded_at=COALESCE(superseded_at,?) WHERE fingerprint=? AND valid='VALID' AND revoked_at IS NULL", params![timestamp, fingerprint])?;
        Ok(())
    }

    pub(crate) fn mark_due_leaves(&self, timestamp: i64) -> Result<()> {
        loop {
            let changed = self.conn.execute(
                "UPDATE certificates SET valid='SUPERSEDED',superseded_at=COALESCE(superseded_at,?1) WHERE idx IN (SELECT idx FROM certificates WHERE kind IN ('server','client','server-and-client') AND valid='VALID' AND revoked_at IS NULL AND not_before<=?1 AND not_after>?1 AND not_after<=?2 ORDER BY not_after,idx LIMIT 256)",
                params![timestamp, timestamp.saturating_add(crate::certificate::validity::RENEWAL_SECONDS)],
            )?;
            if changed < 256 {
                return Ok(());
            }
        }
    }

    /// Called inside the replacement issuance transaction.
    pub(crate) fn record_handover(
        &self,
        previous: &str,
        replacement: &str,
        timestamp: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE certificates SET previous_certificate_idx=(SELECT idx FROM certificates WHERE fingerprint=?) WHERE fingerprint=?",
            params![previous, replacement],
        )?;
        let changed = self.conn.execute(
            "UPDATE certificates SET valid='SUPERSEDED',superseded_at=COALESCE(superseded_at,?) WHERE fingerprint=? AND revoked_at IS NULL AND valid IN ('VALID','SUPERSEDED')",
            params![timestamp, previous],
        )?;
        if changed != 1 {
            return Err("certificate cannot enter renewal handover".into());
        }
        self.conn.execute(
            "UPDATE certificates SET valid='SUPERSEDED',superseded_at=COALESCE(superseded_at,?1) WHERE idx IN (SELECT leaf_idx FROM intermediate_leaf WHERE intermediate_idx=(SELECT idx FROM certificates WHERE fingerprint=?2 AND kind='intermediate')) AND revoked_at IS NULL AND valid IN ('VALID','SUPERSEDED')",
            params![timestamp, previous],
        )?;
        Ok(())
    }

    pub(crate) fn is_superseded(&self, fingerprint: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT valid='SUPERSEDED' FROM certificates WHERE fingerprint=?",
            [fingerprint],
            |r| r.get(0),
        )?)
    }
}
