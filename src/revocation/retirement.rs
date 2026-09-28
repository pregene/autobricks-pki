use crate::{Result, certificate::validity::DAY, server::service::Service};
use rusqlite::params;

pub const SUPERSEDED_SECONDS: i64 = 7 * DAY;
pub const CA_SUPERSEDED_SECONDS: i64 = 48 * DAY;

impl Service {
    /// Commit retirement before performing any signing or external delivery.
    pub fn retire_superseded(&self, timestamp: i64) -> Result<usize> {
        let Some(cutoff) = timestamp.checked_sub(SUPERSEDED_SECONDS) else {
            return Ok(0);
        };
        let ca_cutoff = timestamp.saturating_sub(CA_SUPERSEDED_SECONDS);
        let mut total = 0;
        loop {
            let count = self.db.transaction(|| {
                let mut query = self.db.conn.prepare(
                    "SELECT idx,fingerprint,issuer FROM certificates WHERE valid='SUPERSEDED' AND revoked_at IS NULL AND superseded_at<=?1 AND (kind IN ('server','client','server-and-client','leaf') OR (kind='intermediate' AND superseded_at<=?2)) ORDER BY superseded_at,idx LIMIT 256",
                )?;
                let due = query.query_map(params![cutoff, ca_cutoff], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for (idx, fingerprint, issuer) in &due {
                    self.db.conn.execute(
                        "UPDATE certificates SET valid='REVOKED',revoked_at=? WHERE idx=? AND valid='SUPERSEDED' AND revoked_at IS NULL",
                        params![timestamp, idx],
                    )?;
                    // Keep issuer resolution and signing outside the revocation transaction.
                    if let Some(issuer) = issuer {
                        let pending: bool = self.db.conn.query_row(
                            "SELECT EXISTS(SELECT 1 FROM outbox WHERE kind='crl' AND payload=? AND done=0)",
                            [issuer], |r| r.get(0),
                        )?;
                        if !pending { self.db.enqueue("crl", issuer)?; }
                    }
                    self.db.enqueue("audit", &serde_json::json!({
                        "event":"certificate-revoked", "fingerprint":fingerprint,
                        "timestamp":timestamp, "reason":"superseded", "automatic":true
                    }).to_string())?;
                }
                Ok(due.len())
            })?;
            total += count;
            if count < 256 {
                break;
            }
        }
        if let Err(error) = self.reconcile_crls() {
            eprintln!("superseded certificates retired; CRL publication pending: {error}");
        }
        let missing: bool = self.db.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM certificates WHERE valid='SUPERSEDED' AND revoked_at IS NULL AND superseded_at IS NULL)",
            [], |r| r.get(0),
        )?;
        if missing {
            return Err("SUPERSEDED certificate has no transition timestamp".into());
        }
        Ok(total)
    }
}
