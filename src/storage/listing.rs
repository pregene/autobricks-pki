pub use crate::client::models::{CertificateListEntry, CertificatePage, ListFilter, PAGE_SIZE};
use crate::{Result, storage::database::Database};

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
#[path = "../test/unit/storage_listing.rs"]
mod tests;
