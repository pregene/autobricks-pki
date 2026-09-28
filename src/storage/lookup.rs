use crate::{
    Result,
    certificate::validity::Validity,
    storage::database::{Certificate, Database},
};
use rusqlite::{OptionalExtension, Params};

const COLUMNS: &str = "fingerprint,cn,kind,issuer,serial,not_before,not_after,certificate_path,private_key_path,revoked_at,profile,download_hash";

impl Database {
    fn records(&self, clause: &str, params: impl Params) -> Result<Vec<Certificate>> {
        let mut query = self
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM certificates {clause}"))?;
        Ok(query
            .query_map(params, |r| {
                Ok(Certificate {
                    fingerprint: r.get(0)?,
                    cn: r.get(1)?,
                    kind: r.get(2)?,
                    issuer: r.get(3)?,
                    serial: r.get(4)?,
                    validity: Validity {
                        not_before: r.get(5)?,
                        not_after: r.get(6)?,
                    },
                    pem: r.get(7)?,
                    key_pem: r.get(8)?,
                    revoked_at: r.get(9)?,
                    profile: r.get(10)?,
                    download_hash: r.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
    fn load(&self, mut c: Certificate, private: bool) -> Result<Certificate> {
        c.pem = self.worm.read_text(&c.pem)?;
        c.key_pem = if private {
            self.decrypt_key(&self.worm.read_text(&c.key_pem)?)?
        } else {
            String::new()
        };
        Ok(c)
    }
    fn without_files(mut c: Certificate) -> Certificate {
        c.pem.clear();
        c.key_pem.clear();
        c
    }
    pub fn all(&self) -> Result<Vec<Certificate>> {
        self.records("ORDER BY idx", [])?
            .into_iter()
            .map(|c| self.load(c, true))
            .collect()
    }
    pub fn metadata(&self, id: &str) -> Result<Certificate> {
        self.records("WHERE fingerprint=?", [id])?
            .into_iter()
            .next()
            .map(Self::without_files)
            .ok_or_else(|| "certificate not found".into())
    }
    pub fn get(&self, id: &str) -> Result<Certificate> {
        let c = self
            .records("WHERE fingerprint=?", [id])?
            .into_iter()
            .next()
            .ok_or("certificate not found")?;
        self.load(c, true)
    }
    pub fn public_certificate(&self, id: &str) -> Result<Certificate> {
        let c = self
            .records("WHERE fingerprint=?", [id])?
            .into_iter()
            .next()
            .ok_or("certificate not found")?;
        self.load(c, false)
    }
    pub fn issuer_id(&self, id: &str) -> Result<String> {
        let exact: Option<String> = self
            .conn
            .query_row(
                "SELECT fingerprint FROM certificates WHERE fingerprint=? AND kind='intermediate'",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = exact {
            return Ok(id);
        }
        Ok(self.conn.query_row("SELECT fingerprint FROM certificates WHERE kind='intermediate' AND cn=? ORDER BY not_after DESC,idx DESC LIMIT 1", [id], |r| r.get(0))?)
    }
    pub fn issuer(&self, id: &str) -> Result<Certificate> {
        self.get(&self.issuer_id(id)?)
    }
    pub fn root_id(&self) -> Result<String> {
        Ok(self.conn.query_row(
            "SELECT fingerprint FROM certificates WHERE kind='root' ORDER BY idx LIMIT 1",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn has_certificates(&self) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT EXISTS(SELECT 1 FROM certificates)", [], |r| {
                r.get(0)
            })?)
    }
    pub fn revocation_status(&self, id: &str) -> Result<Option<Option<i64>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT revoked_at FROM certificates WHERE fingerprint=?",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn intermediate_public(&self) -> Result<Vec<Certificate>> {
        self.records("WHERE kind='intermediate' ORDER BY idx", [])?
            .into_iter()
            .map(|c| self.load(c, false))
            .collect()
    }
    pub fn due_intermediates(&self, now: i64) -> Result<Vec<Certificate>> {
        Ok(self.records("WHERE kind='intermediate' AND revoked_at IS NULL AND not_before<=?1 AND not_after>?1 AND (valid='SUPERSEDED' OR not_after<=?2) AND NOT EXISTS(SELECT 1 FROM certificates successor WHERE successor.previous_certificate_idx=certificates.idx AND successor.kind='intermediate') ORDER BY idx", rusqlite::params![now, now.saturating_add(crate::certificate::validity::INTERMEDIATE_RENEWAL_SECONDS)])?.into_iter().map(Self::without_files).collect())
    }
    pub fn by_issuer_serial(&self, issuer: &str, serial: &str) -> Result<Option<Certificate>> {
        Ok(self
            .records(
                "WHERE issuer=? AND serial=?",
                rusqlite::params![issuer, serial],
            )?
            .into_iter()
            .next()
            .map(Self::without_files))
    }
    pub fn revoked_by_issuer(&self, issuer: &str) -> Result<Vec<Certificate>> {
        Ok(self
            .records(
                "WHERE issuer=? AND revoked_at IS NOT NULL ORDER BY idx",
                [issuer],
            )?
            .into_iter()
            .map(Self::without_files)
            .collect())
    }
    pub fn dns_name_exists(&self, name: &str) -> Result<bool> {
        let first: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM certificates WHERE kind IN ('server','server-and-client') AND json_extract(profile,'$.dns_names[0]') COLLATE NOCASE=?1)",
            [name], |r| r.get(0))?;
        if first {
            return Ok(true);
        }
        // Older/imported multi-SAN profiles retain collision protection for every alias.
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM certificates c, json_each(c.profile,'$.dns_names') n WHERE c.kind IN ('server','server-and-client') AND json_array_length(c.profile,'$.dns_names')>1 AND n.value COLLATE NOCASE=?1)",
            [name], |r| r.get(0))?)
    }
}
