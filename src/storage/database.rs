use crate::{Result, certificate::validity::Validity};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    pub fingerprint: String,
    pub cn: String,
    pub kind: String,
    pub issuer: Option<String>,
    pub serial: String,
    pub validity: Validity,
    pub pem: String,
    #[serde(skip_serializing)]
    pub key_pem: String,
    pub revoked_at: Option<i64>,
    #[serde(skip_serializing)]
    pub profile: Option<String>,
    #[serde(skip_serializing)]
    pub download_hash: Option<Vec<u8>>,
}
pub struct Database {
    pub(crate) ocsp_issuers: std::cell::RefCell<crate::revocation::issuer_cache::IssuerCache>,
    pub(crate) conn: Connection,
    pub(crate) worm: crate::storage::worm::Worm,
}
impl Database {
    pub fn open(path: &Path, worm: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize()?;
        let worm = worm.canonicalize()?;
        if parent.starts_with(&worm) {
            return Err("live SQLite must be outside WORM".into());
        }
        if path.exists() && (path.is_symlink() || path.canonicalize()?.starts_with(&worm)) {
            return Err("unsafe database path".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(0x20000)
            .open(path)?;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err("SQLite file must have owner-only permissions".into());
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let schema: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if schema > 1 {
            return Err("database schema is newer than this binary".into());
        }

        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;")?;
        conn.execute_batch(include_str!("schema.sql"))?;
        // Validate the current layout without converting an existing database.
        conn.prepare("SELECT certificate_path, private_key_path, valid FROM certificates LIMIT 0")?;
        conn.prepare("SELECT crl_path FROM crls LIMIT 0")?;
        let database = Self {
            ocsp_issuers: Default::default(),
            conn,
            worm: crate::storage::worm::Worm::new(&worm)?,
        };
        database.initialize_key_encryption()?;
        database.conn.pragma_update(None, "user_version", 1)?;
        Ok(database)
    }
    pub fn setting(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE name=?", [name], |r| {
                r.get(0)
            })
            .optional()?)
    }
    pub fn set_setting(&self, name: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            params![name, value],
        )?;
        Ok(())
    }
    pub fn insert(&self, c: &Certificate) -> Result<()> {
        let (certificate_path, private_key_path) =
            crate::storage::archive::paths(c, c.validity.not_before)?;
        let private_key_path = private_key_path.ok_or("missing private key archive path")?;
        let encrypted_key = self.encrypt_key(&c.key_pem)?;
        self.worm.write_once(&certificate_path, c.pem.as_bytes())?;
        self.worm
            .write_once(&private_key_path, encrypted_key.as_bytes())?;
        self.conn.execute(
            "INSERT INTO certificates(fingerprint,cn,kind,issuer,serial,not_before,not_after,certificate_path,private_key_path,revoked_at,profile,download_hash,valid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                c.fingerprint,
                c.cn,
                c.kind,
                c.issuer,
                c.serial,
                c.validity.not_before,
                c.validity.not_after,
                certificate_path,
                private_key_path,
                c.revoked_at,
                c.profile,
                c.download_hash,
                if c.revoked_at.is_some() { "REVOKED" } else { "VALID" }
            ],
        )?;
        if c.kind == "intermediate" {
            self.ocsp_issuers.borrow_mut().generation = None;
        }
        if let Some(issuer) = &c.issuer {
            self.conn.execute("INSERT INTO intermediate_leaf(intermediate_idx,leaf_idx) SELECT issuer.idx,leaf.idx FROM certificates issuer,certificates leaf WHERE issuer.fingerprint=? AND issuer.kind='intermediate' AND leaf.fingerprint=? AND leaf.kind IN ('server','client','server-and-client','leaf')", params![issuer,c.fingerprint])?;
        }
        Ok(())
    }
    pub fn enqueue(&self, kind: &str, payload: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO outbox(kind,payload) VALUES(?,?)",
            params![kind, payload],
        )?;
        Ok(())
    }
    pub fn pending(&self) -> Result<Vec<(i64, String, String)>> {
        self.pending_after(0)
    }
    pub fn pending_after(&self, after: i64) -> Result<Vec<(i64, String, String)>> {
        let mut q = self.conn.prepare(
            "SELECT id,kind,payload FROM outbox WHERE done=0 AND id>? ORDER BY id LIMIT 64",
        )?;
        Ok(
            q.query_map([after], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )
    }
    pub fn pending_external_after(&self, after: i64) -> Result<Vec<(i64, String, String)>> {
        let mut q = self.conn.prepare(
            "SELECT id,kind,payload FROM outbox WHERE done=0 AND kind<>'crl' AND id>? ORDER BY id LIMIT 64",
        )?;
        Ok(
            q.query_map([after], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )
    }
    pub fn pending_crls(&self) -> Result<Vec<String>> {
        let mut q = self.conn.prepare(
            "SELECT DISTINCT payload FROM outbox WHERE done=0 AND kind='crl' ORDER BY payload LIMIT 64",
        )?;
        Ok(q.query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn has_pending(&self) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE done=0)",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn is_pending(&self, id: i64) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE id=? AND done=0)",
            [id],
            |r| r.get(0),
        )?)
    }
    pub fn complete(&self, id: i64) -> Result<()> {
        self.conn
            .execute("UPDATE outbox SET done=1 WHERE id=?", [id])?;
        Ok(())
    }
    pub fn begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }
    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }
    pub fn rollback(&self) {
        let _ = self.conn.execute_batch("ROLLBACK");
    }
    pub fn transaction<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.begin()?;
        match f() {
            Ok(v) => match self.commit() {
                Ok(()) => Ok(v),
                Err(e) => {
                    self.rollback();
                    Err(e)
                }
            },
            Err(e) => {
                self.rollback();
                Err(e)
            }
        }
    }
}
