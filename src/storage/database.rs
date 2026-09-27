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
    pub(crate) conn: Connection,
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

        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS certificates(idx INTEGER PRIMARY KEY AUTOINCREMENT,fingerprint TEXT NOT NULL UNIQUE,cn TEXT NOT NULL,kind TEXT NOT NULL,issuer TEXT REFERENCES certificates(fingerprint),serial TEXT NOT NULL,not_before INTEGER NOT NULL,not_after INTEGER NOT NULL,pem TEXT NOT NULL,key_pem TEXT NOT NULL,revoked_at INTEGER,profile TEXT,download_hash BLOB,UNIQUE(issuer,serial));
        CREATE TABLE IF NOT EXISTS crls(idx INTEGER PRIMARY KEY AUTOINCREMENT,issuer INTEGER NOT NULL UNIQUE REFERENCES certificates(idx),pem BLOB NOT NULL,next_update INTEGER NOT NULL,number INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,done INTEGER NOT NULL DEFAULT 0);")?;
        let database = Self { conn };
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
        self.conn.execute(
            "INSERT INTO certificates(fingerprint,cn,kind,issuer,serial,not_before,not_after,pem,key_pem,revoked_at,profile,download_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                c.fingerprint,
                c.cn,
                c.kind,
                c.issuer,
                c.serial,
                c.validity.not_before,
                c.validity.not_after,
                c.pem,
                self.encrypt_key(&c.key_pem)?,
                c.revoked_at,
                c.profile,
                c.download_hash
            ],
        )?;
        Ok(())
    }
    pub fn all(&self) -> Result<Vec<Certificate>> {
        let mut q=self.conn.prepare("SELECT fingerprint,cn,kind,issuer,serial,not_before,not_after,pem,key_pem,revoked_at,profile,download_hash FROM certificates ORDER BY idx")?;
        let mut certificates = q
            .query_map([], |r| {
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
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for certificate in &mut certificates {
            certificate.key_pem = self.decrypt_key(&certificate.key_pem)?;
        }
        Ok(certificates)
    }
    pub fn get(&self, id: &str) -> Result<Certificate> {
        self.all()?
            .into_iter()
            .find(|c| c.fingerprint == id)
            .ok_or_else(|| "certificate not found".into())
    }
    pub fn issuer(&self, id: &str) -> Result<Certificate> {
        let all = self.all()?;
        if let Some(c) = all
            .iter()
            .find(|c| c.fingerprint == id && c.kind == "intermediate")
        {
            return Ok(c.clone());
        }
        all.into_iter()
            .filter(|c| c.cn == id && c.kind == "intermediate")
            .max_by_key(|c| c.validity.not_after)
            .ok_or_else(|| "issuer not found".into())
    }

    pub fn enqueue(&self, kind: &str, payload: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO outbox(kind,payload) VALUES(?,?)",
            params![kind, payload],
        )?;
        Ok(())
    }
    pub fn pending(&self) -> Result<Vec<(i64, String, String)>> {
        let mut q = self
            .conn
            .prepare("SELECT id,kind,payload FROM outbox WHERE done=0 ORDER BY id")?;
        Ok(q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
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
