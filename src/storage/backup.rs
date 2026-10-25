use crate::{Result, storage::database::Database};
use rusqlite::{Connection, backup::Backup};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
const LAST: &str = "database_backup_last_success";
impl Database {
    pub fn backup_if_due(&self, dir: &Path, days: u32, now: i64) -> Result<Option<PathBuf>> {
        let last = self
            .setting(LAST)?
            .map(|v| serde_json::from_slice::<i64>(&v))
            .transpose()?;
        if last.is_some_and(|v| now.saturating_sub(v) < i64::from(days) * 86400) {
            return Ok(None);
        }
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let target = dir.join(format!("abpki-{now}.sqlite"));
        let temporary = dir.join(format!(".abpki-{now}.tmp"));
        let result = (|| -> Result<()> {
            let mut dst = Connection::open(&temporary)?;
            Backup::new(&self.conn, &mut dst)?.run_to_completion(
                100,
                Duration::from_millis(10),
                None,
            )?;
            let check: String = dst.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            if check != "ok" {
                return Err("database backup integrity check failed".into());
            }
            drop(dst);
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
            fs::rename(&temporary, &target)?;
            self.set_setting(LAST, &serde_json::to_vec(&now)?)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        Ok(Some(target))
    }
}
