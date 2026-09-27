use crate::Result;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
pub struct Worm {
    root: PathBuf,
}
impl Worm {
    pub fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
        })
    }
    pub fn write_once(&self, name: &str, data: &[u8]) -> Result<()> {
        let parts: Vec<_> = name.split('/').collect();
        if parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'%'))
        }) {
            return Err("invalid archive name".into());
        }
        let mut path = self.root.clone();
        for part in &parts[..parts.len() - 1] {
            path.push(part);
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.into()),
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(
                    "archive directories require owner-only permissions and no symlinks".into(),
                );
            }
        }
        path.push(parts.last().ok_or("missing archive name")?);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(data)?;
                f.sync_all()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if path.is_symlink() {
                    return Err("WORM artifact symlink".into());
                }
                if fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                    return Err("archive files require owner-only permissions".into());
                }
                let existing = fs::read(&path)?;
                if !data.starts_with(&existing) {
                    return Err("WORM artifact conflict".into());
                }
                let mut file = OpenOptions::new()
                    .append(true)
                    .custom_flags(0x20000)
                    .open(&path)?;
                if file.metadata()?.len() != existing.len() as u64 {
                    return Err("WORM artifact changed during retry".into());
                }
                file.write_all(&data[existing.len()..])?;
                file.sync_all()?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}
