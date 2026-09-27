use crate::Result;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
    fn safe_permissions(&self, metadata: &fs::Metadata) -> Result<bool> {
        let mode = metadata.permissions().mode();
        if mode & 0o007 != 0 {
            return Ok(false);
        }
        if mode & 0o070 == 0 {
            return Ok(true);
        }
        let root = fs::metadata(&self.root)?;
        Ok(root.permissions().mode() & 0o070 != 0
            && root.permissions().mode() & 0o007 == 0
            && metadata.uid() == root.uid()
            && metadata.gid() == root.gid())
    }
    pub fn read_text(&self, name: &str) -> Result<String> {
        let relative = Path::new(name);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("invalid WORM path".into());
        }
        let mut path = self.root.clone();
        for component in relative.components() {
            path.push(component);
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !self.safe_permissions(&metadata)? {
                return Err("unsafe WORM path".into());
            }
        }
        Ok(fs::read_to_string(path)?)
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
            if !metadata.is_dir() || !self.safe_permissions(&metadata)? {
                return Err(
                    "archive directory permissions do not match the protected WORM root".into(),
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
                if !self.safe_permissions(&f.metadata()?)? {
                    return Err("unsafe WORM file permissions".into());
                }
                f.write_all(data)?;
                f.sync_all()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if path.is_symlink() {
                    return Err("WORM artifact symlink".into());
                }
                if !self.safe_permissions(&fs::metadata(&path)?)? {
                    return Err(
                        "archive file permissions do not match the protected WORM root".into(),
                    );
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
