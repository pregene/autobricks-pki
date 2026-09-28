use crate::Result;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{BufRead, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
};
fn path(fingerprint: &str) -> Result<PathBuf> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid certificate fingerprint".into());
    }
    let home = PathBuf::from(env::var("HOME")?);
    let directory = home.join(".abpki");
    if !directory.exists() {
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("credential directory must be private (0700)".into());
    }
    Ok(directory.join(fingerprint))
}
pub fn load(fingerprint: &str) -> Result<String> {
    let path = path(fingerprint)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("certificate credential must be a private file".into());
    }
    Ok(fs::read_to_string(path)?)
}
pub fn save_response(response: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(response)?;
    let fingerprint = value["certificate"]["fingerprint"]
        .as_str()
        .or_else(|| value["fingerprint"].as_str())
        .ok_or("missing issued fingerprint")?;
    let token = value["download_token"]
        .as_str()
        .ok_or("missing download token")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path(fingerprint)?)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
pub fn prompt() -> Result<String> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let saved = Command::new("stty")
        .arg("-g")
        .stdin(Stdio::from(tty.try_clone()?))
        .output()?;
    if !saved.status.success() {
        return Err("cannot read terminal settings".into());
    }
    let settings = String::from_utf8(saved.stdout)?.trim().to_owned();
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Ok(tty) = OpenOptions::new().read(true).open("/dev/tty") {
                let _ = Command::new("stty")
                    .arg(&self.0)
                    .stdin(Stdio::from(tty))
                    .status();
            }
        }
    }
    let restore = Restore(settings);
    if !Command::new("stty")
        .arg("-echo")
        .stdin(Stdio::from(tty.try_clone()?))
        .status()?
        .success()
    {
        return Err("cannot disable terminal echo".into());
    }
    write!(tty, "ADMIN password: ")?;
    tty.flush()?;
    let mut value = String::new();
    std::io::BufReader::new(tty.try_clone()?).read_line(&mut value)?;
    writeln!(tty)?;
    drop(restore);
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}
