use crate::Result;
use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

pub struct TrueLog {
    pub executable: PathBuf,
}
impl TrueLog {
    pub fn submit(&self, event: &serde_json::Value) -> Result<()> {
        let mut child = Command::new(&self.executable)
            .args(["write", "--service", "abpkid", "--data"])
            .arg(serde_json::to_string(event)?)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("missing TrueLog output")?;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(1_048_577)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(result);
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let result = (|| -> Result<()> {
            let bytes = receiver.recv_timeout(Duration::from_secs(30))??;
            if bytes.len() > 1_048_576 {
                return Err("TrueLog receipt exceeds limit".into());
            }
            loop {
                if let Some(status) = child.try_wait()? {
                    if !status.success() {
                        return Err("TrueLog submission failed".into());
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("TrueLog submission timed out".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let receipt: serde_json::Value = serde_json::from_slice(&bytes)?;
            if receipt["service"] != "abpkid" || receipt["hostname"].as_str().is_none() {
                return Err("invalid TrueLog receipt identity".into());
            }
            for checkpoint in ["before", "after"] {
                let value = &receipt[checkpoint];
                if value["file"].as_str().is_none()
                    || value["filesize"].as_u64().is_none()
                    || value["checksum"].as_str().is_none()
                {
                    return Err("invalid TrueLog receipt checkpoint".into());
                }
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
