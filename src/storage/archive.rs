use crate::{Result, storage::database::Certificate};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Archive {
    pub fingerprint: String,
    pub created_at: i64,
}

pub fn paths(certificate: &Certificate, created_at: i64) -> Result<(String, Option<String>)> {
    if certificate.fingerprint.len() != 64
        || !certificate
            .fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid certificate fingerprint".into());
    }
    let cn = filename(&certificate.cn)?;
    if certificate.kind == "root" {
        return Ok((format!("root/{cn}.pem"), Some(format!("root/{cn}.key.pem"))));
    }
    let date = chrono::DateTime::from_timestamp(created_at, 0)
        .ok_or("invalid archive creation date")?
        .format("%Y-%m-%d");
    let category = if certificate.kind == "intermediate" {
        "intermediate"
    } else {
        "certificate"
    };
    let base = format!("{category}/{date}/{}/{cn}", certificate.fingerprint);
    let key = Some(format!("{base}.key.pem"));
    Ok((format!("{base}.pem"), key))
}

fn filename(cn: &str) -> Result<String> {
    if cn.is_empty() {
        return Err("empty certificate CN".into());
    }
    let mut output = String::new();
    for byte in cn.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            output.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(output, "%{byte:02X}")?;
        }
    }
    if output.len() > 240 {
        return Err("encoded certificate CN exceeds filename limit".into());
    }
    Ok(output)
}
