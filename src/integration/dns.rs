use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ip: std::net::IpAddr,
}
pub struct Dns {
    pub socket: PathBuf,
}
impl Dns {
    pub fn register(&self, record: &Record) -> Result<()> {
        let mut socket = UnixStream::connect(&self.socket)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let request = serde_json::json!({"command":"ADD","record":record});
        socket.write_all(&serde_json::to_vec(&request)?)?;
        socket.write_all(b"\n")?;
        socket.shutdown(Shutdown::Write)?;
        let mut bytes = Vec::new();
        socket.take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            return Err("DNS response exceeds limit".into());
        }
        let response: serde_json::Value = serde_json::from_slice(&bytes)?;
        if response.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!(
                "DNS registration failed: {}",
                response
                    .get("result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("invalid response")
            )
            .into());
        }
        Ok(())
    }
}
pub fn records(profile: &crate::certificate::profile::LeafProfile) -> Result<Vec<Record>> {
    if !profile.kind.is_server() {
        return Ok(vec![]);
    }
    if profile.dns_names.is_empty() || profile.ip_addresses.is_empty() {
        return Err("server issuance requires DNS names and IP addresses for registration".into());
    }
    if profile.ip_addresses.iter().filter(|a| a.is_ipv4()).count() > 1
        || profile.ip_addresses.iter().filter(|a| a.is_ipv6()).count() > 1
    {
        return Err("autobricks-dns supports one address per name and record type".into());
    }
    let mut out = Vec::new();
    for name in &profile.dns_names {
        if name.len() > 253
            || name.split('.').any(|s| {
                s.is_empty()
                    || s.len() > 63
                    || s.starts_with('-')
                    || s.ends_with('-')
                    || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err("DNS registration requires an exact valid hostname".into());
        }
        for ip in &profile.ip_addresses {
            out.push(Record {
                name: name.to_ascii_lowercase(),
                record_type: if ip.is_ipv4() { "A" } else { "AAAA" }.into(),
                ip: *ip,
            });
        }
    }
    Ok(out)
}
