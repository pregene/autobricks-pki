use crate::Result;
#[cfg(feature = "server")]
use crate::server::routes::Request;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;
pub const MAX_REQUEST: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub method: String,
    pub path: String,
    pub content_type: String,
    pub credential: Option<String>,
    #[serde(default)]
    pub body: Vec<u8>,
}

impl Message {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.method.as_str(), "GET" | "POST")
            || !self.path.starts_with("/api/")
            || self.body.len() > MAX_REQUEST
        {
            return Err("invalid management request".into());
        }
        Ok(())
    }

    #[cfg(feature = "server")]
    pub fn into_request(self) -> Result<Request> {
        self.validate()?;
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("content-type".into(), self.content_type);
        if let Some(credential) = self.credential {
            headers.insert("authorization".into(), format!("Bearer {credential}"));
        }
        Ok(Request {
            method: self.method,
            path: self.path,
            headers,
            body: self.body,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub status: String,
    pub content_type: String,
    #[serde(default)]
    pub body: Vec<u8>,
}
#[cfg(feature = "server")]
impl From<crate::server::routes::Response> for Reply {
    fn from(response: crate::server::routes::Response) -> Self {
        Self {
            status: response.status.into(),
            content_type: response.content_type.into(),
            body: response.body,
        }
    }
}

pub trait Frame: Serialize + serde::de::DeserializeOwned {
    fn header(&self) -> Result<Vec<u8>>;
    fn body(&self) -> &[u8];
    fn set_body(&mut self, body: Vec<u8>);
}
impl Frame for Message {
    fn header(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "method":self.method,
            "path":self.path,
            "content_type":self.content_type,
            "credential":self.credential
        }))?)
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
    fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
    }
}
impl Frame for Reply {
    fn header(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &serde_json::json!({"status":self.status,"content_type":self.content_type}),
        )?)
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
    fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
    }
}

pub fn read_frame<T: Frame>(stream: &mut impl Read, limit: usize) -> Result<T> {
    let mut magic = [0; 4];
    stream.read_exact(&mut magic)?;
    if &magic != b"ABP1" {
        return Err("invalid management frame".into());
    }
    let mut sizes = [0; 8];
    stream.read_exact(&mut sizes)?;
    let header_len = u32::from_be_bytes(sizes[..4].try_into()?) as usize;
    let body_len = u32::from_be_bytes(sizes[4..].try_into()?) as usize;
    let total = 12usize
        .checked_add(header_len)
        .and_then(|n| n.checked_add(body_len))
        .ok_or("frame size overflow")?;
    if header_len > 16_384 || total > limit {
        return Err("management frame exceeds its limit".into());
    }
    let mut header = vec![0; header_len];
    stream.read_exact(&mut header)?;
    let value: serde_json::Value = serde_json::from_slice(&header)?;
    if value.get("body").is_some() {
        return Err("binary header must not contain body".into());
    }
    let mut frame: T = serde_json::from_value(value)?;
    let mut body = vec![0; body_len];
    stream.read_exact(&mut body)?;
    frame.set_body(body);
    Ok(frame)
}
pub fn write_frame(stream: &mut impl Write, value: &impl Frame, limit: usize) -> Result<()> {
    let header = value.header()?;
    let body = value.body();
    let total = 12usize
        .checked_add(header.len())
        .and_then(|n| n.checked_add(body.len()))
        .ok_or("frame size overflow")?;
    if header.len() > 16_384 || total > limit {
        return Err("management frame exceeds its limit".into());
    }
    stream.write_all(b"ABP1")?;
    stream.write_all(&u32::try_from(header.len())?.to_be_bytes())?;
    stream.write_all(&u32::try_from(body.len())?.to_be_bytes())?;
    stream.write_all(&header)?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

pub fn write_structured(stream: &mut impl Write, value: &impl Frame, limit: usize) -> Result<()> {
    let metadata = value.header()?;
    let payload = value.body();
    let total = 20usize
        .checked_add(metadata.len())
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or("structured frame size overflow")?;
    if metadata.is_empty() || metadata.len() > 16_384 || total > limit {
        return Err("structured frame exceeds its limit".into());
    }
    stream.write_all(b"ABT1")?;
    stream.write_all(&1_u16.to_be_bytes())?;
    stream.write_all(&0_u16.to_be_bytes())?;
    stream.write_all(&u32::try_from(metadata.len())?.to_be_bytes())?;
    stream.write_all(&u64::try_from(payload.len())?.to_be_bytes())?;
    stream.write_all(&metadata)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub fn read_structured<T: Frame>(stream: &mut impl Read, limit: usize) -> Result<T> {
    let mut prefix = [0_u8; 20];
    stream.read_exact(&mut prefix)?;
    if &prefix[..4] != b"ABT1"
        || u16::from_be_bytes(prefix[4..6].try_into()?) != 1
        || prefix[6..8] != [0, 0]
    {
        return Err("invalid structured frame".into());
    }
    let metadata_len = u32::from_be_bytes(prefix[8..12].try_into()?) as usize;
    let payload_len = usize::try_from(u64::from_be_bytes(prefix[12..20].try_into()?))?;
    let total = 20usize
        .checked_add(metadata_len)
        .and_then(|n| n.checked_add(payload_len))
        .ok_or("structured frame size overflow")?;
    if metadata_len == 0 || metadata_len > 16_384 || total > limit {
        return Err("structured frame exceeds its limit".into());
    }
    let mut metadata = vec![0; metadata_len];
    stream.read_exact(&mut metadata)?;
    let mut value: T = serde_json::from_slice(&metadata)?;
    let mut payload = vec![0; payload_len];
    stream.read_exact(&mut payload)?;
    value.set_body(payload);
    Ok(value)
}
