use crate::{
    Result,
    transport::request::{MAX_BODY, Request},
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};

pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;

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
    pub fn into_request(self) -> Result<Request> {
        if !matches!(self.method.as_str(), "GET" | "POST")
            || !self.path.starts_with("/api/")
            || self.body.len() > MAX_BODY
        {
            return Err("invalid management request".into());
        }
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

#[derive(Clone, Copy)]
pub enum Format {
    Binary,
    Legacy,
}

pub trait Frame: Serialize + serde::de::DeserializeOwned {
    fn header(&self) -> Result<Vec<u8>>;
    fn body(&self) -> &[u8];
    fn set_body(&mut self, body: Vec<u8>);
}
impl Frame for Message {
    fn header(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &serde_json::json!({"method":self.method,"path":self.path,"content_type":self.content_type,"credential":self.credential}),
        )?)
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
    Ok(read_frame_with_format(stream, limit)?.0)
}
pub fn read_frame_with_format<T: Frame>(
    stream: &mut impl Read,
    limit: usize,
) -> Result<(T, Format)> {
    let read_limit = u64::try_from(limit)?
        .checked_add(1)
        .ok_or("management frame limit is too large")?;
    let mut magic = [0; 4];
    stream.read_exact(&mut magic)?;
    if &magic != b"ABP1" {
        let mut bytes = magic.to_vec();
        let remaining = read_limit.checked_sub(4).ok_or("frame limit too small")?;
        BufReader::new(stream.take(remaining)).read_until(b'\n', &mut bytes)?;
        if bytes.len() > limit || !bytes.ends_with(b"\n") {
            return Err("management frame is incomplete or exceeds its limit".into());
        }
        return Ok((serde_json::from_slice(&bytes)?, Format::Legacy));
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
    Ok((frame, Format::Binary))
}
pub fn write_frame(stream: &mut impl Write, value: &impl Frame, limit: usize) -> Result<()> {
    write_frame_with_format(stream, value, limit, Format::Binary)
}
pub fn write_frame_with_format(
    stream: &mut impl Write,
    value: &impl Frame,
    limit: usize,
    format: Format,
) -> Result<()> {
    if matches!(format, Format::Legacy) {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        if bytes.len() > limit {
            return Err("management frame exceeds its limit".into());
        }
        stream.write_all(&bytes)?;
    } else {
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
    }
    stream.flush()?;
    Ok(())
}
