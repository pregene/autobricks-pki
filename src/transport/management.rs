use crate::{
    Result,
    server::routes::Response,
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
    pub body: Vec<u8>,
}
impl From<Response> for Reply {
    fn from(response: Response) -> Self {
        Self {
            status: response.status.into(),
            content_type: response.content_type.into(),
            body: response.body,
        }
    }
}

pub fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    limit: usize,
) -> Result<T> {
    let read_limit = u64::try_from(limit)?
        .checked_add(1)
        .ok_or("management frame limit is too large")?;
    let mut bytes = Vec::new();
    BufReader::new(stream.take(read_limit)).read_until(b'\n', &mut bytes)?;
    if bytes.len() > limit || !bytes.ends_with(b"\n") {
        return Err("management frame is incomplete or exceeds its limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn write_frame(stream: &mut impl Write, value: &impl Serialize, limit: usize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    if bytes.len() > limit {
        return Err("management frame exceeds its limit".into());
    }
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}
