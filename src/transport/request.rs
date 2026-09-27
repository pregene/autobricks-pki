use crate::Result;
use std::collections::BTreeMap;
use std::io::Read;
pub const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
fn line(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        if out.len() >= limit {
            return Err("HTTP line exceeds limit".into());
        }
        let mut b = [0];
        reader.read_exact(&mut b)?;
        out.push(b[0]);
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            return Ok(out);
        }
    }
}
impl Request {
    pub fn read(reader: &mut impl Read) -> Result<Self> {
        let first = line(reader, MAX_HEADERS)?;
        let first = std::str::from_utf8(&first)?;
        let parts: Vec<_> = first.split(' ').collect();
        if parts.len() != 3
            || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
            || !parts[1].starts_with('/')
            || parts[1].contains('#')
        {
            return Err("invalid HTTP request line".into());
        }
        let method = parts[0].to_owned();
        let path = parts[1].to_owned();
        let mut headers = BTreeMap::new();
        let mut used = first.len() + 2;
        loop {
            let raw = line(reader, MAX_HEADERS.saturating_sub(used))?;
            used += raw.len() + 2;
            if raw.is_empty() {
                break;
            }
            let value = std::str::from_utf8(&raw)?;
            let (name, value) = value.split_once(':').ok_or("invalid header")?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            {
                return Err("invalid header name".into());
            }
            if value.bytes().any(|b| b < 32 && b != 9 || b == 127) {
                return Err("invalid header value".into());
            }
            if headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err("duplicate header".into());
            }
        }
        if parts[2] == "HTTP/1.1" && !headers.contains_key("host") {
            return Err("missing Host header".into());
        }
        let mut body = Vec::new();
        if let Some(encoding) = headers.get("transfer-encoding") {
            if headers.contains_key("content-length") || !encoding.eq_ignore_ascii_case("chunked") {
                return Err("ambiguous or unsupported transfer encoding".into());
            }
            loop {
                let raw = line(reader, 1024)?;
                let raw = std::str::from_utf8(&raw)?;
                let size =
                    usize::from_str_radix(raw.split(';').next().ok_or("invalid chunk")?, 16)?;
                if size == 0 {
                    let mut total = 0;
                    loop {
                        let trailer = line(reader, MAX_HEADERS.saturating_sub(total))?;
                        total += trailer.len() + 2;
                        if trailer.is_empty() {
                            break;
                        }
                    }
                    break;
                }
                if size > MAX_BODY.saturating_sub(body.len()) {
                    return Err("body exceeds limit".into());
                }
                let start = body.len();
                body.resize(start + size, 0);
                reader.read_exact(&mut body[start..])?;
                let mut end = [0; 2];
                reader.read_exact(&mut end)?;
                if end != *b"\r\n" {
                    return Err("invalid chunk terminator".into());
                }
            }
        } else if let Some(length) = headers.get("content-length") {
            if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid content length".into());
            }
            let length: usize = length.parse()?;
            if length > MAX_BODY {
                return Err("body exceeds limit".into());
            }
            body.resize(length, 0);
            reader.read_exact(&mut body)?;
        } else if method == "POST" {
            return Err("POST requires body framing".into());
        }
        Ok(Self {
            method,
            path,
            headers,
            body,
        })
    }
}
