pub mod credentials;
pub mod daemon;
use crate::{Result, transport::tls};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};
pub fn request(
    origin: &str,
    trust: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    token: Option<&str>,
) -> Result<Vec<u8>> {
    crate::certificate::profile::Distribution::new(origin)?;
    if path.bytes().any(|b| b < 32 || b == 127)
        || token.is_some_and(|v| v.bytes().any(|b| b < 32 || b == 127))
    {
        return Err("invalid request header value".into());
    }
    let url = url::Url::parse(origin)?;
    let port = url.port_or_known_default().ok_or("missing port")?;
    let mut stream = connect(&url, trust, port)?;
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    if let Some(token) = token {
        write!(stream, "Authorization: Bearer {token}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut response = Vec::new();
    loop {
        if response.len() > 16_384 {
            return Err("response headers exceed limit".into());
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let headers = std::str::from_utf8(&response)?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or("missing HTTP status")?;
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(format!("server returned {status}").into());
    }
    let mut length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            if length.is_some() {
                return Err("duplicate response content length".into());
            }
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = length.ok_or("missing response content length")?;
    if length > 16 * 1024 * 1024 {
        return Err("response exceeds limit".into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}
pub fn segment(value: &str) -> Result<String> {
    let mut u = url::Url::parse("https://localhost/")?;
    u.path_segments_mut()
        .map_err(|_| "cannot encode URL path segment")?
        .pop_if_empty()
        .push(value);
    Ok(u.path().trim_start_matches('/').to_owned())
}

fn connect(
    url: &url::Url,
    trust: &[u8],
    port: u16,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let host = match url.host().ok_or("missing hostname")? {
        url::Host::Domain(name) => name.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let mut socket = None;
    for address in (host.as_str(), port).to_socket_addrs()? {
        if let Ok(s) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            socket = Some(s);
            break;
        }
    }
    let socket = socket.ok_or("cannot connect to PKI server")?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
    let stream = rustls::StreamOwned::new(
        rustls::ClientConnection::new(tls::client(trust)?, name)?,
        socket,
    );
    Ok(stream)
}

pub fn management_request(
    origin: &str,
    trust: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    token: Option<&str>,
) -> Result<Vec<u8>> {
    use crate::transport::management::{self, Message, Reply};
    let url = url::Url::parse(origin)?;
    if !matches!(url.scheme(), "tls" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("management address must be a TLS origin".into());
    }
    let mut stream = connect(&url, trust, url.port().unwrap_or(5545))?;
    let message = Message {
        method: method.into(),
        path: path.into(),
        content_type: "application/json".into(),
        credential: token.map(str::to_owned),
        body: body.to_vec(),
    };
    management::write_frame(&mut stream, &message, crate::transport::request::MAX_BODY)?;
    let response: Reply = management::read_frame(&mut stream, management::MAX_RESPONSE)?;
    if response.status != "200 OK" {
        return Err(format!("server returned {}", response.status).into());
    }
    Ok(response.body)
}

pub fn public_origin(management_origin: &str, port: u16) -> Result<String> {
    if port == 0 {
        return Err("HTTPS port must be nonzero".into());
    }
    let mut url = url::Url::parse(management_origin)?;
    // Reparse through HTTPS because url disallows switching non-special schemes in place.
    if url.scheme() == "tls" {
        url = url::Url::parse(&management_origin.replacen("tls://", "https://", 1))?;
    }
    url.set_port(Some(port)).map_err(|_| "invalid HTTPS port")?;
    crate::certificate::profile::Distribution::new(url.as_str())?;
    Ok(url.into())
}
