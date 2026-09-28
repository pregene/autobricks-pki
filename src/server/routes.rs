use crate::{
    Result,
    revocation::{self, Status},
    server::service::{Create, Service, now},
    transport::request::Request,
};
use serde_json::{Value, json};
pub struct Response {
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}
fn json_response(v: impl serde::Serialize) -> Result<Response> {
    Ok(Response {
        status: "200 OK",
        content_type: "application/json",
        body: serde_json::to_vec(&v)?,
    })
}
fn file(body: Vec<u8>, content_type: &'static str) -> Response {
    Response {
        status: "200 OK",
        content_type,
        body,
    }
}
fn bearer(r: &Request) -> &str {
    r.headers
        .get("authorization")
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
}
pub fn dispatch_public(service: &Service, request: Request) -> Response {
    if request.path == "/"
        || request.path == "/root"
        || request.path == "/ocsp/"
        || request.path.starts_with("/crl/")
    {
        dispatch(service, request)
    } else {
        Response {
            status: "404 Not Found",
            content_type: "text/plain",
            body: b"Not Found\n".to_vec(),
        }
    }
}

pub fn dispatch(service: &Service, r: Request) -> Response {
    match route(service,&r){Ok(v)=>v,Err(_)=>Response{status:"400 Bad Request",content_type:"application/json",body:br#"{"error":"Request rejected; check parameters, permissions, validity, and service availability."}"#.to_vec()}}
}
fn route(s: &Service, r: &Request) -> Result<Response> {
    if r.method == "POST" && r.path == "/api/create-ca" {
        return Ok(Response {
            status: "501 Not Implemented",
            content_type: "application/json",
            body: br#"{"error":"Not implemented: additional Intermediate CA creation is unavailable in version 1.0"}"#.to_vec(),
        });
    }
    if r.path == "/ocsp/" {
        if r.method != "POST" {
            return Ok(Response {
                status: "405 Method Not Allowed",
                content_type: "text/plain",
                body: vec![],
            });
        }
        if !r
            .headers
            .get("content-type")
            .is_some_and(|v| v.eq_ignore_ascii_case(revocation::ocsp::REQUEST_TYPE))
        {
            return Ok(Response {
                status: "415 Unsupported Media Type",
                content_type: "text/plain",
                body: vec![],
            });
        }
        return Ok(file(
            revocation::ocsp::respond_database(&r.body, &s.db, now())?,
            revocation::ocsp::RESPONSE_TYPE,
        ));
    }
    if r.method == "GET" {
        if r.path == "/" {
            return json_response(json!({"product":crate::PRODUCT,"version":crate::VERSION}));
        }
        if let Some(id) = r.path.strip_prefix("/crl/") {
            let id = decode_segment(id)?;
            return Ok(file(s.crl(&id)?, "application/x-pem-file"));
        }
        if r.path == "/root" || r.path == "/api/root" {
            return Ok(file(
                s.public_root()?.pem.into_bytes(),
                "application/x-pem-file",
            ));
        }
        if let Some((path, query)) = r.path.split_once('?')
            && matches!(path, "/api/list" | "/api/list-ca")
        {
            let mut after = None;
            let mut through = None;
            let mut filter = None;
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                match key.as_ref() {
                    "after" if after.is_none() => after = Some(value.parse::<i64>()?),
                    "through" if through.is_none() => through = Some(value.parse::<i64>()?),
                    "status" if filter.is_none() => {
                        filter = Some(crate::storage::listing::ListFilter::parse(&value)?);
                    }
                    _ => return Err("invalid list query".into()),
                }
            }
            return json_response(s.db.filtered_certificate_page(
                path == "/api/list-ca",
                filter.unwrap_or(crate::storage::listing::ListFilter::Valid),
                after.ok_or("missing list cursor")?,
                through,
            )?);
        }
        if r.path == "/api/list-ca" {
            return json_response(s.db.list_certificates(true)?);
        }
        if r.path == "/api/list" {
            return json_response(s.db.list_certificates(false)?);
        }
        if let Some(id) = r.path.strip_prefix("/api/chain/") {
            return Ok(file(
                s.chain(&decode_segment(id)?)?,
                "application/x-pem-file",
            ));
        }
        if let Some(id) = r.path.strip_prefix("/api/info/") {
            return Ok(match s.certificate_info(&decode_segment(id)?)? {
                Some(text) => file(text, "text/plain; charset=utf-8"),
                None => Response {
                    status: "404 Not Found",
                    content_type: "text/plain",
                    body: b"Certificate not found\n".to_vec(),
                },
            });
        }
        if let Some(id) = r.path.strip_prefix("/api/check/") {
            let status = match s.db.revocation_status(id)? {
                Some(Some(_)) => Status::Revoked,
                Some(_) => Status::Good,
                None => Status::Unknown,
            };
            return json_response(json!({"status":status}));
        }
        if let Some(id) = r.path.strip_prefix("/api/download/") {
            return Ok(file(s.download(id, bearer(r))?, "application/gzip"));
        }
    }
    if r.method == "POST" && r.path.starts_with("/api/") {
        if !r
            .headers
            .get("content-type")
            .is_some_and(|v| v == "application/json")
        {
            return Err("JSON content type required".into());
        }
        if r.path == "/api/create" {
            return json_response(s.create(serde_json::from_slice::<Create>(&r.body)?)?);
        }
        if matches!(
            r.path.as_str(),
            "/api/renew" | "/api/renew-ca" | "/api/renew-admin"
        ) {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct RenewalRequest {
                fingerprint: String,
            }
            let request: RenewalRequest = serde_json::from_slice(&r.body)?;
            let outcome = match r.path.as_str() {
                "/api/renew-admin" => {
                    s.request_admin_renewal(&request.fingerprint, bearer(r).as_bytes())?
                }
                "/api/renew-ca" => {
                    s.renew_intermediate(&request.fingerprint, bearer(r).as_bytes())?
                }
                _ => s.poll_renewal(&request.fingerprint, bearer(r))?,
            };
            let conflict = outcome.result == 409;
            let mut response = json_response(outcome)?;
            if conflict {
                response.status = "409 Conflict";
            }
            return Ok(response);
        }
        let body: Value = serde_json::from_slice(&r.body)?;
        let text = |key: &str| {
            body.get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| crate::Error::from("missing request field"))
        };
        if r.path == "/api/revoke" {
            s.revoke(text("fingerprint")?, bearer(r).as_bytes())?;
            return json_response(json!({"status":"REVOKED"}));
        }
    }
    Ok(Response {
        status: "404 Not Found",
        content_type: "text/plain",
        body: b"Not Found\n".to_vec(),
    })
}
fn decode_segment(raw: &str) -> Result<String> {
    if raw.contains('/') || raw.contains('?') {
        return Err("invalid path segment".into());
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw.get(i + 1..i + 3).ok_or("invalid URL escape")?;
            out.push(u8::from_str_radix(hex, 16)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
