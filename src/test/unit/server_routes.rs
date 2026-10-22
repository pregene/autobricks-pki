use super::{Request, tls_enrollment_route};
use std::collections::BTreeMap;

fn request(method: &str, path: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        headers: BTreeMap::new(),
        body: Vec::new(),
    }
}

#[test]
fn tls_is_limited_to_root_and_credential_enrollment() {
    assert!(tls_enrollment_route(&request("GET", "/root")));
    assert!(tls_enrollment_route(&request("POST", "/api/create")));
    assert!(tls_enrollment_route(&request(
        "GET",
        "/api/download/fingerprint"
    )));
    for (method, path) in [
        ("GET", "/api/list"),
        ("GET", "/api/list-ca"),
        ("POST", "/api/revoke"),
        ("POST", "/api/renew"),
        ("GET", "/api/check/fingerprint"),
    ] {
        assert!(!tls_enrollment_route(&request(method, path)), "{path}");
    }
}
