use super::*;

#[test]
fn client_origins_require_verified_https_without_extra_url_components() {
    for origin in [
        "http://pki.example/",
        "https://user@pki.example/",
        "https://pki.example/path",
        "https://pki.example/?query=1",
        "https://pki.example/#fragment",
    ] {
        assert!(Distribution::new(origin).is_err(), "{origin}");
    }
    assert!(Distribution::new("https://pki.example:5546/").is_ok());
    assert!(Distribution::new("https://[::1]:5546/").is_ok());
}

#[test]
fn shared_distribution_preserves_issuer_path_encoding() {
    let origin = Distribution::new("https://pki.example:5546/").unwrap();
    assert_eq!(origin.ocsp(), "https://pki.example:5546/ocsp/");
    assert_eq!(
        origin.crl("ca/name").unwrap(),
        "https://pki.example:5546/crl/ca%2Fname"
    );
    assert!(origin.crl("..").is_err());
}
