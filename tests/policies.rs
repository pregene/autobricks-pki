use autobricks_pki::{
    certificate::{
        access::Access,
        profile::Distribution,
        purpose,
        validity::{DAY, Validity},
    },
    revocation::crl,
};
#[test]
fn validity_boundaries() {
    let parent = Validity::new(0, 398, None).unwrap();
    assert!(Validity::new(0, 399, Some(parent)).is_err());
    assert!(Validity::new(-1, 47, Some(parent)).is_err());
    assert!(Validity::new(0, 0, None).is_err());
    assert!(Validity::new(i64::MAX, 1, None).is_err());
    let leaf = Validity::new(0, 47, Some(parent)).unwrap();
    assert!(leaf.renewable(40 * DAY));
    assert!(!leaf.renewable(40 * DAY - 1));
    assert!(!leaf.renewable(47 * DAY));
    assert_eq!(crl::next_update(0).unwrap(), 7 * DAY);
    assert!(crl::refresh_required(1, 7 * DAY, true));
}
#[test]
fn purposes_and_cidr() {
    assert!(purpose::validate(&[], true).is_err());
    assert!(purpose::validate(&["urn:autobricks:purpose:kms".into()], true).is_ok());
    assert!(purpose::validate(&["urn:autobricks:purpose:other".into()], true).is_err());
    for uri in [
        "urn:autobricks:allowed-source-cidr:192.0.2.0/24",
        "urn:autobricks:database-server:rw:192.0.2.1/32",
        "urn:autobricks:web-server:r:2001:db8::1/128",
    ] {
        assert!(Access::parse(uri).is_ok(), "{uri}");
    }
    for uri in [
        "urn:autobricks:source-cidr:192.0.2.0/24",
        "urn:autobricks:database-server:rw:192.0.2.1/24",
        "urn:autobricks:web-server:192.0.2.0/24",
        "urn:autobricks:allowed-source-cidr:2001:db8::/32",
    ] {
        assert!(Access::parse(uri).is_err(), "{uri}");
    }
}
#[test]
fn urls() {
    let d = Distribution::new("https://pki.example.internal").unwrap();
    assert_eq!(d.ocsp(), "https://pki.example.internal/ocsp/");
    assert_eq!(
        d.crl("CA / A").unwrap(),
        "https://pki.example.internal/crl/CA%20%2F%20A"
    );
    assert!(Distribution::new("http://pki.example.internal").is_err());
    assert!(Distribution::new("https://user:pass@pki.example.internal").is_err());
}
