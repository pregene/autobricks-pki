use autobricks_pki::authority::domain::validate;

#[test]
fn domain_validation_rejects_invalid_ca_names() {
    assert_eq!(
        validate("Autobricks.Internal").unwrap(),
        "autobricks.internal"
    );
    for domain in [
        "",
        "192.0.2.10",
        "a..internal",
        "-a.internal",
        "a-.internal",
        "*.internal",
        "a/internal",
        "https://a.internal",
    ] {
        assert!(validate(domain).is_err(), "{domain}");
    }
    let limit = format!("{}.internal", "a".repeat(15));
    assert_eq!(limit.len(), 24);
    assert_eq!(validate(&limit).unwrap(), limit);
    let too_long = format!("{}.internal", "a".repeat(16));
    assert_eq!(too_long.len(), 25);
    assert!(validate(&too_long).is_err());
}
