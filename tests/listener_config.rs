use autobricks_pki::server::listener_config::ListenerConfig;

#[test]
fn bind_address_is_separate_from_both_ports() {
    let c = ListenerConfig::parse("0.0.0.0", "5545", "5546").unwrap();
    assert_eq!(c.tls_address().to_string(), "0.0.0.0:5545");
    assert_eq!(c.https_address().to_string(), "0.0.0.0:5546");
    let c = ListenerConfig::parse("::1", "5545", "5546").unwrap();
    assert_eq!(c.https_address().to_string(), "[::1]:5546");
}

#[test]
fn invalid_or_overlapping_listeners_are_rejected() {
    for (bind, tls, https) in [
        ("0.0.0.0:443", "5545", "5546"),
        ("0.0.0.0", "5545", "5545"),
        ("0.0.0.0", "0", "5546"),
        ("0.0.0.0", "5545", "65536"),
    ] {
        assert!(ListenerConfig::parse(bind, tls, https).is_err());
    }
}
