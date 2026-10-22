use autobricks_pki::client::listing::render;

#[test]
fn list_formats_only_requested_columns_with_full_fingerprint_and_utc_time() {
    let fingerprint = "a".repeat(64);
    let response = serde_json::to_vec(&serde_json::json!([{
        "idx": 7, "cn": "web01", "fingerprint": fingerprint,
        "valid": "SUPERSEDED", "issue_at": 0, "remain": 47
    }]))
    .unwrap();
    let output = render(&response).unwrap();
    assert!(output.contains("Common Name"));
    assert!(output.contains("IssuedAt"));
    assert!(output.contains("remain"));
    assert!(output.contains(&fingerprint));
    assert!(output.contains("SUPERSEDED"));
    assert!(output.contains("1970-01-01 00:00:00"));
    assert_eq!(output.lines().count(), 2);
    assert!(output.lines().nth(1).unwrap().ends_with(&fingerprint));
    assert!(!output.contains("pem"));
}

#[test]
fn empty_lists_keep_headers_and_legacy_payloads_are_not_dumped() {
    assert_eq!(render(b"[]").unwrap().lines().count(), 1);
    assert!(render(br#"[{"pem":"certificate body"}]"#).is_err());
}
