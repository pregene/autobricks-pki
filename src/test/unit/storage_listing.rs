use super::*;

#[test]
fn list_needs_only_metadata_and_excludes_other_certificate_kinds() {
    let directory = tempfile::tempdir().unwrap();
    let db = Database {
        ocsp_issuers: Default::default(),
        worm: crate::storage::worm::Worm::new(directory.path()).unwrap(),
        conn: rusqlite::Connection::open_in_memory().unwrap(),
    };
    db.conn
        .execute_batch(
            "CREATE TABLE certificates (
        idx INTEGER, cn TEXT, fingerprint TEXT, kind TEXT,
        valid TEXT, not_before INTEGER, not_after INTEGER);
        INSERT INTO certificates VALUES
        (1, 'root', 'r', 'root', 'VALID', 0, 86400),
        (2, 'app', 'i', 'intermediate', 'VALID', 0, 30931200),
        (3, 'web', 'l', 'server', 'REVOKED', 0, 4060800);",
        )
        .unwrap();
    let ca = db.list_certificates(true).unwrap();
    assert_eq!(ca.len(), 1);
    assert_eq!(ca[0].idx, 2);
    assert_eq!(ca[0].remain, 0);
    assert!(db.list_certificates(false).unwrap().is_empty());
    let leaves = db
        .filtered_certificate_page(false, ListFilter::All, 0, None)
        .unwrap()
        .entries;
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].valid, "REVOKED");
    assert_eq!(leaves[0].remain, 0);
    let json = serde_json::to_value(&leaves[0]).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 6);
    assert!(json.get("pem").is_none());
    assert!(json.get("key_pem").is_none());
}
