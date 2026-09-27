use autobricks_pki::storage::worm::Worm;

#[test]
fn nested_artifact_retries_preserve_bytes_and_reject_escape() {
    let directory = tempfile::tempdir().unwrap();
    let worm = Worm::new(directory.path()).unwrap();
    worm.write_once("certificate/2026-09-27/abc/client.key.pem", b"partial")
        .unwrap();
    worm.write_once(
        "certificate/2026-09-27/abc/client.key.pem",
        b"partial-complete",
    )
    .unwrap();
    assert!(
        worm.write_once("certificate/2026-09-27/abc/client.key.pem", b"replacement")
            .is_err()
    );
    assert_eq!(
        std::fs::read(
            directory
                .path()
                .join("certificate/2026-09-27/abc/client.key.pem")
        )
        .unwrap(),
        b"partial-complete"
    );
    for name in ["../escape", "/absolute", "a/../b", "a//b"] {
        assert!(worm.write_once(name, b"key").is_err());
    }
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), directory.path().join("link")).unwrap();
    assert!(worm.write_once("link/key.pem", b"key").is_err());
    assert!(!outside.path().join("key.pem").exists());
}
