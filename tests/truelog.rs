mod common;
use autobricks_pki::integration::truelog::TrueLog;

#[test]
fn cli_failure_and_invalid_receipts_do_not_acknowledge_audit() {
    let directory = tempfile::tempdir().unwrap();
    let executable = common::truelog(directory.path());
    let log = TrueLog {
        executable: executable.clone(),
    };
    let event = serde_json::json!({"event_id":"id-1","event":"certificate-created"});
    log.submit(&event).unwrap();
    for script in ["#!/bin/sh\nexit 1\n", "#!/bin/sh\nprintf '{}\\n'\n"] {
        std::fs::write(&executable, script).unwrap();
        assert!(log.submit(&event).is_err());
    }
}
