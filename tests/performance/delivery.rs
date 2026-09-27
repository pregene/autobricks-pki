use super::*;
use crate::{
    certificate::profile::Distribution,
    storage::{database::Database, worm::Worm},
};
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    sync::mpsc,
};

fn fixture(directory: &std::path::Path) -> Arc<Mutex<Service>> {
    let worm = directory.join("worm");
    std::fs::create_dir(&worm).unwrap();
    let db = Database::open(&directory.join("test.sqlite"), &worm).unwrap();
    // Delivery needs the root identifier only, never its certificate or private key.
    db.conn.execute("INSERT INTO certificates(fingerprint,cn,kind,serial,not_before,not_after,certificate_path,private_key_path) VALUES('root-id','root','root','01',0,9999999999,'absent.pem','absent.key.pem')", []).unwrap();
    Arc::new(Mutex::new(Service {
        background_delivery: true,
        db,
        distribution: Distribution::new("https://localhost").unwrap(),
        worm: Worm::new(&worm).unwrap(),
        dns: Dns {
            socket: directory.join("dns.sock"),
        },
        truelog: TrueLog {
            executable: directory.join("truelog"),
        },
    }))
}

#[test]
fn dns_wait_releases_service_lock_and_acknowledges_only_success() {
    let dir = tempfile::tempdir().unwrap();
    let service = fixture(dir.path());
    let listener = UnixListener::bind(dir.path().join("dns.sock")).unwrap();
    let payload = r#"{"name":"test.internal","type":"A","ip":"192.0.2.1"}"#;
    service.lock().unwrap().db.enqueue("dns", payload).unwrap();
    let id = service.lock().unwrap().db.pending().unwrap()[0].0;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).unwrap();
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        socket.write_all(br#"{"ok":true}"#).unwrap();
    });
    let copy = service.clone();
    let worker = std::thread::spawn(move || deliver(&copy, id, "dns", payload));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let unlocked_and_pending = service
        .try_lock()
        .map(|s| s.db.is_pending(id).unwrap())
        .unwrap_or(false);
    release_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    server.join().unwrap();
    assert!(
        unlocked_and_pending,
        "DNS wait held the service lock or acknowledged early"
    );
    assert!(!service.lock().unwrap().db.is_pending(id).unwrap());
}

#[test]
fn truelog_wait_releases_lock_and_completed_event_is_not_resubmitted() {
    let dir = tempfile::tempdir().unwrap();
    let service = fixture(dir.path());
    let executable = dir.path().join("truelog");
    std::fs::write(&executable, r#"#!/usr/bin/python3
import json, pathlib, sys, time
base = pathlib.Path(sys.argv[0]).parent
(base / 'event').write_text(sys.argv[5])
(base / 'entered').touch()
deadline = time.monotonic() + 5
while not (base / 'release').exists():
    if time.monotonic() > deadline: sys.exit(1)
    time.sleep(0.01)
print(json.dumps({'service':'abpkid','hostname':'test','before':{'file':'log','filesize':0,'checksum':'a'},'after':{'file':'log','filesize':1,'checksum':'b'}}))
"#).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    service
        .lock()
        .unwrap()
        .db
        .enqueue("audit", r#"{"event":"test"}"#)
        .unwrap();
    let (id, kind, payload) = service.lock().unwrap().db.pending().unwrap().remove(0);
    let copy = service.clone();
    let worker = std::thread::spawn(move || deliver(&copy, id, &kind, &payload));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !dir.path().join("entered").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let entered = dir.path().join("entered").exists();
    let unlocked_and_pending = service
        .try_lock()
        .map(|s| s.db.is_pending(id).unwrap())
        .unwrap_or(false);
    std::fs::write(dir.path().join("release"), "").unwrap();
    worker.join().unwrap().unwrap();
    assert!(entered && unlocked_and_pending);
    let event: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("event")).unwrap()).unwrap();
    assert_eq!(event["event_id"], format!("root-id:{id}"));
    assert!(!service.lock().unwrap().db.is_pending(id).unwrap());
    std::fs::remove_file(executable).unwrap();
    deliver(&service, id, "audit", "{}").unwrap();
}

#[test]
fn failed_external_delivery_stays_pending_and_later_work_can_complete() {
    let dir = tempfile::tempdir().unwrap();
    let service = fixture(dir.path());
    for _ in 0..65 {
        service.lock().unwrap().db.enqueue("audit", "{}").unwrap();
    }
    let first = service
        .lock()
        .unwrap()
        .db
        .pending_external_after(0)
        .unwrap();
    assert_eq!(first.len(), 64);
    assert!(deliver(&service, first[0].0, "audit", "{}").is_err());
    assert!(service.lock().unwrap().db.is_pending(first[0].0).unwrap());
    let next = service
        .lock()
        .unwrap()
        .db
        .pending_external_after(first.last().unwrap().0)
        .unwrap();
    assert_eq!(next.len(), 1);
    let executable = dir.path().join("truelog");
    std::fs::write(&executable, "#!/bin/sh\nprintf '%s\\n' '{\"service\":\"abpkid\",\"hostname\":\"test\",\"before\":{\"file\":\"log\",\"filesize\":0,\"checksum\":\"a\"},\"after\":{\"file\":\"log\",\"filesize\":1,\"checksum\":\"b\"}}'\n").unwrap();
    std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    deliver(&service, next[0].0, "audit", "{}").unwrap();
    assert!(!service.lock().unwrap().db.is_pending(next[0].0).unwrap());
    assert!(service.lock().unwrap().db.is_pending(first[0].0).unwrap());
}
