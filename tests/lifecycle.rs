mod common;
use autobricks_pki::{
    certificate::{
        profile::{Distribution, LeafKind, LeafProfile},
        validity::Validity,
    },
    integration::dns::Dns,
    revocation::ocsp,
    server::service::{Create, Service, now},
    storage::{database::Database, worm::Worm},
};
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus},
    stack::Stack,
    x509::{X509, X509Crl, store::X509StoreBuilder},
};
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
const ADMIN: &[u8] = b"test-administrator-password";
struct Fixture {
    service: Service,
    _temp: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let worm = temp.path().join("worm");
        std::fs::create_dir(&worm).unwrap();
        let socket = temp.path().join("dns.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut b = vec![];
                    s.read_to_end(&mut b).unwrap();
                    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
                    assert_eq!(v["command"], "ADD");
                    s.write_all(b"{\"ok\":true,\"result\":\"ADDED\"}\n")
                        .unwrap();
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        let service = Service {
            db: Database::open(&temp.path().join("pki.sqlite"), &worm).unwrap(),
            worm: Worm::new(&worm).unwrap(),
            dns: Dns { socket },
            truelog: autobricks_pki::integration::truelog::TrueLog {
                executable: common::truelog(temp.path()),
            },
            distribution: Distribution::new("https://localhost").unwrap(),
        };
        service
            .initialize(
                ADMIN,
                "localhost",
                "127.0.0.1".parse().unwrap(),
                "autobricks.internal",
            )
            .unwrap();
        Self {
            service,
            _temp: temp,
            stop,
            thread: Some(thread),
        }
    }
    fn issue(&self, days: u32) -> autobricks_pki::server::service::Issued {
        self.service
            .create(Create {
                issuer: "www.autobricks.internal".into(),
                profile: LeafProfile {
                    kind: LeafKind::Server,
                    common_name: format!("web{}", self.service.db.all().unwrap().len()),
                    dns_names: vec![],
                    ip_addresses: vec!["192.0.2.20".parse().unwrap()],
                    uri_sans: vec!["urn:autobricks:purpose:www".into()],
                    validity: Validity::new(now(), days, None).unwrap(),
                },
            })
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}
fn request(leaf: &X509, issuer: &X509) -> Vec<u8> {
    let mut r = OcspRequest::new().unwrap();
    r.add_id(OcspCertId::from_cert(MessageDigest::sha1(), leaf, issuer).unwrap())
        .unwrap();
    r.to_der().unwrap()
}
#[test]
fn complete_lifecycle_and_signed_status() {
    let f = Fixture::new();
    let s = &f.service;
    assert_eq!(
        s.db.all()
            .unwrap()
            .iter()
            .filter(|c| c.kind == "intermediate")
            .count(),
        6
    );
    let issued = f.issue(47);
    assert!(!issued.integrations_pending);
    let c = &issued.certificate;
    let leaf = X509::from_pem(c.pem.as_bytes()).unwrap();
    let ca = s.db.get(c.issuer.as_deref().unwrap()).unwrap();
    let issuer = X509::from_pem(ca.pem.as_bytes()).unwrap();
    assert!(leaf.verify(&issuer.public_key().unwrap()).unwrap());
    let text = String::from_utf8(leaf.to_text().unwrap()).unwrap();
    assert!(text.contains("https://localhost/ocsp/"));
    assert!(text.contains(&format!("https://localhost/crl/{}", ca.fingerprint)));
    assert!(s.download(&c.fingerprint, "wrong").is_err());
    let archive = s.download(&c.fingerprint, &issued.download_token).unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(archive.as_slice()));
    let paths: Vec<_> = archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        paths,
        vec!["certificate.pem", "private-key.pem", "trust-chain"]
    );
    let req = request(&leaf, &issuer);
    let der = ocsp::respond(&req, &s.db.all().unwrap(), now()).unwrap();
    let response = OcspResponse::from_der(&der).unwrap();
    assert_eq!(response.status(), OcspResponseStatus::SUCCESSFUL);
    let basic = response.basic().unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store
        .add_cert(X509::from_pem(s.root().unwrap().pem.as_bytes()).unwrap())
        .unwrap();
    basic
        .verify(&Stack::new().unwrap(), &store.build(), OcspFlag::empty())
        .unwrap();
    let id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &issuer).unwrap();
    assert_eq!(basic.find_status(&id).unwrap().status, OcspCertStatus::GOOD);
    assert!(s.revoke(&c.fingerprint, b"wrong-password").is_err());
    s.revoke(&c.fingerprint, ADMIN).unwrap();
    let crl = X509Crl::from_pem(&s.crl(&ca.fingerprint).unwrap()).unwrap();
    assert!(crl.verify(&issuer.public_key().unwrap()).unwrap());
    assert_eq!(crl.get_revoked().unwrap().len(), 1);
    let response =
        OcspResponse::from_der(&ocsp::respond(&req, &s.db.all().unwrap(), now()).unwrap()).unwrap();
    assert_eq!(
        response.basic().unwrap().find_status(&id).unwrap().status,
        OcspCertStatus::REVOKED
    );
    assert!(
        s.renew(&c.fingerprint, &issued.download_token, None)
            .is_err()
    );
}
#[test]
fn renewal_and_authorization() {
    let f = Fixture::new();
    let issued = f.issue(6);
    let renewed = f
        .service
        .renew(
            &issued.certificate.fingerprint,
            &issued.download_token,
            None,
        )
        .unwrap();
    assert_ne!(
        issued.certificate.fingerprint,
        renewed.certificate.fingerprint
    );
    assert!(f.service.create_ca("extra", None, b"wrong").is_err());
    assert!(f.service.create_ca("extra", None, ADMIN).is_ok());
    assert!(f.service.create_ca("extra", None, ADMIN).is_err());
    assert!(
        f.service
            .initialize(
                ADMIN,
                "localhost",
                "127.0.0.1".parse().unwrap(),
                "autobricks.internal"
            )
            .is_err()
    );
}
#[test]
fn malformed_ocsp_is_protocol_error() {
    let der = ocsp::respond(b"bad", &[], now()).unwrap();
    assert_eq!(
        OcspResponse::from_der(&der).unwrap().status(),
        OcspResponseStatus::MALFORMED_REQUEST
    );
}
#[test]
fn database_rejects_worm_and_broad_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let worm = tmp.path().join("worm");
    std::fs::create_dir(&worm).unwrap();
    assert!(Database::open(&worm.join("db"), &worm).is_err());
    let db = tmp.path().join("db");
    std::fs::write(&db, b"").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Database::open(&db, &worm).is_err());
}
#[test]
fn tls_client_without_certificate_and_hostname_validation() {
    let f = Fixture::new();
    let c = f
        .service
        .db
        .all()
        .unwrap()
        .into_iter()
        .find(|c| c.kind == "server")
        .unwrap();
    let mut chain = c.pem.as_bytes().to_vec();
    chain.extend(f.service.chain(c.issuer.as_deref().unwrap()).unwrap());
    let config = autobricks_pki::transport::tls::server(&chain, c.key_pem.as_bytes()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut stream =
            autobricks_pki::transport::tls::DeadlineStream::new(socket, config).unwrap();
        let request = autobricks_pki::transport::request::Request::read(&mut stream).unwrap();
        assert_eq!(request.path, "/");
        autobricks_pki::transport::response::write_response(
            &mut stream,
            "200 OK",
            "text/plain",
            b"ok",
        )
        .unwrap();
    });
    let body = autobricks_pki::client::request(
        &format!("https://localhost:{}", addr.port()),
        f.service.root().unwrap().pem.as_bytes(),
        "GET",
        "/",
        &[],
        None,
    )
    .unwrap();
    assert_eq!(body, b"ok");
    server.join().unwrap();
}

#[test]
fn ca_renewal_preserves_status_and_dns_retries() {
    let f = Fixture::new();
    let s = &f.service;
    let old = s.create_ca("short-lived", Some(6), ADMIN).unwrap();
    let issued = s
        .create(Create {
            issuer: old.fingerprint.clone(),
            profile: LeafProfile {
                kind: LeafKind::Client,
                common_name: "client".into(),
                dns_names: vec![],
                ip_addresses: vec![],
                uri_sans: vec![],
                validity: Validity::new(now(), 5, None).unwrap(),
            },
        })
        .unwrap();
    s.maintain().unwrap();
    let new = s.db.issuer("short-lived").unwrap();
    assert_ne!(old.fingerprint, new.fingerprint);
    let old_x = X509::from_pem(old.pem.as_bytes()).unwrap();
    let new_x = X509::from_pem(new.pem.as_bytes()).unwrap();
    assert!(
        old_x
            .public_key()
            .unwrap()
            .public_eq(&new_x.public_key().unwrap())
    );
    s.revoke(&issued.certificate.fingerprint, ADMIN).unwrap();
    for id in [
        &old.fingerprint,
        &new.fingerprint,
        &"short-lived".to_owned(),
    ] {
        let crl = X509Crl::from_pem(&s.crl(id).unwrap()).unwrap();
        assert_eq!(crl.get_revoked().unwrap().len(), 1);
    }
    let leaf = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let req = request(&leaf, &old_x);
    let response =
        OcspResponse::from_der(&ocsp::respond(&req, &s.db.all().unwrap(), now()).unwrap()).unwrap();
    let id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &old_x).unwrap();
    assert_eq!(
        response.basic().unwrap().find_status(&id).unwrap().status,
        OcspCertStatus::REVOKED
    );
}

#[test]
fn ocsp_unknown_and_sha256_certid() {
    let f = Fixture::new();
    let issued = f.issue(47);
    let ca = f
        .service
        .db
        .get(issued.certificate.issuer.as_deref().unwrap())
        .unwrap();
    let leaf = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let issuer = X509::from_pem(ca.pem.as_bytes()).unwrap();
    let mut req = OcspRequest::new().unwrap();
    req.add_id(OcspCertId::from_cert(MessageDigest::sha256(), &leaf, &issuer).unwrap())
        .unwrap();
    let request = req.to_der().unwrap();
    let data: Vec<_> = f
        .service
        .db
        .all()
        .unwrap()
        .into_iter()
        .filter(|c| c.fingerprint != issued.certificate.fingerprint)
        .collect();
    let response = OcspResponse::from_der(&ocsp::respond(&request, &data, now()).unwrap()).unwrap();
    let id = OcspCertId::from_cert(MessageDigest::sha256(), &leaf, &issuer).unwrap();
    assert_eq!(
        response.basic().unwrap().find_status(&id).unwrap().status,
        OcspCertStatus::UNKNOWN
    );
    let mut trailing = request;
    trailing.push(0);
    assert_eq!(
        OcspResponse::from_der(&ocsp::respond(&trailing, &data, now()).unwrap())
            .unwrap()
            .status(),
        OcspResponseStatus::MALFORMED_REQUEST
    );
}

#[test]
fn integration_failure_is_durable_and_private_keys_are_not_public() {
    let mut f = Fixture::new();
    let socket = f.service.dns.socket.clone();
    f.service.dns.socket = f._temp.path().join("missing.sock");
    let issued = f.issue(47);
    assert!(issued.integrations_pending);
    assert!(!f.service.db.pending().unwrap().is_empty());
    let json = serde_json::to_string(&issued.certificate).unwrap();
    assert!(!json.contains("PRIVATE KEY"));
    assert!(!json.contains("download_hash"));
    assert!(!json.contains(&issued.download_token));
    f.service.dns.socket = socket;
    f.service.reconcile().unwrap();
    assert!(f.service.db.pending().unwrap().is_empty());
    let dbpath = f._temp.path().join("pki.sqlite");
    let worm = f._temp.path().join("worm");
    let reopened = Database::open(&dbpath, &worm).unwrap();
    assert_eq!(
        reopened.get(&issued.certificate.fingerprint).unwrap().pem,
        issued.certificate.pem
    );
}

#[test]
fn binaries_and_openssl_ocsp_interoperate() {
    use std::process::{Command, Stdio};
    struct Running(std::process::Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let f = Fixture::new();
    let directory = f._temp.path();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let management_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let management_address = management_listener.local_addr().unwrap();
    drop(listener);
    drop(management_listener);
    let management_origin = format!("tls://localhost:{}", management_address.port());
    let origin = format!("https://localhost:{}", address.port());
    let root = directory.join("root-trust.pem");
    std::fs::write(&root, f.service.root().unwrap().pem).unwrap();
    let mut server = Running(
        Command::new(env!("CARGO_BIN_EXE_abpkid"))
            .arg("serve")
            .env("ABPKI_DATABASE", directory.join("pki.sqlite"))
            .env("ABPKI_WORM", directory.join("worm"))
            .env("AUTOBRICKS_DNS_SOCKET", &f.service.dns.socket)
            .env("ABPKI_TRUELOG_CLI", &f.service.truelog.executable)
            .env("ABPKI_ORIGIN", &origin)
            .env("ABPKI_BIND", "127.0.0.1")
            .env("ABPKI_TLS_PORT", management_address.port().to_string())
            .env("ABPKI_HTTPS_PORT", address.port().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(address).is_ok() {
            ready = true;
            break;
        }
        assert!(server.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ready);
    let cli = |args: &[&str], input: Option<&[u8]>, token: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_abpki-cli"));
        cmd.args(args)
            .current_dir(directory)
            .env("ABPKI_SERVER", &management_origin)
            .env("ABPKI_HTTPS_PORT", address.port().to_string())
            .env("ABPKI_TRUST_FILE", &root)
            .env(
                "ABPKI_ADMIN_PASSWORD",
                String::from_utf8_lossy(ADMIN).as_ref(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(token) = token {
            cmd.env("ABPKI_ACCESS_TOKEN", token);
        }
        let mut child = cmd.spawn().unwrap();
        if let Some(data) = input {
            child.stdin.take().unwrap().write_all(data).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    let downloaded_root = autobricks_pki::client::request(
        &origin,
        &std::fs::read(&root).unwrap(),
        "GET",
        "/root",
        &[],
        None,
    )
    .unwrap();
    assert_eq!(downloaded_root, std::fs::read(&root).unwrap());
    assert!(X509::from_pem(&downloaded_root).is_ok());
    assert!(
        autobricks_pki::client::request(
            &origin,
            &std::fs::read(&root).unwrap(),
            "GET",
            "/api/list-ca",
            &[],
            None
        )
        .is_err()
    );
    assert!(
        autobricks_pki::client::management_request(
            &management_origin,
            &std::fs::read(&root).unwrap(),
            "GET",
            "/root",
            &[],
            None
        )
        .is_err()
    );
    let root_output = cli(&["root"], None, None);
    assert!(
        root_output.status.success(),
        "{}",
        String::from_utf8_lossy(&root_output.stderr)
    );
    assert_eq!(
        std::fs::read(directory.join("root.crt")).unwrap(),
        std::fs::read(&root).unwrap()
    );
    assert!(cli(&["list-ca"], None, None).status.success());
    let created=cli(&["create"],Some(br#"{"issuer":"www.autobricks.internal","profile":{"kind":"server","common_name":"web","ip_addresses":["192.0.2.21"],"uri_sans":["urn:autobricks:purpose:www"]}}"#),None);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let id = created["certificate"]["fingerprint"].as_str().unwrap();
    let token = created["download_token"].as_str().unwrap();
    assert!(
        cli(&["download", id, "issued"], None, Some(token))
            .status
            .success()
    );
    assert!(directory.join("issued.tar.gz").exists());
    assert!(
        !cli(&["download", id, "denied"], None, Some("wrong"))
            .status
            .success()
    );
    let issuer = f
        .service
        .db
        .get(created["certificate"]["issuer"].as_str().unwrap())
        .unwrap();
    let issuer_path = directory.join("issuer.pem");
    let leaf_path = directory.join("leaf.pem");
    std::fs::write(&issuer_path, issuer.pem).unwrap();
    std::fs::write(&leaf_path, created["certificate"]["pem"].as_str().unwrap()).unwrap();
    let ocsp_check = || {
        Command::new("openssl")
            .args(["ocsp", "-issuer"])
            .arg(&issuer_path)
            .arg("-cert")
            .arg(&leaf_path)
            .arg("-url")
            .arg(format!("{origin}/ocsp/"))
            .arg("-CAfile")
            .arg(&root)
            .arg("-timeout")
            .arg("5")
            .output()
            .unwrap()
    };
    let good = ocsp_check();
    assert!(
        good.status.success(),
        "{} {}",
        String::from_utf8_lossy(&good.stdout),
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(String::from_utf8_lossy(&good.stdout).contains(": good"));
    assert!(String::from_utf8_lossy(&good.stderr).contains("Response verify OK"));
    assert!(cli(&["revoke", id, "--pass"], None, None).status.success());
    let revoked = ocsp_check();
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    assert!(String::from_utf8_lossy(&revoked.stdout).contains(": revoked"));
    assert!(String::from_utf8_lossy(&cli(&["check", id], None, None).stdout).contains("REVOKED"));
}

#[test]
fn tls_rejects_an_untrusted_root() {
    let f = Fixture::new();
    let config = f.service.tls_config().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut stream =
            autobricks_pki::transport::tls::DeadlineStream::new(socket, config).unwrap();
        assert!(autobricks_pki::transport::request::Request::read(&mut stream).is_err());
    });
    let (other, _) = autobricks_pki::certificate::crypto::ca(
        "Other Root",
        None,
        Validity::new(now(), 398, None).unwrap(),
    )
    .unwrap();
    assert!(
        autobricks_pki::client::request(
            &format!("https://localhost:{}", address.port()),
            &other.to_pem().unwrap(),
            "GET",
            "/",
            &[],
            None
        )
        .is_err()
    );
    server.join().unwrap();
}

#[test]
fn local_initialization_and_root_export() {
    use std::process::Command;
    let f = Fixture::new();
    let dir = f._temp.path();
    let db = dir.join("second.sqlite");
    let worm = dir.join("second-worm");
    std::fs::create_dir(&worm).unwrap();
    let command = |action: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_abpkid"));
        command.arg(action);
        if action == "init" {
            command.args(["192.0.2.44", "example.internal"]);
        }
        command
            .env("ABPKI_DATABASE", &db)
            .env("ABPKI_WORM", &worm)
            .env("AUTOBRICKS_DNS_SOCKET", &f.service.dns.socket)
            .env("ABPKI_TRUELOG_CLI", &f.service.truelog.executable)
            .env("ABPKI_ORIGIN", "https://second.example.internal")
            .env(
                "ABPKI_ADMIN_PASSWORD",
                String::from_utf8_lossy(ADMIN).as_ref(),
            )
            .output()
            .unwrap()
    };
    let init = command("init");
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let root = command("root");
    assert!(root.status.success());
    let cert = X509::from_pem(&root.stdout).unwrap();
    assert!(cert.verify(&cert.public_key().unwrap()).unwrap());
    assert!(!command("init").status.success());
    let conn = rusqlite::Connection::open(&db).unwrap();
    let users:i64=conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('users','accounts','roles')",[],|r|r.get(0)).unwrap();
    assert_eq!(users, 0);
}

#[test]
fn worm_archives_keys_with_unique_paths_and_truelog_owns_audits() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new();
    let first = f.issue(6);
    let second = f.issue(6);
    let worm = f._temp.path().join("worm");
    for issued in [&first, &second] {
        let (pem, key) =
            autobricks_pki::storage::archive::paths(&issued.certificate, now()).unwrap();
        let key = worm.join(key.unwrap());
        assert_eq!(
            std::fs::read_to_string(worm.join(pem)).unwrap(),
            issued.certificate.pem
        );
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            f.service
                .db
                .encrypted_key(&issued.certificate.fingerprint)
                .unwrap()
        );
        assert_eq!(
            std::fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(std::fs::read_dir(&worm).unwrap().count(), 3);
    for ca in f
        .service
        .db
        .all()
        .unwrap()
        .iter()
        .filter(|c| c.kind == "intermediate")
    {
        let (pem, key) = autobricks_pki::storage::archive::paths(ca, now()).unwrap();
        assert!(pem.starts_with("intermediate/"));
        let key = worm.join(key.unwrap());
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            f.service.db.encrypted_key(&ca.fingerprint).unwrap()
        );
        assert_eq!(
            std::fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(worm.join(pem)).unwrap(), ca.pem);
    }
    assert!(worm.join("root/pki.autobricks.internal.pem").exists());
    let root_key = worm.join("root/pki.autobricks.internal.key.pem");
    assert_eq!(
        std::fs::read_to_string(&root_key).unwrap(),
        f.service
            .db
            .encrypted_key(&f.service.root().unwrap().fingerprint)
            .unwrap()
    );
    assert_eq!(
        std::fs::metadata(root_key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let executable = f.service.truelog.executable.clone();
    let events = executable.with_file_name("ab-truelog-cli.events");
    let content = std::fs::read_to_string(&events).unwrap();
    assert!(!content.contains("PRIVATE KEY"));
    assert!(!content.contains(&first.download_token));
    assert!(content.lines().all(|line| {
        serde_json::from_str::<serde_json::Value>(line).unwrap()["event_id"]
            .as_str()
            .is_some()
    }));
    f.service.truelog.executable = f._temp.path().join("missing-cli");
    let pending = f.issue(47);
    assert!(pending.integrations_pending);
    assert!(
        f.service
            .db
            .pending()
            .unwrap()
            .iter()
            .all(|(_, kind, _)| kind == "audit")
    );
    f.service.truelog.executable = executable;
    f.service.reconcile().unwrap();
    assert!(f.service.db.pending().unwrap().is_empty());
    let content = std::fs::read_to_string(events).unwrap();
    assert!(content.contains(&pending.certificate.fingerprint));
}

#[test]
fn stored_keys_are_encrypted_and_legacy_sqlite_keys_migrate() {
    let f = Fixture::new();
    let issued = f.issue(47);
    let database = f._temp.path().join("pki.sqlite");
    let connection = rusqlite::Connection::open(&database).unwrap();
    let password: Vec<u8> = connection
        .query_row(
            "SELECT value FROM settings WHERE name='private_key_password'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(password.len(), 64);
    for certificate in f.service.db.all().unwrap() {
        let encrypted = f
            .service
            .db
            .encrypted_key(&certificate.fingerprint)
            .unwrap();
        assert!(encrypted.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(!encrypted.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(
            openssl::pkey::PKey::private_key_from_pem_passphrase(encrypted.as_bytes(), b"wrong")
                .is_err()
        );
        let key =
            openssl::pkey::PKey::private_key_from_pem_passphrase(encrypted.as_bytes(), &password)
                .unwrap();
        let public = X509::from_pem(certificate.pem.as_bytes())
            .unwrap()
            .public_key()
            .unwrap();
        assert!(key.public_eq(&public));
    }
    let original = &issued.certificate;
    connection
        .execute(
            "UPDATE certificates SET key_pem=? WHERE fingerprint=?",
            rusqlite::params![original.key_pem, original.fingerprint],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    let reopened = Database::open(&database, &f._temp.path().join("worm")).unwrap();
    assert!(
        reopened
            .encrypted_key(&original.fingerprint)
            .unwrap()
            .starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    );
    assert_eq!(
        reopened.get(&original.fingerprint).unwrap().key_pem,
        original.key_pem
    );
    assert!(
        !std::fs::read(&database)
            .unwrap()
            .windows(27)
            .any(|part| part == b"-----BEGIN PRIVATE KEY-----")
    );
    connection
        .execute("DELETE FROM settings WHERE name='private_key_password'", [])
        .unwrap();
    assert!(Database::open(&database, &f._temp.path().join("worm")).is_err());
}

#[test]
fn installation_prompts_for_base_domain_and_builds_ca_subjects() {
    use openssl::nid::Nid;
    use std::process::{Command, Stdio};
    let fixture = Fixture::new();
    for (index, input, domain) in [
        (0, "\n", "autobricks.internal"),
        (1, "Example.Internal\n", "example.internal"),
    ] {
        let directory = fixture._temp.path().join(format!("installation-{index}"));
        std::fs::create_dir(&directory).unwrap();
        let worm = directory.join("worm");
        std::fs::create_dir(&worm).unwrap();
        let database = directory.join("pki.sqlite");
        let mut child = Command::new(env!("CARGO_BIN_EXE_abpkid"))
            .args(["init", "192.0.2.10"])
            .env("ABPKI_DATABASE", &database)
            .env("ABPKI_WORM", &worm)
            .env_remove("ABPKI_ORIGIN")
            .env(
                "ABPKI_ADMIN_PASSWORD",
                String::from_utf8_lossy(ADMIN).as_ref(),
            )
            .env("ABPKI_TRUELOG_CLI", &fixture.service.truelog.executable)
            .env("AUTOBRICKS_DNS_SOCKET", &fixture.service.dns.socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("Base domain [autobricks.internal]")
        );
        let db = Database::open(&database, &worm).unwrap();
        assert_eq!(
            db.setting("base_domain").unwrap().unwrap(),
            domain.as_bytes()
        );
        let certificates = db.all().unwrap();
        for prefix in ["pki", "database", "www", "vpn", "worm", "app", "truelog"] {
            let certificate = certificates
                .iter()
                .find(|c| {
                    c.cn == format!("{prefix}.{domain}")
                        && matches!(c.kind.as_str(), "root" | "intermediate")
                })
                .unwrap();
            let x509 = X509::from_pem(certificate.pem.as_bytes()).unwrap();
            for (nid, expected) in [
                (Nid::COUNTRYNAME, "KR"),
                (Nid::STATEORPROVINCENAME, "Seoul"),
                (Nid::LOCALITYNAME, "Seoul"),
                (Nid::ORGANIZATIONNAME, "Autobricks, Co."),
                (Nid::ORGANIZATIONALUNITNAME, "Autobricks PKI Service"),
            ] {
                let values: Vec<_> = x509
                    .subject_name()
                    .entries_by_nid(nid)
                    .map(|entry| entry.data().to_string().unwrap())
                    .collect();
                assert_eq!(values, [expected]);
            }
        }
        let server = certificates.iter().find(|c| c.kind == "server").unwrap();
        assert_eq!(server.cn, "pki");
        let x509 = X509::from_pem(server.pem.as_bytes()).unwrap();
        assert!(
            x509.subject_alt_names()
                .unwrap()
                .iter()
                .any(|name| name.dnsname() == Some(format!("pki.{domain}").as_str()))
        );
    }
}

#[test]
fn leaf_names_are_unique_and_dns_names_follow_issuer_and_cn() {
    let f = Fixture::new();
    let make = |cn: &str, issuer: &str, kind: LeafKind| Create {
        issuer: issuer.into(),
        profile: LeafProfile {
            common_name: cn.into(),
            kind,
            dns_names: vec![],
            ip_addresses: vec!["192.0.2.20".parse().unwrap()],
            uri_sans: vec!["urn:autobricks:purpose:www".into()],
            validity: Validity::new(now(), 6, None).unwrap(),
        },
    };
    let issued = f
        .service
        .create(make("WEB01", "www.autobricks.internal", LeafKind::Server))
        .unwrap();
    assert_eq!(issued.certificate.cn, "web01");
    let cert = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    assert!(
        cert.subject_alt_names()
            .unwrap()
            .iter()
            .any(|name| name.dnsname() == Some("www-web01.autobricks.internal"))
    );
    let before = f.service.db.all().unwrap().len();
    assert!(
        f.service
            .create(make(
                "web01",
                "database.autobricks.internal",
                LeafKind::Client
            ))
            .is_err()
    );
    assert_eq!(f.service.db.all().unwrap().len(), before);
    let renewed = f
        .service
        .renew(
            &issued.certificate.fingerprint,
            &issued.download_token,
            None,
        )
        .unwrap();
    assert_eq!(renewed.certificate.cn, "web01");
    assert_ne!(
        renewed.certificate.fingerprint,
        issued.certificate.fingerprint
    );
    f.service
        .revoke(&renewed.certificate.fingerprint, ADMIN)
        .unwrap();
    assert!(
        f.service
            .create(make("web01", "www.autobricks.internal", LeafKind::Server))
            .is_err()
    );
    assert!(
        f.service
            .create(make(
                &"a".repeat(24),
                "www.autobricks.internal",
                LeafKind::Client
            ))
            .is_ok()
    );
    for cn in ["a".repeat(25), "a.b".into(), "-a".into(), "a_1".into()] {
        assert!(
            f.service
                .create(make(&cn, "www.autobricks.internal", LeafKind::Client))
                .is_err()
        );
    }
    let mut mismatch = make("web02", "www.autobricks.internal", LeafKind::Server);
    mismatch.profile.dns_names = vec!["other.example.internal".into()];
    assert!(f.service.create(mismatch).is_err());
    f.service
        .create_ca("www-a.autobricks.internal", None, ADMIN)
        .unwrap();
    f.service
        .create(make("b", "www-a.autobricks.internal", LeafKind::Server))
        .unwrap();
    assert!(
        f.service
            .create(make("a-b", "www.autobricks.internal", LeafKind::Server))
            .is_err()
    );
}

#[test]
fn intermediate_name_limit_excludes_domain_suffix() {
    let f = Fixture::new();
    let label = "a".repeat(16);
    assert!(f.service.create_ca(&label, None, ADMIN).is_ok());
    let qualified = format!("{}.autobricks.internal", "b".repeat(16));
    assert!(f.service.create_ca(&qualified, None, ADMIN).is_ok());
    let count = f.service.db.all().unwrap().len();
    for name in [
        "c".repeat(17),
        format!("{}.autobricks.internal", "d".repeat(17)),
    ] {
        assert!(f.service.create_ca(&name, None, ADMIN).is_err());
    }
    assert_eq!(f.service.db.all().unwrap().len(), count);
}
