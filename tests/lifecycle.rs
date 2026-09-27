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
        std::fs::write(temp.path().join("truelog.env"), "AB_WORM_RETAIN_DAYS=365\n").unwrap();
        let service = Service {
            background_delivery: false,
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
                365,
            )
            .unwrap();
        Self {
            service,
            _temp: temp,
            stop,
            thread: Some(thread),
        }
    }
    fn seed_intermediate(
        &self,
        cn: &str,
        days: u32,
    ) -> autobricks_pki::storage::database::Certificate {
        use autobricks_pki::{certificate::crypto, storage::database::Certificate};
        let root = self.service.root().unwrap();
        let root_cert = X509::from_pem(root.pem.as_bytes()).unwrap();
        let root_key = openssl::pkey::PKey::private_key_from_pem(root.key_pem.as_bytes()).unwrap();
        let validity = Validity::new(now(), days, Some(root.validity)).unwrap();
        let (cert, key) = crypto::ca(cn, Some((&root_cert, &root_key)), validity).unwrap();
        let record = Certificate {
            fingerprint: crypto::fingerprint(&cert).unwrap(),
            cn: cn.into(),
            kind: "intermediate".into(),
            issuer: Some(root.fingerprint),
            serial: crypto::serial(&cert).unwrap(),
            validity,
            pem: String::from_utf8(cert.to_pem().unwrap()).unwrap(),
            key_pem: String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
            revoked_at: None,
            profile: None,
            download_hash: None,
        };
        self.service.db.insert(&record).unwrap();
        let timestamp = now();
        let crl = autobricks_pki::revocation::crl::generate(
            &record,
            &self.service.db.all().unwrap(),
            timestamp,
            1,
        )
        .unwrap();
        let connection = rusqlite::Connection::open(self._temp.path().join("pki.sqlite")).unwrap();
        let crl_path = format!("crl/{}/test.pem", record.fingerprint);
        self.service.worm.write_once(&crl_path, &crl).unwrap();
        connection.execute("INSERT INTO crls(issuer,crl_path,next_update,number) VALUES((SELECT idx FROM certificates WHERE fingerprint=?),?,?,1)",
            rusqlite::params![record.fingerprint, crl_path, autobricks_pki::revocation::crl::next_update(timestamp).unwrap()]).unwrap();
        record
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
    assert!(s.renew(&c.fingerprint, &issued.download_token).is_err());
}
#[test]
fn renewal_and_authorization() {
    let f = Fixture::new();
    let issued = f.issue(6);
    let renewed = f
        .service
        .renew(&issued.certificate.fingerprint, &issued.download_token)
        .unwrap();
    assert_eq!(
        renewed.certificate.validity.not_after - renewed.certificate.validity.not_before,
        issued.certificate.validity.not_after - issued.certificate.validity.not_before,
    );
    assert_ne!(
        issued.certificate.fingerprint,
        renewed.certificate.fingerprint
    );
    assert!(f.service.create_ca("extra", None, b"wrong").is_err());
    assert!(f.service.create_ca("extra", None, ADMIN).is_err());
    assert!(f.service.create_ca("extra", None, ADMIN).is_err());
    assert!(
        f.service
            .initialize(
                ADMIN,
                "localhost",
                "127.0.0.1".parse().unwrap(),
                "autobricks.internal",
                365,
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
    let old = f.seed_intermediate("short-lived", 6);
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
            .env("ABPKI_TRUELOG_CONFIG", f._temp.path().join("truelog.env"))
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
    let client_socket = directory.join("client.sock");
    let client_config = directory.join("client.json");
    std::fs::write(
        &client_config,
        serde_json::to_vec(&autobricks_pki::client::daemon::Config {
            server: "localhost".into(),
            port: management_address.port(),
            https_port: address.port(),
            unix_socket: client_socket.to_string_lossy().into_owned(),
            ca: root.to_string_lossy().into_owned(),
        })
        .unwrap(),
    )
    .unwrap();
    let mut local_client = Running(
        Command::new(env!("CARGO_BIN_EXE_abpki-cli"))
            .args(["daemon", "--config"])
            .arg(&client_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if client_socket.exists() {
            break;
        }
        assert!(local_client.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(client_socket.exists());
    let cli = |args: &[&str], input: Option<&[u8]>, token: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_abpki-cli"));
        cmd.args(args)
            .current_dir(directory)
            .env("ABPKI_SOCKET", &client_socket)
            .env("HOME", directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(token) = token {
            // Exercise explicit credential-file -> Unix socket forwarding, including wrong tokens.
            std::fs::write(directory.join(".abpki").join(args[1]), token).unwrap();
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
    let info = cli(&["info", id], None, None);
    assert!(info.status.success());
    let text = String::from_utf8(info.stdout).unwrap();
    for field in [
        "Certificate:",
        "Subject:",
        "Issuer:",
        "Validity",
        "X509v3 Subject Alternative Name",
        "urn:autobricks:purpose:www",
    ] {
        assert!(text.contains(field), "missing {field}");
    }
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("BEGIN CERTIFICATE"));
    assert!(!cli(&["info", &"0".repeat(64)], None, None).status.success());
    assert!(created.get("download_token").is_none());
    let token = std::fs::read_to_string(directory.join(".abpki").join(id)).unwrap();
    assert!(
        cli(&["download", id, "issued"], None, Some(&token))
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
    assert!(
        cli(
            &["revoke", id, "--pass", std::str::from_utf8(ADMIN).unwrap()],
            None,
            None
        )
        .status
        .success()
    );
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
            .env("ABPKI_TRUELOG_CONFIG", f._temp.path().join("truelog.env"))
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
    assert_eq!(std::fs::read_dir(&worm).unwrap().count(), 4);
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
fn stored_keys_are_encrypted_and_require_the_password() {
    let f = Fixture::new();
    f.issue(47);
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
    let columns: Vec<String> = connection
        .prepare("PRAGMA table_info(certificates)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        !columns
            .iter()
            .any(|name| name == "pem" || name == "key_pem")
    );
    assert!(columns.iter().any(|name| name == "certificate_path"));
    assert!(columns.iter().any(|name| name == "private_key_path"));
    let queued: i64 = connection
        .query_row(
            "SELECT count(*) FROM outbox WHERE kind='certificate'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queued, 0);

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
            .env(
                "ABPKI_TRUELOG_CONFIG",
                fixture._temp.path().join("truelog.env"),
            )
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
        .renew(&issued.certificate.fingerprint, &issued.download_token)
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
    f.seed_intermediate("www-a.autobricks.internal", 358);
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
    use autobricks_pki::certificate::common_name::intermediate;
    let domain = "autobricks.internal";
    assert!(intermediate(&"a".repeat(16), domain).is_ok());
    assert!(intermediate(&format!("{}.{}", "b".repeat(16), domain), domain).is_ok());
    assert!(intermediate(&"c".repeat(17), domain).is_err());
    assert!(intermediate(&format!("{}.{}", "d".repeat(17), domain), domain).is_err());
}

#[test]
fn additional_ca_creation_is_unavailable_without_side_effects() {
    let f = Fixture::new();
    let before = f.service.db.all().unwrap().len();
    let pending = f.service.db.pending().unwrap();
    for admin in [ADMIN, b"wrong".as_slice()] {
        assert!(
            f.service
                .create_ca("extra", None, admin)
                .unwrap_err()
                .to_string()
                .contains("Not implemented")
        );
    }
    let response = autobricks_pki::server::routes::dispatch(
        &f.service,
        autobricks_pki::transport::request::Request {
            method: "POST".into(),
            path: "/api/create-ca".into(),
            headers: Default::default(),
            body: vec![],
        },
    );
    assert_eq!(response.status, "501 Not Implemented");
    assert_eq!(f.service.db.all().unwrap().len(), before);
    assert_eq!(f.service.db.pending().unwrap(), pending);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_abpki-cli"))
        .arg("create-ca")
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Not implemented")
    );
}

#[test]
fn hourly_scheduler_renews_due_ca_and_persists_attempt() {
    let f = Fixture::new();
    let old = f.seed_intermediate("scheduled", 6);
    let timestamp = now();
    assert!(f.service.run_hourly_renewal(timestamp).unwrap());
    let all = f.service.db.all().unwrap();
    let generations: Vec<_> = all.iter().filter(|c| c.cn == old.cn).collect();
    assert_eq!(generations.len(), 2);
    assert_eq!(
        generations[1].validity.not_after - generations[1].validity.not_before,
        old.validity.not_after - old.validity.not_before
    );
    assert!(!f.service.run_hourly_renewal(timestamp + 3599).unwrap());
    let reopened = Database::open(
        &f._temp.path().join("pki.sqlite"),
        &f._temp.path().join("worm"),
    )
    .unwrap();
    let saved: i64 = serde_json::from_slice(
        &reopened
            .setting("renewal_scheduler_last_attempt")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(saved, timestamp);
    assert!(!autobricks_pki::server::scheduler::due(
        Some(saved),
        timestamp + 1
    ));
    assert_eq!(
        f.service
            .db
            .all()
            .unwrap()
            .iter()
            .filter(|c| c.cn == old.cn)
            .count(),
        2
    );
}

#[test]
fn crl_failure_never_rolls_back_revocation_and_publication_retries() {
    let f = Fixture::new();
    let issued = f.issue(47);
    let issuer = issued.certificate.issuer.as_deref().unwrap();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_crl BEFORE UPDATE ON crls BEGIN SELECT RAISE(ABORT,'simulated publication failure'); END;").unwrap();
    f.service
        .revoke(&issued.certificate.fingerprint, ADMIN)
        .unwrap();
    let state: String = connection
        .query_row(
            "SELECT valid FROM certificates WHERE fingerprint=?",
            [&issued.certificate.fingerprint],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "REVOKED");
    assert!(
        f.service
            .db
            .get(&issued.certificate.fingerprint)
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert!(
        f.service
            .db
            .pending()
            .unwrap()
            .iter()
            .any(|(_, kind, _)| kind == "crl")
    );
    assert!(f.service.crl(issuer).is_err());
    let leaf = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let ca = X509::from_pem(f.service.db.get(issuer).unwrap().pem.as_bytes()).unwrap();
    let query = request(&leaf, &ca);
    let response = OcspResponse::from_der(
        &ocsp::respond(&query, &f.service.db.all().unwrap(), now()).unwrap(),
    )
    .unwrap();
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &ca).unwrap();
    assert_eq!(
        response
            .basic()
            .unwrap()
            .find_status(&cert_id)
            .unwrap()
            .status,
        OcspCertStatus::REVOKED
    );

    connection.execute_batch("DROP TRIGGER fail_crl;").unwrap();
    f.service.reconcile().unwrap();
    let crl = X509Crl::from_pem(&f.service.crl(issuer).unwrap()).unwrap();
    assert_eq!(crl.get_revoked().unwrap().len(), 1);
    assert!(
        !f.service
            .db
            .pending()
            .unwrap()
            .iter()
            .any(|(_, kind, _)| kind == "crl")
    );
}

#[test]
fn crl_download_reads_published_worm_file_without_signing_or_database_writes() {
    let f = Fixture::new();
    let issuer = f.service.db.issuer("www.autobricks.internal").unwrap();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let (path, number): (String,i64) = connection.query_row("SELECT crl_path,number FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [&issuer.fingerprint], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
    let expected = std::fs::read(f._temp.path().join("worm").join(&path)).unwrap();
    assert_eq!(number, 1);
    let initial_crl = X509Crl::from_pem(&expected).unwrap();
    assert!(
        initial_crl
            .get_revoked()
            .is_none_or(|entries| entries.is_empty())
    );

    connection
        .execute("DELETE FROM settings WHERE name='private_key_password'", [])
        .unwrap();
    assert_eq!(f.service.crl(&issuer.fingerprint).unwrap(), expected);
    assert_eq!(f.service.crl(&issuer.cn).unwrap(), expected);
    connection.execute("UPDATE crls SET next_update=0 WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [&issuer.fingerprint]).unwrap();
    assert!(f.service.crl(&issuer.fingerprint).is_err());
    let after: i64 = connection.query_row("SELECT number FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [&issuer.fingerprint], |row| row.get(0)).unwrap();
    assert_eq!(after, number);
}

#[test]
fn scheduler_replaces_expired_crl_and_preserves_previous_worm_file() {
    let f = Fixture::new();
    let issuer = f.service.db.issuer("www.autobricks.internal").unwrap();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let old: String = connection.query_row("SELECT crl_path FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [&issuer.fingerprint], |row| row.get(0)).unwrap();
    let old_bytes = std::fs::read(f._temp.path().join("worm").join(&old)).unwrap();
    connection.execute("UPDATE crls SET next_update=0 WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [&issuer.fingerprint]).unwrap();
    f.service.refresh_status_and_deliver().unwrap();
    let new: String = connection.query_row("SELECT crl_path FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [&issuer.fingerprint], |row| row.get(0)).unwrap();
    assert_ne!(old, new);
    assert_eq!(
        std::fs::read(f._temp.path().join("worm").join(old)).unwrap(),
        old_bytes
    );
    assert!(X509Crl::from_pem(&f.service.crl(&issuer.fingerprint).unwrap()).is_ok());
}

#[test]
fn ca_lineage_keeps_crl_numbers_and_revocations_across_generations() {
    let f = Fixture::new();
    let old = f.seed_intermediate("continuous", 6);
    let issue = |cn: &str, issuer: &str| {
        f.service
            .create(Create {
                issuer: issuer.into(),
                profile: LeafProfile {
                    kind: LeafKind::Client,
                    common_name: cn.into(),
                    dns_names: vec![],
                    ip_addresses: vec![],
                    uri_sans: vec![],
                    validity: Validity::new(now(), 5, None).unwrap(),
                },
            })
            .unwrap()
    };
    let first = issue("before", &old.fingerprint);
    f.service
        .revoke(&first.certificate.fingerprint, ADMIN)
        .unwrap();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let number = |fingerprint: &str| {
        connection.query_row("SELECT number FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [fingerprint], |row| row.get::<_,i64>(0)).unwrap()
    };
    let previous = number(&old.fingerprint);
    f.service.maintain().unwrap();
    let generations = f.service.db.ca_lineage(&old.fingerprint).unwrap();
    assert_eq!(generations.len(), 2);
    let new = &generations[1];
    assert!(number(new) > previous);
    assert_eq!(number(new), number(&old.fingerprint));
    assert_eq!(
        f.service.crl(new).unwrap(),
        f.service.crl(&old.fingerprint).unwrap()
    );
    assert_eq!(
        X509Crl::from_pem(&f.service.crl(new).unwrap())
            .unwrap()
            .get_revoked()
            .unwrap()
            .len(),
        1
    );
    let second = issue("after", new);
    let before_revocation = number(new);
    f.service
        .revoke(&second.certificate.fingerprint, ADMIN)
        .unwrap();
    assert_eq!(
        X509Crl::from_pem(&f.service.crl(&old.fingerprint).unwrap())
            .unwrap()
            .get_revoked()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(number(new), before_revocation + 1);
    assert_eq!(f.service.crl(new).unwrap(), f.service.crl(&old.cn).unwrap());
    let before_refresh = number(new);
    connection.execute("UPDATE crls SET next_update=0 WHERE issuer IN (SELECT idx FROM certificates WHERE fingerprint IN (?1,?2))", rusqlite::params![old.fingerprint,new]).unwrap();
    f.service.refresh_expired_crls().unwrap();
    assert_eq!(number(new), before_refresh + 1);
    assert_eq!(number(new), number(&old.fingerprint));
    let unrelated = f.seed_intermediate("continuous", 6);
    assert_eq!(
        f.service.db.ca_lineage(&unrelated.fingerprint).unwrap(),
        vec![unrelated.fingerprint]
    );
    assert_eq!(f.service.db.ca_lineage(&old.fingerprint).unwrap().len(), 2);
}

#[test]
fn database_contains_no_pem_in_any_table_after_issue_revoke_and_renewal() {
    let f = Fixture::new();
    let leaf = f.issue(47);
    f.service
        .revoke(&leaf.certificate.fingerprint, ADMIN)
        .unwrap();
    f.seed_intermediate("db-check", 6);
    f.service.maintain().unwrap();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for table in tables {
        let mut query = connection
            .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
            .unwrap();
        let count = query.column_count();
        let mut rows = query.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..count {
                use rusqlite::types::ValueRef;
                match row.get_ref(i).unwrap() {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => assert!(
                        !bytes
                            .windows(b"-----BEGIN ".len())
                            .any(|w| w == b"-----BEGIN "),
                        "PEM in {table}"
                    ),
                    _ => (),
                }
            }
        }
    }
}

#[test]
fn certificate_info_reads_only_public_artifact_and_handles_missing_fingerprint() {
    let f = Fixture::new();
    let ids: Vec<_> = f
        .service
        .db
        .all()
        .unwrap()
        .into_iter()
        .map(|c| c.fingerprint)
        .collect();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    connection
        .execute("DELETE FROM settings WHERE name='private_key_password'", [])
        .unwrap();
    for id in ids {
        let output = f.service.certificate_info(&id).unwrap().unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Certificate:"));
        assert!(text.contains(&id));
        assert!(!text.contains("PRIVATE KEY"));
    }
    assert!(
        f.service
            .certificate_info(&"0".repeat(64))
            .unwrap()
            .is_none()
    );
    assert!(f.service.certificate_info("../invalid").is_err());
}

#[test]
fn cached_tls_keeps_metadata_checks_without_reopening_keys() {
    let f = Fixture::new();
    let cache = autobricks_pki::server::tls_cache::TlsCache::default();
    let first = cache.config(&f.service).unwrap();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    connection
        .execute("DELETE FROM settings WHERE name='private_key_password'", [])
        .unwrap();
    let second = cache.config(&f.service).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let id = String::from_utf8(f.service.db.setting("tls_certificate").unwrap().unwrap()).unwrap();
    connection
        .execute(
            "UPDATE certificates SET revoked_at=1 WHERE fingerprint=?",
            [&id],
        )
        .unwrap();
    assert!(cache.config(&f.service).is_err());
    connection
        .execute(
            "UPDATE certificates SET revoked_at=NULL,not_after=0 WHERE fingerprint=?",
            [&id],
        )
        .unwrap();
    assert!(cache.config(&f.service).is_err());
}

#[test]
fn pending_delivery_batches_advance_past_uncompleted_rows() {
    let f = Fixture::new();
    for _ in 0..130 {
        f.service.db.enqueue("audit", "{}").unwrap();
    }
    let first = f.service.db.pending().unwrap();
    assert_eq!(first.len(), 64);
    let second = f.service.db.pending_after(first.last().unwrap().0).unwrap();
    assert_eq!(second.len(), 64);
    let third = f
        .service
        .db
        .pending_after(second.last().unwrap().0)
        .unwrap();
    assert_eq!(third.len(), 2);
    assert!(
        f.service
            .db
            .pending_after(third.last().unwrap().0)
            .unwrap()
            .is_empty()
    );
    assert!(f.service.db.has_pending().unwrap());
    assert_eq!(f.service.db.pending().unwrap(), first);
}

#[test]
fn background_delivery_defers_external_tools_but_publishes_revocation() {
    let mut f = Fixture::new();
    f.service.background_delivery = true;
    f.service.truelog.executable = f._temp.path().join("unavailable-truelog");
    let issued = f.issue(47);
    assert!(issued.integrations_pending);
    assert!(f.service.db.has_pending().unwrap());
    f.service
        .revoke(&issued.certificate.fingerprint, ADMIN)
        .unwrap();
    let crl = X509Crl::from_pem(
        &f.service
            .crl(issued.certificate.issuer.as_deref().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(crl.get_revoked().unwrap().len(), 1);
    assert!(
        !f.service
            .db
            .pending()
            .unwrap()
            .iter()
            .any(|(_, kind, _)| kind == "crl")
    );
    assert!(f.service.db.has_pending().unwrap());
}

#[path = "performance/client.rs"]
mod client_performance;

#[test]
fn tls_cache_reloads_changed_fingerprint_and_rejects_broken_replacement() {
    let f = Fixture::new();
    let cache = autobricks_pki::server::tls_cache::TlsCache::default();
    let first = cache.config(&f.service).unwrap();
    let replacement = f.issue(47);
    f.service
        .db
        .set_setting(
            "tls_certificate",
            replacement.certificate.fingerprint.as_bytes(),
        )
        .unwrap();
    let second = cache.config(&f.service).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&second, &cache.config(&f.service).unwrap()));
    let broken = f.issue(47);
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    conn.execute(
        "UPDATE certificates SET private_key_path='missing.pem' WHERE fingerprint=?",
        [&broken.certificate.fingerprint],
    )
    .unwrap();
    f.service
        .db
        .set_setting("tls_certificate", broken.certificate.fingerprint.as_bytes())
        .unwrap();
    assert!(
        cache.config(&f.service).is_err(),
        "old TLS config hid a broken replacement"
    );
}

#[test]
fn outbox_filters_completed_rows_and_separates_crl_work() {
    let f = Fixture::new();
    for _ in 0..70 {
        f.service.db.enqueue("audit", "{}").unwrap();
    }
    let initial = f.service.db.pending().unwrap();
    for (id, _, _) in &initial {
        f.service.db.complete(*id).unwrap();
    }
    f.service.db.enqueue("crl", "issuer-a").unwrap();
    f.service.db.enqueue("crl", "issuer-a").unwrap();
    let external = f.service.db.pending_external_after(0).unwrap();
    assert_eq!(external.len(), 6);
    assert!(
        external
            .iter()
            .all(|(id, kind, _)| *id > initial.last().unwrap().0 && kind == "audit")
    );
    assert_eq!(f.service.db.pending_crls().unwrap(), vec!["issuer-a"]);
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    for index in ["outbox_pending_id", "outbox_pending_kind_payload"] {
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                [index],
                |r| r.get(0),
            )
            .unwrap();
        assert!(sql.contains("WHERE done=0"));
    }
}

#[test]
fn failed_crl_publications_coalesce_and_retry_independently_of_external_delivery() {
    let mut f = Fixture::new();
    f.service.background_delivery = true;
    f.service.truelog.executable = f._temp.path().join("unavailable-truelog");
    let first = f.issue(47);
    let second = f.issue(47);
    let issuer = first.certificate.issuer.as_deref().unwrap();
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let before: i64 = conn.query_row("SELECT number FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [issuer], |r| r.get(0)).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_crl BEFORE UPDATE ON crls BEGIN SELECT RAISE(ABORT,'publication failure'); END;").unwrap();
    for certificate in [&first.certificate, &second.certificate] {
        f.service.revoke(&certificate.fingerprint, ADMIN).unwrap();
        assert!(
            f.service
                .db
                .metadata(&certificate.fingerprint)
                .unwrap()
                .revoked_at
                .is_some()
        );
    }
    let jobs: i64 = conn
        .query_row(
            "SELECT count(*) FROM outbox WHERE kind='crl' AND done=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 1, "same-lineage failures duplicated pending CRL work");
    assert!(f.service.crl(issuer).is_err());
    conn.execute_batch("DROP TRIGGER fail_crl").unwrap();
    f.service.refresh_status_and_deliver().unwrap();
    let after: i64 = conn.query_row("SELECT number FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)", [issuer], |r| r.get(0)).unwrap();
    assert_eq!(after, before + 1);
    let crl = X509Crl::from_pem(&f.service.crl(issuer).unwrap()).unwrap();
    assert_eq!(crl.get_revoked().unwrap().len(), 2);
    assert!(f.service.db.pending_crls().unwrap().is_empty());
    assert!(!f.service.db.pending_external_after(0).unwrap().is_empty());
}

#[test]
fn dns_index_allows_renewal_but_blocks_new_issuance_and_finds_aliases() {
    let f = Fixture::new();
    let issued = f.issue(6);
    let profile: LeafProfile =
        serde_json::from_str(issued.certificate.profile.as_deref().unwrap()).unwrap();
    let host = &profile.dns_names[0];
    assert!(f.service.db.dns_name_exists(&host.to_uppercase()).unwrap());
    let renewed = f
        .service
        .renew(&issued.certificate.fingerprint, &issued.download_token)
        .unwrap();
    let replacement: LeafProfile =
        serde_json::from_str(renewed.certificate.profile.as_deref().unwrap()).unwrap();
    assert_eq!(profile.common_name, replacement.common_name);
    assert_eq!(profile.dns_names, replacement.dns_names);
    assert!(
        f.service
            .create(Create {
                issuer: issued.certificate.issuer.clone().unwrap(),
                profile
            })
            .is_err()
    );
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='certificates_dns_name'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!sql.contains("UNIQUE"));
    conn.execute("UPDATE certificates SET profile=json_set(profile,'$.dns_names[1]','Legacy.Example') WHERE fingerprint=?", [&issued.certificate.fingerprint]).unwrap();
    assert!(f.service.db.dns_name_exists("legacy.example").unwrap());
    assert!(!f.service.db.dns_name_exists("absent.example").unwrap());
}

#[test]
fn ocsp_cache_avoids_unrelated_pem_reads_and_observes_live_revocation() {
    let f = Fixture::new();
    let issued = f.issue(47);
    let leaf = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let issuer = f
        .service
        .db
        .public_certificate(issued.certificate.issuer.as_deref().unwrap())
        .unwrap();
    let ca = X509::from_pem(issuer.pem.as_bytes()).unwrap();
    let check = |digest, expected| {
        let mut req = OcspRequest::new().unwrap();
        req.add_id(OcspCertId::from_cert(digest, &leaf, &ca).unwrap())
            .unwrap();
        let bytes = ocsp::respond_database(&req.to_der().unwrap(), &f.service.db, now()).unwrap();
        let response = OcspResponse::from_der(&bytes).unwrap().basic().unwrap();
        let id = OcspCertId::from_cert(digest, &leaf, &ca).unwrap();
        assert_eq!(response.find_status(&id).unwrap().status, expected);
    };
    check(MessageDigest::sha1(), OcspCertStatus::GOOD);
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    conn.execute(
        "UPDATE certificates SET certificate_path='missing.pem' WHERE cn='vpn.autobricks.internal'",
        [],
    )
    .unwrap();
    check(MessageDigest::sha256(), OcspCertStatus::GOOD);
    f.service
        .revoke(&issued.certificate.fingerprint, ADMIN)
        .unwrap();
    check(MessageDigest::sha1(), OcspCertStatus::REVOKED);
    check(MessageDigest::sha256(), OcspCertStatus::REVOKED);
}

#[test]
fn ocsp_cache_refreshes_after_intermediate_renewal() {
    let f = Fixture::new();
    let old = f.seed_intermediate("cache-ca", 6);
    let issued = f
        .service
        .create(Create {
            issuer: old.fingerprint.clone(),
            profile: LeafProfile {
                kind: LeafKind::Client,
                common_name: "cache-leaf".into(),
                dns_names: vec![],
                ip_addresses: vec![],
                uri_sans: vec![],
                validity: Validity::new(now(), 5, None).unwrap(),
            },
        })
        .unwrap();
    let leaf = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let ca = X509::from_pem(old.pem.as_bytes()).unwrap();
    let body = request(&leaf, &ca);
    ocsp::respond_database(&body, &f.service.db, now()).unwrap();
    f.service.maintain().unwrap();
    let latest = f.service.db.issuer(&old.cn).unwrap();
    assert_ne!(old.fingerprint, latest.fingerprint);
    let response = ocsp::respond_database(&body, &f.service.db, now()).unwrap();
    let cert_der = X509::from_pem(latest.pem.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    assert!(
        response
            .windows(cert_der.len())
            .any(|part| part == cert_der)
    );
    let id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &ca).unwrap();
    assert_eq!(
        OcspResponse::from_der(&response)
            .unwrap()
            .basic()
            .unwrap()
            .find_status(&id)
            .unwrap()
            .status,
        OcspCertStatus::GOOD
    );
}

#[test]
fn paginated_lists_bound_memory_preserve_order_and_exclude_new_rows() {
    let f = Fixture::new();
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    conn.execute_batch("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<600) INSERT INTO certificates(fingerprint,cn,kind,serial,not_before,not_after,certificate_path,private_key_path) SELECT printf('%064x',i),'page-'||i,'client',printf('%x',i),0,9999999999,'absent.pem','absent.key.pem' FROM n;").unwrap();
    assert!(
        f.service.db.list_certificates(false).is_err(),
        "legacy list silently truncated"
    );
    let mut calls = 0;
    let mut output = Vec::new();
    autobricks_pki::client::listing::stream_pages(|after,through| {
        calls+=1;
        let page=f.service.db.certificate_page(false,after,through)?;
        assert!(page.entries.len()<=256);
        if calls==1 {
            conn.execute("INSERT INTO certificates(fingerprint,cn,kind,serial,not_before,not_after,certificate_path,private_key_path) VALUES('late','late','client','FFF',0,9999999999,'absent.pem','absent.key.pem')",[]).unwrap();
        }
        Ok(page)
    },&mut output).unwrap();
    assert_eq!(calls, 3);
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 602); // Header, existing PKI leaf, and 600 fixture rows.
    assert_eq!(text.matches("Fingerprint").count(), 1);
    assert!(!text.contains("late"));
    let ids: Vec<i64> = text
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().next().unwrap().parse().unwrap())
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(f.service.db.certificate_page(false, -1, None).is_err());
}
