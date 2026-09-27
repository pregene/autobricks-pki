use super::Fixture;
use autobricks_pki::{
    client::daemon,
    transport::{
        management::{self, Message, Reply},
        tls,
    },
};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

struct Relay {
    child: Child,
    socket: PathBuf,
    received: mpsc::Receiver<String>,
    release: Arc<(Mutex<bool>, Condvar)>,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
    _fixture: Fixture,
}
impl Relay {
    fn new() -> Self {
        let fixture = Fixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = fixture.service.tls_config().unwrap();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, received) = mpsc::channel();
        let gate = release.clone();
        let stopping = stop.clone();
        let server = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let config = config.clone();
                        let gate = gate.clone();
                        let tx = tx.clone();
                        workers.push(std::thread::spawn(move || {
                            let mut stream = tls::DeadlineStream::new(socket, config).unwrap();
                            let request: Message =
                                management::read_frame(&mut stream, 1_048_576).unwrap();
                            let credential = request.credential.unwrap();
                            tx.send(credential.clone()).unwrap();
                            if credential.starts_with("hold-") {
                                let (lock, ready) = &*gate;
                                let (_released, timeout) = ready
                                    .wait_timeout_while(
                                        lock.lock().unwrap(),
                                        Duration::from_secs(8),
                                        |released| !*released,
                                    )
                                    .unwrap();
                                assert!(!timeout.timed_out(), "test did not release held request");
                            }
                            let _ = management::write_frame(
                                &mut stream,
                                &Reply {
                                    status: "200 OK".into(),
                                    content_type: "text/plain".into(),
                                    body: credential.into_bytes(),
                                },
                                management::MAX_RESPONSE,
                            );
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("listener error: {e}"),
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let socket = fixture._temp.path().join("client.sock");
        let trust = fixture._temp.path().join("root.pem");
        std::fs::write(&trust, fixture.service.public_root().unwrap().pem).unwrap();
        let path = fixture._temp.path().join("client.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&daemon::Config {
                server: "127.0.0.1".into(),
                port,
                https_port: if port == 5546 { 5547 } else { 5546 },
                unix_socket: socket.to_str().unwrap().into(),
                ca: trust.to_str().unwrap().into(),
            })
            .unwrap(),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_abpki-cli"))
            .args(["daemon", "--config"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let relay = Self {
            child,
            socket,
            received,
            release,
            stop,
            server: Some(server),
            _fixture: fixture,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !relay.socket.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(relay.socket.exists(), "client socket not created");
        // Normal requests must continue using the startup trust configuration.
        std::fs::remove_file(trust).unwrap();
        relay
    }
    fn call(&self, credential: &str) -> std::thread::JoinHandle<autobricks_pki::Result<Vec<u8>>> {
        let socket = self.socket.clone();
        let credential = credential.to_owned();
        std::thread::spawn(move || {
            daemon::call(
                &socket,
                &Message {
                    method: "GET".into(),
                    path: "/api/check/test".into(),
                    content_type: "application/json".into(),
                    credential: Some(credential),
                    body: vec![],
                },
            )
        })
    }
    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.release();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

#[test]
fn client_relays_overlap_and_keep_credentials_separate_with_cached_trust() {
    let relay = Relay::new();
    let first = relay.call("hold-first-secret");
    assert_eq!(
        relay.received.recv_timeout(Duration::from_secs(5)).unwrap(),
        "hold-first-secret"
    );
    let second = relay.call("second-secret");
    let received = relay.received.recv_timeout(Duration::from_secs(5));
    relay.release();
    assert_eq!(
        received.unwrap(),
        "second-secret",
        "second request waited for the first"
    );
    assert_eq!(first.join().unwrap().unwrap(), b"hold-first-secret");
    assert_eq!(second.join().unwrap().unwrap(), b"second-secret");
}

#[test]
fn client_caps_relays_at_sixteen_and_recovers_slots() {
    let relay = Relay::new();
    let mut calls = Vec::new();
    for i in 0..16 {
        let credential = format!("hold-{i}");
        calls.push((credential.clone(), relay.call(&credential)));
        assert_eq!(
            relay.received.recv_timeout(Duration::from_secs(5)).unwrap(),
            credential
        );
    }
    let overflow = relay.call("overflow");
    assert!(overflow.join().unwrap().is_err());
    assert!(
        relay.received.try_recv().is_err(),
        "overflow reached the remote server"
    );
    relay.release();
    for (credential, call) in calls {
        assert_eq!(call.join().unwrap().unwrap(), credential.as_bytes());
    }
    // Reply completion precedes the worker's slot release by a few instructions.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match relay.call("after-release").join().unwrap() {
            Ok(reply) => {
                assert_eq!(reply, b"after-release");
                break;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => panic!("relay slot was not released: {error}"),
        }
    }
}
