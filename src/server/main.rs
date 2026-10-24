use autobricks_pki::{
    Result,
    certificate::profile::Distribution,
    integration::dns::Dns,
    server::{config::Config, service::Service},
    storage::{database::Database, worm::Worm},
};
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
fn main() {
    if let Err(e) = run() {
        eprintln!("abpkid: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut args: Vec<_> = env::args().skip(1).collect();
    if autobricks_pki::help::print_if_requested("abpkid", &args)? {
        return Ok(());
    }
    let config_path = if args.first().is_some_and(|value| value == "--config") {
        if args.len() < 3 {
            return Err("--config requires a JSON file before the command".into());
        }
        let path = std::path::PathBuf::from(args.remove(1));
        args.remove(0);
        Some(path)
    } else {
        env::var_os("ABPKI_CONFIG").map(Into::into)
    };
    if !((args.len() == 2 || args.len() == 3) && args[0] == "init")
        && !(args.len() == 2 && args[0] == "identity")
        && args != ["serve"]
        && args != ["root"]
    {
        return Err("unknown command".into());
    }
    let installation_domain = if args[0] == "init" {
        Some(autobricks_pki::authority::domain::installation_input(
            args.get(2).map(String::as_str),
        )?)
    } else {
        None
    };
    let c = Config::load(config_path.as_deref())?;
    let database = Database::open(&c.database, &c.worm)?;
    let saved_domain = database
        .setting("base_domain")?
        .map(String::from_utf8)
        .transpose()?;
    let origin = if c.origin.is_empty() {
        format!(
            "https://pki.{}",
            installation_domain
                .as_ref()
                .or(saved_domain.as_ref())
                .ok_or("missing baseDomain; configure ABPKI_ORIGIN for a legacy database")?
        )
    } else {
        c.origin.clone()
    };
    let origin = url::Url::parse(&origin)?;
    let distribution = Distribution::new(origin.as_str())?;
    let mut service = Service {
        auth: None,
        auth_2fa: c.auth_2fa,
        background_delivery: args == ["serve"],
        db: database,
        distribution,
        truelog: autobricks_pki::integration::truelog::TrueLog {
            executable: c.truelog_cli.clone(),
        },
        worm: Worm::new(&c.worm)?,
        dns: Dns {
            socket: c.dns_socket.clone(),
        },
    };
    if args == ["root"] {
        print!("{}", service.public_root()?.pem);
        return Ok(());
    }
    if args[0] == "identity" {
        let directory = std::path::Path::new(&args[1]);
        fs::create_dir_all(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let identity = service.tls_identity()?;
        let root = service.public_root()?.pem.into_bytes();
        let mut fullchain = identity.certificate.clone();
        fullchain.extend_from_slice(&identity.chain);
        for (name, value) in [
            ("certificate.pem", identity.certificate),
            ("private-key.pem", identity.key),
            ("trust-chain.pem", identity.chain),
            ("fullchain.pem", fullchain),
            ("client-ca.pem", root),
        ] {
            let path = directory.join(name);
            fs::write(&path, value)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        println!("PKI TLS identity prepared");
        return Ok(());
    }
    if args[0] == "init" {
        let registration_ip: std::net::IpAddr = args[1].parse()?;
        if registration_ip.is_unspecified() || registration_ip.is_multicast() {
            return Err("registration IP must identify a server interface, not a wildcard or multicast address".into());
        }
        service.initialize(
            env::var("ABPKI_ADMIN_PASSWORD")?.as_bytes(),
            origin.host_str().ok_or("missing hostname")?,
            registration_ip,
            installation_domain
                .as_deref()
                .ok_or("missing installation baseDomain")?,
            c.retention_days,
        )?;
        println!("PKI initialized");
        return Ok(());
    }
    service.auth = c
        .auth_support
        .then(autobricks_pki::auth::Runtime::initialize)
        .transpose()?;
    if let Err(error) = service.run_hourly_renewal(autobricks_pki::server::service::now()) {
        eprintln!("hourly renewal failed: {error}");
    }
    let service = Arc::new(Mutex::new(service));
    let comm_config_path = c
        .comm_config
        .as_ref()
        .ok_or("serve requires comm_config or ABPKI_COMM_CONFIG")?;
    let comm_config: serde_json::Value = serde_json::from_slice(&fs::read(comm_config_path)?)?;
    comm_config
        .as_object()
        .ok_or("Comm configuration root must be a JSON object")?;
    let ipc_service = service.clone();
    let http_service = service.clone();
    let structured_service = service.clone();
    let _comm = autobricks_pki::comm::Runtime::start(
        std::path::Path::new(autobricks_pki::comm::LIBRARY_NAME),
        &serde_json::to_string(&comm_config)?,
        move |payload| dispatch_ipc(&ipc_service, payload),
        move |request| dispatch_http(&http_service, request),
        move |request| dispatch_structured(&structured_service, request),
    )?;
    let delivery = service.clone();
    std::thread::Builder::new()
        .name("abpkid-delivery".into())
        .spawn(move || {
            if let Err(error) = autobricks_pki::server::delivery::run(delivery) {
                eprintln!("integration delivery worker stopped: {error}");
            }
        })?;
    let maintenance = service.clone();
    std::thread::Builder::new()
        .name("abpkid-maintenance".into())
        .spawn(move || {
            loop {
                match maintenance.lock() {
                    Ok(s) => {
                        match s.run_hourly_renewal(autobricks_pki::server::service::now()) {
                            Ok(true) => eprintln!("hourly renewal completed"),
                            Ok(false) => (),
                            Err(error) => eprintln!("hourly renewal failed: {error}"),
                        }
                        if let Err(error) = s.refresh_status_and_deliver() {
                            eprintln!("status refresh or integration delivery failed: {error}");
                        }
                    }
                    Err(_) => return,
                };
                std::thread::sleep(Duration::from_secs(30));
            }
        })?;
    println!(
        "abpkid {} Comm configuration={}",
        autobricks_pki::VERSION,
        comm_config_path.display()
    );
    loop {
        std::thread::park_timeout(Duration::from_secs(3600));
    }
}

fn dispatch_http(
    service: &Arc<Mutex<Service>>,
    request: autobricks_pki::comm::HttpRequest,
) -> std::result::Result<autobricks_pki::comm::HttpResponse, String> {
    let request = autobricks_pki::server::routes::Request {
        method: request.method,
        path: request.path,
        headers: request.headers,
        body: request.body,
    };
    let response = autobricks_pki::server::routes::dispatch_public(
        &*service.lock().map_err(|_| "service lock failed")?,
        request,
    );
    let status = response
        .status
        .split_once(' ')
        .and_then(|(value, _)| value.parse().ok())
        .ok_or_else(|| "invalid PKI HTTP status".to_owned())?;
    Ok(autobricks_pki::comm::HttpResponse {
        status,
        content_type: response.content_type.to_owned(),
        headers: vec![("Cache-Control".to_owned(), "no-store".to_owned())],
        body: response.body,
    })
}

fn dispatch_message(
    service: &Arc<Mutex<Service>>,
    message: autobricks_pki::transport::management::Message,
    mtls: bool,
) -> Result<autobricks_pki::transport::management::Reply> {
    let request = message.into_request()?;
    Ok(autobricks_pki::transport::management::Reply::from(
        autobricks_pki::server::routes::dispatch_remote(
            &*service.lock().map_err(|_| "service lock failed")?,
            request,
            mtls,
        ),
    ))
}

fn dispatch_ipc(
    service: &Arc<Mutex<Service>>,
    payload: &str,
) -> std::result::Result<String, String> {
    let message = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    let reply = dispatch_message(service, message, true).map_err(|e| e.to_string())?;
    serde_json::to_string(&reply).map_err(|e| e.to_string())
}

fn dispatch_structured(
    service: &Arc<Mutex<Service>>,
    request: autobricks_pki::comm::StructuredRequest,
) -> std::result::Result<autobricks_pki::comm::StructuredResponse, String> {
    let mtls = !request.certificate.is_empty();
    let mut message: autobricks_pki::transport::management::Message =
        serde_json::from_slice(&request.metadata).map_err(|e| e.to_string())?;
    message.body = request.payload;
    let reply = dispatch_message(service, message, mtls).map_err(|e| e.to_string())?;
    let metadata = serde_json::to_vec(&serde_json::json!({
        "status":reply.status,
        "content_type":reply.content_type
    }))
    .map_err(|e| e.to_string())?;
    Ok(autobricks_pki::comm::StructuredResponse {
        metadata,
        payload: reply.body,
    })
}
