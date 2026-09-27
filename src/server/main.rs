use autobricks_pki::{
    Result,
    certificate::profile::Distribution,
    integration::dns::Dns,
    server::{config::Config, listener, service::Service},
    storage::{database::Database, worm::Worm},
};
use std::{
    env,
    net::TcpListener,
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
    let args: Vec<_> = env::args().skip(1).collect();
    if autobricks_pki::help::print_if_requested("abpkid", &args)? {
        return Ok(());
    }
    if !((args.len() == 2 || args.len() == 3) && args[0] == "init")
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
    let c = Config::environment()?;
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
    let mut origin = url::Url::parse(&origin)?;
    origin
        .set_port(Some(c.listeners.https_port))
        .map_err(|_| "invalid HTTPS origin")?;
    let distribution = Distribution::new(origin.as_str())?;
    let service = Service {
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
            autobricks_pki::integration::retention::days(&c.truelog_config)?,
        )?;
        println!("PKI initialized");
        return Ok(());
    }
    if let Err(error) = service.run_hourly_renewal(autobricks_pki::server::service::now()) {
        eprintln!("hourly renewal failed: {error}");
    }
    service.tls_config()?;
    let management_listener = TcpListener::bind(c.listeners.tls_address())?;
    let https_listener = TcpListener::bind(c.listeners.https_address())?;
    let service = Arc::new(Mutex::new(service));
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
        "abpkid {} management TLS={} public HTTPS={}",
        autobricks_pki::VERSION,
        management_listener.local_addr()?,
        https_listener.local_addr()?
    );
    listener::serve(management_listener, https_listener, service)
}
