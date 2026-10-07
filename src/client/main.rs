use autobricks_pki::{Result, client};
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
};
fn main() {
    if let Err(e) = run() {
        eprintln!("abpki-cli: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut args: Vec<_> = env::args().skip(1).collect();
    if autobricks_pki::help::print_if_requested("abpki-cli", &args)? {
        return Ok(());
    }
    let command = args.remove(0);
    #[cfg(target_os = "macos")]
    if command == "configure" {
        return client::macos::configure(&args);
    }
    if command == "create-ca" {
        return Err(
            "Not implemented: additional Intermediate CA creation is unavailable in version 1.0"
                .into(),
        );
    }
    if command == "daemon" {
        if args.len() != 2 || args[0] != "--config" {
            return Err("daemon requires --config PATH".into());
        }
        return client::daemon::serve(std::path::Path::new(&args[1]));
    }
    let mut admin = None;
    if let Some(pos) = args.iter().position(|a| a == "--pass") {
        args.remove(pos);
        admin = Some(if pos < args.len() {
            args.remove(pos)
        } else {
            client::credentials::prompt()?
        });
    }
    let admin_renewal = command == "renew" && admin.is_some();
    if admin.is_some() && !matches!(command.as_str(), "revoke" | "renew" | "create-ca") {
        return Err("--pass is only supported by administrator operations".into());
    }
    if matches!(command.as_str(), "create-ca" | "revoke") && admin.is_none() {
        return Err("--pass is required for this command".into());
    }

    if matches!(command.as_str(), "list" | "list-ca") {
        let filter = match args.as_slice() {
            [] => autobricks_pki::client::models::ListFilter::Valid,
            [value] => autobricks_pki::client::models::ListFilter::parse(value)?,
            _ => return Err("invalid list arguments; see list --help".into()),
        };
        let socket = env::var("ABPKI_SOCKET").unwrap_or_else(|_| client::daemon::SOCKET.into());
        return client::listing::print_all(
            std::path::Path::new(&socket),
            &command,
            filter,
            &mut std::io::stdout().lock(),
        );
    }
    let mut method = "GET";
    let mut body = vec![];
    let mut output = None;
    let path = match command.as_str() {
        "root" if args.is_empty() => {
            output = Some("root.crt".to_owned());
            "/root".to_owned()
        }
        "chain" if args.len() == 1 => {
            output = Some("trust-chain".to_owned());
            format!("/api/chain/{}", client::segment(&args[0])?)
        }
        "check" | "info" if args.len() == 1 => {
            format!("/api/{command}/{}", client::segment(&args[0])?)
        }
        "download" if args.len() == 2 => {
            output = Some(format!("{}.tar.gz", args[1]));
            format!("/api/download/{}", client::segment(&args[0])?)
        }
        "create" | "create-ca" if args.is_empty() => {
            method = "POST";
            std::io::stdin().take(1_048_577).read_to_end(&mut body)?;
            if body.len() > 1_048_576 {
                return Err("request exceeds limit".into());
            }
            format!("/api/{command}")
        }
        "revoke" | "renew" if args.len() == 1 => {
            method = "POST";
            body = serde_json::to_vec(&serde_json::json!({"fingerprint":args[0]}))?;
            if admin_renewal {
                "/api/renew-admin".to_owned()
            } else {
                format!("/api/{command}")
            }
        }
        _ => return Err("invalid command or arguments; see --help".into()),
    };
    let credential = if command == "revoke" || admin_renewal {
        admin
    } else if matches!(command.as_str(), "download" | "renew") {
        Some(client::credentials::load(&args[0])?)
    } else {
        None
    };
    let socket = env::var("ABPKI_SOCKET").unwrap_or_else(|_| client::daemon::SOCKET.into());
    let mut response = client::daemon::call(
        std::path::Path::new(&socket),
        &autobricks_pki::transport::management::Message {
            method: method.into(),
            path,
            content_type: "application/json".into(),
            credential,
            body,
        },
    )?;
    let save_token = command == "create"
        || (command == "renew"
            && serde_json::from_slice::<serde_json::Value>(&response)?["renewed"] == true);
    if save_token && let Err(error) = client::credentials::save_response(&response) {
        // Preserve the successful issuance response for credential recovery.
        std::io::stdout().write_all(&response)?;
        return Err(format!("certificate issued but local credential save failed: {error}").into());
    }
    if matches!(command.as_str(), "create" | "renew") {
        let mut public: serde_json::Value = serde_json::from_slice(&response)?;
        if let Some(object) = public.as_object_mut() {
            object.remove("download_token");
        }
        response = serde_json::to_vec(&public)?;
    }
    if matches!(command.as_str(), "list" | "list-ca") {
        print!("{}", client::listing::render(&response)?);
        return Ok(());
    }
    if let Some(path) = output {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&response)?;
        file.sync_all()?;
        println!("{path}");
    } else {
        std::io::stdout().write_all(&response)?;
        println!();
    }
    Ok(())
}
