use autobricks_pki::{Result, client};
use std::{
    env,
    fs::{self, OpenOptions},
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
    if args == ["--version"] {
        println!("abpki-cli {}", autobricks_pki::VERSION);
        return Ok(());
    }
    if args.is_empty() || args == ["--help"] {
        println!(
            "Usage: abpki-cli COMMAND [ARGUMENTS]\nCommands: create, create-ca --pass [PASSWORD], revoke FINGERPRINT --pass [PASSWORD], renew FINGERPRINT, check FINGERPRINT, list-ca, list, download FINGERPRINT TARGET, root, chain ISSUER\ncreate and create-ca read JSON from stdin.\nConnection: ABPKI_SERVER, ABPKI_TRUST_FILE, ABPKI_HTTPS_PORT\nCredentials: ABPKI_ADMIN_PASSWORD, ABPKI_ACCESS_TOKEN"
        );
        return Ok(());
    }
    let command = args.remove(0);
    let mut admin = None;
    if let Some(pos) = args.iter().position(|a| a == "--pass") {
        args.remove(pos);
        admin = Some(if pos < args.len() {
            args.remove(pos)
        } else {
            env::var("ABPKI_ADMIN_PASSWORD")?
        });
    }
    if matches!(command.as_str(), "create-ca" | "revoke") && admin.is_none() {
        return Err("--pass is required for this command".into());
    }
    let token = env::var("ABPKI_ACCESS_TOKEN").ok();
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
            format!("/api/chain/{}", client::segment(&args[0]))
        }
        "list-ca" | "list" if args.is_empty() => format!("/api/{command}"),
        "check" if args.len() == 1 => format!("/api/check/{}", client::segment(&args[0])),
        "download" if args.len() == 2 => {
            output = Some(format!("{}.tar.gz", args[1]));
            format!("/api/download/{}", client::segment(&args[0]))
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
            format!("/api/{command}")
        }
        _ => return Err("invalid command or arguments; see --help".into()),
    };
    let credential = if matches!(command.as_str(), "create-ca" | "revoke") {
        admin.as_deref()
    } else if matches!(command.as_str(), "download" | "renew") {
        Some(token.as_deref().ok_or("ABPKI_ACCESS_TOKEN is required")?)
    } else {
        None
    };
    let origin = env::var("ABPKI_SERVER")?;
    let trust = fs::read(env::var("ABPKI_TRUST_FILE")?)?;
    let response = if command == "root" {
        let port = env::var("ABPKI_HTTPS_PORT")
            .unwrap_or_else(|_| "5546".into())
            .parse()?;
        client::request(
            &client::public_origin(&origin, port)?,
            &trust,
            method,
            &path,
            &body,
            credential,
        )?
    } else {
        client::management_request(&origin, &trust, method, &path, &body, credential)?
    };
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
