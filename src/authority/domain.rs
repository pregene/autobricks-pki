use crate::Result;
use std::io::Write;

pub const DEFAULT_BASE_DOMAIN: &str = "autobricks.internal";

pub fn validate(value: &str) -> Result<String> {
    let domain = value.trim().to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 24
        || domain.parse::<std::net::IpAddr>().is_ok()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("baseDomain must be a DNS domain of at most 24 ASCII characters".into());
    }
    Ok(domain)
}

pub fn installation_input(argument: Option<&str>) -> Result<String> {
    if let Some(domain) = argument {
        return validate(domain);
    }
    eprint!("Base domain [{DEFAULT_BASE_DOMAIN}]: ");
    std::io::stderr().flush()?;
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input)? == 0 {
        return Err(
            "baseDomain input is required; pass BASE_DOMAIN for unattended initialization".into(),
        );
    }
    validate(if input.trim().is_empty() {
        DEFAULT_BASE_DOMAIN
    } else {
        input.trim()
    })
}
