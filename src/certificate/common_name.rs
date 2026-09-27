use crate::{Result, certificate::profile::LeafProfile, storage::database::Certificate};

pub fn leaf(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 24 || !label(value) {
        return Err("leaf CN must contain 1 to 24 ASCII letters, digits, or hyphens, with no leading or trailing hyphen".into());
    }
    Ok(value.to_ascii_lowercase())
}

pub fn intermediate<'a>(cn: &'a str, base_domain: &str) -> Result<&'a str> {
    let suffix = format!(".{base_domain}");
    let name = cn.strip_suffix(&suffix).unwrap_or(cn);
    if name.len() > 16 || !label(name) {
        return Err("Intermediate CA name must contain 1 to 16 ASCII letters, digits, or hyphens, excluding the baseDomain suffix".into());
    }
    Ok(name)
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn server_dns(
    profile: &mut LeafProfile,
    issuer: &Certificate,
    base_domain: &str,
) -> Result<()> {
    let intermediate = intermediate(&issuer.cn, base_domain)?;
    let host_label = format!("{intermediate}-{}", profile.common_name).to_ascii_lowercase();
    if !label(&host_label) {
        return Err("generated DNS label exceeds 63 characters".into());
    }
    let hostname = format!("{host_label}.{base_domain}");
    if hostname.len() > 253 {
        return Err("generated DNS name exceeds 253 characters".into());
    }
    if !profile.dns_names.is_empty()
        && (profile.dns_names.len() != 1 || !profile.dns_names[0].eq_ignore_ascii_case(&hostname))
    {
        return Err("DNS SAN must match <intermediate>-<cn>.<baseDomain>".into());
    }
    profile.dns_names = vec![hostname];
    Ok(())
}
