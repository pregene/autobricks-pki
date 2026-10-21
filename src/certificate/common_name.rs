use crate::{Result, certificate::profile::LeafProfile, storage::database::Certificate};

pub use autobricks_certificate::common_name::{intermediate, leaf};

fn label(value: &str) -> bool {
    autobricks_certificate::common_name::label(value)
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
