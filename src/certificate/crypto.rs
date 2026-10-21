//! Dynamic Autobricks Certificate library boundary.

use crate::Result;
use autobricks_certificate::validity::Validity;
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

pub use autobricks_certificate::crypto::{fingerprint, serial};

pub fn ca(
    common_name: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    validity: Validity,
) -> Result<(X509, PKey<Private>)> {
    Ok(autobricks_certificate::dynamic::ca(
        common_name,
        issuer,
        validity,
    )?)
}

pub fn leaf(
    profile: &autobricks_certificate::profile::LeafProfile,
    issuer: &X509,
    issuer_key: &PKey<Private>,
    distribution: &autobricks_certificate::profile::Distribution,
    issuer_id: &str,
) -> Result<(X509, PKey<Private>)> {
    Ok(autobricks_certificate::dynamic::leaf(
        profile,
        issuer,
        issuer_key,
        distribution,
        issuer_id,
    )?)
}
