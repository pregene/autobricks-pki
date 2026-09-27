use crate::{
    Result,
    certificate::{
        crypto,
        profile::{Distribution, LeafProfile},
        validity::Validity,
    },
    integration::dns::Dns,
    storage::{
        database::{Certificate, Database},
        worm::Worm,
    },
};
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub issuer: String,
    pub profile: LeafProfile,
}
#[derive(Serialize)]
pub struct Issued {
    pub certificate: Certificate,
    pub download_token: String,
    pub integrations_pending: bool,
}
pub struct Service {
    pub db: Database,
    pub distribution: Distribution,
    pub worm: Worm,
    pub dns: Dns,
    pub truelog: crate::integration::truelog::TrueLog,
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub(crate) fn record(
    cert: X509,
    key: PKey<Private>,
    kind: &str,
    issuer: Option<String>,
    validity: Validity,
) -> Result<Certificate> {
    Ok(Certificate {
        fingerprint: crypto::fingerprint(&cert)?,
        cn: cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .ok_or("missing CN")?
            .data()
            .to_string()?,
        kind: kind.into(),
        issuer,
        serial: crypto::serial(&cert)?,
        validity,
        pem: String::from_utf8(cert.to_pem()?)?,
        key_pem: String::from_utf8(key.private_key_to_pem_pkcs8()?)?,
        revoked_at: None,
        profile: None,
        download_hash: None,
    })
}
