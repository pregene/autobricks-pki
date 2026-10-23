use crate::{
    Result,
    authorization::password,
    certificate::{
        profile::{LeafKind, LeafProfile},
        validity::Validity,
    },
    server::service::{Service, now},
};
use openssl::{asn1::Asn1Time, x509::X509};

const URI_PREFIX: &str = "urn:autobricks:certificate:";

impl Service {
    pub fn issue_renewal_authorization(&self, targets: &[String], admin: &[u8]) -> Result<Vec<u8>> {
        password::verify(&self.db, admin)?;
        if targets.is_empty() || targets.len() > 64 {
            return Err("certificate requires 1 to 64 fingerprints".into());
        }
        let mut normalized = Vec::with_capacity(targets.len());
        for target in targets {
            if target.len() != 64 || !target.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("invalid certificate fingerprint".into());
            }
            let target = target.to_ascii_lowercase();
            if normalized.contains(&target) {
                return Err("duplicate certificate fingerprint".into());
            }
            let target_certificate = self.db.metadata(&target)?;
            if !matches!(
                target_certificate.kind.as_str(),
                "server" | "client" | "server-and-client" | "leaf"
            ) {
                return Err("leaf certificate fingerprint required".into());
            }
            if target_certificate.revoked_at.is_some() {
                return Err("renewal target is revoked".into());
            }
            normalized.push(target);
        }
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing installation baseDomain")?,
        )?;
        let issuer = self.db.issuer(&format!("cert.{base_domain}"))?;
        let timestamp = now();
        let validity = Validity::new(timestamp, 47, Some(issuer.validity))?;
        let profile = LeafProfile {
            kind: LeafKind::Client,
            common_name: format!("renew-{}", &normalized[0][..16]),
            dns_names: vec![],
            ip_addresses: vec![],
            uri_sans: normalized
                .iter()
                .map(|target| format!("{URI_PREFIX}{target}"))
                .collect(),
            validity,
            extra: Default::default(),
        };
        let issued = self
            .db
            .transaction(|| self.create_inner(&issuer, &profile))?;
        let _ = self.reconcile();
        Ok(issued.certificate.pem.into_bytes())
    }

    pub(crate) fn authorize_renewal_certificate(&self, target: &str, pem: &[u8]) -> Result<()> {
        if target.len() != 64 || !target.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid certificate fingerprint".into());
        }
        let authorization = X509::from_pem(pem)?;
        let fingerprint = super::crypto::fingerprint(&authorization)?;
        let metadata = self.db.metadata(&fingerprint)?;
        if metadata.revoked_at.is_some() || metadata.kind != "client" {
            return Err("renewal authorization certificate is not VALID".into());
        }
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing installation baseDomain")?,
        )?;
        let issuer = self.db.issuer(&format!("cert.{base_domain}"))?;
        if metadata.issuer.as_deref() != Some(issuer.fingerprint.as_str()) {
            return Err("renewal authorization certificate was not issued by cert CA".into());
        }
        let issuer_certificate = X509::from_pem(issuer.pem.as_bytes())?;
        let issuer_key = issuer_certificate.public_key()?;
        if !authorization.verify(&issuer_key)? {
            return Err("renewal authorization certificate signature is invalid".into());
        }
        let current = Asn1Time::from_unix(now())?;
        if authorization.not_before() > current || authorization.not_after() <= current {
            return Err("renewal authorization certificate is outside its validity".into());
        }
        let expected = format!("{URI_PREFIX}{}", target.to_ascii_lowercase());
        let permitted = authorization.subject_alt_names().is_some_and(|names| {
            names
                .iter()
                .any(|name| name.uri() == Some(expected.as_str()))
        });
        if !permitted {
            return Err(
                "renewal authorization certificate does not permit this fingerprint".into(),
            );
        }
        Ok(())
    }
}
