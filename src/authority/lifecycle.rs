use crate::{
    Result,
    authority::DEFAULT_ISSUERS,
    authorization::password,
    certificate::{
        crypto,
        profile::{LeafKind, LeafProfile},
        validity::{INTERMEDIATE_DAYS, LEAF_DAYS, Validity},
    },
    server::service::{Service, now, record},
    storage::database::Certificate,
};
use openssl::{pkey::PKey, x509::X509};

impl Service {
    pub fn initialize(
        &self,
        admin: &[u8],
        hostname: &str,
        ip: std::net::IpAddr,
        base_domain: &str,
    ) -> Result<()> {
        let base_domain = crate::authority::domain::validate(base_domain)?;
        if !self.db.all()?.is_empty() {
            return Err("database already initialized".into());
        }
        self.db.transaction(|| {
            password::set(&self.db, admin)?;
            self.db.set_setting("base_domain", base_domain.as_bytes())?;
            let start = now();
            let validity = Validity {
                not_before: start,
                not_after: 253402300799,
            };
            let (cert, key) = crypto::ca(&format!("pki.{base_domain}"), None, validity)?;
            let root = record(cert, key, "root", None, validity)?;
            self.db.insert(&root)?;
            self.archive(&root, "root-created")?;
            let root_cert = X509::from_pem(root.pem.as_bytes())?;
            let root_key = PKey::private_key_from_pem(root.key_pem.as_bytes())?;
            for name in DEFAULT_ISSUERS {
                let validity = Validity::new(start, INTERMEDIATE_DAYS, Some(root.validity))?;
                let (cert, key) = crypto::ca(
                    &format!("{}.{base_domain}", name.name()),
                    Some((&root_cert, &root_key)),
                    validity,
                )?;
                let c = record(
                    cert,
                    key,
                    "intermediate",
                    Some(root.fingerprint.clone()),
                    validity,
                )?;
                self.db.insert(&c)?;
                self.archive(&c, "intermediate-created")?;
                self.publish_crl(&c, start)?;
            }
            let issuer = self.db.issuer(&format!("app.{base_domain}"))?;
            let profile = LeafProfile {
                kind: LeafKind::Server,
                common_name: "pki".into(),
                dns_names: vec![hostname.into()],
                ip_addresses: vec![ip],
                uri_sans: vec!["urn:autobricks:purpose:pki".into()],
                validity: Validity::new(start, LEAF_DAYS, Some(issuer.validity))?,
            };
            let issued = self.create_inner(&issuer, &profile)?;
            self.db
                .set_setting("tls_certificate", issued.certificate.fingerprint.as_bytes())?;
            Ok(())
        })?;
        self.reconcile()?;
        Ok(())
    }
    pub fn create_ca(&self, cn: &str, days: Option<u32>, admin: &[u8]) -> Result<Certificate> {
        password::verify(&self.db, admin)?;
        let normalized = cn.to_ascii_lowercase();
        let cn = normalized.as_str();
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing installation baseDomain")?,
        )?;
        crate::certificate::common_name::intermediate(cn, &base_domain)?;
        if cn.is_empty()
            || cn.chars().any(char::is_control)
            || self
                .db
                .all()?
                .iter()
                .any(|c| c.kind == "intermediate" && c.cn == cn)
        {
            return Err("invalid or duplicate Intermediate CA name".into());
        }
        let c = self.db.transaction(|| {
            let root = self.root()?;
            let validity = Validity::new(
                now(),
                days.unwrap_or(INTERMEDIATE_DAYS),
                Some(root.validity),
            )?;
            let rc = X509::from_pem(root.pem.as_bytes())?;
            let rk = PKey::private_key_from_pem(root.key_pem.as_bytes())?;
            let (cert, key) = crypto::ca(cn, Some((&rc, &rk)), validity)?;
            let c = record(cert, key, "intermediate", Some(root.fingerprint), validity)?;
            self.db.insert(&c)?;
            self.archive(&c, "intermediate-created")?;
            self.publish_crl(&c, now())?;
            Ok(c)
        })?;
        let _ = self.reconcile();
        Ok(c)
    }
    pub fn root(&self) -> Result<Certificate> {
        self.db
            .all()?
            .into_iter()
            .find(|c| c.kind == "root")
            .ok_or_else(|| "root CA is not initialized".into())
    }
    pub fn chain(&self, issuer: &str) -> Result<Vec<u8>> {
        let ca = self.db.issuer(issuer)?;
        let root = self.db.get(ca.issuer.as_deref().ok_or("missing root")?)?;
        Ok(format!("{}{}", ca.pem, root.pem).into_bytes())
    }
    pub fn maintain(&self) -> Result<()> {
        for ca in self
            .db
            .all()?
            .into_iter()
            .filter(|c| c.kind == "intermediate")
        {
            let _ = self.crl(&ca.fingerprint)?;
            if ca.validity.renewable(now())
                && !self
                    .db
                    .all()?
                    .iter()
                    .any(|c| c.cn == ca.cn && c.validity.not_after > ca.validity.not_after)
            {
                self.db.transaction(|| {
                    let root = self.root()?;
                    let rc = X509::from_pem(root.pem.as_bytes())?;
                    let rk = PKey::private_key_from_pem(root.key_pem.as_bytes())?;
                    let validity = Validity::new(now(), INTERMEDIATE_DAYS, Some(root.validity))?;
                    let previous = X509::from_pem(ca.pem.as_bytes())?;
                    let (cert, key) = crypto::ca_with_subject(
                        &ca.cn,
                        Some((&rc, &rk)),
                        validity,
                        PKey::private_key_from_pem(ca.key_pem.as_bytes())?,
                        Some(previous.subject_name()),
                    )?;
                    let replacement =
                        record(cert, key, "intermediate", Some(root.fingerprint), validity)?;
                    self.db.insert(&replacement)?;
                    self.archive(&replacement, "intermediate-renewed")?;
                    self.publish_crl(&replacement, now())
                })?;
            }
        }
        if let Some(id) = self.db.setting("tls_certificate")? {
            let current = self.db.get(&String::from_utf8(id)?)?;
            if current.validity.renewable(now()) && current.revoked_at.is_none() {
                let mut profile: LeafProfile =
                    serde_json::from_str(current.profile.as_deref().ok_or("missing TLS profile")?)?;
                let old = self
                    .db
                    .get(current.issuer.as_deref().ok_or("missing TLS issuer")?)?;
                let issuer = self.db.issuer(&old.cn)?;
                profile.validity = Validity::new(now(), LEAF_DAYS, Some(issuer.validity))?;
                self.db.transaction(|| {
                    let issued = self.create_inner(&issuer, &profile)?;
                    self.db
                        .set_setting("tls_certificate", issued.certificate.fingerprint.as_bytes())
                })?;
            }
        }
        self.reconcile()
    }
    pub fn tls_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>> {
        let id = String::from_utf8(
            self.db
                .setting("tls_certificate")?
                .ok_or("PKI is not initialized")?,
        )?;
        let cert = self.db.get(&id)?;
        if cert.revoked_at.is_some() || now() >= cert.validity.not_after {
            return Err("PKI TLS certificate is revoked or expired".into());
        }
        let mut chain = cert.pem.as_bytes().to_vec();
        chain.extend(self.chain(cert.issuer.as_deref().ok_or("missing TLS issuer")?)?);
        crate::transport::tls::server(&chain, cert.key_pem.as_bytes())
    }
}
