use crate::{
    Result,
    authority::DEFAULT_ISSUERS,
    authorization::password,
    certificate::{
        ca_subject::CaSubject,
        crypto,
        profile::{LeafKind, LeafProfile},
        validity::{LEAF_DAYS, Validity},
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
        retention_days: u32,
        ca_subject: CaSubject,
    ) -> Result<()> {
        let ca_subject = ca_subject.validate()?;
        let base_domain = crate::authority::domain::validate(base_domain)?;
        let policy = super::validity::Policy::new(retention_days)?;
        if self.db.has_certificates()? {
            return Err("database already initialized".into());
        }
        self.db.transaction(|| {
            password::set(&self.db, admin)?;
            self.db
                .set_setting("ca_validity_policy", &serde_json::to_vec(&policy)?)?;
            self.db.set_setting("base_domain", base_domain.as_bytes())?;
            self.db
                .set_setting("ca_subject", &serde_json::to_vec(&ca_subject)?)?;
            let start = now();
            let validity = Validity {
                not_before: start,
                not_after: 253402300799,
            };
            let (cert, key) =
                crypto::ca(&format!("pki.{base_domain}"), None, validity, &ca_subject)?;
            let root = record(cert, key, "root", None, validity)?;
            self.db.insert(&root)?;
            self.archive(&root, "root-created")?;
            let root_cert = X509::from_pem(root.pem.as_bytes())?;
            let root_key = PKey::private_key_from_pem(root.key_pem.as_bytes())?;
            for name in DEFAULT_ISSUERS {
                let validity = Validity::new(start, policy.intermediate_days, Some(root.validity))?;
                let (cert, key) = crypto::ca(
                    &format!("{}.{base_domain}", name.name()),
                    Some((&root_cert, &root_key)),
                    validity,
                    &ca_subject,
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
                extra: Default::default(),
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
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing baseDomain")?,
        )?;
        let name = crate::certificate::common_name::intermediate(cn, &base_domain)?;
        let common_name = format!("{name}.{base_domain}");
        let maximum = self.intermediate_days()?;
        let days = days.unwrap_or(maximum);
        if days == 0 || days > maximum {
            return Err(format!("Intermediate CA days must be between 1 and {maximum}").into());
        }
        let exists: bool = self.db.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM certificates WHERE kind='intermediate' AND cn=?1)",
            [&common_name],
            |row| row.get(0),
        )?;
        if exists {
            return Err("Intermediate CA already exists".into());
        }
        let start = now();
        let root = self.root()?;
        let validity = Validity::new(start, days, Some(root.validity))?;
        let root_cert = X509::from_pem(root.pem.as_bytes())?;
        let root_key = PKey::private_key_from_pem(root.key_pem.as_bytes())?;
        let ca_subject: CaSubject =
            serde_json::from_slice(&self.db.setting("ca_subject")?.ok_or("missing CA subject")?)?;
        let (cert, key) = crypto::ca(
            &common_name,
            Some((&root_cert, &root_key)),
            validity,
            &ca_subject,
        )?;
        let created = record(cert, key, "intermediate", Some(root.fingerprint), validity)?;
        self.db.transaction(|| {
            self.db.insert(&created)?;
            self.archive(&created, "intermediate-created")?;
            self.publish_crl(&created, start)
        })?;
        self.reconcile()?;
        self.db.metadata(&created.fingerprint)
    }
    pub fn root(&self) -> Result<Certificate> {
        self.db.get(&self.db.root_id()?)
    }
    pub fn public_root(&self) -> Result<Certificate> {
        self.db.public_certificate(&self.db.root_id()?)
    }
    pub fn chain(&self, issuer: &str) -> Result<Vec<u8>> {
        let ca = self.db.public_certificate(&self.db.issuer_id(issuer)?)?;
        let root = self
            .db
            .public_certificate(ca.issuer.as_deref().ok_or("missing root")?)?;
        Ok(format!("{}{}", ca.pem, root.pem).into_bytes())
    }
    pub fn maintain(&self) -> Result<()> {
        self.db.mark_due_leaves(now())?;
        for candidate in self.db.due_intermediates(now())? {
            let ca = candidate;
            if ca.revoked_at.is_none()
                && (ca.validity.intermediate_renewable(now())
                    || self.db.is_superseded(&ca.fingerprint)?)
                && !self.db.ca_has_successor(&ca.fingerprint)?
            {
                self.db.mark_superseded(&ca.fingerprint, now())?;
                self.renew_intermediate_internal(&ca.fingerprint)?;
            }
        }
        if let Some(id) = self.db.setting("tls_certificate")? {
            let current = self.db.metadata(&String::from_utf8(id)?)?;
            if (current.validity.renewable(now()) || self.db.is_superseded(&current.fingerprint)?)
                && current.revoked_at.is_none()
                && now() >= current.validity.not_before
                && now() < current.validity.not_after
            {
                let mut profile: LeafProfile =
                    serde_json::from_str(current.profile.as_deref().ok_or("missing TLS profile")?)?;
                let old = self
                    .db
                    .metadata(current.issuer.as_deref().ok_or("missing TLS issuer")?)?;
                let issuer = self.db.issuer(&old.cn)?;
                profile.validity = current.validity.renewed(now(), issuer.validity)?;
                self.db.transaction(|| {
                    let issued = self.create_inner(&issuer, &profile)?;
                    self.db.record_handover(
                        &current.fingerprint,
                        &issued.certificate.fingerprint,
                        now(),
                    )?;
                    self.db
                        .set_setting("tls_certificate", issued.certificate.fingerprint.as_bytes())
                })?;
            }
        }
        self.reconcile()
    }
    pub fn tls_identity(&self) -> Result<crate::server::service::TlsIdentity> {
        let id = String::from_utf8(
            self.db
                .setting("tls_certificate")?
                .ok_or("PKI is not initialized")?,
        )?;
        let cert = self.db.get(&id)?;
        if cert.revoked_at.is_some() || now() >= cert.validity.not_after {
            return Err("PKI TLS certificate is revoked or expired".into());
        }
        let certificate = cert.pem.as_bytes().to_vec();
        let mut chain = certificate.clone();
        chain.extend(self.chain(cert.issuer.as_deref().ok_or("missing TLS issuer")?)?);
        Ok(crate::server::service::TlsIdentity {
            certificate,
            chain,
            key: cert.key_pem.into_bytes(),
        })
    }
}
