use crate::{
    Result,
    authorization::password,
    certificate::{
        profile::{LeafKind, LeafProfile},
        validity::Validity,
    },
    server::service::{Issued, Service, now},
};
use openssl::{asn1::Asn1Time, x509::X509};

impl Service {
    fn authentication_issuer(&self, admin: &[u8]) -> Result<crate::storage::database::Certificate> {
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing installation baseDomain")?,
        )?;
        let issuer_name = format!("auth.{base_domain}");
        match self.db.issuer(&issuer_name) {
            Ok(issuer) => Ok(issuer),
            Err(_) => {
                self.create_ca("auth", None, admin)?;
                Ok(self.db.issuer(&issuer_name)?)
            }
        }
    }

    pub fn issue_authentication_credential(&self, role: &str, admin: &[u8]) -> Result<Issued> {
        password::verify(&self.db, admin)?;
        let (common_name, purpose) = match role {
            "auth" => ("autobricks-auth-ipc", "urn:autobricks:ipc:auth"),
            "pki" => ("autobricks-pki-ipc", "urn:autobricks:ipc:pki"),
            _ => return Err("authentication credential role must be auth or pki".into()),
        };
        let issuer = self.authentication_issuer(admin)?;
        let profile = LeafProfile {
            kind: LeafKind::Client,
            common_name: common_name.into(),
            dns_names: vec![],
            ip_addresses: vec![],
            uri_sans: vec![purpose.into()],
            validity: Validity::new(now(), 47, Some(issuer.validity))?,
            extra: Default::default(),
        };
        let issued = self
            .db
            .transaction(|| self.create_inner(&issuer, &profile))?;
        let _ = self.reconcile();
        Ok(issued)
    }

    pub fn issue_administrator_certificate(&self, admin: &[u8]) -> Result<Issued> {
        password::verify(&self.db, admin)?;
        let issuer = self.authentication_issuer(admin)?;
        let profile = LeafProfile {
            kind: LeafKind::Client,
            common_name: "autobricks-administrator".into(),
            dns_names: vec![],
            ip_addresses: vec![],
            uri_sans: vec!["urn:autobricks:administrator".into()],
            validity: Validity::new(now(), 47, Some(issuer.validity))?,
            extra: Default::default(),
        };
        let issued = self
            .db
            .transaction(|| self.create_inner(&issuer, &profile))?;
        let _ = self.reconcile();
        Ok(issued)
    }

    pub(crate) fn authorize_administrator_certificate(&self, pem: &[u8]) -> Result<()> {
        let authorization = X509::from_pem(pem)?;
        let fingerprint = super::crypto::fingerprint(&authorization)?;
        let metadata = self.db.metadata(&fingerprint)?;
        if metadata.revoked_at.is_some() || metadata.kind != "client" {
            return Err("administrator certificate is not VALID".into());
        }
        let issuer = self.authentication_issuer_without_creation()?;
        if metadata.issuer.as_deref() != Some(issuer.fingerprint.as_str()) {
            return Err("administrator certificate was not issued by auth CA".into());
        }
        let issuer_certificate = X509::from_pem(issuer.pem.as_bytes())?;
        let issuer_key = issuer_certificate.public_key()?;
        if !authorization.verify(&issuer_key)? {
            return Err("administrator certificate signature is invalid".into());
        }
        let current = Asn1Time::from_unix(now())?;
        if authorization.not_before() > current || authorization.not_after() <= current {
            return Err("administrator certificate is outside its validity".into());
        }
        if !authorization.subject_alt_names().is_some_and(|names| {
            names
                .iter()
                .any(|name| name.uri() == Some("urn:autobricks:administrator"))
        }) {
            return Err("administrator certificate purpose is invalid".into());
        }
        Ok(())
    }

    fn authentication_issuer_without_creation(
        &self,
    ) -> Result<crate::storage::database::Certificate> {
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing installation baseDomain")?,
        )?;
        Ok(self.db.issuer(&format!("auth.{base_domain}"))?)
    }
}
