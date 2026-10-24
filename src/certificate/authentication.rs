use crate::{
    Result,
    authorization::password,
    certificate::{
        profile::{LeafKind, LeafProfile},
        validity::Validity,
    },
    server::service::{Issued, Service, now},
};

impl Service {
    pub fn issue_authentication_credential(&self, role: &str, admin: &[u8]) -> Result<Issued> {
        password::verify(&self.db, admin)?;
        let (common_name, purpose) = match role {
            "auth" => ("autobricks-auth-ipc", "urn:autobricks:ipc:auth"),
            "pki" => ("autobricks-pki-ipc", "urn:autobricks:ipc:pki"),
            _ => return Err("authentication credential role must be auth or pki".into()),
        };
        let base_domain = String::from_utf8(
            self.db
                .setting("base_domain")?
                .ok_or("missing installation baseDomain")?,
        )?;
        let issuer_name = format!("auth.{base_domain}");
        let issuer = match self.db.issuer(&issuer_name) {
            Ok(issuer) => issuer,
            Err(_) => {
                self.create_ca("auth", None, admin)?;
                self.db.issuer(&issuer_name)?
            }
        };
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
}
