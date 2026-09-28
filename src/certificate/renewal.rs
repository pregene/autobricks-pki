use crate::{
    Result,
    authorization::password,
    certificate::{profile::LeafProfile, renewal_response::RenewalResponse, validity::DAY},
    server::service::{Issued, Service, now},
};

impl Service {
    pub fn request_admin_renewal(&self, id: &str, admin: &[u8]) -> Result<RenewalResponse> {
        password::verify(&self.db, admin)?;
        self.mark_admin_renewal(id)
    }

    pub(crate) fn mark_admin_renewal(&self, id: &str) -> Result<RenewalResponse> {
        self.db.transaction(|| {
            let old = self.db.metadata(id)?;
            let timestamp = now();
            let days = match old.kind.as_str() {
                "intermediate" => 48,
                "server" | "client" | "server-and-client" => 7,
                _ => return Err("Root CA renewal is not supported".into()),
            };
            if old.revoked_at.is_some() {
                return Ok(RenewalResponse::state(409, "REVOKED", id));
            }
            if timestamp < old.validity.not_before || timestamp >= old.validity.not_after {
                return Err("certificate is outside its validity".into());
            }
            self.db.mark_superseded(id, timestamp)?;
            let started: i64 = self.db.conn.query_row(
                "SELECT superseded_at FROM certificates WHERE fingerprint=?",
                [id],
                |r| r.get(0),
            )?;
            let mut response = RenewalResponse::state(200, "SUPERSEDED", id);
            response.superseded_at = Some(started);
            response.revoke_at = Some(
                started
                    .checked_add(days * DAY)
                    .ok_or("retirement timestamp overflow")?,
            );
            Ok(response)
        })
    }

    pub fn renew_leaf_as_admin(&self, id: &str, admin: &[u8]) -> Result<RenewalResponse> {
        password::verify(&self.db, admin)?;
        if !matches!(
            self.db.metadata(id)?.kind.as_str(),
            "server" | "client" | "server-and-client"
        ) {
            return Err("leaf certificate fingerprint required".into());
        }
        self.mark_admin_renewal(id)
    }

    pub fn poll_renewal(&self, id: &str, token: &str) -> Result<RenewalResponse> {
        let old = self.db.metadata(id)?;
        self.authorize_download(&old, token)?;
        if old.revoked_at.is_some() {
            return Ok(RenewalResponse::state(409, "REVOKED", id));
        }
        if now() < old.validity.not_before || now() >= old.validity.not_after {
            return Err("certificate is outside its validity".into());
        }
        if old.validity.renewable(now()) {
            self.db.mark_superseded(id, now())?;
        }
        if !self.db.is_superseded(id)? {
            return Ok(RenewalResponse::state(200, "VALID", id));
        }
        let issued = self.renew(id, token)?;
        let mut response = RenewalResponse::state(200, "VALID", &issued.certificate.fingerprint);
        response.renewed = true;
        response.previous_fingerprint = Some(id.into());
        response.download_token = Some(issued.download_token);
        Ok(response)
    }

    pub fn renew(&self, id: &str, token: &str) -> Result<Issued> {
        let old = self.db.metadata(id)?;
        self.authorize_download(&old, token)?;
        let timestamp = now();
        if old.revoked_at.is_some()
            || timestamp < old.validity.not_before
            || timestamp >= old.validity.not_after
        {
            return Err("certificate is revoked or outside its validity".into());
        }
        if old.validity.renewable(timestamp) {
            self.db.mark_superseded(id, timestamp)?;
        }
        if !self.db.is_superseded(id)? {
            return Err("certificate is not awaiting renewal".into());
        }
        let mut profile: LeafProfile =
            serde_json::from_str(old.profile.as_deref().ok_or("missing leaf profile")?)?;
        let old_ca = self
            .db
            .metadata(old.issuer.as_deref().ok_or("missing issuer")?)?;
        let issuer = self.db.issuer(&old_ca.cn)?;
        if self.db.is_superseded(&issuer.fingerprint)? {
            return Err("replacement Intermediate CA is pending".into());
        }
        profile.validity = old.validity.renewed(timestamp, issuer.validity)?;
        let mut issued = self.db.transaction(|| {
            let issued = self.create_inner(&issuer, &profile)?;
            self.db.record_handover(
                &old.fingerprint,
                &issued.certificate.fingerprint,
                timestamp,
            )?;
            Ok(issued)
        })?;
        issued.integrations_pending = self.reconcile().is_err() || self.db.has_pending()?;
        Ok(issued)
    }
}
