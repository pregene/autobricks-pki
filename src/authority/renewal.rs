use crate::{
    Result,
    authorization::password,
    certificate::{crypto, validity::DAY},
    server::service::{Service, now, record},
    storage::database::Certificate,
};
use openssl::{pkey::PKey, x509::X509};

impl Service {
    pub fn renew_intermediate(
        &self,
        fingerprint: &str,
        admin: &[u8],
    ) -> Result<crate::certificate::renewal_response::RenewalResponse> {
        password::verify(&self.db, admin)?;
        if self.db.metadata(fingerprint)?.kind != "intermediate" {
            return Err("Intermediate CA fingerprint required".into());
        }
        self.mark_admin_renewal(fingerprint)
    }

    pub(crate) fn renew_intermediate_internal(&self, fingerprint: &str) -> Result<Certificate> {
        self.db.transaction(|| {
            let metadata = self.db.metadata(fingerprint)?;
            let timestamp = now();
            if metadata.kind != "intermediate" {
                return Err("Intermediate CA fingerprint required".into());
            }
            if metadata.revoked_at.is_some()
                || timestamp < metadata.validity.not_before
                || timestamp >= metadata.validity.not_after
            {
                return Err("Intermediate CA is revoked or outside its validity".into());
            }
            if self.db.ca_has_successor(fingerprint)? {
                return Err("Intermediate CA already has a replacement".into());
            }
            let ca = self.db.get(fingerprint)?;
            let root = self.db.get(&self.db.root_id()?)?;
            let validity = ca.validity.renewed(timestamp, root.validity)?;
            if validity.not_after - validity.not_before > i64::from(self.intermediate_days()?) * DAY
            {
                return Err("stored Intermediate CA duration exceeds installation policy".into());
            }
            let rc = X509::from_pem(root.pem.as_bytes())?;
            let rk = PKey::private_key_from_pem(root.key_pem.as_bytes())?;
            let previous = X509::from_pem(ca.pem.as_bytes())?;
            let (cert, key) = crypto::ca_with_subject(
                &ca.cn,
                Some((&rc, &rk)),
                validity,
                PKey::private_key_from_pem(ca.key_pem.as_bytes())?,
                Some(previous.subject_name()),
            )?;
            let replacement = record(cert, key, "intermediate", Some(root.fingerprint), validity)?;
            self.db.insert(&replacement)?;
            self.db
                .record_handover(&ca.fingerprint, &replacement.fingerprint, timestamp)?;
            self.archive(&replacement, "intermediate-renewed")?;
            self.publish_crl(&replacement, timestamp)?;
            self.db.metadata(&replacement.fingerprint)
        })
    }
}
