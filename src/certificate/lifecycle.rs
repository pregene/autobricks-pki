use crate::{
    Result,
    certificate::{
        crypto,
        profile::{LeafKind, LeafProfile},
    },
    integration::dns,
    server::service::{Create, Issued, Service, now, record},
    storage::database::Certificate,
};
use openssl::{
    hash::{MessageDigest, hash},
    memcmp,
    pkey::PKey,
    rand::rand_bytes,
    x509::X509,
};

impl Service {
    pub fn create(&self, mut request: Create) -> Result<Issued> {
        let issuer = self.db.issuer(&request.issuer)?;
        request.profile.common_name = super::common_name::leaf(&request.profile.common_name)?;
        if request.profile.kind.is_server() {
            let domain = String::from_utf8(
                self.db
                    .setting("base_domain")?
                    .ok_or("missing installation baseDomain")?,
            )?;
            super::common_name::server_dns(&mut request.profile, &issuer, &domain)?;
        }
        let mut issued = self.db.transaction(|| {
            let duplicate: bool = self.db.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM certificates WHERE kind NOT IN ('root','intermediate') AND lower(cn)=?)",
                [&request.profile.common_name], |row| row.get(0))?;
            if duplicate {
                return Err("leaf CN already exists; use renewal for an existing certificate".into());
            }
            for certificate in self.db.all()?.iter().filter(|c| c.profile.is_some()) {
                let previous: LeafProfile = serde_json::from_str(certificate.profile.as_deref().ok_or("missing profile")?)?;
                if request.profile.kind.is_server() && previous.kind.is_server()
                    && previous.dns_names.iter().any(|name| request.profile.dns_names.iter().any(|requested| requested.eq_ignore_ascii_case(name)))
                {
                    return Err("generated DNS name is already assigned to another certificate; use renewal".into());
                }
            }
            self.create_inner(&issuer, &request.profile)
        })?;
        issued.integrations_pending = self.reconcile().is_err();
        Ok(issued)
    }
    pub(crate) fn create_inner(
        &self,
        issuer: &Certificate,
        profile: &LeafProfile,
    ) -> Result<Issued> {
        profile.validate(issuer.validity)?;
        let records = dns::records(profile)?;
        let cert = X509::from_pem(issuer.pem.as_bytes())?;
        let key = PKey::private_key_from_pem(issuer.key_pem.as_bytes())?;
        let (cert, key) = crypto::leaf(
            profile,
            &cert,
            &key,
            &self.distribution,
            &issuer.fingerprint,
        )?;
        let kind = match profile.kind {
            LeafKind::Server => "server",
            LeafKind::Client => "client",
            LeafKind::ServerAndClient => "server-and-client",
        };
        let mut c = record(
            cert,
            key,
            kind,
            Some(issuer.fingerprint.clone()),
            profile.validity,
        )?;
        c.profile = Some(serde_json::to_string(profile)?);
        let mut token = [0u8; 32];
        rand_bytes(&mut token)?;
        let token: String = token.iter().map(|b| format!("{b:02x}")).collect();
        c.download_hash = Some(hash(MessageDigest::sha256(), token.as_bytes())?.to_vec());
        self.db.insert(&c)?;
        self.archive(&c, "certificate-created")?;
        for record in records {
            self.db.enqueue("dns", &serde_json::to_string(&record)?)?;
        }
        Ok(Issued {
            certificate: c,
            download_token: token,
            integrations_pending: true,
        })
    }
    pub fn authorize_download(&self, c: &Certificate, token: &str) -> Result<()> {
        let expected = c
            .download_hash
            .as_ref()
            .ok_or("CA private keys cannot be downloaded")?;
        let actual = hash(MessageDigest::sha256(), token.as_bytes())?;
        if expected.len() != actual.len() || !memcmp::eq(expected, actual.as_ref()) {
            return Err("invalid certificate access token".into());
        }
        Ok(())
    }
    pub fn download(&self, id: &str, token: &str) -> Result<Vec<u8>> {
        let c = self.db.get(id)?;
        self.authorize_download(&c, token)?;
        let chain = self.chain(c.issuer.as_deref().ok_or("missing issuer")?)?;
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for (name, data) in [
            ("certificate.pem", c.pem.as_bytes()),
            ("private-key.pem", c.key_pem.as_bytes()),
            ("trust-chain", chain.as_slice()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            h.set_cksum();
            tar.append_data(&mut h, name, data)?;
        }
        Ok(tar.into_inner()?.finish()?)
    }
    pub fn renew(&self, id: &str, token: &str) -> Result<Issued> {
        let old = self.db.get(id)?;
        self.authorize_download(&old, token)?;
        if old.revoked_at.is_some() || !old.validity.renewable(now()) {
            return Err("certificate is revoked or outside renewal window".into());
        }
        let mut profile: LeafProfile =
            serde_json::from_str(old.profile.as_deref().ok_or("missing leaf profile")?)?;
        let old_ca = self
            .db
            .get(old.issuer.as_deref().ok_or("missing issuer")?)?;
        let issuer = self
            .db
            .all()?
            .into_iter()
            .filter(|c| c.kind == "intermediate" && c.cn == old_ca.cn)
            .max_by_key(|c| c.validity.not_after)
            .ok_or("missing issuer")?;
        profile.validity = old.validity.renewed(now(), issuer.validity)?;
        let mut issued = self
            .db
            .transaction(|| self.create_inner(&issuer, &profile))?;
        issued.integrations_pending = self.reconcile().is_err();
        Ok(issued)
    }
}
