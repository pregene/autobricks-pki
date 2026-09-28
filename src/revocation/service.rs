use crate::{
    Result,
    authorization::password,
    revocation,
    server::service::{Service, now},
    storage::database::Certificate,
};
use rusqlite::params;

impl Service {
    pub fn revoke(&self, id: &str, admin: &[u8]) -> Result<()> {
        password::verify(&self.db, admin)?;
        self.db.transaction(|| {
            let (kind, revoked_at): (String, Option<i64>) = self.db.conn.query_row(
                "SELECT kind,revoked_at FROM certificates WHERE fingerprint=?", [id],
                |row| Ok((row.get(0)?,row.get(1)?)))?;
            if kind == "root" || kind == "intermediate" {
                return Err("this operation revokes leaf certificates only".into());
            }
            if revoked_at.is_some() { return Ok(()); }
            let timestamp = now();
            self.db.conn.execute("UPDATE certificates SET valid='REVOKED',revoked_at=? WHERE fingerprint=?", params![timestamp,id])?;
            let issuer: String = self.db.conn.query_row("SELECT issuer FROM certificates WHERE fingerprint=?", [id], |row| row.get(0))?;
            let lineage = self.db.crl_issuers(&issuer)?;
            let identity = lineage.first().ok_or("empty CA lineage")?;
            let pending: bool = self.db.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE kind='crl' AND payload=? AND done=0)",
                [identity], |r| r.get(0))?;
            if !pending {
                self.db.enqueue("crl", identity)?;
            }
            self.db.enqueue("audit", &serde_json::json!({"event":"certificate-revoked","fingerprint":id,"timestamp":timestamp}).to_string())?;
            Ok(())
        })?;
        let publication = (|| -> Result<()> {
            let certificate = self.db.metadata(id)?;
            self.publish_pending_crl(certificate.issuer.as_deref().ok_or("missing issuer")?)
        })();
        if let Err(error) = publication {
            eprintln!("certificate revoked; CRL publication pending: {error}");
        }
        if let Err(error) = self.reconcile() {
            eprintln!("certificate revoked; publication or audit pending: {error}");
        }
        Ok(())
    }
    pub(crate) fn publish_pending_crl(&self, id: &str) -> Result<()> {
        self.db.transaction(|| {
            let lineage = self.db.crl_issuers(id)?;
            let mut pending = false;
            for fingerprint in &lineage {
                pending |= self.db.conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM outbox WHERE kind='crl' AND payload=? AND done=0)",
                    [fingerprint],
                    |r| r.get::<_, bool>(0),
                )?;
            }
            if !pending {
                return Ok(());
            }
            let issuer = self.db.get(lineage.last().ok_or("empty CA lineage")?)?;
            self.publish_crl(&issuer, now())
        })
    }
    pub(crate) fn publish_crl(&self, issuer: &Certificate, timestamp: i64) -> Result<()> {
        let lineage = self.db.crl_issuers(&issuer.fingerprint)?;
        let mut previous = 0i64;
        for fingerprint in &lineage {
            let number: i64 = self.db.conn.query_row(
                "SELECT COALESCE(MAX(number),0) FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)",
                [fingerprint], |row| row.get(0))?;
            previous = previous.max(number);
        }
        let number = previous.checked_add(1).ok_or("CRL number overflow")?;
        let mut certificates = Vec::new();
        for fingerprint in &lineage {
            certificates.push(self.db.public_certificate(fingerprint)?);
            certificates.extend(self.db.revoked_by_issuer(fingerprint)?);
        }
        let signer = openssl::x509::X509::from_pem(issuer.pem.as_bytes())?;
        let signer_key = signer.public_key()?;
        for ca in certificates
            .iter()
            .filter(|c| lineage.contains(&c.fingerprint))
        {
            let certificate = openssl::x509::X509::from_pem(ca.pem.as_bytes())?;
            if certificate.subject_name().to_der()? != signer.subject_name().to_der()?
                || !certificate.public_key()?.public_eq(&signer_key)
            {
                return Err("CA renewal lineage changed its signing identity".into());
            }
        }
        let pem = revocation::crl::generate(issuer, &certificates, timestamp, number)?;
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &pem)?;
        let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = format!("crl/{}/{number}-{digest}.pem", issuer.fingerprint);
        self.worm.write_once(&path, &pem)?;
        for fingerprint in &lineage {
            self.db.conn.execute("INSERT INTO crls(issuer,crl_path,next_update,number) VALUES((SELECT idx FROM certificates WHERE fingerprint=?),?,?,?) ON CONFLICT(issuer) DO UPDATE SET crl_path=excluded.crl_path,next_update=excluded.next_update,number=excluded.number",params![fingerprint,path,revocation::crl::next_update(timestamp)?,number])?;
        }
        for fingerprint in &lineage {
            self.db.conn.execute(
                "UPDATE outbox SET done=1 WHERE kind='crl' AND payload=? AND done=0",
                [fingerprint],
            )?;
        }
        Ok(())
    }
    pub fn crl(&self, id: &str) -> Result<Vec<u8>> {
        let (fingerprint, path, next): (String, String, i64) = self.db.conn.query_row(
            "SELECT c.fingerprint,r.crl_path,r.next_update FROM certificates c JOIN crls r ON r.issuer=c.idx WHERE c.kind IN ('root','intermediate') AND (c.fingerprint=?1 OR c.cn=?1) ORDER BY (c.fingerprint=?1) DESC,c.not_after DESC,c.idx DESC LIMIT 1",
            [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
        let mut pending = false;
        for generation in self.db.crl_issuers(&fingerprint)? {
            pending |= self.db.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE kind='crl' AND payload=? AND done=0)",
                [&generation],
                |row| row.get::<_, bool>(0),
            )?;
        }
        if now() >= next || pending {
            return Err("CRL publication is pending".into());
        }
        Ok(self.worm.read_text(&path)?.into_bytes())
    }

    pub fn refresh_expired_crls(&self) -> Result<()> {
        let mut query = self.db.conn.prepare("SELECT c.fingerprint FROM certificates c LEFT JOIN crls r ON r.issuer=c.idx WHERE (c.kind='intermediate' OR (c.kind='root' AND r.idx IS NOT NULL)) AND (r.idx IS NULL OR r.next_update<=?)")?;
        let issuers = query
            .query_map([now()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut failure = None;
        let mut visited = std::collections::HashSet::new();
        for id in issuers {
            if visited.contains(&id) {
                continue;
            }
            let lineage = self.db.crl_issuers(&id)?;
            visited.extend(lineage.iter().cloned());
            if let Err(error) = self.db.transaction(|| {
                let issuer = self.db.get(lineage.last().ok_or("empty CA lineage")?)?;
                self.publish_crl(&issuer, now())
            }) {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
