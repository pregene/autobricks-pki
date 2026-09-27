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
            let c=self.db.get(id)?;
            if c.kind=="root" || c.kind=="intermediate" { return Err("this operation revokes leaf certificates only".into()); }
            if c.revoked_at.is_some() { return Ok(()); }
            let timestamp=now();
            self.db.conn.execute("UPDATE certificates SET revoked_at=? WHERE fingerprint=?",params![timestamp,id])?;
            let issuer=self.db.get(c.issuer.as_deref().ok_or("missing issuer")?)?;
            for generation in self.db.all()?.iter().filter(|entry| entry.kind=="intermediate" && entry.cn==issuer.cn) { self.publish_crl(generation,timestamp)?; }
            self.db.enqueue("audit",&serde_json::json!({"event":"certificate-revoked","fingerprint":id,"timestamp":timestamp}).to_string())?;
            Ok(())
        })?;
        let _ = self.reconcile();
        Ok(())
    }
    pub(crate) fn publish_crl(&self, issuer: &Certificate, timestamp: i64) -> Result<()> {
        let previous:i64=self.db.conn.query_row(
            "SELECT COALESCE(MAX(crls.number),0) FROM crls JOIN certificates ON certificates.idx=crls.issuer WHERE certificates.cn=? AND certificates.kind='intermediate'",
            [&issuer.cn],|r|r.get(0))?;
        let number = previous.checked_add(1).ok_or("CRL number overflow")?;
        let pem = revocation::crl::generate(issuer, &self.db.all()?, timestamp, number)?;
        self.db.conn.execute("INSERT INTO crls(issuer,pem,next_update,number) VALUES((SELECT idx FROM certificates WHERE fingerprint=?),?,?,?) ON CONFLICT(issuer) DO UPDATE SET pem=excluded.pem,next_update=excluded.next_update,number=excluded.number",params![issuer.fingerprint,pem,revocation::crl::next_update(timestamp)?,number])?;
        Ok(())
    }
    pub fn crl(&self, id: &str) -> Result<Vec<u8>> {
        let issuer = self.db.issuer(id)?;
        let (pem, next): (Vec<u8>, i64) = self.db.conn.query_row(
            "SELECT pem,next_update FROM crls WHERE issuer=(SELECT idx FROM certificates WHERE fingerprint=?)",
            [&issuer.fingerprint],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if now() >= next {
            self.db.transaction(|| self.publish_crl(&issuer, now()))?;
            return self.crl(id);
        }
        Ok(pem)
    }
}
