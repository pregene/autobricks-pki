use crate::{
    Result,
    server::service::{Service, now},
    storage::database::Certificate,
};

impl Service {
    pub(crate) fn archive(&self, c: &Certificate, event: &str) -> Result<()> {
        let created_at = now();
        crate::storage::archive::paths(c, created_at)?;
        self.db.enqueue(
            "certificate",
            &serde_json::to_string(&crate::storage::archive::Archive {
                fingerprint: c.fingerprint.clone(),
                created_at,
            })?,
        )?;
        self.db.enqueue(
            "audit",
            &serde_json::json!({"event":event,"fingerprint":c.fingerprint,"timestamp":now()})
                .to_string(),
        )
    }
    pub fn reconcile(&self) -> Result<()> {
        let mut failure = None;
        for (id, kind, payload) in self.db.pending()? {
            let result = match kind.as_str() {
                "certificate" => (|| -> Result<()> {
                    // Older pending records contain only the fingerprint.
                    let archive =
                        serde_json::from_str::<crate::storage::archive::Archive>(&payload)
                            .or_else(|_| {
                                self.db
                                    .get(&payload)
                                    .map(|c| crate::storage::archive::Archive {
                                        fingerprint: c.fingerprint,
                                        created_at: c.validity.not_before,
                                    })
                            })?;
                    let certificate = self.db.get(&archive.fingerprint)?;
                    let (pem, key) =
                        crate::storage::archive::paths(&certificate, archive.created_at)?;
                    self.worm.write_once(&pem, certificate.pem.as_bytes())?;
                    if let Some(key) = key {
                        self.worm.write_once(
                            &key,
                            self.db.encrypted_key(&certificate.fingerprint)?.as_bytes(),
                        )?;
                    }
                    Ok(())
                })(),
                "audit" => (|| -> Result<()> {
                    let mut event: serde_json::Value = serde_json::from_str(&payload)?;
                    event["event_id"] = format!("{}:{id}", self.root()?.fingerprint).into();
                    self.truelog.submit(&event)
                })(),
                "dns" => serde_json::from_str(&payload)
                    .map_err(Into::into)
                    .and_then(|r| self.dns.register(&r)),
                _ => Err("unknown outbox operation".into()),
            };
            match result {
                Ok(()) => self.db.complete(id)?,
                Err(e) => failure = Some(e),
            }
        }
        if let Some(e) = failure {
            Err(e)
        } else {
            Ok(())
        }
    }
}
