use crate::{
    Result,
    server::service::{Service, now},
    storage::database::Certificate,
};

impl Service {
    pub(crate) fn archive(&self, c: &Certificate, event: &str) -> Result<()> {
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
                "crl" => self.db.transaction(|| {
                    let issuer = self.db.get(&payload)?;
                    self.publish_crl(&issuer, now())
                }),
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
