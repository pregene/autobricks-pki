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
        if self.background_delivery {
            return Ok(());
        }
        let mut failure = None;
        for (id, kind, payload) in self.db.pending()? {
            if !self.db.is_pending(id)? {
                continue;
            }
            let result = self.deliver_one(&kind, &payload, id);
            match result {
                Ok(()) => self.db.complete(id)?,
                Err(e) => failure = Some(e),
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    pub(crate) fn reconcile_crls(&self) -> Result<()> {
        let mut failure = None;
        for issuer in self.db.pending_crls()? {
            if let Err(error) = self.publish_pending_crl(&issuer) {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub(crate) fn deliver_one(&self, kind: &str, payload: &str, id: i64) -> Result<()> {
        match kind {
            "crl" => self.publish_pending_crl(payload),
            "audit" => {
                let mut event: serde_json::Value = serde_json::from_str(payload)?;
                event["event_id"] = format!("{}:{id}", self.db.root_id()?).into();
                self.truelog.submit(&event)
            }
            "dns" => self.dns.register(&serde_json::from_str(payload)?),
            _ => Err("unknown outbox operation".into()),
        }
    }
}
