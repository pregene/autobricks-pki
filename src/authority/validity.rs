use crate::{Result, server::service::Service};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Policy {
    pub retention_days: u32,
    pub intermediate_days: u32,
}
impl Policy {
    pub fn new(retention_days: u32) -> Result<Self> {
        let available = retention_days
            .checked_sub(7)
            .filter(|days| *days > 0)
            .ok_or("TrueLog retention must exceed seven days")?;
        Ok(Self {
            retention_days,
            intermediate_days: available.min(crate::certificate::validity::INTERMEDIATE_MAX_DAYS),
        })
    }
}
impl Service {
    pub(crate) fn intermediate_days(&self) -> Result<u32> {
        let saved = self
            .db
            .setting("ca_validity_policy")?
            .ok_or("missing installation CA validity policy")?;
        let policy: Policy = serde_json::from_slice(&saved)?;
        if policy.intermediate_days != Policy::new(policy.retention_days)?.intermediate_days {
            return Err("invalid stored CA validity policy".into());
        }
        Ok(policy.intermediate_days)
    }
}
