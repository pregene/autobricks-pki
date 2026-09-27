use crate::Result;
use serde::{Deserialize, Serialize};
pub const DAY: i64 = 86_400;
pub const INTERMEDIATE_DAYS: u32 = 398;
pub const LEAF_DAYS: u32 = 47;
pub const RENEWAL_SECONDS: i64 = 7 * DAY;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}
impl Validity {
    pub fn new(not_before: i64, days: u32, issuer: Option<Self>) -> Result<Self> {
        if days == 0 {
            return Err("validity duration must be positive".into());
        }
        let not_after = not_before
            .checked_add(i64::from(days) * DAY)
            .ok_or("validity overflow")?;
        let validity = Self {
            not_before,
            not_after,
        };
        validity.validate(issuer)?;
        Ok(validity)
    }
    pub fn validate(self, issuer: Option<Self>) -> Result<()> {
        if self.not_before >= self.not_after {
            return Err("invalid validity interval".into());
        }
        if let Some(parent) = issuer
            && (parent.not_before >= parent.not_after
                || self.not_before < parent.not_before
                || self.not_after > parent.not_after)
        {
            return Err("certificate validity exceeds issuer validity".into());
        }
        Ok(())
    }
    pub fn renewable(self, now: i64) -> bool {
        now >= self.not_before
            && self
                .not_after
                .checked_sub(now)
                .is_some_and(|remaining| remaining > 0 && remaining <= RENEWAL_SECONDS)
    }
}

impl Default for Validity {
    fn default() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            not_before: now,
            not_after: now + 47 * DAY,
        }
    }
}
