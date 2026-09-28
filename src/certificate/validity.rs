use crate::Result;
use serde::{Deserialize, Serialize};
pub const DAY: i64 = 86_400;
pub const INTERMEDIATE_MAX_DAYS: u32 = 398;
pub const LEAF_DAYS: u32 = 47;
pub const RENEWAL_SECONDS: i64 = 7 * DAY;
pub const INTERMEDIATE_RENEWAL_SECONDS: i64 = 48 * DAY;
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
    pub fn renewed(self, not_before: i64, issuer: Self) -> Result<Self> {
        self.validate(None)?;
        let duration = self
            .not_after
            .checked_sub(self.not_before)
            .ok_or("validity duration overflow")?;
        let not_after = not_before
            .checked_add(duration)
            .ok_or("validity overflow")?;
        let renewed = Self {
            not_before,
            not_after,
        };
        renewed.validate(Some(issuer))?;
        Ok(renewed)
    }

    pub fn renewable(self, now: i64) -> bool {
        self.renewable_within(now, RENEWAL_SECONDS)
    }

    pub fn intermediate_renewable(self, now: i64) -> bool {
        self.renewable_within(now, INTERMEDIATE_RENEWAL_SECONDS)
    }

    fn renewable_within(self, now: i64, window: i64) -> bool {
        now >= self.not_before
            && self
                .not_after
                .checked_sub(now)
                .is_some_and(|remaining| remaining > 0 && remaining <= window)
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
