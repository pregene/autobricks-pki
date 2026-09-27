use crate::{Result, server::service::Service};

const INTERVAL: i64 = 3600;
const LAST_ATTEMPT: &str = "renewal_scheduler_last_attempt";

pub fn due(last_attempt: Option<i64>, timestamp: i64) -> bool {
    last_attempt.is_none_or(|last| timestamp.saturating_sub(last) >= INTERVAL)
}

impl Service {
    /// Persist the attempt before renewal so restarts do not repeat an hourly run.
    pub fn run_hourly_renewal(&self, timestamp: i64) -> Result<bool> {
        let last = self
            .db
            .setting(LAST_ATTEMPT)?
            .map(|bytes| serde_json::from_slice::<i64>(&bytes))
            .transpose()?;
        if !due(last, timestamp) {
            return Ok(false);
        }
        self.db
            .set_setting(LAST_ATTEMPT, &serde_json::to_vec(&timestamp)?)?;
        self.maintain()?;
        Ok(true)
    }

    pub fn refresh_status_and_deliver(&self) -> Result<()> {
        let mut failure = if self.background_delivery {
            self.reconcile_crls().err()
        } else {
            self.reconcile().err()
        };
        if let Err(error) = self.refresh_expired_crls() {
            failure = Some(error);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hourly_boundary_and_clock_rollback() {
        assert!(due(None, 100));
        assert!(!due(Some(100), 100));
        assert!(!due(Some(100), 99));
        assert!(!due(Some(100), 100 + INTERVAL - 1));
        assert!(due(Some(100), 100 + INTERVAL));
        assert!(due(Some(100), 100 + 2 * INTERVAL));
    }
}
