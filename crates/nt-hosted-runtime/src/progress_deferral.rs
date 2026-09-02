/// Bounded grace policy for a runtime frontier observed by a progress watchdog.
///
/// A changed snapshot may receive one grace interval, up to `grant_limit` intervals for the current
/// progress epoch. Repeating the same snapshot is never progress. A new durable progress epoch
/// resets both the snapshot and the bounded grant count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressDeferralBudget<S> {
    epoch: u64,
    last_snapshot: Option<S>,
    grants: u8,
    grant_limit: u8,
}

impl<S: Copy + Eq> ProgressDeferralBudget<S> {
    pub const fn new(epoch: u64, grant_limit: u8) -> Self {
        Self {
            epoch,
            last_snapshot: None,
            grants: 0,
            grant_limit,
        }
    }

    /// Record a durable progress epoch. Returns true only when the epoch advanced.
    pub fn observe_progress(&mut self, epoch: u64) -> bool {
        if epoch == self.epoch {
            return false;
        }
        self.epoch = epoch;
        self.last_snapshot = None;
        self.grants = 0;
        true
    }

    /// Grant one interval to a changed frontier snapshot within the current epoch.
    pub fn grant(&mut self, epoch: u64, snapshot: S) -> bool {
        self.observe_progress(epoch);
        if self.grants >= self.grant_limit || self.last_snapshot == Some(snapshot) {
            return false;
        }
        self.last_snapshot = Some(snapshot);
        self.grants += 1;
        true
    }

    pub const fn grants(self) -> u8 {
        self.grants
    }
}

#[cfg(test)]
mod tests {
    use super::ProgressDeferralBudget;

    #[test]
    fn unchanged_frontier_receives_only_one_grace() {
        let mut budget = ProgressDeferralBudget::new(7, 2);
        assert!(budget.grant(7, 10));
        assert!(!budget.grant(7, 10));
        assert_eq!(budget.grants(), 1);
    }

    #[test]
    fn changed_frontiers_remain_bounded_within_one_epoch() {
        let mut budget = ProgressDeferralBudget::new(7, 2);
        assert!(budget.grant(7, 10));
        assert!(budget.grant(7, 11));
        assert!(!budget.grant(7, 12));
        assert_eq!(budget.grants(), 2);
    }

    #[test]
    fn durable_progress_resets_the_budget() {
        let mut budget = ProgressDeferralBudget::new(7, 1);
        assert!(budget.grant(7, 10));
        assert!(!budget.grant(7, 11));
        assert!(budget.observe_progress(8));
        assert_eq!(budget.grants(), 0);
        assert!(budget.grant(8, 10));
    }

    #[test]
    fn zero_limit_never_grants() {
        let mut budget = ProgressDeferralBudget::new(0, 0);
        assert!(!budget.grant(0, 1));
        assert!(!budget.grant(1, 2));
    }
}
