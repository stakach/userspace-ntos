/// Wall-clock watchdog over the finite boot-milestone epoch.
///
/// Before the interactive shell is up, a boot that publishes no milestone for the whole budget
/// is a stall candidate. Once Explorer's paint milestones seal the epoch, no further milestones
/// exist by construction: an idle desktop is a normal state, never a stall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootMilestoneWatch {
    epoch: u64,
    last_progress_100ns: u64,
    budget_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MilestoneVerdict {
    /// The epoch advanced at this observation.
    Progressed,
    /// The boot is still within its milestone budget.
    Waiting,
    /// The pre-seal boot published nothing for the whole budget.
    Silent,
    /// The epoch is sealed; the desktop is interactive and silence is expected.
    Interactive,
}

impl BootMilestoneWatch {
    pub const fn new(epoch: u64, now_100ns: u64, budget_100ns: u64) -> Self {
        Self { epoch, last_progress_100ns: now_100ns, budget_100ns }
    }

    pub fn observe(&mut self, epoch: u64, sealed: bool, now_100ns: u64) -> MilestoneVerdict {
        if epoch != self.epoch {
            self.epoch = epoch;
            self.last_progress_100ns = now_100ns;
            return MilestoneVerdict::Progressed;
        }
        if sealed {
            return MilestoneVerdict::Interactive;
        }
        if now_100ns.wrapping_sub(self.last_progress_100ns) >= self.budget_100ns {
            MilestoneVerdict::Silent
        } else {
            MilestoneVerdict::Waiting
        }
    }

    /// A granted deferral restarts the budget without counting as a milestone.
    pub fn extend(&mut self, now_100ns: u64) {
        self.last_progress_100ns = now_100ns;
    }

    pub const fn budget_100ns(self) -> u64 {
        self.budget_100ns
    }
}

#[cfg(test)]
mod tests {
    use super::{BootMilestoneWatch, MilestoneVerdict};

    const BUDGET: u64 = 180 * 10_000_000;

    #[test]
    fn a_silent_boot_before_the_seal_is_a_stall_candidate() {
        let mut watch = BootMilestoneWatch::new(4, 0, BUDGET);
        assert_eq!(watch.observe(4, false, BUDGET - 1), MilestoneVerdict::Waiting);
        assert_eq!(watch.observe(4, false, BUDGET), MilestoneVerdict::Silent);
        watch.extend(BUDGET);
        assert_eq!(watch.observe(4, false, BUDGET + 1), MilestoneVerdict::Waiting);
    }

    #[test]
    fn an_idle_desktop_after_the_seal_never_stalls() {
        // Boot 44246316182: the epoch sealed, the desktop idled ~360 s, and the gate fired.
        let mut watch = BootMilestoneWatch::new(90, 0, BUDGET);
        assert_eq!(watch.observe(91, true, 10), MilestoneVerdict::Progressed);
        for now in [11, BUDGET, 2 * BUDGET + 10, 100 * BUDGET] {
            assert_eq!(watch.observe(91, true, now), MilestoneVerdict::Interactive);
        }
    }

    #[test]
    fn progress_restarts_the_budget() {
        let mut watch = BootMilestoneWatch::new(1, 0, BUDGET);
        assert_eq!(watch.observe(2, false, BUDGET - 5), MilestoneVerdict::Progressed);
        assert_eq!(watch.observe(2, false, 2 * BUDGET - 6), MilestoneVerdict::Waiting);
        assert_eq!(watch.observe(2, false, 2 * BUDGET - 5), MilestoneVerdict::Silent);
    }
}
