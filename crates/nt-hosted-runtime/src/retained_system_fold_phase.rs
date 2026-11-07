//! Eligibility for redriving a retained SYSTEM fold after native snapshot completion.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedSystemFoldPhase {
    Folding,
    Acknowledging,
    Installing,
    Failed,
}

impl RetainedSystemFoldPhase {
    pub const fn can_redrive(self, cm_channel_idle: bool) -> bool {
        match self {
            Self::Acknowledging => cm_channel_idle,
            Self::Installing => true,
            Self::Folding | Self::Failed => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RetainedSystemFoldPhase as Phase;

    #[test]
    fn cm_ack_needs_an_idle_channel() {
        assert!(!Phase::Acknowledging.can_redrive(false));
        assert!(Phase::Acknowledging.can_redrive(true));
    }

    #[test]
    fn acknowledged_install_does_not_wait_for_unrelated_cm_traffic() {
        assert!(Phase::Installing.can_redrive(false));
        assert!(Phase::Installing.can_redrive(true));
    }

    #[test]
    fn unfinished_or_failed_physical_fold_cannot_reenter() {
        for phase in [Phase::Folding, Phase::Failed] {
            assert!(!phase.can_redrive(false));
            assert!(!phase.can_redrive(true));
        }
    }
}
