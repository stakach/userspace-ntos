//! Admission of an existing exact source-completion lane during nested dispatch.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingLanePhase {
    Preparing,
    Prepared,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingLanePreparation {
    InProgress,
    Ready,
    RetainedUncertain,
}

pub const fn admit_existing(
    phase: ExistingLanePhase,
    current: bool,
) -> ExistingLanePreparation {
    match (phase, current) {
        (ExistingLanePhase::Preparing, true) => ExistingLanePreparation::InProgress,
        (ExistingLanePhase::Prepared, true) => ExistingLanePreparation::Ready,
        _ => ExistingLanePreparation::RetainedUncertain,
    }
}

/// Whether a retained CONNECT owner may run in a nested receive turn.
pub const fn nested_connect_ready(
    active: bool,
    provider_entered: bool,
    source_prepared: bool,
) -> bool {
    active && (provider_entered || source_prepared)
}

#[cfg(test)]
mod tests {
    use super::{admit_existing, ExistingLanePhase, ExistingLanePreparation};

    #[test]
    fn reentrant_prepare_waits_for_the_same_worker_without_poisoning_its_source() {
        let mut phase = ExistingLanePhase::Preparing;
        assert_eq!(admit_existing(phase, true), ExistingLanePreparation::InProgress);
        // The first invocation owns construction. A nested attempt neither enters a
        // provider nor creates a second worker while its READY receipt is outstanding.
        assert_eq!(admit_existing(phase, true), ExistingLanePreparation::InProgress);
        phase = ExistingLanePhase::Prepared;
        assert_eq!(admit_existing(phase, true), ExistingLanePreparation::Ready);
    }

    #[test]
    fn stale_or_uncertain_lane_does_not_become_ready() {
        assert_eq!(
            admit_existing(ExistingLanePhase::Preparing, false),
            ExistingLanePreparation::RetainedUncertain,
        );
        assert_eq!(
            admit_existing(ExistingLanePhase::Prepared, false),
            ExistingLanePreparation::RetainedUncertain,
        );
        assert_eq!(
            admit_existing(ExistingLanePhase::Other, true),
            ExistingLanePreparation::RetainedUncertain,
        );
    }

    #[test]
    fn nested_connect_waits_for_prepared_source_but_preserves_entered_progress() {
        assert!(!super::nested_connect_ready(true, false, false));
        assert!(super::nested_connect_ready(true, false, true));
        assert!(super::nested_connect_ready(true, true, false));
        assert!(!super::nested_connect_ready(false, true, true));
    }
}
