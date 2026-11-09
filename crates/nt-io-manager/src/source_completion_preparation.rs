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

/// Whether a retained CONNECT owner may run in a nested receive turn. An entered
/// provider is not itself work: its exact owner must expose a step that can advance
/// before the root selects it as a child of another parked dispatch.
pub const fn nested_connect_ready(
    active: bool,
    provider_entered: bool,
    source_admissible: bool,
    entered_actionable: bool,
) -> bool {
    active && if provider_entered { entered_actionable } else { source_admissible }
}

/// Admission before a nested CONNECT provider entry, using the exact source lane state.
pub const fn nested_source_preparation_ready(
    phase: Option<ExistingLanePhase>,
    current: bool,
    prepared_route_ready: bool,
) -> bool {
    current && match phase {
        None => true,
        Some(ExistingLanePhase::Prepared) => prepared_route_ready,
        Some(_) => false,
    }
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
        assert!(!super::nested_connect_ready(true, false, false, false));
        assert!(super::nested_connect_ready(true, false, true, false));
        assert!(super::nested_connect_ready(true, true, false, true));
        assert!(!super::nested_connect_ready(false, true, true, true));
    }

    #[test]
    fn entered_pending_connect_is_not_a_nested_child_until_a_real_step_is_ready() {
        use super::nested_connect_ready;
        // The provider has already returned Pending, but its source has not sent the
        // separate arm Call. Selecting it here would run no step and quarantine its parent.
        assert!(!nested_connect_ready(true, true, false, false));
        // An exact entered step may be selected after native code proves it actionable.
        assert!(nested_connect_ready(true, true, false, true));
        assert!(nested_connect_ready(true, false, true, false));
        assert!(!nested_connect_ready(false, true, false, true));
    }

    #[test]
    fn absent_lane_can_be_constructed_once_while_preparing_defers() {
        use super::nested_source_preparation_ready as ready;
        assert!(ready(None, true, false), "the first nested turn owns construction");
        assert!(!ready(Some(ExistingLanePhase::Preparing), true, false));
        assert!(ready(Some(ExistingLanePhase::Prepared), true, true));
        assert!(!ready(Some(ExistingLanePhase::Prepared), true, false));
        assert!(!ready(None, false, false));
        assert!(!ready(Some(ExistingLanePhase::Preparing), false, false));
        assert!(!ready(Some(ExistingLanePhase::Prepared), false, true));
        assert!(!ready(Some(ExistingLanePhase::Other), true, false));
    }
}
