//! Retained completion stages for a hosted interrupt's irreversible retirement effects.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RetirementProgress {
    pub physical_lease_released: bool,
    pub actual_lock_unregistered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetirementTailAction {
    ReleasePhysicalLease,
    UnregisterActualLock,
    Finish,
}

pub(crate) fn next_tail_action(progress: RetirementProgress) -> RetirementTailAction {
    if !progress.physical_lease_released {
        RetirementTailAction::ReleasePhysicalLease
    } else if !progress.actual_lock_unregistered {
        RetirementTailAction::UnregisterActualLock
    } else {
        RetirementTailAction::Finish
    }
}
