//! A component that yields for scheduler work keeps its lane executing: only that lane's own
//! receive may collect its next message. The scheduler service parks the lane, runs timer, IRQ
//! and DPC work, and restores it. A refused restore leaves the lane held, and receiving on it
//! then blocks the root on a lane that nobody resumes (#333). This continuation names the step
//! still owed, so the caller unwinds to the owner that keeps it instead of receiving or
//! panicking, and the work resumes once that owner's retry restores the exact parent.

/// How one scheduler service ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerServiceEnd<T> {
    /// The parked lane was restored; its receive may continue.
    Restored,
    /// The park was refused before any timer, IRQ or DPC work ran.
    ParkRefused,
    /// The work ran and the lane is still held by the retained parent `T`.
    ParentRetained(T),
}

/// The result of one retry of a retained parent's restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreRetry {
    Restored,
    /// A preflight refusal with no native effect: the same parent may be retried.
    RefusedNoEffect,
    /// Native entry or identity is uncertain: the parent is fenced.
    Uncertain,
}

/// The step a scheduler-yield continuation still owes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerYieldStep<T> {
    /// No scheduler effect ran. The owner runs the service again; nothing may be received.
    Service,
    /// The service ran. The exact parent's restore is owed before the lane's receive.
    Restore(T),
    /// The lane runs again: only its receive continuation may follow.
    Receive,
    /// The restore entered an uncertain effect. Every resource stays held; it is never retried.
    Quarantined(T),
}

impl<T: Copy> SchedulerYieldStep<T> {
    pub const fn after_service(end: SchedulerServiceEnd<T>) -> Self {
        match end {
            SchedulerServiceEnd::Restored => Self::Receive,
            SchedulerServiceEnd::ParkRefused => Self::Service,
            SchedulerServiceEnd::ParentRetained(parent) => Self::Restore(parent),
        }
    }

    /// Retry the owed restore once. Any other step is returned unchanged and `restore` is not
    /// entered: a fenced parent is never replayed, and a service still owed restores nothing.
    pub fn retry_restore(self, restore: impl FnOnce(T) -> RestoreRetry) -> Self {
        let Self::Restore(parent) = self else { return self };
        match restore(parent) {
            RestoreRetry::Restored => Self::Receive,
            RestoreRetry::RefusedNoEffect => Self::Restore(parent),
            RestoreRetry::Uncertain => Self::Quarantined(parent),
        }
    }

    pub const fn may_receive(&self) -> bool { matches!(self, Self::Receive) }

    /// Whether an owner may drive this continuation again.
    pub const fn retryable(&self) -> bool { matches!(self, Self::Service | Self::Restore(_)) }

    /// The retained parent this continuation keeps, if any.
    pub const fn parent(&self) -> Option<T> {
        match self {
            Self::Restore(parent) | Self::Quarantined(parent) => Some(*parent),
            Self::Service | Self::Receive => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_restore_owes_the_exact_parent_before_any_receive() {
        let step = SchedulerYieldStep::after_service(SchedulerServiceEnd::ParentRetained(7u32));
        assert_eq!(step, SchedulerYieldStep::Restore(7));
        assert!(!step.may_receive(), "a held lane must not be received from");
        assert!(step.retryable());
        assert_eq!(step.parent(), Some(7));
    }

    #[test]
    fn the_work_resumes_after_the_owner_restores_the_parent() {
        let mut retried = None;
        let step = SchedulerYieldStep::Restore(3u32)
            .retry_restore(|parent| { retried = Some(parent); RestoreRetry::Restored });
        assert_eq!(retried, Some(3));
        assert_eq!(step, SchedulerYieldStep::Receive);
        assert!(step.may_receive());
    }

    #[test]
    fn a_no_effect_retry_keeps_the_same_parent_owed() {
        let step = SchedulerYieldStep::Restore(5u32).retry_restore(|_| RestoreRetry::RefusedNoEffect);
        assert_eq!(step, SchedulerYieldStep::Restore(5));
        assert!(step.retryable() && !step.may_receive());
    }

    #[test]
    fn an_uncertain_retry_is_fenced_and_never_replayed() {
        let step = SchedulerYieldStep::Restore(9u32).retry_restore(|_| RestoreRetry::Uncertain);
        assert_eq!(step, SchedulerYieldStep::Quarantined(9));
        let mut entered = false;
        let step = step.retry_restore(|_| { entered = true; RestoreRetry::Restored });
        assert!(!entered, "a quarantined parent is never restored again");
        assert!(!step.retryable() && !step.may_receive());
        assert_eq!(step.parent(), Some(9));
    }

    #[test]
    fn a_park_refusal_owes_the_service_and_restores_nothing() {
        let step = SchedulerYieldStep::<u32>::after_service(SchedulerServiceEnd::ParkRefused);
        assert_eq!(step, SchedulerYieldStep::Service);
        let mut entered = false;
        let step = step.retry_restore(|_| { entered = true; RestoreRetry::Restored });
        assert!(!entered);
        assert!(step.retryable() && !step.may_receive());
        assert_eq!(step.parent(), None);
    }

    #[test]
    fn a_restored_service_continues_the_receive() {
        let step = SchedulerYieldStep::<u32>::after_service(SchedulerServiceEnd::Restored);
        assert!(step.may_receive() && !step.retryable());
    }
}
