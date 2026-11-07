//! Exact ownership for a provider process-create callout before the initial user loader.

use crate::process_identity::ProcessIdentity;
use crate::hosted_return_target::HostedReturnTarget;
use crate::thread_binding::ThreadBinding;

/// A suspended Ps callout runs for the dormant target, while its saved syscall Reply belongs
/// to the creating source. These identities must never be inferred from one another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialThreadReplyOrigin<R: Copy + Eq> {
    source: ThreadBinding<R>,
    target: ThreadBinding<R>,
}

impl<R: Copy + Eq> InitialThreadReplyOrigin<R> {
    pub fn new(source: ThreadBinding<R>, target: ThreadBinding<R>) -> Option<Self> {
        (source.process.is_valid() && target.process.is_valid()
            && source.tid != 0 && target.tid != 0
            && source.tcb > 1 && target.tcb > 1
            && source != target).then_some(Self { source, target })
    }

    pub const fn source(self) -> ThreadBinding<R> { self.source }
    pub const fn target(self) -> ThreadBinding<R> { self.target }

    pub fn request_source_abandonment<C: Copy>(
        self, source: ThreadBinding<R>, reply: &mut HostedReturnTarget<C>,
    ) -> bool {
        if self.source != source { return false; }
        reply.request_abandonment();
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalloutResult {
    NotEntered(u32),
    Suspended,
    Returned(u32),
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessCreateCalloutPhase {
    Pending,
    Invoking,
    Suspended,
    Returned,
    Imported,
    Complete,
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessCreateCalloutError {
    StaleProcess,
    InvalidPhase,
}

/// The retained main-thread runtime owns this record from the first provider entry through
/// process retirement. A returned callout must have its provider W32PROCESS imported into the
/// process manager and its PEB Section alias validated before the user loader may run.
/// Suspended and ambiguous effects remain owned and cannot replay.
#[derive(Debug)]
pub struct ProcessCreateCalloutOwner {
    pi: usize,
    process: ProcessIdentity,
    phase: ProcessCreateCalloutPhase,
}

impl ProcessCreateCalloutOwner {
    pub fn new(pi: usize, process: ProcessIdentity) -> Option<Self> {
        process.is_valid().then_some(Self { pi, process, phase: ProcessCreateCalloutPhase::Pending })
    }

    pub const fn phase(&self) -> ProcessCreateCalloutPhase { self.phase }

    pub fn ready(&self, pi: usize, process: ProcessIdentity) -> bool {
        self.pi == pi && self.process == process && self.phase == ProcessCreateCalloutPhase::Complete
    }

    pub fn begin(&mut self, pi: usize, process: ProcessIdentity) -> Result<(), ProcessCreateCalloutError> {
        if self.pi != pi || self.process != process { return Err(ProcessCreateCalloutError::StaleProcess); }
        if self.phase != ProcessCreateCalloutPhase::Pending { return Err(ProcessCreateCalloutError::InvalidPhase); }
        self.phase = ProcessCreateCalloutPhase::Invoking;
        Ok(())
    }

    pub fn record(&mut self, result: CalloutResult) -> Result<(), ProcessCreateCalloutError> {
        if self.phase != ProcessCreateCalloutPhase::Invoking { return Err(ProcessCreateCalloutError::InvalidPhase); }
        self.phase = match result {
            CalloutResult::NotEntered(_) => ProcessCreateCalloutPhase::Pending,
            CalloutResult::Suspended => ProcessCreateCalloutPhase::Suspended,
            CalloutResult::Returned(0) => ProcessCreateCalloutPhase::Returned,
            CalloutResult::Returned(status) | CalloutResult::Indeterminate(status) => {
                ProcessCreateCalloutPhase::Indeterminate(status)
            }
        };
        Ok(())
    }

    /// A wait completes the original provider entry; it never starts another callout. The
    /// process identity must still name the exact owner that entered the provider.
    pub fn resolve_suspended(
        &mut self, pi: usize, process: ProcessIdentity, result: CalloutResult,
    ) -> Result<(), ProcessCreateCalloutError> {
        if self.pi != pi || self.process != process { return Err(ProcessCreateCalloutError::StaleProcess); }
        if self.phase != ProcessCreateCalloutPhase::Suspended { return Err(ProcessCreateCalloutError::InvalidPhase); }
        self.phase = match result {
            CalloutResult::Returned(0) => ProcessCreateCalloutPhase::Returned,
            CalloutResult::Returned(status) | CalloutResult::Indeterminate(status) => {
                ProcessCreateCalloutPhase::Indeterminate(status)
            }
            CalloutResult::NotEntered(_) | CalloutResult::Suspended => {
                return Err(ProcessCreateCalloutError::InvalidPhase);
            }
        };
        Ok(())
    }

    pub fn confirm_projection(
        &mut self, pi: usize, process: ProcessIdentity,
    ) -> Result<(), ProcessCreateCalloutError> {
        if self.pi != pi || self.process != process { return Err(ProcessCreateCalloutError::StaleProcess); }
        if self.phase != ProcessCreateCalloutPhase::Imported { return Err(ProcessCreateCalloutError::InvalidPhase); }
        self.phase = ProcessCreateCalloutPhase::Complete;
        Ok(())
    }

    /// The executive has imported the provider's exact nonzero W32PROCESS into its process
    /// manager. This retained ownership drives the genuine process-exit callout at retirement.
    pub fn confirm_process_import(
        &mut self, pi: usize, process: ProcessIdentity, w32process: u64,
    ) -> Result<(), ProcessCreateCalloutError> {
        if self.pi != pi || self.process != process { return Err(ProcessCreateCalloutError::StaleProcess); }
        if self.phase != ProcessCreateCalloutPhase::Returned || w32process == 0 {
            return Err(ProcessCreateCalloutError::InvalidPhase);
        }
        self.phase = ProcessCreateCalloutPhase::Imported;
        Ok(())
    }

    pub fn fail_projection(&mut self, status: u32) -> Result<(), ProcessCreateCalloutError> {
        if !matches!(self.phase, ProcessCreateCalloutPhase::Returned | ProcessCreateCalloutPhase::Imported) {
            return Err(ProcessCreateCalloutError::InvalidPhase);
        }
        self.phase = ProcessCreateCalloutPhase::Indeterminate(status);
        Ok(())
    }

    pub fn may_retire(&self) -> bool {
        matches!(self.phase, ProcessCreateCalloutPhase::Pending | ProcessCreateCalloutPhase::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_identity::{ProcessGeneration, ProcessIdentity};

    fn process(generation: u64) -> ProcessIdentity {
        ProcessIdentity { pid: 60, generation: ProcessGeneration::Hosted(generation) }
    }

    #[test]
    fn indeterminate_early_process_callout_cannot_replay_for_same_or_recycled_slot() {
        let mut owner = ProcessCreateCalloutOwner::new(7, process(2)).unwrap();
        assert_eq!(owner.begin(7, process(2)), Ok(()));
        assert_eq!(owner.record(CalloutResult::Indeterminate(0xc000_0001)), Ok(()));
        assert!(!owner.ready(7, process(2)));
        assert!(owner.begin(7, process(2)).is_err(), "ambiguous provider effect stays owned");
        assert!(owner.begin(7, process(3)).is_err(), "recycled slot cannot adopt old callout");
    }

    #[test]
    fn only_an_exact_returned_success_opens_the_initial_loader_gate() {
        let mut owner = ProcessCreateCalloutOwner::new(7, process(2)).unwrap();
        assert_eq!(owner.begin(7, process(2)), Ok(()));
        assert_eq!(owner.record(CalloutResult::NotEntered(0xc000_00a3)), Ok(()));
        assert!(!owner.ready(7, process(2)));
        assert_eq!(owner.begin(7, process(2)), Ok(()));
        assert_eq!(owner.record(CalloutResult::Returned(0)), Ok(()));
        assert!(!owner.ready(7, process(2)), "provider process backing still needs PM ownership");
        assert_eq!(owner.confirm_projection(7, process(2)), Err(ProcessCreateCalloutError::InvalidPhase));
        assert_eq!(owner.confirm_process_import(7, process(3), 0x1000),
            Err(ProcessCreateCalloutError::StaleProcess));
        assert_eq!(owner.confirm_process_import(7, process(2), 0),
            Err(ProcessCreateCalloutError::InvalidPhase));
        assert_eq!(owner.confirm_process_import(7, process(2), 0x1000), Ok(()));
        assert!(!owner.ready(7, process(2)), "PEB alias still needs exact validation");
        assert_eq!(owner.confirm_projection(7, process(2)), Ok(()));
        assert!(owner.ready(7, process(2)));
        assert!(!owner.ready(7, process(3)));
        assert!(owner.begin(7, process(2)).is_err(), "completed callout is never replayed");
    }

    #[test]
    fn suspended_callout_retains_exact_owner_until_provider_completion() {
        let mut owner = ProcessCreateCalloutOwner::new(7, process(2)).unwrap();
        assert_eq!(owner.begin(7, process(2)), Ok(()));
        assert_eq!(owner.record(CalloutResult::Suspended), Ok(()));
        assert_eq!(owner.phase(), ProcessCreateCalloutPhase::Suspended);
        assert!(!owner.ready(7, process(2)));
        assert!(!owner.may_retire());
        assert_eq!(owner.begin(7, process(2)), Err(ProcessCreateCalloutError::InvalidPhase));
        assert_eq!(owner.resolve_suspended(7, process(3), CalloutResult::Returned(0)),
            Err(ProcessCreateCalloutError::StaleProcess));
        assert_eq!(owner.resolve_suspended(7, process(2), CalloutResult::NotEntered(0xc000_00a3)),
            Err(ProcessCreateCalloutError::InvalidPhase));
        assert_eq!(owner.resolve_suspended(7, process(2), CalloutResult::Returned(0)), Ok(()));
        assert_eq!(owner.phase(), ProcessCreateCalloutPhase::Returned);
        assert_eq!(owner.resolve_suspended(7, process(2), CalloutResult::Returned(0)),
            Err(ProcessCreateCalloutError::InvalidPhase), "completion cannot be consumed twice");
        assert_eq!(owner.confirm_process_import(7, process(2), 0x1000), Ok(()));
        assert_eq!(owner.confirm_projection(7, process(2)), Ok(()));
        assert!(owner.ready(7, process(2)));
    }

    #[test]
    fn failed_suspended_completion_never_replays_or_opens_loader_gate() {
        for completion in [CalloutResult::Returned(0xc000_0001), CalloutResult::Indeterminate(0xc000_0001)] {
            let mut owner = ProcessCreateCalloutOwner::new(7, process(2)).unwrap();
            assert_eq!(owner.begin(7, process(2)), Ok(()));
            assert_eq!(owner.record(CalloutResult::Suspended), Ok(()));
            assert_eq!(owner.resolve_suspended(7, process(2), completion), Ok(()));
            assert_eq!(owner.phase(), ProcessCreateCalloutPhase::Indeterminate(0xc000_0001));
            assert!(!owner.ready(7, process(2)));
            assert!(!owner.may_retire());
            assert_eq!(owner.begin(7, process(2)), Err(ProcessCreateCalloutError::InvalidPhase));
        }
    }

    #[test]
    fn transferred_initial_thread_reply_tracks_source_and_target_independently() {
        use crate::thread_binding::ThreadBinding;

        let source = ThreadBinding {
            pi: 3, process: ProcessIdentity { pid: 50, generation: ProcessGeneration::Hosted(10) },
            tid: 100, badge: 17, role: 0u8,
            tcb: 0x1000, reservations: None,
        };
        let target = ThreadBinding {
            pi: 8, process: process(20), tid: 200, badge: 29, role: 0u8,
            tcb: 0x2000, reservations: None,
        };
        let origin = InitialThreadReplyOrigin::new(source, target).unwrap();
        let mut reply = crate::hosted_return_target::HostedReturnTarget::<u8>::new(41, None).unwrap();
        assert_eq!(origin.target(), target);
        assert_eq!(origin.source(), source);
        for stale in [target, ThreadBinding { process: ProcessIdentity {
            pid: 50, generation: ProcessGeneration::Hosted(11),
        }, ..source },
            ThreadBinding { tcb: 0x3000, ..source }]
        {
            assert!(!origin.request_source_abandonment(stale, &mut reply));
            assert!(reply.delivery().is_some());
        }
        assert!(origin.request_source_abandonment(source, &mut reply));
        assert!(reply.delivery().is_none());
        assert!(!reply.can_resume(), "Reply retirement still requires mechanism acknowledgements");
        assert!(origin.request_source_abandonment(source, &mut reply),
            "exact repeated teardown preserves the same retirement intent");
    }

    #[test]
    fn source_abandonment_does_not_cancel_the_entered_target_callout() {
        use crate::thread_binding::ThreadBinding;

        let source = ThreadBinding {
            pi: 3, process: ProcessIdentity { pid: 50, generation: ProcessGeneration::Hosted(10) },
            tid: 100, badge: 17, role: 0u8,
            tcb: 0x1000, reservations: None,
        };
        let target = ThreadBinding {
            pi: 8, process: process(20), tid: 200, badge: 29, role: 0u8,
            tcb: 0x2000, reservations: None,
        };
        let mut callout = ProcessCreateCalloutOwner::new(target.pi, target.process).unwrap();
        callout.begin(target.pi, target.process).unwrap();
        callout.record(CalloutResult::Suspended).unwrap();
        let origin = InitialThreadReplyOrigin::new(source, target).unwrap();
        let mut reply = crate::hosted_return_target::HostedReturnTarget::<u8>::new(41, None).unwrap();
        assert!(origin.request_source_abandonment(source, &mut reply));
        assert!(reply.delivery().is_none());
        assert_eq!(callout.phase(), ProcessCreateCalloutPhase::Suspended);
        assert!(!callout.may_retire());
        assert_eq!(callout.resolve_suspended(
            target.pi, target.process, CalloutResult::Returned(0),
        ), Ok(()));
        assert!(reply.delivery().is_none());
        assert_eq!(callout.resolve_suspended(
            target.pi, target.process, CalloutResult::Returned(0),
        ), Err(ProcessCreateCalloutError::InvalidPhase));
    }
}
