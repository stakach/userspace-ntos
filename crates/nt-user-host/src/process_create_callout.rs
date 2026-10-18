//! Exact ownership for a provider process-create callout before the initial user loader.

use crate::process_identity::ProcessIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalloutResult {
    NotEntered(u32),
    Returned(u32),
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessCreateCalloutPhase {
    Pending,
    Invoking,
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
/// Ambiguous effects remain owned and cannot replay.
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
            CalloutResult::Returned(0) => ProcessCreateCalloutPhase::Returned,
            CalloutResult::Returned(status) | CalloutResult::Indeterminate(status) => {
                ProcessCreateCalloutPhase::Indeterminate(status)
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
}
