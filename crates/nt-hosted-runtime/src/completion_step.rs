//! A work row's copy or ACK of a completed IRP's storage (#420).
//!
//! A hosted backend's completion copy and completion ACK can stop unfinished in a kept pump.
//! The I/O Manager then answers `STATUS_PENDING`: the operation is still running, or another
//! operation owns the IRP, and the identical call collects its true result on a later turn
//! ([`crate::IrpOperations`]). `STATUS_PENDING` is therefore never a copy or ACK's result. A
//! row that receives it keeps its phase and every resource it owns and calls the identical
//! operation again; any other error is the operation's final result.
//!
//! [`CompletionRetryWake`] redrives such a row when a kept pump returns, so its retry never
//! waits for an unrelated event.

use nt_status::NtStatus;

const STATUS_PENDING: u32 = NtStatus::PENDING.raw() as u32;

/// What a row does with one copy or ACK result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionStep<T> {
    /// The operation's certain result.
    Done(T),
    /// Still running: keep the phase and its resources, and call the identical operation again.
    Retry,
    /// The operation's final error.
    Failed(u32),
}

impl<T> CompletionStep<T> {
    /// Classify an executive copy or ACK result (a raw NTSTATUS error).
    pub fn of(result: Result<T, u32>) -> Self {
        match result {
            Ok(value) => Self::Done(value),
            Err(STATUS_PENDING) => Self::Retry,
            Err(status) => Self::Failed(status),
        }
    }

    /// Classify an I/O Manager copy or ACK result.
    pub fn of_status(result: Result<T, NtStatus>) -> Self {
        Self::of(result.map_err(|status| status.raw() as u32))
    }
}

/// Redrives rows waiting on a [`CompletionStep::Retry`] when a kept backend pump returns.
///
/// A row parks after a retry. A kept pump's return makes the parked rows due. The root takes
/// the wake at the start of its row pass ([`Self::begin_pass`]); every row it drives in that
/// pass sees itself due, and a row that is still waiting parks again for the next return. A
/// spurious redrive is harmless: the row only calls its identical operation again.
#[derive(Debug, Default)]
pub struct CompletionRetryWake {
    waiting: bool,
    due: bool,
    in_pass: bool,
}

impl CompletionRetryWake {
    pub const fn new() -> Self { Self { waiting: false, due: false, in_pass: false } }

    /// A row's copy or ACK answered retry: it waits for a kept pump's return.
    pub fn park(&mut self) {
        self.waiting = true;
    }

    /// A kept backend pump returned.
    pub fn returned(&mut self) {
        if self.waiting {
            self.due = true;
        }
    }

    /// Whether a parked row must be redriven now, ahead of its own retry deadline.
    pub fn due(&self) -> bool {
        self.due || self.in_pass
    }

    /// Whether the root must not wait for an event before its next row pass.
    pub fn pending(&self) -> bool {
        self.due
    }

    /// Start a row pass: take the wake. Rows driven before [`Self::end_pass`] see themselves due.
    pub fn begin_pass(&mut self) {
        self.in_pass = core::mem::take(&mut self.due);
        if self.in_pass {
            self.waiting = false;
        }
    }

    pub fn end_pass(&mut self) {
        self.in_pass = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IrpOperationAdmission, IrpOperationKey, IrpOperations};

    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

    #[test]
    fn pending_is_a_retry_and_every_other_error_is_final() {
        assert_eq!(CompletionStep::of(Ok(4usize)), CompletionStep::Done(4));
        assert_eq!(CompletionStep::<usize>::of(Err(STATUS_PENDING)), CompletionStep::Retry);
        assert_eq!(CompletionStep::<usize>::of(Err(STATUS_INVALID_PARAMETER)),
            CompletionStep::Failed(STATUS_INVALID_PARAMETER));
        assert_eq!(CompletionStep::<()>::of_status(Err(NtStatus::PENDING)), CompletionStep::Retry);
        assert_eq!(CompletionStep::<()>::of_status(Err(NtStatus::DELETE_PENDING)),
            CompletionStep::Failed(NtStatus::DELETE_PENDING.raw() as u32),
            "DELETE_PENDING is a final refusal, not a running operation");
    }

    /// A backend whose copy stops unfinished once, exactly as the executive's kept control.
    struct Backend {
        operations: IrpOperations<&'static str>,
        pump_returned: bool,
        issued: usize,
    }

    impl Backend {
        fn copy(&mut self, irp: u64, offset: u64, output: &mut [u8]) -> Result<usize, u32> {
            let key = IrpOperationKey { instance: 1, irp, operation: 2, offset, len: output.len() };
            match self.operations.admit(key) {
                IrpOperationAdmission::Busy => Err(STATUS_PENDING),
                IrpOperationAdmission::Issue => {
                    self.issued += 1;
                    self.operations.reserve().unwrap();
                    self.operations.keep(key, "pump");
                    Err(STATUS_PENDING)
                }
                IrpOperationAdmission::Collect(pump) if !self.pump_returned => {
                    self.operations.still_running(key, pump).unwrap();
                    Err(STATUS_PENDING)
                }
                IrpOperationAdmission::Collect(_) => {
                    assert!(self.operations.settled(key));
                    output.copy_from_slice(&[7; 4][..output.len()]);
                    Ok(output.len())
                }
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Phase {
        Copying { irp: u64, output: [u8; 4] },
        Acknowledge { irp: u64, copied: [u8; 4] },
        Failed(u32),
    }

    /// One turn of a row's copy phase, as an executive work row drives it.
    fn turn(phase: &mut Phase, backend: &mut Backend) {
        let Phase::Copying { irp, output } = phase else { return };
        let irp = *irp;
        match CompletionStep::of(backend.copy(irp, 0, &mut output[..])) {
            CompletionStep::Retry => {}
            CompletionStep::Done(_) => *phase = Phase::Acknowledge { irp, copied: *output },
            CompletionStep::Failed(status) => *phase = Phase::Failed(status),
        }
    }

    #[test]
    fn a_row_given_pending_keeps_its_phase_and_completes_with_the_true_result() {
        let mut backend = Backend { operations: IrpOperations::new(), pump_returned: false, issued: 0 };
        let mut phase = Phase::Copying { irp: 9, output: [0; 4] };
        turn(&mut phase, &mut backend);
        assert_eq!(phase, Phase::Copying { irp: 9, output: [0; 4] },
            "a copy still running is not the row's failure");
        turn(&mut phase, &mut backend);
        assert_eq!(phase, Phase::Copying { irp: 9, output: [0; 4] });
        backend.pump_returned = true;
        turn(&mut phase, &mut backend);
        assert_eq!(phase, Phase::Acknowledge { irp: 9, copied: [7; 4] },
            "the identical retry collects the copy's true result");
        assert_eq!(backend.issued, 1, "the copy is issued once and collected, never replayed");
    }

    #[test]
    fn a_kept_return_redrives_a_parked_row_once() {
        let mut wake = CompletionRetryWake::new();
        wake.returned();
        assert!(!wake.pending(), "a return with no parked row wakes nothing");
        wake.park();
        assert!(!wake.due(), "a parked row waits for a return");
        wake.returned();
        assert!(wake.pending() && wake.due(), "the return alone makes the row due");
        wake.begin_pass();
        assert!(!wake.pending(), "the pass takes the wake");
        assert!(wake.due(), "every row driven in the pass sees itself due");
        wake.park();
        wake.end_pass();
        assert!(!wake.due(), "a row still waiting parks for the next return");
        wake.returned();
        assert!(wake.pending(), "and the next return wakes it again");
    }

    #[test]
    fn a_return_during_the_pass_wakes_a_row_parked_in_it() {
        let mut wake = CompletionRetryWake::new();
        wake.park();
        wake.returned();
        wake.begin_pass();
        wake.park();
        wake.returned();
        wake.end_pass();
        assert!(wake.pending(), "a return after the row parked in the pass is not lost");
    }
}
