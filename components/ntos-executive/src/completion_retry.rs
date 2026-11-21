//! Work rows' copies and ACKs of completed IRPs (#420).
//!
//! A copy or ACK whose kept backend pump is still running answers `STATUS_PENDING`. Every row
//! classifies its copy and ACK results here (`nt_hosted_runtime::CompletionStep`): a retry
//! keeps the row's phase and resources, and parks it until a kept pump returns. The return
//! makes parked rows due ahead of their own retry deadlines, and the root runs its next row
//! pass without waiting for an event.

use nt_hosted_runtime::{CompletionRetryWake, CompletionStep};

static mut WAKE: CompletionRetryWake = CompletionRetryWake::new();

fn wake() -> &'static mut CompletionRetryWake {
    // SAFETY: only the root's single service thread classifies results and runs row passes.
    unsafe { &mut *core::ptr::addr_of_mut!(WAKE) }
}

fn parked<T>(step: CompletionStep<T>) -> CompletionStep<T> {
    if matches!(step, CompletionStep::Retry) {
        wake().park();
    }
    step
}

/// Classify an executive copy or ACK result. A retry parks the row for the next kept return.
pub(crate) fn step<T>(result: Result<T, u32>) -> CompletionStep<T> {
    parked(CompletionStep::of(result))
}

/// [`step`] for an I/O Manager result.
pub(crate) fn step_status<T>(result: Result<T, nt_status::NtStatus>) -> CompletionStep<T> {
    parked(CompletionStep::of_status(result))
}

/// [`step`] for a row that already retries on any error: the result is unchanged, and a
/// still-running operation parks the row for the next kept return.
pub(crate) fn retried<T>(result: Result<T, u32>) -> Result<T, u32> {
    if result.as_ref().is_err_and(|status| *status == nt_status::NtStatus::PENDING.raw() as u32) {
        wake().park();
    }
    result
}

/// [`retried`] for an I/O Manager result.
pub(crate) fn retried_status<T>(
    result: Result<T, nt_status::NtStatus>,
) -> Result<T, nt_status::NtStatus> {
    if result.as_ref().is_err_and(|status| *status == nt_status::NtStatus::PENDING) {
        wake().park();
    }
    result
}

/// A kept backend pump returned.
pub(crate) fn returned() {
    wake().returned();
}

/// Whether a kept return has made parked rows due ahead of their own retry deadlines.
pub(crate) fn due() -> bool {
    wake().due()
}

/// A row's next deadline: now while a kept return has made parked rows due.
pub(crate) fn row_deadline(deadline: u64) -> u64 {
    if due() { 0 } else { deadline }
}

/// The root's own deadline for a due wake, so it runs its row pass instead of waiting.
pub(crate) fn next_deadline() -> Option<u64> {
    wake().pending().then_some(0)
}

/// Bracket the root's row pass: rows driven inside it see a taken wake as due.
pub(crate) fn begin_pass() {
    wake().begin_pass();
}

pub(crate) fn end_pass() {
    wake().end_pass();
}
