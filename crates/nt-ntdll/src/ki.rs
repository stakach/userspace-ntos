//! `Ki*` — the user-mode dispatchers the **kernel jumps to** (not imported by name — the kernel
//! sets RIP to these entry points to deliver APCs / exceptions / callbacks).
//!
//! These are load-bearing even though nothing imports them (0 in the Step-1 measurement): the
//! kernel/executive delivers asynchronous events by pushing a frame onto the target thread's stack
//! and setting RIP to the matching `Ki*` dispatcher, which unpacks the frame, does its work, and
//! resumes the interrupted context via `NtContinue` (or returns into the kernel).
//!
//! * [`apc_dispatcher`] — `KiUserApcDispatcher`: the kernel delivered a queued APC (`NtQueueApcThread`
//!   / I/O completion). Unpack `(routine, arg1, arg2, arg3, CONTEXT*)`, call the APC routine, then
//!   `NtContinue(CONTEXT, alertable=TRUE)` back to the interrupted point.
//! * [`exception_dispatcher`] — `KiUserExceptionDispatcher`: the kernel delivered an exception
//!   (`(EXCEPTION_RECORD*, CONTEXT*)`). Run [`crate::rtl::exception::dispatch_exception`]; on handled
//!   `NtContinue(CONTEXT)`, on unhandled `NtRaiseException(..., FirstChance=FALSE)` → the process
//!   default (terminate).
//! * [`callback_dispatcher`] — `KiUserCallbackDispatcher`: the win32k `KeUserModeCallback` bridge
//!   (`project_win32k_graphics`). The kernel called *out* to user mode with `(ApiIndex, InputBuffer,
//!   Length)`; dispatch to `PEB->KernelCallbackTable[ApiIndex]`, then `NtCallbackReturn(result)` back
//!   into the kernel.
//! * [`raise_exception_dispatcher`] — `KiRaiseUserExceptionDispatcher`: a kernel-detected user error
//!   is re-raised in user mode as a normal exception via [`crate::rtl::exception`].
//!
//! The **dispatch LOGIC** here is host-testable (given a mock frame / callback table); the machine-
//! context save/restore + the `NtContinue`/`NtCallbackReturn` syscalls are target-gated seams.

use crate::rtl::exception::{dispatch_exception, DispatchResult, ExceptionRecord, FrameModel};
use crate::NtStatus;
use crate::{STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};

/// A pending APC as unpacked from the `KiUserApcDispatcher` stack frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ApcFrame {
    /// The user-mode APC routine (`PKNORMAL_ROUTINE`).
    pub routine: u64,
    /// `NormalContext` (arg 1 to the routine).
    pub arg1: u64,
    /// `SystemArgument1` (arg 2).
    pub arg2: u64,
    /// `SystemArgument2` (arg 3).
    pub arg3: u64,
    /// Pointer to the interrupted `CONTEXT` to resume via `NtContinue`.
    pub context: u64,
}

/// The verdict of an APC-dispatch step: whether the APC routine should be called + the context to
/// resume. (The actual call + `NtContinue` are target-gated; this is the decision the dispatcher
/// makes so the wiring is host-testable.)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ApcDispatch {
    /// The routine to invoke (0 = none — a bare "alert" APC just resumes).
    pub call_routine: u64,
    /// The context pointer to `NtContinue` back into.
    pub resume_context: u64,
}

/// `KiUserApcDispatcher` dispatch logic: given the unpacked frame, decide the routine to call + the
/// context to resume. A null routine (`routine == 0`) is a bare alert — resume without calling.
pub fn apc_dispatcher(frame: &ApcFrame) -> ApcDispatch {
    ApcDispatch {
        call_routine: frame.routine,
        resume_context: frame.context,
    }
}

/// The verdict of `KiUserExceptionDispatcher`: resume the (possibly handler-fixed) context, or
/// escalate to the process default (last-chance → terminate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExceptionOutcome {
    /// A handler continued execution — resume via `NtContinue(context)`.
    Continue { context: u64 },
    /// Unhandled — re-raise as a last-chance exception (`NtRaiseException(FirstChance=FALSE)`),
    /// which the kernel turns into process termination.
    LastChance,
    /// A noncontinuable exception a handler tried to continue — raise
    /// `STATUS_NONCONTINUABLE_EXCEPTION`.
    Noncontinuable,
}

/// `KiUserExceptionDispatcher(ExceptionRecord*, Context*)` dispatch logic: run the SEH dispatch over
/// the frame set; map the result to the resume/escalate decision. `context` is the pointer to the
/// interrupted `CONTEXT` (resumed on the handled path).
pub fn exception_dispatcher(
    record: &ExceptionRecord,
    frames: &[FrameModel],
    context: u64,
) -> ExceptionOutcome {
    match dispatch_exception(record, frames) {
        DispatchResult::Handled { .. } => ExceptionOutcome::Continue { context },
        DispatchResult::Unhandled => ExceptionOutcome::LastChance,
        DispatchResult::Noncontinuable => ExceptionOutcome::Noncontinuable,
    }
}

/// A win32k `KeUserModeCallback` request as unpacked from the `KiUserCallbackDispatcher` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackFrame {
    /// The `ApiIndex` into `PEB->KernelCallbackTable`.
    pub api_index: u32,
    /// The input buffer (copied out to user mode by the kernel).
    pub input: alloc::vec::Vec<u8>,
}

/// The verdict of `KiUserCallbackDispatcher`: the resolved callback routine address (from the
/// callback table) + the input to pass. The routine is invoked target-side, then
/// `NtCallbackReturn(result)` returns into the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackDispatch {
    /// The resolved callback routine (0 = the api index was out of range → return an error status).
    pub routine: u64,
    /// The input buffer to pass to the routine.
    pub input: alloc::vec::Vec<u8>,
}

/// `KiUserCallbackDispatcher` dispatch logic: resolve `api_index` against the callback table (the
/// `PEB->KernelCallbackTable`, modelled here as a slice of routine addresses). Out-of-range →
/// `routine == 0` (the dispatcher returns `STATUS_INVALID_PARAMETER` via `NtCallbackReturn`).
pub fn callback_dispatcher(frame: &CallbackFrame, callback_table: &[u64]) -> CallbackDispatch {
    let routine = callback_table.get(frame.api_index as usize).copied().unwrap_or(0);
    CallbackDispatch {
        routine,
        input: frame.input.clone(),
    }
}

/// `KiRaiseUserExceptionDispatcher` dispatch logic: a kernel-detected user error is re-raised as a
/// user-mode exception. Returns the [`ExceptionOutcome`] of dispatching it (same machinery as
/// [`exception_dispatcher`]).
pub fn raise_exception_dispatcher(
    record: &ExceptionRecord,
    frames: &[FrameModel],
    context: u64,
) -> ExceptionOutcome {
    exception_dispatcher(record, frames, context)
}

// --- Target-gated resume seams ----------------------------------------------------------------

/// `NtContinue(Context*, Alertable)` — resume the interrupted context (the tail of every dispatcher).
/// Target-gated: on the host there is no context to resume, so this is an honest seam returning
/// `STATUS_NOT_IMPLEMENTED` (never a fabricated resume).
#[cfg(not(target_arch = "x86_64"))]
pub fn nt_continue(_context: u64, _alertable: bool) -> NtStatus {
    STATUS_NOT_IMPLEMENTED
}

/// `NtContinue(Context*, Alertable)` — the real resume (SSN 60) on the target. Wired with the
/// transport in Step 6; declared here so the dispatcher tail has its call site.
#[cfg(target_arch = "x86_64")]
pub fn nt_continue(_context: u64, _alertable: bool) -> NtStatus {
    // Real: issue the NtContinue trap/Call. Wired with the transport in Step 6.
    STATUS_NOT_IMPLEMENTED
}

/// `NtCallbackReturn(Result*, ResultLength, Status)` — return from a user-mode callback into the
/// kernel (the tail of [`callback_dispatcher`]). Modelled: returns the status the callback produced.
/// The real syscall (SSN via the `ZwCallbackReturn` alias) is wired in Step 6.
pub fn nt_callback_return(status: NtStatus) -> NtStatus {
    // On success this does not return to user mode (control resumes in the kernel); we model the
    // status hand-back for host testing.
    status
}

/// A convenience: the status a callback dispatch hands back when the api index was valid.
pub const CALLBACK_OK: NtStatus = STATUS_SUCCESS;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::rtl::exception::Disposition;
    use std::vec;

    fn rec() -> ExceptionRecord {
        ExceptionRecord {
            code: 0xC000_0005,
            flags: 0,
            address: 0x1400_1000,
            information: vec![0, 0xDEAD],
        }
    }

    #[test]
    fn apc_dispatch_calls_routine_then_resumes() {
        let f = ApcFrame { routine: 0x1000, arg1: 1, arg2: 2, arg3: 3, context: 0x7FFF_0000 };
        let d = apc_dispatcher(&f);
        assert_eq!(d.call_routine, 0x1000);
        assert_eq!(d.resume_context, 0x7FFF_0000);
    }

    #[test]
    fn apc_dispatch_bare_alert() {
        let f = ApcFrame { routine: 0, arg1: 0, arg2: 0, arg3: 0, context: 0x1234 };
        let d = apc_dispatcher(&f);
        assert_eq!(d.call_routine, 0); // no routine — just resume
        assert_eq!(d.resume_context, 0x1234);
    }

    #[test]
    fn exception_dispatch_continue_on_handled() {
        let frames = [FrameModel { control_pc: 0x1400_1000, handler: Some(Disposition::ContinueExecution) }];
        assert_eq!(
            exception_dispatcher(&rec(), &frames, 0xC0FFEE),
            ExceptionOutcome::Continue { context: 0xC0FFEE }
        );
    }

    #[test]
    fn exception_dispatch_last_chance_when_unhandled() {
        let frames = [FrameModel { control_pc: 0x1400_1000, handler: Some(Disposition::ContinueSearch) }];
        assert_eq!(exception_dispatcher(&rec(), &frames, 0), ExceptionOutcome::LastChance);
    }

    #[test]
    fn callback_resolves_from_table() {
        let table = [0xAAAA, 0xBBBB, 0xCCCC];
        let f = CallbackFrame { api_index: 1, input: vec![1, 2, 3] };
        let d = callback_dispatcher(&f, &table);
        assert_eq!(d.routine, 0xBBBB);
        assert_eq!(d.input, vec![1, 2, 3]);
    }

    #[test]
    fn callback_out_of_range_is_null_routine() {
        let table = [0xAAAA];
        let f = CallbackFrame { api_index: 5, input: vec![] };
        let d = callback_dispatcher(&f, &table);
        assert_eq!(d.routine, 0); // → dispatcher returns an error via NtCallbackReturn
    }

    #[test]
    fn resume_seams_are_honest() {
        // No fabricated resume on the host.
        assert_eq!(nt_continue(0x1000, true), STATUS_NOT_IMPLEMENTED);
        // NtCallbackReturn models the status hand-back.
        assert_eq!(nt_callback_return(CALLBACK_OK), STATUS_SUCCESS);
    }
}
