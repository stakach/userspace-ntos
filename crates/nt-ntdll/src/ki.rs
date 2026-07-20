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
use crate::{STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};

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

/// The x64 `MACHINE_FRAME` tail of a ReactOS `UCALLOUT_FRAME`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CallbackMachineFrame {
    pub rip: u64,
    pub seg_cs: u16,
    pub fill1: [u16; 3],
    pub eflags: u32,
    pub fill2: u32,
    pub rsp: u64,
    pub seg_ss: u16,
    pub fill3: [u16; 3],
}

/// The exact x64 user callback stack frame consumed by `KiUserCallbackDispatcher`.
///
/// This mirrors ReactOS `UCALLOUT_FRAME`: the four ABI home slots are followed by `Buffer` at
/// `+0x20`, `Length` at `+0x28`, `ApiNumber` at `+0x2c`, then a `MACHINE_FRAME`. The callback input
/// remains in the caller-provided user buffer; the frame never allocates or copies it.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CallbackFrame {
    pub home: [u64; 4],
    pub input: u64,
    pub input_length: u32,
    pub api_index: u32,
    pub machine_frame: CallbackMachineFrame,
}

/// A validated, allocation-free callback request unpacked from [`CallbackFrame`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CallbackRequest {
    pub api_index: u32,
    pub input: u64,
    pub input_length: u32,
}

/// Why a user callback frame or table could not be dispatched.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CallbackError {
    NullInput,
    InputRangeOverflow,
    NullTable,
    UnalignedTable,
    IndexOutOfRange,
    TableRangeOverflow,
    NullRoutine,
}

impl CallbackError {
    pub const fn status(self) -> NtStatus {
        STATUS_INVALID_PARAMETER
    }
}

/// The validated callback routine and borrowed input range to pass to it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CallbackDispatch {
    pub routine: u64,
    pub input: u64,
    pub input_length: u32,
}

/// Validate the buffer range in a raw x64 callback frame and unpack its request.
pub fn callback_request(frame: &CallbackFrame) -> Result<CallbackRequest, CallbackError> {
    if frame.input_length != 0 {
        if frame.input == 0 {
            return Err(CallbackError::NullInput);
        }
        if frame.input.checked_add(u64::from(frame.input_length) - 1).is_none() {
            return Err(CallbackError::InputRangeOverflow);
        }
    }
    Ok(CallbackRequest {
        api_index: frame.api_index,
        input: frame.input,
        input_length: frame.input_length,
    })
}

/// Resolve the address of an indexed callback-table slot without dereferencing it.
pub fn callback_table_slot(
    table_base: u64,
    table_entries: u32,
    api_index: u32,
) -> Result<u64, CallbackError> {
    if table_base == 0 {
        return Err(CallbackError::NullTable);
    }
    if table_base & 7 != 0 {
        return Err(CallbackError::UnalignedTable);
    }
    if api_index >= table_entries {
        return Err(CallbackError::IndexOutOfRange);
    }
    table_base
        .checked_add(u64::from(api_index) * 8)
        .ok_or(CallbackError::TableRangeOverflow)
}

/// Host-testable callback resolution against a bounded table.
pub fn callback_dispatcher(
    request: CallbackRequest,
    callback_table: &[u64],
) -> Result<CallbackDispatch, CallbackError> {
    let routine = callback_table
        .get(request.api_index as usize)
        .copied()
        .ok_or(CallbackError::IndexOutOfRange)?;
    if routine == 0 {
        return Err(CallbackError::NullRoutine);
    }
    Ok(CallbackDispatch {
        routine,
        input: request.input,
        input_length: request.input_length,
    })
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
        let f = CallbackFrame {
            input: 0x1000,
            input_length: 3,
            api_index: 1,
            ..Default::default()
        };
        let request = callback_request(&f).unwrap();
        let d = callback_dispatcher(request, &table).unwrap();
        assert_eq!(d.routine, 0xBBBB);
        assert_eq!(d.input, 0x1000);
        assert_eq!(d.input_length, 3);
    }

    #[test]
    fn callback_out_of_range_is_rejected() {
        let table = [0xAAAA];
        let request = CallbackRequest { api_index: 5, input: 0, input_length: 0 };
        assert_eq!(
            callback_dispatcher(request, &table),
            Err(CallbackError::IndexOutOfRange)
        );
    }

    #[test]
    fn callback_frame_matches_reactos_amd64_layout() {
        assert_eq!(core::mem::size_of::<CallbackMachineFrame>(), 0x28);
        assert_eq!(core::mem::size_of::<CallbackFrame>(), 0x58);
        let frame = CallbackFrame::default();
        let base = core::ptr::addr_of!(frame) as usize;
        assert_eq!(core::ptr::addr_of!(frame.input) as usize - base, 0x20);
        assert_eq!(core::ptr::addr_of!(frame.input_length) as usize - base, 0x28);
        assert_eq!(core::ptr::addr_of!(frame.api_index) as usize - base, 0x2c);
        assert_eq!(core::ptr::addr_of!(frame.machine_frame) as usize - base, 0x30);
        let machine = core::ptr::addr_of!(frame.machine_frame) as usize;
        assert_eq!(core::ptr::addr_of!(frame.machine_frame.rip) as usize - machine, 0x00);
        assert_eq!(core::ptr::addr_of!(frame.machine_frame.eflags) as usize - machine, 0x10);
        assert_eq!(core::ptr::addr_of!(frame.machine_frame.rsp) as usize - machine, 0x18);
    }

    #[test]
    fn callback_request_validates_null_and_overflowing_input() {
        let null = CallbackFrame { input_length: 1, ..Default::default() };
        assert_eq!(callback_request(&null), Err(CallbackError::NullInput));
        let overflow = CallbackFrame {
            input: u64::MAX,
            input_length: 2,
            ..Default::default()
        };
        assert_eq!(callback_request(&overflow), Err(CallbackError::InputRangeOverflow));
        let empty = CallbackFrame::default();
        assert_eq!(callback_request(&empty).unwrap().input, 0);
    }

    #[test]
    fn callback_table_slot_validates_base_index_and_overflow() {
        assert_eq!(callback_table_slot(0, 20, 0), Err(CallbackError::NullTable));
        assert_eq!(callback_table_slot(0x1004, 20, 0), Err(CallbackError::UnalignedTable));
        assert_eq!(callback_table_slot(0x1000, 20, 20), Err(CallbackError::IndexOutOfRange));
        assert_eq!(callback_table_slot(u64::MAX - 7, 20, 1), Err(CallbackError::TableRangeOverflow));
        assert_eq!(callback_table_slot(0x1000, 20, 3), Ok(0x1018));
    }

    #[test]
    fn callback_rejects_null_routine() {
        let request = CallbackRequest { api_index: 0, input: 0, input_length: 0 };
        assert_eq!(callback_dispatcher(request, &[0]), Err(CallbackError::NullRoutine));
        assert_eq!(CallbackError::NullRoutine.status(), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn resume_seams_are_honest() {
        // No fabricated resume on the host.
        assert_eq!(nt_continue(0x1000, true), STATUS_NOT_IMPLEMENTED);
        // NtCallbackReturn models the status hand-back.
        assert_eq!(nt_callback_return(CALLBACK_OK), STATUS_SUCCESS);
    }
}
