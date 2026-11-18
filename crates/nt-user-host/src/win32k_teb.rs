//! Choose the TEB view needed by a win32k dispatch.
//!
//! `CreateThreadInfo` binds `THREADINFO.pClientInfo` to the inline
//! `Win32ClientInfo` in the TEB used for its thread callout. An entry point
//! that checks that link must run with the same TEB selected.

const WIN32_CLIENT_INFO_OFFSET: u64 = 0x800;

/// `TEB.LastErrorValue`.
pub const TEB_LAST_ERROR_VALUE: u64 = 0x68;

/// The caller's last error after a dispatch that ran on the THREADINFO-bound TEB.
///
/// win32k reports a failure with `EngSetLastError` (`win32ss/gdi/eng/error.c`), which writes
/// `NtCurrentTeb()->LastErrorValue`; in NT that is the calling thread's own TEB. When the
/// dispatch ran on a different TEB view, the value it held before the call was the caller's
/// (`seeded`), so a different value afterwards (`after`) is what win32k set and the caller
/// must see. An unchanged value leaves the caller's own, including anything a user-mode
/// callback set during the dispatch.
pub fn caller_last_error_after_dispatch(seeded: u32, after: u32) -> Option<u32> {
    (after != seeded).then_some(after)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchTebPurpose {
    ThreadInfo,
    UserObjectName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchTebCandidates {
    pub callout_teb: u64,
    pub client_teb: u64,
    pub thread_client_info: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchTebError {
    MissingTeb,
    ClientInfoMismatch,
}

/// Native GUI calls run on the TEB bound to their THREADINFO. The object-name capture calls
/// instead need the guest TEB while probing user OBJECT_ATTRIBUTES.
pub fn purpose_for_win32k_syscall(ssn: u64) -> DispatchTebPurpose {
    match ssn {
        0x1ffd | 0x122f | 0x122d => DispatchTebPurpose::UserObjectName,
        _ => DispatchTebPurpose::ThreadInfo,
    }
}

pub fn select_dispatch_teb(
    purpose: DispatchTebPurpose,
    candidates: DispatchTebCandidates,
) -> Result<u64, DispatchTebError> {
    match purpose {
        DispatchTebPurpose::ThreadInfo => {
            let client_info = candidates.callout_teb
                .checked_add(WIN32_CLIENT_INFO_OFFSET)
                .filter(|_| candidates.callout_teb != 0)
                .ok_or(DispatchTebError::MissingTeb)?;
            if client_info != candidates.thread_client_info {
                return Err(DispatchTebError::ClientInfoMismatch);
            }
            Ok(candidates.callout_teb)
        }
        DispatchTebPurpose::UserObjectName =>
            (candidates.client_teb != 0).then_some(candidates.client_teb)
                .ok_or(DispatchTebError::MissingTeb),
    }
}
