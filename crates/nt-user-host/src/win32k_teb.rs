//! Choose the TEB view needed by a win32k dispatch.
//!
//! `CreateThreadInfo` binds `THREADINFO.pClientInfo` to the inline
//! `Win32ClientInfo` in the TEB used for its thread callout. An entry point
//! that checks that link must run with the same TEB selected.

const WIN32_CLIENT_INFO_OFFSET: u64 = 0x800;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchTebPurpose {
    ThreadInfo,
    UserObjectName,
    Compatibility,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchTebCandidates {
    pub callout_teb: u64,
    pub client_teb: u64,
    pub compatibility_teb: u64,
    pub thread_client_info: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchTebError {
    MissingTeb,
    ClientInfoMismatch,
}

/// Select the TEB view for entry points whose native call chain is established. A desktop switch
/// reaches window-position code that checks `THREADINFO.pClientInfo` against `NtCurrentTeb()`;
/// desktop creation instead captures a user `OBJECT_ATTRIBUTES` name from the client TEB.
pub fn purpose_for_win32k_syscall(ssn: u64, arg1: u64) -> DispatchTebPurpose {
    match ssn {
        // CreateEmptyCurObject (0x21) calls GetW32ThreadInfo, whose debug hook verifies that
        // NtCurrentTeb()->Win32ClientInfo is the THREADINFO's published pClientInfo.
        0x1002 if matches!(arg1, 0x21 | 0x22) => DispatchTebPurpose::ThreadInfo,
        // SetCursorIconData enters GetW32ThreadInfo, which checks the current TEB's inline
        // Win32ClientInfo against THREADINFO.pClientInfo after captured user input is staged.
        0x10a8 => DispatchTebPurpose::ThreadInfo,
        // LoadKeyboardLayoutEx activates the new layout through GetW32ThreadInfo after its
        // optional charset and IMM callbacks have returned.
        0x125c => DispatchTebPurpose::ThreadInfo,
        0x1288 => DispatchTebPurpose::ThreadInfo,
        0x1ffd | 0x122f | 0x122d => DispatchTebPurpose::UserObjectName,
        _ => DispatchTebPurpose::Compatibility,
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
        DispatchTebPurpose::Compatibility =>
            (candidates.compatibility_teb != 0).then_some(candidates.compatibility_teb)
                .ok_or(DispatchTebError::MissingTeb),
    }
}
