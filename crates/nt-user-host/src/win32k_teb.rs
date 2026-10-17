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
