//! Executive-owned active console state and publication to every KUSER alias.

use super::*;

static ACTIVE_CONSOLE_ID: AtomicU32 = AtomicU32::new(0);

pub(crate) fn current() -> u32 {
    ACTIVE_CONSOLE_ID.load(Ordering::Acquire)
}

/// The caller holds the authenticated win32k provider dispatch. The executive
/// pump serializes this update with process KUSER snapshot creation and alias
/// registration; each live page receives one aligned 32-bit store.
pub(crate) unsafe fn publish(session_id: u32) {
    unsafe { for_each_kuser_page_alias(|alias| {
        nt_ntdll_layout::kuser::publish_active_console_id(alias as *mut u8, session_id)
    }) };
    ACTIVE_CONSOLE_ID.store(session_id, Ordering::Release);
}

/// Admit only the exact physical win32k provider invocation before changing
/// executive-owned KUSER pages. The native export is void, so rejection is a
/// provider failure rather than a silent successful return.
pub(crate) unsafe fn service(
    channel: &spawn_hosts::PumpChannel,
    session_id: u64,
) -> u32 {
    if unsafe { provider_ps_projection::authenticated_target(channel) }.is_err() {
        return nt_process::STATUS_INVALID_HANDLE;
    }
    let Ok(session_id) = u32::try_from(session_id) else {
        return nt_process::STATUS_INVALID_PARAMETER;
    };
    unsafe { publish(session_id) };
    0
}
