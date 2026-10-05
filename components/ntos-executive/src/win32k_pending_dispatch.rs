//! Captured win32k wait payloads and pump outcomes.

use super::*;

pub(super) static PROVIDER_WAIT_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);
pub(super) static LPC_WAIT_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) struct PendingProviderWaitDispatch {
    pub request: nt_provider_wait::ProviderWaitRequest,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub nested_user_callback: bool,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut PROVIDER_WAIT_PENDING_DISPATCH: Option<PendingProviderWaitDispatch> = None;

#[derive(Clone, Copy)]
pub(crate) struct PendingLpcWaitDispatch {
    pub request: win32k_subsystem::Win32kLpcWaitRequest,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub nested_user_callback: bool,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut LPC_WAIT_PENDING_DISPATCH: Option<PendingLpcWaitDispatch> = None;

pub(crate) enum ProviderWaitPumpCompletion {
    Completed(CompletedWin32kDispatch),
    Reparked(PendingProviderWaitDispatch),
    LpcReparked(PendingLpcWaitDispatch),
    UserCallbackSuspended,
    Failed(i32),
}

pub(crate) enum LpcWaitPumpCompletion {
    Completed(CompletedWin32kDispatch),
    ProviderReparked(PendingProviderWaitDispatch),
    Reparked(PendingLpcWaitDispatch),
    UserCallbackSuspended,
    Failed(i32),
}

pub(crate) unsafe fn take_pending_provider_wait_dispatch() -> Option<PendingProviderWaitDispatch> {
    if PROVIDER_WAIT_LAST_PUMP_SUSPENDED.swap(0, Ordering::AcqRel) == 0 {
        return None;
    }
    core::ptr::replace(
        core::ptr::addr_of_mut!(PROVIDER_WAIT_PENDING_DISPATCH),
        None,
    )
}

pub(crate) unsafe fn take_pending_lpc_wait_dispatch() -> Option<PendingLpcWaitDispatch> {
    if LPC_WAIT_LAST_PUMP_SUSPENDED.swap(0, Ordering::AcqRel) == 0 {
        return None;
    }
    core::ptr::replace(core::ptr::addr_of_mut!(LPC_WAIT_PENDING_DISPATCH), None)
}

pub(super) unsafe fn capture_provider_wait_repark(
    prior: PendingProviderWaitDispatch,
) -> PendingProviderWaitDispatch {
    let page = win32k_subsystem::WIN32K_PROVIDER_WAIT_VADDR
        as *const nt_provider_wait::ProviderWaitSharedPage;
    PendingProviderWaitDispatch {
        request: core::ptr::read_volatile(core::ptr::addr_of!((*page).request)),
        dispatch: prior.dispatch,
        client: prior.client,
        nested_user_callback: prior.nested_user_callback,
        arg_snapshot_len: prior.arg_snapshot_len,
        arg_snapshot: prior.arg_snapshot,
    }
}

pub(super) unsafe fn capture_lpc_wait_repark(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
    nested_user_callback: bool,
    arg_snapshot_len: u32,
    arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
) -> Option<PendingLpcWaitDispatch> {
    Some(PendingLpcWaitDispatch {
        request: win32k_subsystem::capture_lpc_wait_request()?,
        dispatch,
        client,
        nested_user_callback,
        arg_snapshot_len,
        arg_snapshot,
    })
}

pub(super) unsafe fn capture_initial_arg_snapshot(
    ssn: u64,
    completion_args: [u64; 4],
) -> (u32, [u8; COMPLETED_ARG_SNAPSHOT_BYTES]) {
    let mut arg_snapshot = [0u8; COMPLETED_ARG_SNAPSHOT_BYTES];
    let arg_snapshot_len = match ssn {
        nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN => {
            nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES as usize
        }
        win32k_subsystem::SSN_NT_USER_INITIALIZE => {
            (completion_args[2] as usize).min(COMPLETED_ARG_SNAPSHOT_BYTES)
        }
        _ => 0,
    };
    if arg_snapshot_len != 0 {
        core::ptr::copy_nonoverlapping(
            win32k_subsystem::WIN32K_ARG_VADDR as *const u8,
            arg_snapshot.as_mut_ptr(),
            arg_snapshot_len,
        );
    }
    (arg_snapshot_len as u32, arg_snapshot)
}
