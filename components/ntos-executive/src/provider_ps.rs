//! Ps provider requests use one canonical manager before and after live-handler transfer.

use super::*;

/// The enclosing pump authenticates the caller before entering this request decoder. No borrowed
/// manager state crosses provider IPC; yielding below only yields the executive's physical TCB.
pub(crate) fn dispatch(
    pm: &mut nt_process::ProcessManager,
    op: u64,
    object: u64,
    value: u64,
) -> (i32, u64, u64, u64) {
    use win32k_subsystem::*;
    const INVALID_HANDLE: u32 = 0xc000_0008;
    const INVALID_PARAMETER: u32 = 0xc000_000d;
    let result = match op {
        W32_PS_OP_QUERY_PROCESS => pm
            .kernel_process_state(object)
            .map(|state| {
                (
                    u64::from(state.exit_status),
                    u64::from(state.session_id),
                    u64::from(state.exit_process_called),
                )
            })
            .ok_or(INVALID_HANDLE),
        W32_PS_OP_QUERY_THREAD => pm
            .kernel_thread_state(object)
            .map(|state| {
                let flags = u64::from(state.terminating) | (u64::from(state.system_thread) << 1);
                (
                    u64::from(state.exit_status),
                    u64::from(state.freeze_count),
                    flags | (u64::from(state.priority as u32) << 32),
                )
            })
            .ok_or(INVALID_HANDLE),
        W32_PS_OP_SET_THREAD_PRIORITY => pm
            .set_kernel_thread_priority(object, value as u32 as i32)
            .map(|previous| (u64::from(previous as u32), 0, 0)),
        W32_PS_OP_LOOKUP_PROCESS => nt_process::ProcessId::try_from(object)
            .map_err(|_| INVALID_PARAMETER)
            .and_then(|pid| pm.lookup_kernel_process_by_id(pid))
            .map(|(body, references)| (body, u64::from(references), 0)),
        W32_PS_OP_LOOKUP_THREAD => nt_process::ThreadId::try_from(object)
            .map_err(|_| INVALID_PARAMETER)
            .and_then(|tid| pm.lookup_kernel_thread_by_id(tid))
            .map(|(body, references)| (body, u64::from(references), 0)),
        W32_PS_OP_RETAIN_POINTER => pm
            .retain_kernel_object_pointer(object)
            .map(|references| (u64::from(references), 0, 0)),
        W32_PS_OP_RELEASE_POINTER => pm
            .release_kernel_object_pointer(object)
            .map(|references| (u64::from(references), 0, 0)),
        W32_PS_OP_YIELD_EXECUTION => pm
            .tid_for_kernel_thread_object(object)
            .ok_or(INVALID_HANDLE)
            .and_then(|tid| {
                if !pm.has_yield_candidate(tid) {
                    return Err(0x4000_0024);
                }
                sel4_rt::yield_now();
                Ok((0, 0, 0))
            }),
        _ => Err(INVALID_PARAMETER),
    };
    match result {
        Ok((out1, out2, out3)) => (0, out1, out2, out3),
        Err(status) => (status as i32, 0, 0, 0),
    }
}
