//! Priority effects for a PsCreateSystemThread worker's own canonical ETHREAD and TCB.

use super::*;

pub(super) unsafe fn dispatch(
    runtime: HostedDriverThreadRuntime,
    lifetime: nt_process::ThreadLifetime,
    thread: u64,
    priority: i32,
) -> Result<i32, u32> {
    let (previous, next) = hosted_thread_resources::prepare_priority(
        runtime, lifetime, thread, priority,
    )?;
    let physical_previous = nt_user_host::hosted_priority::hosted_tcb_priority(previous)?;
    let physical_next = nt_user_host::hosted_priority::hosted_tcb_priority(next)?;
    if physical_previous != physical_next && tcb_set_priority_r(runtime.tcb, u64::from(physical_next)) != 0 {
        // Keep the retained plan. The native effect may have reached the TCB before refusal.
        return Err(nt_process::STATUS_UNSUCCESSFUL);
    }
    hosted_thread_resources::commit_priority(runtime, lifetime)
}
