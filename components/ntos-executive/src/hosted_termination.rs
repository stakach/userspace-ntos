//! Retry physical termination using retained caller provenance, never recycled numeric IDs.

use crate::*;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

pub(crate) unsafe fn reconcile(
    handler: &mut ExecNtHandler,
    queue: &mut nt_delay_execution::Queue,
    caller: ProviderLogicalCaller,
) -> bool {
    let tid = caller.thread().thread_id();
    if handler.capture_process_identity(caller.pi()) != Some(caller.process()) {
        return true;
    }
    if handler
        .pm
        .process(caller.process().pid)
        .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
    {
        // A process-wide barrier may have stopped termination before visiting any peer threads.
        if let Ok(pi) = u8::try_from(caller.pi()) {
            let _ = terminate_hosted_process_mechanisms(pi, None, queue, handler);
        }
        return !handler.thread_runtime.has_process(caller.pi());
    }
    let same_thread = |handler: &ExecNtHandler| {
        caller
            .validate(
                handler
                    .thread_runtime
                    .get_by_tid(u64::from(tid))
                    .map(|runtime| runtime.binding()),
                handler.pm.thread_lifetime(tid),
            )
            .is_ok()
    };
    // Ownership-visible bindings are authoritative; temporarily blocked ingress is not retirement.
    if !same_thread(handler) {
        return true;
    }
    if handler
        .pm
        .thread(tid)
        .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
    {
        let _ = terminate_hosted_thread_mechanism(u64::from(tid), queue, handler);
        return !same_thread(handler);
    }
    false
}
