//! Retain an exact Event while an origin commits its source-IRP completion.

use crate::ExecNtHandler;
use nt_kernel_exec::{DeferredEventSignal, EventLeaseId, EventLeaseKind, EventObjectId};

const INVALID_PARAMETER: u32 = 0xc000_000d;
const INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

#[derive(Clone, Copy)]
pub(crate) struct Barrier {
    id: EventObjectId,
    lease: EventLeaseId,
    signal: DeferredEventSignal,
}

impl Barrier {
    pub(crate) fn sequence(self) -> u64 {
        self.signal.state_sequence()
    }
}

/// Preparation is durable but does not make the completion observable by waiters.
pub(crate) unsafe fn capture(
    handler: *mut ExecNtHandler,
    id: EventObjectId,
) -> Result<Barrier, u32> {
    let handler = &mut *handler;
    let snapshot = handler
        .event_objects
        .snapshot(id)
        .map_err(|_| INVALID_PARAMETER)?;
    if snapshot.delete_pending {
        return Err(INVALID_PARAMETER);
    }
    let lease = handler
        .event_objects
        .acquire_wait(id, EventLeaseKind::Operation)
        .map_err(|_| INSUFFICIENT_RESOURCES)?;
    let signal = match handler
        .events
        .begin_deferred_signal(snapshot.native_identity)
    {
        Ok(signal) => signal,
        Err(_) => {
            if let Some(retired) = handler
                .event_objects
                .release_wait(lease, EventLeaseKind::Operation)
                .expect("unentered source completion Event lease")
            {
                handler.finalize_retired_event_object(retired);
            }
            return Err(INSUFFICIENT_RESOURCES);
        }
    };
    Ok(Barrier { id, lease, signal })
}

/// Call only after the origin's exact commit ACK. A missing identity never permits signaling
/// replacement backing. Native uncertainty before this point retains the entire barrier.
pub(crate) unsafe fn release(handler: *mut ExecNtHandler, barrier: Barrier) -> Result<(), u32> {
    let handler = &mut *handler;
    if handler
        .event_objects
        .event_for_lease(barrier.lease, EventLeaseKind::Operation)
        != Ok(barrier.id)
        || !handler
            .event_objects
            .snapshot(barrier.id)
            .is_ok_and(|snapshot| snapshot.native_identity == barrier.signal.native_identity())
    {
        return Err(INVALID_PARAMETER);
    }
    let native =
        usize::try_from(barrier.signal.native_identity()).map_err(|_| INVALID_PARAMETER)?;
    handler
        .events
        .commit_deferred_signal(barrier.signal)
        .map_err(|_| INVALID_PARAMETER)?;
    if handler
        .events
        .query_with_sequence(barrier.signal.native_identity())
        .is_some_and(|(_, _, sequence)| sequence == barrier.sequence())
    {
        crate::wait_wake_event_set(native, handler);
    }
    if let Some(retired) = handler
        .event_objects
        .release_wait(barrier.lease, EventLeaseKind::Operation)
        .expect("committed source completion Event lease")
    {
        handler.finalize_retired_event_object(retired);
    }
    Ok(())
}
