//! Bounded, memory-local admission of stopped kernel jobs into the live dispatcher.

use super::*;
use crate::provider_dispatcher_backend::NativeEventBacking;
use nt_provider_wait::{ProviderDispatcherWaitAdmission, ProviderDispatcherWaitError};
use nt_user_host::provider_dispatcher_backend::{
    ProviderDispatcherAccess, ProviderDispatcherObjects,
};
use nt_user_host::provider_kernel_activation::{
    KernelProviderWaitAdmissionError, KernelProviderWaitWork,
};

static PUBLICATION_FAILURES: AtomicU64 = AtomicU64::new(0);

fn admission_status(error: KernelProviderWaitAdmissionError<u32>) -> u32 {
    match error {
        KernelProviderWaitAdmissionError::Authority(status)
        | KernelProviderWaitAdmissionError::Dispatcher(ProviderDispatcherWaitError::Backend(
            status,
        )) => status,
        KernelProviderWaitAdmissionError::Dispatcher(ProviderDispatcherWaitError::NoCapacity)
        | KernelProviderWaitAdmissionError::Lane(nt_component_suspension::LaneError::NoCapacity) => {
            nt_process::STATUS_INSUFFICIENT_RESOURCES
        }
        _ => nt_process::STATUS_INVALID_PARAMETER,
    }
}

/// Only the live service-loop boundary owns this pass. Bootstrap cannot acquire observed Event
/// waits before it has receive/deadline scheduling. This does not enter the pump or claim a
/// selected resume; the rendezvous blocking guard remains in place until that owner exists.
pub(crate) unsafe fn publish_runtime_waits(handler: &mut ExecNtHandler) {
    let queue =
        SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *const nt_delay_execution::Queue;
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) != handler as *mut ExecNtHandler as u64
        || queue.is_null()
        || DELAY_TIMER_HANDLER.load(Ordering::Relaxed) == 0
        || DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire) != DELAY_TIMER_IRQ_ACTIVE
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let mut published = false;
    let mut cursor = (&*core::ptr::addr_of!(ACTIVATIONS)).wait_work_cursor();
    loop {
        let next = (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).next_wait_work(
            &mut cursor,
            &handler.pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
        );
        let Some((caller, work)) = next else { break };
        let result = work.and_then(|work| {
            let sequence = next_dispatcher_wait_sequence();
            let mut backend = ProviderDispatcherObjects {
                events: &mut handler.events,
                event_objects: &mut handler.event_objects,
                timers: None,
                backing: NativeEventBacking(&mut handler.obj_ns),
                access: Some(ProviderDispatcherAccess::kernel_events(caller.owner())?),
            };
            let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
            let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
            let arbiter = &mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER);
            let catalog = &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS);
            match work {
                KernelProviderWaitWork::Initial(capture) => activations.admit_dispatcher_wait(
                    caller, &handler.pm, catalog, lanes, arbiter, &mut backend, capture,
                    sequence, nt_time_snapshot(), ComponentNativeContinuation::Kernel(capture),
                    ComponentSuspensionCompletion::provider,
                ).map_err(|(error, offered)| {
                    assert!(matches!(offered, ComponentNativeContinuation::Kernel(retained) if retained == capture));
                    admission_status(error)
                }),
                KernelProviderWaitWork::Repark { previous, next } => activations.repark_dispatcher_wait(
                    caller, &handler.pm, catalog, lanes, arbiter, &mut backend, previous, next,
                    sequence, nt_time_snapshot(), ComponentNativeContinuation::Kernel(next),
                    ComponentSuspensionCompletion::provider,
                ).map(|(admission, replaced)| {
                    // Only copied capture metadata is retired here. The activation continues
                    // to own its original channel, bank and canonical Ps references.
                    assert!(matches!(replaced, ComponentNativeContinuation::Kernel(retained) if retained == previous));
                    admission
                }).map_err(|(error, offered)| {
                    assert!(matches!(offered, ComponentNativeContinuation::Kernel(retained) if retained == next));
                    admission_status(error)
                }),
            }
        });
        match result {
            Ok(admission) => {
                published = true;
                PROVIDER_WAIT_DISPATCH_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
                COMPONENT_WAIT_DISPATCH_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
                if matches!(admission, ProviderDispatcherWaitAdmission::Parked { .. }) {
                    PROVIDER_WAIT_PARKED_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(status) => {
                if PUBLICATION_FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
                    print_str(b"[kernel-wait] publication retained provider=");
                    print_u64(caller.owner().provider_domain);
                    print_str(b" status=0x");
                    print_hex(status);
                    print_str(b"\n");
                }
            }
        }
    }
    if published {
        // Publication may add the earliest deadline after the previous timer programming.
        // All activation/lane/dispatcher borrows have ended before touching the timer source.
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        delay_timer_rearm(&*queue, handler);
    }
}
