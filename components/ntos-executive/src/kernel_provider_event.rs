//! Event operations after canonical kernel activation authentication.

use super::*;
use nt_user_host::provider_local_event_request::LocalEventRequest;

fn execute(
    state: &mut crate::provider_local_event::LocalEventState<'_>,
    provider: nt_provider_wait::ProviderDomainIdentity,
    request: LocalEventRequest,
) -> Result<(i32, u64, u64, u64), u32> {
    fn encoded(id: nt_kernel_exec::EventObjectId) -> (u64, u64) {
        (id.0.slot() + 1, u64::from(id.0.generation().0))
    }
    Ok(match request {
        LocalEventRequest::Publish {
            local,
            event_type,
            signaled,
        } => {
            let (id, metadata) = state.publish(provider, local, event_type, signaled)?;
            let (slot, generation) = encoded(id);
            (0, slot, generation, metadata)
        }
        LocalEventRequest::Read { local } => (0, u64::from(state.read(provider, local)?), 0, 0),
        LocalEventRequest::Reset { local } => (0, u64::from(state.reset(provider, local)?), 0, 0),
        LocalEventRequest::Clear { local } => {
            state.clear(provider, local)?;
            (0, 0, 0, 0)
        }
        LocalEventRequest::Retire { local } => match state.retire(provider, local)? {
            Some(id) => {
                let (slot, generation) = encoded(id);
                (0, slot, generation, 0)
            }
            None => (0x103, 0, 0, 0),
        },
        LocalEventRequest::Ack { local, id } => {
            state.ack(provider, local, id)?;
            (0, 0, 0, 0)
        }
        LocalEventRequest::Set { local } | LocalEventRequest::Pulse { local } => {
            let mode = if matches!(request, LocalEventRequest::Set { .. }) {
                nt_kernel_exec::EventSignalMode::Set
            } else {
                nt_kernel_exec::EventSignalMode::Pulse
            };
            let (previous, current) = state.signal_unobserved(provider, local, mode)?;
            (0, u64::from(previous), u64::from(current), 0)
        }
    })
}

pub(super) unsafe fn dispatch(
    provider: nt_provider_wait::ProviderDomainIdentity,
    request: LocalEventRequest,
) -> Result<(i32, u64, u64, u64), u32> {
    let _durable = allocator::enter_durable();
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if let Some(handler) = handler.as_mut() {
        match request {
            LocalEventRequest::Set { local } => {
                return crate::provider_local_event::signal(
                    handler,
                    provider,
                    local,
                    nt_kernel_exec::EventSignalMode::Set,
                );
            }
            LocalEventRequest::Pulse { local } => {
                return crate::provider_local_event::signal(
                    handler,
                    provider,
                    local,
                    nt_kernel_exec::EventSignalMode::Pulse,
                );
            }
            _ => {}
        }
        let mut state = crate::provider_local_event::LocalEventState::new(
            &mut handler.obj_ns,
            &mut handler.anon_event_seq,
            &mut handler.events,
            &mut handler.event_objects,
        );
        execute(&mut state, provider, request)
    } else {
        dispatcher_bootstrap::with_local_events(|state| execute(state, provider, request))
    }
}
