//! Receive-only GUI continuations retain the original physical invocation and child settlement.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;

pub(crate) enum ReceivePumpCompletion {
    Restored(ProviderWaitPumpCompletion),
    Reparked(PendingReceiveDispatch),
    Deferred(runtime::ReceiveSettlementBoundary),
}

static RECEIVE_PHASE_TRACES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn trace_receive_phase(
    phase: &'static [u8],
    parent: nt_component_suspension::NestedExecutionIdentity,
    child: nt_component_suspension::ExternalAdmissionKey,
    owner: nt_component_suspension::SuspensionOwner,
) {
    if RECEIVE_PHASE_TRACES.fetch_add(1, Ordering::Relaxed) >= 128 {
        return;
    }
    print_str(b"[receive-child] phase=");
    print_str(phase);
    print_str(b" parent-lane=");
    print_u64(u64::from(parent.dispatch().lane().index));
    print_str(b" lane-generation=");
    print_u64(parent.dispatch().lane().generation);
    print_str(b" epoch=");
    print_u64(parent.dispatch().epoch());
    print_str(b" dispatch=");
    print_u64(owner.dispatch_id);
    print_str(b" provider-domain=");
    print_u64(owner.provider_domain);
    print_str(b" provider-generation=");
    print_u64(owner.provider_generation);
    print_str(b" child-tcb=");
    print_u64(child.executor());
    print_str(b" admission=");
    print_u64(child.admission_sequence());
    print_str(b"\n");
}

/// Inspect only already-authenticated ingress and registered dispatch metadata. The outer
/// executive handler is still borrowed by the entered provider; no handler reborrow is allowed.
pub(crate) unsafe fn prepare_receive_yield(
    channel: &crate::spawn_hosts::PumpChannel,
) -> Result<Option<ReceiveYield>, runtime::Error> {
    if !channel.caps.hosted_receive_yield
        || channel.kernel_caller.is_some()
        || channel.caps.kind != crate::spawn_hosts::ReqKind::Syscall
        || crate::writable_fs::registry_journal::owns_volume()
    {
        return Ok(None);
    }
    let Some(caller) = channel.logical_caller else {
        return Ok(None);
    };
    let nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =
        caller.process().generation
    else {
        return Ok(None);
    };
    let snapshot = runtime::hold_snapshot();
    let Some(child) = snapshot.oldest else {
        return Ok(None);
    };
    if child.info >> 12 != 6 || child.info & 0xfff != 4 {
        return Ok(None);
    }
    let Some(observation) = crate::exec_handler::private_residency::resident_read_fault_candidate(
        child.binding,
        caller.process(),
        child.registers,
    ) else {
        return Ok(None);
    };
    let Some(running) = snapshot.running else {
        return Ok(None);
    };
    let Some(dispatch) = running.dispatch else {
        return Ok(None);
    };
    let Some(binding) = running.binding else {
        return Ok(None);
    };
    let route = runtime::channel_route(channel)?.ok_or(runtime::Error::PhysicalIdentity)?;
    let active = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    if active.lane != running.lane
        || binding.executor_id != channel.tcb
        || binding.receive_endpoint != channel.fault_ep
        || running.route != Some(route)
        || route.identity().lane != active.lane
        || !(&*core::ptr::addr_of!(WIN32K_DISPATCH_CLIENT_REGISTRY))
            .dispatch(active.dispatch_id)
            .is_some_and(|client| {
                client.logical_caller == Some(caller)
                    && client.tcb == caller.tcb()
                    && client.generation == generation
            })
    {
        return Err(runtime::Error::PhysicalIdentity);
    }
    let provider =
        crate::current_win32k_provider_domain().ok_or(runtime::Error::PhysicalIdentity)?;
    if !running.physical.is_some_and(|physical| {
        matches!(physical.domain, runtime::PhysicalDomain::Provider { domain, .. } if domain == provider)
            && physical.pml4 == channel.pml4 && physical.tcb == channel.tcb
    }) {
        return Err(runtime::Error::PhysicalIdentity);
    }
    let Some(child_root) = crate::service_sec_image::receive_vspace::peek_root(child.binding)
    else {
        return Ok(None);
    };
    if !crate::service_sec_image::receive_vspace::validate_pair(
        child.binding.tcb,
        child_root,
        channel.tcb,
        channel.pml4,
    ) {
        return Ok(None);
    }
    let pi = u32::try_from(caller.pi()).map_err(|_| runtime::Error::PhysicalIdentity)?;
    if u64::from(pi) != channel.client_pi || generation != channel.client_generation {
        return Err(runtime::Error::PhysicalIdentity);
    }
    let owner = nt_component_suspension::SuspensionOwner {
        provider_domain: provider.domain,
        provider_generation: provider.generation,
        dispatch_id: active.dispatch_id,
        caller: nt_component_suspension::SuspensionCaller::Hosted(
            nt_component_suspension::SuspensionHostedClient {
                client_pi: pi,
                client_generation: generation,
                client_tid: u64::from(caller.thread().thread_id()),
                client_badge: caller.badge(),
            },
        ),
    };
    let replaces = {
        // Canonical lane storage outlives any transient arena inherited by this pump.
        let _durable = crate::allocator::enter_durable();
        let lanes = &mut *core::ptr::addr_of_mut!(crate::service_sec_image::COMPONENT_SUSPENSIONS);
        let replaces = lanes
            .top(running.lane)
            .map_err(|_| runtime::Error::Admission)?
            .map(|frame| frame.key);
        if let Some(old_key) = replaces {
            lanes
                .reserve_receive_rearm_capacity(running.lane, binding.reply_object, old_key, owner)
                .map_err(|_| runtime::Error::Capacity)?;
        } else {
            lanes
                .reserve_receive_capacity(running.lane, binding.reply_object, owner)
                .map_err(|_| runtime::Error::Capacity)?;
        }
        replaces
    };
    let child_key =
        runtime::prepare_receive_settlement(child, observation, channel.tcb, channel.pml4, owner)?;
    let parent = runtime::nested::park_current()?.ok_or(runtime::Error::PhysicalIdentity)?;
    let identity = parent.identity();
    if let Err((_error, retained_parent)) =
        runtime::bind_receive_settlement(child, parent, dispatch)
    {
        // The actual parent row and child barrier remain retained after a physical park.
        let _retained_parent = retained_parent;
        panic!("receive child binding failed after parent park");
    }
    trace_receive_phase(b"parked", identity, child_key, owner);
    Ok(Some(ReceiveYield {
        parent: identity,
        child: child_key,
        owner,
        replaces,
    }))
}

pub(crate) unsafe fn receive_continuation_is_current(
    channel: &crate::spawn_hosts::PumpChannel,
    yielded: ReceiveYield,
) -> bool {
    let lanes = &*core::ptr::addr_of!(crate::service_sec_image::COMPONENT_SUSPENSIONS);
    let lane = yielded.parent.dispatch().lane();
    let key = nt_component_suspension::SuspensionKey::receive(yielded.child.admission_sequence());
    lanes.running() == Some(lane)
        && lanes.active_dispatch_identity(lane).ok().flatten() == Some(yielded.parent.dispatch())
        && lanes.binding(lane).is_ok_and(|binding| {
            binding.executor_id == channel.tcb && binding.receive_endpoint == channel.fault_ep
        })
        && runtime::channel_route(channel).is_ok_and(|route| route == Some(yielded.parent.route()))
        && lanes.frame(lane, key).is_ok_and(|frame| {
            frame.is_some_and(|frame| {
                frame.owner == yielded.owner
                    && matches!(
                        frame.phase,
                        nt_component_suspension::SuspensionPhase::Resuming { .. }
                    )
            })
        })
}

pub(crate) unsafe fn resume_suspended_receive_component(
    pending: PendingReceiveDispatch,
    mut boundary: runtime::ReceiveSettlementBoundary,
) -> ReceivePumpCompletion {
    if boundary.parent.as_ref().map(|parent| parent.identity()) != Some(pending.yielded.parent) {
        return ReceivePumpCompletion::Deferred(boundary);
    }
    if runtime::nested::restore(&mut boundary.parent).is_err() {
        return ReceivePumpCompletion::Deferred(boundary);
    }
    trace_receive_phase(
        b"parent-restored",
        pending.yielded.parent,
        pending.yielded.child,
        pending.yielded.owner,
    );
    let channel = pending.channel;
    let previous = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        pending.dispatch,
    );
    let result = crate::spawn_hosts::component_pump_continue_receive(&channel, &pending.pump);
    trace_receive_phase(
        b"receive-continued",
        pending.yielded.parent,
        pending.yielded.child,
        pending.yielded.owner,
    );
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous,
    );
    let mut pump = match result {
        Ok(pump) => pump,
        Err(status) => {
            return ReceivePumpCompletion::Restored(ProviderWaitPumpCompletion::Failed(
                status as i32,
            ))
        }
    };
    if let Some(yielded) = pump.receive_yield {
        return ReceivePumpCompletion::Reparked(PendingReceiveDispatch {
            yielded,
            pump,
            channel,
            ..pending
        });
    }
    pump.dispatch_return = capture_win32k_dispatch_return(
        pump.dispatch_return_receipt,
        pending.dispatch.dispatch_id,
        pending.dispatch.ssn,
        pump.result,
        pump.completed,
    );
    retire_win32k_on_wall(&pump);
    let completion = if pump.provider_wait_suspended {
        let page = win32k_subsystem::WIN32K_PROVIDER_WAIT_VADDR
            as *const nt_provider_wait::ProviderWaitSharedPage;
        ProviderWaitPumpCompletion::Reparked(PendingProviderWaitDispatch {
            request: core::ptr::read_volatile(core::ptr::addr_of!((*page).request)),
            dispatch: pending.dispatch,
            client: pending.client,
            nested_user_callback: false,
            arg_snapshot_len: pending.arg_snapshot_len,
            arg_snapshot: pending.arg_snapshot,
        })
    } else if pump.lpc_wait_suspended {
        capture_lpc_wait_repark(
            pending.dispatch,
            pending.client,
            false,
            pending.arg_snapshot_len,
            pending.arg_snapshot,
        )
        .map(ProviderWaitPumpCompletion::LpcReparked)
        .unwrap_or(ProviderWaitPumpCompletion::Failed(0xC000_0001u32 as i32))
    } else if pump.callback_suspended {
        ProviderWaitPumpCompletion::UserCallbackSuspended
    } else if !pump.completed {
        ProviderWaitPumpCompletion::Failed(pump.status)
    } else {
        complete_resumed_dispatch(
            pending.dispatch,
            pending.client,
            false,
            pending.arg_snapshot_len,
            pending.arg_snapshot,
            pump,
        )
    };
    ReceivePumpCompletion::Restored(completion)
}
