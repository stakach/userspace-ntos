//! Receive-only GUI continuations retain the original physical invocation and child settlement.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;

#[derive(Clone, Copy)]
pub(crate) enum ReceiveFaultCapture {
    Resident(crate::exec_handler::private_residency::ResidentReadFaultCapture),
    StackGuard(StackGuardFaultCapture),
    NativeImage(NativeImageFaultCapture),
}

/// Deny-only observation of a child's image page fault. The root owner must recheck this mapping
/// and resolve the exact live image view before any page installation or writecopy promotion.
#[derive(Clone, Copy)]
pub(crate) struct NativeImageFaultCapture {
    pub(crate) child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    pub(crate) page: u64,
    pub(crate) access: nt_address_space::FaultAccess,
    pub(crate) observation: nt_address_space::ImageFaultObservation,
    pub(crate) information: nt_address_space::VmBasicInformation,
}

pub(crate) unsafe fn native_image_fault_candidate(
    child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    registers: [u64; 4],
) -> Option<NativeImageFaultCapture> {
    if !child.process.is_valid()
        || child.tcb <= 1
        || child.tid == 0
        || registers[2] != 0
    {
        return None;
    }
    let page = registers[1] & !(nt_address_space::PAGE_SIZE - 1);
    if hosted_thread_memory_access(child.pi as u64, page, nt_address_space::PAGE_SIZE).is_err() {
        return None;
    }
    let information = process_committed_mapping_basic_information(child.pi as u64, page)?;
    if information.type_ != nt_address_space::MEM_IMAGE
        || information.state != nt_address_space::MEM_COMMIT
        || information.protect & nt_address_space::PAGE_GUARD != 0
    {
        return None;
    }
    let (access, observation) = nt_address_space::x86_user_image_receive_fault(
        registers[3], information.protect,
    )?;
    if nt_address_space::image_view_fault_access_status(information.protect, access).is_err() {
        return None;
    }
    Some(NativeImageFaultCapture { child, page, access, observation, information })
}

/// Read-only pump hint. The root owner rechecks the VAD, thread, and stack geometry.
#[derive(Clone, Copy)]
pub(crate) struct StackGuardFaultCapture {
    pub(crate) child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    pub(crate) address: u64,
    pub(crate) error_code: u64,
    pub(crate) allocation_base: u64,
    pub(crate) protection: u32,
}

pub(crate) unsafe fn stack_guard_fault_candidate(
    child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    registers: [u64; 4],
) -> Option<StackGuardFaultCapture> {
    if !child.process.is_valid()
        || child.tcb <= 1
        || child.tid == 0
        || registers[2] != 0
        || registers[3] & 0x5 != 0x5
        || registers[3] & 0x10 != 0
    {
        return None;
    }
    let address = registers[1];
    let page = address & !(nt_address_space::PAGE_SIZE - 1);
    let (allocation_base, stack_base) =
        crate::hosted_thread_runtime::hosted_thread_user_stack_for_binding(child)?;
    if page < allocation_base || page >= stack_base {
        return None;
    }
    let map = process_vm_region_map(child.pi)?;
    let extent = map.extent_at(page)?;
    if extent.type_ != nt_address_space::MEM_PRIVATE
        || extent.state != nt_address_space::VmExtentState::Committed
        || extent.allocation_base != allocation_base
    {
        return None;
    }
    let protection = map.protection_at(page)?;
    if protection & nt_address_space::PAGE_GUARD == 0
        || nt_address_space::private_guard_page_fault_plan(
            protection,
            crate::service_sec_image::vm_fault_access_from_x86_error(registers[3]),
        )
        .is_none()
    {
        return None;
    }
    Some(StackGuardFaultCapture {
        child,
        address,
        error_code: registers[3],
        allocation_base,
        protection,
    })
}

pub(crate) enum ReceivePumpCompletion {
    Restored(ProviderWaitPumpCompletion),
    Reparked(PendingReceiveDispatch),
    ServiceReparked(PendingServiceWaitDispatch),
    Deferred(runtime::ReceiveSettlementBoundary),
}

pub(crate) enum ServiceWaitPumpCompletion {
    Restored(ProviderWaitPumpCompletion),
    ServiceReparked(PendingServiceWaitDispatch),
    ReceiveReparked(PendingReceiveDispatch),
}

static RECEIVE_PHASE_TRACES: AtomicU64 = AtomicU64::new(0);
static RECEIVE_FAILURE_TRACES: AtomicU64 = AtomicU64::new(0);

unsafe fn trace_receive_failure(
    stage: &'static [u8],
    error: runtime::Error,
    channel: &crate::spawn_hosts::PumpChannel,
    route: Option<nt_component_suspension::peer_registry::PeerRoute>,
) -> runtime::Error {
    if RECEIVE_FAILURE_TRACES.fetch_add(1, Ordering::Relaxed) >= 24 {
        return error;
    }
    let snapshot = runtime::hold_snapshot();
    let active = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    let provider = crate::current_win32k_provider_domain();
    let registered = (&*core::ptr::addr_of!(WIN32K_DISPATCH_CLIENT_REGISTRY))
        .dispatch(active.dispatch_id);
    print_str(b"[receive-yield-failure] stage=");
    print_str(stage);
    print_str(b" error=");
    print_str(match &error {
        runtime::Error::PhysicalIdentity => b"physical",
        runtime::Error::Admission => b"admission",
        runtime::Error::Capacity => b"capacity",
        runtime::Error::Receive => b"receive",
        _ => b"other",
    });
    print_str(b" channel=");
    print_u64(channel.tcb);
    print_str(b"/");
    print_u64(channel.pml4);
    print_str(b"/");
    print_u64(channel.fault_ep);
    print_str(b" client=");
    print_u64(channel.client_pi);
    print_str(b"/");
    print_u64(channel.client_generation);
    print_str(b" active=");
    print_u64(u64::from(active.lane.index));
    print_str(b"/");
    print_u64(active.lane.generation);
    print_str(b"/");
    print_u64(active.dispatch_id);
    print_str(b" registered=");
    print_u64(registered.is_some() as u64);
    print_str(b" caller-match=");
    print_u64(registered.is_some_and(|client| client.logical_caller == channel.logical_caller) as u64);
    print_str(b" registered-client=");
    print_u64(registered.map_or(0, |client| client.tcb));
    print_str(b"/");
    print_u64(registered.map_or(0, |client| client.generation));
    print_str(b" route=");
    print_u64(route.map_or(0, |route| route.badge()));
    print_str(b"/");
    print_u64(route.map_or(0, |route| u64::from(route.identity().lane.index)));
    print_str(b"/");
    print_u64(route.map_or(0, |route| route.identity().lane.generation));
    print_str(b" provider=");
    print_u64(provider.map_or(0, |provider| provider.domain));
    print_str(b"/");
    print_u64(provider.map_or(0, |provider| provider.generation));
    if let Some(running) = snapshot.running {
        print_str(b" running=");
        print_u64(u64::from(running.lane.index));
        print_str(b"/");
        print_u64(running.lane.generation);
        print_str(b"/");
        print_u64(running.dispatch.map_or(0, |dispatch| dispatch.epoch()));
        print_str(b" binding=");
        print_u64(running.binding.map_or(0, |binding| binding.executor_id));
        print_str(b"/");
        print_u64(running.binding.map_or(0, |binding| binding.receive_endpoint));
        print_str(b" physical=");
        print_u64(running.physical.map_or(0, |physical| physical.tcb));
        print_str(b"/");
        print_u64(running.physical.map_or(0, |physical| physical.pml4));
        print_str(b" provider-match=");
        print_u64(running.physical.is_some_and(|physical| {
            matches!(physical.domain, runtime::PhysicalDomain::Provider { domain, .. }
                if Some(domain) == provider)
        }) as u64);
        print_str(b" route-match=");
        print_u64((running.route == route) as u64);
        if let Ok(Some(frame)) = (&*core::ptr::addr_of!(crate::service_sec_image::COMPONENT_SUSPENSIONS))
            .top(running.lane)
        {
            print_str(b" top=");
            print_u64(match frame.key.kind {
                nt_component_suspension::SuspensionKind::Receive => 1,
                nt_component_suspension::SuspensionKind::ServiceWait => 2,
                nt_component_suspension::SuspensionKind::ProviderWait => 3,
                nt_component_suspension::SuspensionKind::LpcRequest => 4,
            });
            print_str(b"/");
            print_u64(frame.key.id);
            print_str(b"/");
            print_u64(matches!(frame.phase, nt_component_suspension::SuspensionPhase::Resuming { .. }) as u64);
            print_str(b"/");
            print_u64(frame.owner.dispatch_id);
            print_str(b"/");
            print_u64(frame.owner.provider_generation);
        }
    } else {
        print_str(b" running=none");
    }
    if let Some(child) = snapshot.oldest {
        print_str(b" child=");
        print_u64(child.binding.tcb);
        print_str(b"/");
        print_u64(child.binding.pi as u64);
        print_str(b"/");
        print_u64(child.binding.badge);
        print_str(b"/");
        print_u64(child.admission_sequence);
        print_str(b" fault=");
        print_hex_u64(child.registers[1]);
        print_str(b"/");
        print_hex_u64(child.registers[3]);
    } else {
        print_str(b" child=none");
    }
    print_str(b"\n");
    error
}

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

/// Leave an entered syscall pump at the root boundary while its own service Reply is parked.
/// No hosted child is selected here: root ingress can service any retained child normally.
pub(crate) unsafe fn prepare_service_wait_yield(
    channel: &crate::spawn_hosts::PumpChannel,
) -> Result<Option<ServiceWaitYield>, runtime::Error> {
    if !channel.caps.hosted_receive_yield
        || channel.kernel_caller.is_some()
        || channel.caps.kind != crate::spawn_hosts::ReqKind::Syscall
        || crate::writable_fs::registry_journal::owns_volume()
        || runtime::hold_snapshot().running.is_some()
    {
        return Ok(None);
    }
    let Some(caller) = channel.logical_caller else { return Ok(None); };
    let nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =
        caller.process().generation
    else { return Ok(None); };
    let route = runtime::channel_route(channel)?.ok_or(runtime::Error::PhysicalIdentity)?;
    let dispatch = runtime::dispatch(route)?;
    let active = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    let binding = (&*core::ptr::addr_of!(crate::service_sec_image::COMPONENT_SUSPENSIONS))
        .binding(dispatch.lane())
        .map_err(|_| runtime::Error::Admission)?;
    let provider =
        crate::current_win32k_provider_domain().ok_or(runtime::Error::PhysicalIdentity)?;
    let physical = runtime::physical_source(route)?;
    let pi = u32::try_from(caller.pi()).map_err(|_| runtime::Error::PhysicalIdentity)?;
    if active.lane != dispatch.lane()
        || route.identity().lane != dispatch.lane()
        || binding.executor_id != channel.tcb
        || binding.receive_endpoint != channel.fault_ep
        || !matches!(physical.kind, runtime::PhysicalSourceKind::Primary | runtime::PhysicalSourceKind::DispatchWorker { .. })
        || !matches!(physical.domain, runtime::PhysicalDomain::Provider { domain, .. } if domain == provider)
        || physical.pml4 != channel.pml4
        || physical.tcb != channel.tcb
        || u64::from(pi) != channel.client_pi
        || generation != channel.client_generation
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
    let Some((reply, token)) = runtime::parked_service_wait_identity(route, dispatch)? else {
        return Ok(None);
    };
    Ok(Some(ServiceWaitYield { route, dispatch, reply, token }))
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
    let Some(observation) = native_image_fault_candidate(child.binding, child.registers)
        .map(ReceiveFaultCapture::NativeImage)
        .or_else(|| {
            stack_guard_fault_candidate(child.binding, child.registers)
                .map(ReceiveFaultCapture::StackGuard)
        })
        .or_else(|| {
            crate::exec_handler::private_residency::resident_read_fault_candidate(
                child.binding,
                caller.process(),
                child.registers,
            )
            .map(ReceiveFaultCapture::Resident)
        }) else {
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
    let route = runtime::channel_route(channel)
        .map_err(|error| trace_receive_failure(b"channel-route", error, channel, None))?
        .ok_or_else(|| trace_receive_failure(b"missing-route", runtime::Error::PhysicalIdentity, channel, None))?;
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
        return Err(trace_receive_failure(b"dispatch-identity", runtime::Error::PhysicalIdentity, channel, Some(route)));
    }
    let provider =
        crate::current_win32k_provider_domain().ok_or_else(||
            trace_receive_failure(b"provider-domain", runtime::Error::PhysicalIdentity, channel, Some(route)))?;
    if !running.physical.is_some_and(|physical| {
        matches!(physical.domain, runtime::PhysicalDomain::Provider { domain, .. } if domain == provider)
            && physical.pml4 == channel.pml4 && physical.tcb == channel.tcb
    }) {
        return Err(trace_receive_failure(b"physical-source", runtime::Error::PhysicalIdentity, channel, Some(route)));
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
    let pi = u32::try_from(caller.pi()).map_err(|_| trace_receive_failure(
        b"client-pi-width", runtime::Error::PhysicalIdentity, channel, Some(route)))?;
    if u64::from(pi) != channel.client_pi || generation != channel.client_generation {
        return Err(trace_receive_failure(b"client-generation", runtime::Error::PhysicalIdentity, channel, Some(route)));
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
            .map_err(|_| trace_receive_failure(b"lane-top", runtime::Error::Admission, channel, Some(route)))?
            .map(|frame| frame.key);
        if let Some(old_key) = replaces {
            lanes
                .reserve_receive_rearm_capacity(running.lane, binding.reply_object, old_key, owner)
                .map_err(|_| trace_receive_failure(b"rearm-capacity", runtime::Error::Capacity, channel, Some(route)))?;
        } else {
            lanes
                .reserve_receive_capacity(running.lane, binding.reply_object, owner)
                .map_err(|_| trace_receive_failure(b"receive-capacity", runtime::Error::Capacity, channel, Some(route)))?;
        }
        replaces
    };
    let child_key =
        runtime::prepare_receive_settlement(child, observation, channel.tcb, channel.pml4, owner)
            .map_err(|error| trace_receive_failure(b"settlement", error, channel, Some(route)))?;
    let parent = runtime::nested::park_current()
        .map_err(|error| trace_receive_failure(b"park-parent", error, channel, Some(route)))?
        .ok_or_else(|| trace_receive_failure(b"missing-parent", runtime::Error::PhysicalIdentity, channel, Some(route)))?;
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

pub(crate) unsafe fn service_wait_continuation_is_current(
    channel: &crate::spawn_hosts::PumpChannel,
    yielded: ServiceWaitYield,
) -> bool {
    if channel.caps.kind != crate::spawn_hosts::ReqKind::Syscall
        || !channel.caps.hosted_receive_yield
        || channel.kernel_caller.is_some()
        || yielded.route.identity().lane != yielded.dispatch.lane()
        || runtime::channel_route(channel).ok().flatten() != Some(yielded.route)
        || runtime::dispatch(yielded.route).ok() != Some(yielded.dispatch)
    {
        return false;
    }
    let lanes = &*core::ptr::addr_of!(crate::service_sec_image::COMPONENT_SUSPENSIONS);
    if !lanes.binding(yielded.dispatch.lane()).is_ok_and(|binding| {
        binding.executor_id == channel.tcb
            && binding.receive_endpoint == channel.fault_ep
    }) {
        return false;
    }
    matches!(runtime::service_wait_resume_completed_exact(
        yielded.route, yielded.dispatch, yielded.reply, yielded.token,
    ), Ok(true))
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
    if !select_win32k_client_window(pending.client)
        || !restore_shared_resume_snapshot(pending.shared_resume, pending.dispatch, pending.client)
    {
        return ReceivePumpCompletion::Restored(ProviderWaitPumpCompletion::Failed(
            nt_process::STATUS_INVALID_PARAMETER as i32,
        ));
    }
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
            callback_token: None,
            shared_resume: capture_shared_resume_snapshot(pending.dispatch, pending.client),
            ..pending
        });
    }
    if let Some(yielded) = pump.service_wait_yield {
        return ReceivePumpCompletion::ServiceReparked(PendingServiceWaitDispatch {
            yielded, pump, channel,
            dispatch: pending.dispatch,
            client: pending.client,
            callback_token: None,
            shared_resume: capture_shared_resume_snapshot(pending.dispatch, pending.client),
            arg_snapshot_len: pending.arg_snapshot_len,
            arg_snapshot: pending.arg_snapshot,
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

/// Continue a root-parked win32k syscall after its exact external service Reply and lane
/// transition have been acknowledged. The saved request is never sent a second time.
pub(crate) unsafe fn resume_suspended_service_wait_component(
    pending: PendingServiceWaitDispatch,
) -> ServiceWaitPumpCompletion {
    let selected = select_win32k_client_window(pending.client);
    let restored = selected
        && restore_shared_resume_snapshot(pending.shared_resume, pending.dispatch, pending.client);
    if !restored {
        static SERVICE_RESTORE_FAILURES: AtomicU64 = AtomicU64::new(0);
        if SERVICE_RESTORE_FAILURES.fetch_add(1, Ordering::Relaxed) < 8 {
            print_str(b"[service-wait-resume] stage=restore selected/restored/pi/tid/dispatch=");
            print_u64(selected as u64); print_str(b"/"); print_u64(restored as u64);
            print_str(b"/"); print_u64(pending.client.pi as u64);
            print_str(b"/"); print_u64(pending.client.tid);
            print_str(b"/"); print_u64(pending.dispatch.dispatch_id);
            print_str(b"\n");
        }
        return ServiceWaitPumpCompletion::Restored(ProviderWaitPumpCompletion::Failed(
            nt_process::STATUS_INVALID_PARAMETER as i32,
        ));
    }
    let channel = pending.channel;
    let previous = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        pending.dispatch,
    );
    let result = crate::spawn_hosts::component_pump_continue_service_wait(
        &channel, &pending.pump,
    );
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous,
    );
    let mut pump = match result {
        Ok(pump) => pump,
        Err(status) => {
            static SERVICE_CONTINUE_FAILURES: AtomicU64 = AtomicU64::new(0);
            if SERVICE_CONTINUE_FAILURES.fetch_add(1, Ordering::Relaxed) < 8 {
                print_str(b"[service-wait-resume] stage=continue pi/tid/dispatch/status=");
                print_u64(pending.client.pi as u64); print_str(b"/"); print_u64(pending.client.tid);
                print_str(b"/"); print_u64(pending.dispatch.dispatch_id);
                print_str(b"/0x"); print_hex(status);
                print_str(b"\n");
            }
            return ServiceWaitPumpCompletion::Restored(
                ProviderWaitPumpCompletion::Failed(status as i32),
            );
        }
    };
    if let Some(yielded) = pump.service_wait_yield {
        return ServiceWaitPumpCompletion::ServiceReparked(PendingServiceWaitDispatch {
            yielded, pump, channel, callback_token: None,
            shared_resume: capture_shared_resume_snapshot(pending.dispatch, pending.client),
            ..pending
        });
    }
    if let Some(yielded) = pump.receive_yield {
        return ServiceWaitPumpCompletion::ReceiveReparked(PendingReceiveDispatch {
            yielded, pump, channel,
            dispatch: pending.dispatch,
            client: pending.client,
            callback_token: None,
            shared_resume: capture_shared_resume_snapshot(pending.dispatch, pending.client),
            arg_snapshot_len: pending.arg_snapshot_len,
            arg_snapshot: pending.arg_snapshot,
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
    ServiceWaitPumpCompletion::Restored(completion)
}
