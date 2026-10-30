//! Live class-to-port CONNECT source and provider ownership.
//!
//! A parked source Call, port-local detached IRP, reverse aliases and callback thunk are one
//! transaction. The slot is stable across reentrant i8042 HOOK dispatch. A pending provider
//! return is never treated as completion, and neither the source nor port IRP can be replayed.

use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply;
use nt_io_manager::retained_connect_forward::{
    ConnectDispatchReturn, ConnectForwardPhase, ConnectPayloadIdentity, HookForwardPhase,
    I8042ConnectHookSequence, RetainedConnectForward,
};
use nt_io_manager::{HostedDevicePointerRegistration, HostedDomainIdentity};

const INVALID: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
const HANDLE: i32 = nt_status::NtStatus::INVALID_HANDLE.raw();
const BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct Work {
    class_instance: usize,
    class_domain: HostedDomainIdentity,
    class_port_address: u64,
    port_instance: usize,
    port_domain: HostedDomainIdentity,
    port_storage_instance: usize,
    port_storage_domain: HostedDomainIdentity,
    reverse_owner_id: u64,
    source: hosted_connect_work::RetainedConnectWork,
    port: hosted_input_connect_dispatch::PortLocalConnect,
    permit: hosted_class_callback_lane::ClassCallbackExecutionPermit,
    sequence: I8042ConnectHookSequence,
    caller: nt_process::native_handle::NativeHandleCaller,
    provider_entered: bool,
    blocked: bool,
    source_acknowledged: bool,
    port_acknowledged: bool,
}

static mut WORK: Vec<Option<Box<Work>>> = Vec::new();

fn trace_connect_live(stage: u64, source_irp: u64, first: u64, second: u64) {
    static TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
    if TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 64 {
        return;
    }
    print_str(b"[hosted-connect-live] stage=");
    print_u64(stage);
    print_str(b" irp=");
    print_hex64(source_irp);
    print_str(b" first=");
    print_hex64(first);
    print_str(b" second=");
    print_hex64(second);
    print_str(b"\n");
}

fn trace_connect_gate(stage: u64, source_irp: u64, detail: u64) {
    static TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
    if TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 12 {
        trace_connect_live(stage, source_irp, detail, 0);
    }
}

fn trace_parked_connect_gate(stage: u64, tcb: u64, detail: u64) {
    static TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
    if TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 20 {
        return;
    }
    print_str(b"[hosted-connect-receiver] stage=");
    print_u64(stage);
    print_str(b" tcb=");
    print_hex64(tcb);
    print_str(b" detail=");
    print_hex64(detail);
    print_str(b"\n");
}

fn rows() -> &'static mut Vec<Option<Box<Work>>> {
    unsafe { &mut *core::ptr::addr_of_mut!(WORK) }
}

/// A parked CONNECT has not replied to its class source yet. Keep only that physical
/// dispatch receiver in its nested pump so the retained row can enter the port provider.
pub(super) unsafe fn parked_source_channel(ch: &crate::spawn_hosts::PumpChannel) -> bool {
    if !rows().iter().flatten().any(|work| !work.port_acknowledged && work.source.source_pin_owned()) {
        return false;
    }
    let Ok(Some(route)) = runtime::channel_route(ch) else {
        trace_parked_connect_gate(0, ch.tcb, 0);
        return false;
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        trace_parked_connect_gate(1, ch.tcb, 0);
        return false;
    };
    let Ok(reply) = runtime::current_reply(route) else {
        trace_parked_connect_gate(2, ch.tcb, 0);
        return false;
    };
    rows().iter_mut().flatten().any(|work| {
        let state = u64::from(work.blocked)
            | (u64::from(work.provider_entered) << 1)
            | (u64::from(work.source_acknowledged) << 2)
            | (u64::from(work.source.source_pin_owned()) << 3)
            | (u64::from(ch.physical_domain == Some(work.class_domain)) << 4)
            | (u64::from(instance(work.class_instance).is_some_and(|inst| inst.pml4 == ch.pml4)) << 5);
        trace_parked_connect_gate(3, ch.tcb, state);
        if work.blocked || work.provider_entered || work.source_acknowledged
            || !work.source.source_pin_owned() || ch.physical_domain != Some(work.class_domain)
            || instance(work.class_instance).is_none_or(|inst| inst.pml4 != ch.pml4)
        {
            return false;
        }
        let origin = work.source.origin_mut();
        let identity = u64::from(origin.route == route)
            | (u64::from(origin.dispatch == dispatch) << 1)
            | (u64::from(origin.reply == reply) << 2)
            | (u64::from(!origin.reply_entered) << 3);
        trace_parked_connect_gate(4, ch.tcb, identity);
        origin.route == route && origin.dispatch == dispatch && origin.reply == reply
            && !origin.reply_entered
    })
}

unsafe fn work_for_source(source_instance: DriverInstance, source_irp: u64) -> Option<usize> {
    rows().iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            work.class_instance < driver_instances().map_or(0, |table| table.len())
                && instance(work.class_instance).is_some_and(|owned| {
                    owned.pml4 == source_instance.pml4
                        && owned.hosted_domain_id == source_instance.hosted_domain_id
                        && owned.hosted_domain_cookie == source_instance.hosted_domain_cookie
                })
                && work.source.source_irp_address() == source_irp
                && work.source.source_pin_owned()
        })
    })
}

/// Resolve the exact class PortDO alias used by i8042's queued HOOK. Only a live source owner
/// can authorize the reverse path; the alias registration by itself is insufficient.
pub(super) unsafe fn lookup_hook_owner(
    port_domain: HostedDomainIdentity,
    class_port_address: u64,
) -> Option<(u64, ConnectPayloadIdentity)> {
    rows().iter().flatten().find_map(|work| {
        let aliases = hosted_reverse_class_projection::validate(work.reverse_owner_id).ok()?;
        (aliases.port_do_registration.domain() == port_domain
            && aliases.port_domain_port_do == class_port_address
            && work.source.source_pin_owned())
            .then_some((work.reverse_owner_id, work.source.payload()))
    })
}

/// The boxed row stays in the registry during provider entry. The HOOK owner may borrow the
/// immutable CONNECT identity and its separate ordering witness during nested dispatch.
pub(super) unsafe fn with_hook_sequence<R>(
    reverse_owner_id: u64,
    f: impl FnOnce(&RetainedConnectForward, &mut I8042ConnectHookSequence) -> R,
) -> Option<R> {
    let work = rows().iter_mut().flatten()
        .find(|work| work.reverse_owner_id == reverse_owner_id && work.source.source_pin_owned())?;
    let forward = work.source.forward()?;
    Some(f(forward, &mut work.sequence))
}

unsafe fn abort_capture(mut source: hosted_connect_capture::CapturedConnect) {
    if source.abort_unentered().is_err() {
        core::mem::forget(source);
        crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_CONNECT_FORWARD_LABEL, 9, 0, 0]);
    }
}

unsafe fn abort_published_unentered(
    source: hosted_connect_capture::CapturedConnect,
    reverse_owner_id: u64,
    thunk_cookie: u64,
) {
    if hosted_class_callback_thunk::retire_after_quiescence(thunk_cookie).is_err() {
        hosted_class_callback_thunk::block(thunk_cookie);
        hosted_reverse_class_projection::block_uncertain(reverse_owner_id);
    } else if hosted_reverse_class_projection::abort_before_provider_entry(reverse_owner_id)
        .is_err()
    {
        hosted_reverse_class_projection::block_uncertain(reverse_owner_id);
    }
    abort_capture(source);
}

/// Operation 1 captures the source before any foreign effect. All fallible owner storage is
/// reserved before entering i8042. Once a thunk or alias publication is uncertain, the exact
/// owner is quarantined; no second CONNECT may reuse its source or target.
unsafe fn submit(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    address: u64,
    source_irp: u64,
) -> Option<(i32, bool)> {
    trace_connect_live(0, source_irp, address, badge);
    if address == 0 || source_irp == 0
        || hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none()
    {
        return Some((HANDLE, false));
    }
    let Some((class_index, class_inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some((HANDLE, false));
    };
    let Some(class_domain) = instance_domain_identity(class_inst) else {
        return Some((HANDLE, false));
    };
    if work_for_source(class_inst, source_irp).is_some() {
        return Some((BUSY, false));
    }
    let Ok(Some((target, class_driver))) =
        hosted_upper_filter_projection::entered_lower_registration(class_domain, address)
    else {
        trace_connect_live(1, source_irp, address, 0);
        return Some((INVALID, false));
    };
    let Ok(Some(class_port)) = hosted_add_device_rollback::inflight_created_above_lower(
        class_domain, ch, reply_cap, badge, target.device_id(), class_driver,
    ) else { return Some((INVALID, false)); };
    let source = match hosted_connect_capture::capture(
        ch, reply_cap, source_irp, address, class_port.address(), class_driver,
    ) {
        Ok(source) => source,
        Err(_) => {
            trace_connect_live(2, source_irp, address, 0);
            return Some((INVALID, false));
        }
    };
    if source.payload().forward.target != target {
        abort_capture(source);
        return Some((INVALID, false));
    }
    let Some(lower_origin) = hosted_upper_filter_projection::entered_lower_origin_registration(
        class_domain, address,
    ).ok().flatten().filter(|origin| origin.device_id() == target.device_id())
    else {
        abort_capture(source);
        return Some((INVALID, false));
    };
    let Some(port_index) = driver_instances().and_then(|table| {
        table.iter().copied().enumerate().find_map(|(index, candidate)| {
            (candidate.used && instance_domain_identity(candidate) == Some(lower_origin.domain()))
                .then_some(index)
        })
    }) else {
        abort_capture(source);
        return Some((INVALID, false));
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        abort_capture(source);
        return Some((HANDLE, false));
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        abort_capture(source);
        return Some((HANDLE, false));
    };
    let Ok(reply) = runtime::current_reply(route) else {
        abort_capture(source);
        return Some((HANDLE, false));
    };
    let Ok(token) = runtime::next_service_wait_token() else {
        abort_capture(source);
        return Some((nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw(), false));
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        abort_capture(source);
        return Some((HANDLE, false));
    };
    if rows().try_reserve(1).is_err() {
        abort_capture(source);
        return Some((nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw(), false));
    }
    let prepared = match hosted_reverse_class_projection::prepare(
        class_index, port_index, class_port, source.payload().class_device, lower_origin,
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            abort_capture(source);
            return Some((status.raw(), false));
        }
    };
    let configured = match hosted_reverse_class_projection::dispatch_configure(
        prepared, crate::initial_system_driver_caller(),
    ) {
        Ok(configured) => configured,
        Err(status) => {
            // A component effect may have happened. The reverse owner quarantines aliases;
            // the source IRP has not entered the provider and can retire independently.
            abort_capture(source);
            return Some((status.raw(), false));
        }
    };
    let thunk = match hosted_class_callback_thunk::publish(
        configured.owner_id, port_index, class_index, source.payload().class_device,
        source.payload().class_service, source.payload().forward.control,
    ) {
        Ok(thunk) => thunk,
        Err(status) => {
            // Publication may have reserved executable bytes before a failed component ACK.
            // Keep both alias generations until that effect can be reconciled.
            hosted_reverse_class_projection::block_uncertain(configured.owner_id);
            abort_capture(source);
            return Some((status.raw(), false));
        }
    };
    let permit = match hosted_class_callback_thunk::issue_permit(thunk) {
        Ok(permit) => permit,
        Err(status) => {
            abort_published_unentered(source, configured.owner_id, thunk.cookie);
            return Some((status.raw(), false));
        }
    };
    let port = match hosted_input_connect_dispatch::PortLocalConnect::prepare(
        source.payload(), configured.owner_id, lower_origin, thunk,
    ) {
        Ok(port) => port,
        Err(status) => {
            abort_published_unentered(source, configured.owner_id, thunk.cookie);
            return Some((status.raw(), false));
        }
    };
    let port_storage_instance = hosted_completion_storage_instance(port_index);
    let Some(port_storage_domain) =
        instance(port_storage_instance).and_then(instance_domain_identity)
    else {
        abort_published_unentered(source, configured.owner_id, thunk.cookie);
        return Some((nt_status::NtStatus::DEVICE_NOT_CONNECTED.raw(), false));
    };
    let sequence = I8042ConnectHookSequence::new(source.payload().forward);
    let origin = hosted_forward_origin::HostedForwardOrigin::new(route, dispatch, reply, token);
    let work = Box::new(Work {
        class_instance: class_index,
        class_domain,
        class_port_address: class_port.address(),
        port_instance: port_index,
        port_domain: lower_origin.domain(),
        port_storage_instance,
        port_storage_domain,
        reverse_owner_id: configured.owner_id,
        source: hosted_connect_work::RetainedConnectWork::new(source, origin),
        port,
        permit,
        sequence,
        caller,
        provider_entered: false,
        blocked: false,
        source_acknowledged: false,
        port_acknowledged: false,
    });
    if runtime::park_retained_service(route, token).is_err() {
        // No provider effect has occurred; retire the published thunk before its aliases.
        let mut work = work;
        if hosted_class_callback_thunk::retire_after_quiescence(thunk.cookie).is_err() {
            hosted_class_callback_thunk::block(thunk.cookie);
            hosted_reverse_class_projection::block_uncertain(configured.owner_id);
        } else if hosted_reverse_class_projection::abort_before_provider_entry(configured.owner_id)
            .is_err() {
            hosted_reverse_class_projection::block_uncertain(configured.owner_id);
        }
        if !work.source.abort_unentered() {
            core::mem::forget(work);
            crate::provider_bugcheck::report(
                0xc4, [FSD_SERVICE_CONNECT_FORWARD_LABEL, 10, source_irp, token],
            );
        }
        return Some((nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw(), false));
    }
    rows().push(Some(work));
    trace_connect_live(3, source_irp, token, port_index as u64);
    None
}

unsafe fn arm(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
    token: u64,
) -> Option<(i32, bool)> {
    trace_connect_live(4, source_irp, token, badge);
    let Some((_, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some((HANDLE, false));
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() {
        return Some((HANDLE, false));
    }
    let Some(index) = work_for_source(inst, source_irp) else {
        return Some((HANDLE, false));
    };
    let work = rows()[index].as_mut().unwrap();
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || runtime::channel_route(ch).ok().flatten() != Some(work.source.origin_mut().route)
        || token != work.source.origin_mut().token
        || work.source.completion_command().is_err()
    {
        return Some((HANDLE, false));
    }
    let status = work.source.origin_mut().arm(token).map_or_else(|status| status, |_| 0);
    trace_connect_live(5, source_irp, token, status as u32 as u64);
    if status == 0 {
        // A failed wake can still consume the Reply. This exact source arm reconciles its
        // acknowledgement without a second wake or provider dispatch.
        work.blocked = false;
    }
    Some((status, false))
}

pub(super) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    operation: u64,
    address: u64,
    irp_or_token: u64,
) -> Option<(i32, bool)> {
    match operation {
        1 => submit(ch, reply_cap, badge, address, irp_or_token),
        3 => arm(ch, reply_cap, badge, address, irp_or_token),
        _ => Some((INVALID, false)),
    }
}

pub(super) unsafe fn redrive() {
    redrive_inner(false);
}

unsafe fn redrive_inner(nested_ready_only: bool) {
    let count = rows().len();
    for index in 0..count {
        // A parked i8042 dispatch can synchronously reenter the executive for HOOK. The boxed
        // row stays at one address even if a nested CONNECT grows the slot vector. Do not keep
        // a borrow of the vector or the whole row across the foreign call.
        let work_ptr = match rows().get_mut(index).and_then(Option::as_deref_mut) {
            Some(work) => work as *mut Work,
            None => continue,
        };
        if (*work_ptr).port_acknowledged || (*work_ptr).blocked
            || (nested_ready_only && !(*work_ptr).nested_ready()) {
            continue;
        }
        static REDRIVE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
        if REDRIVE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8 {
            trace_connect_live(
                6,
                (*work_ptr).source.source_irp_address(),
                u64::from((*work_ptr).provider_entered)
                    | (u64::from((*work_ptr).source.origin_mut().armed()) << 1)
                    | (u64::from((*work_ptr).source_acknowledged) << 2),
                (*work_ptr).reverse_owner_id,
            );
        }
        if (*work_ptr).provider_entered
            && (*work_ptr).source.origin_mut().armed()
            && matches!((*work_ptr).port.phase(),
                hosted_input_connect_dispatch::PortConnectPhase::AwaitingCompletion(_))
        {
            let pending_irp = match (*work_ptr).port.phase() {
                hosted_input_connect_dispatch::PortConnectPhase::AwaitingCompletion(irp) => irp,
                _ => unreachable!(),
            };
            let _ = drain_hosted_connect_io_work_item(
                (*work_ptr).port_instance,
                (*work_ptr).port_domain,
                (*work_ptr).port_storage_instance,
                (*work_ptr).port_storage_domain,
                (*work_ptr).source.payload().forward.target.device_id(),
                pending_irp,
            );
        }
        if !(*work_ptr).provider_entered {
            let work = &mut *work_ptr;
            let Ok(command) = work.source.completion_command() else {
                trace_connect_gate(11, work.source.source_irp_address(), 0);
                continue;
            };
            if !matches!(work.source.origin_mut().prepare_lane(command),
                hosted_source_completion_lane::SourceCompletionPreparation::Ready) {
                trace_connect_gate(12, work.source.source_irp_address(), 0);
                continue;
            }
            let Ok(projection) = hosted_connect_work::ProviderConnectProjection::admitted(
                work.reverse_owner_id, work.port_thunk(), &work.permit,
            ) else {
                trace_connect_gate(13, work.source.source_irp_address(), work.reverse_owner_id);
                continue;
            };
            if work.source.validate_source().is_err() {
                work.blocked = true;
                hosted_class_callback_thunk::block(work.port_thunk().cookie);
                hosted_reverse_class_projection::block_uncertain(work.reverse_owner_id);
                continue;
            }
            // A synchronous CONNECT can need its mutable input copy before dispatch returns.
            // Admit the exact port completion worker before entering that native request.
            if instance(work.port_storage_instance).is_none_or(|inst| {
                instance_domain_identity(inst) != Some(work.port_storage_domain)
            }) || hosted_class_irp_lane::prepare(work.port_storage_instance).is_err()
                || hosted_class_irp_lane::select_new(work.port_storage_instance).is_none()
            {
                trace_connect_gate(14, work.source.source_irp_address(), work.port_storage_instance as u64);
                continue;
            }
            if work.source.enter(projection).is_err() {
                work.blocked = true;
                hosted_class_callback_thunk::block(work.port_thunk().cookie);
                hosted_reverse_class_projection::block_uncertain(work.reverse_owner_id);
                continue;
            }
            if hosted_reverse_class_projection::begin_provider_entry(work.reverse_owner_id)
                .is_err() {
                work.blocked = true;
                hosted_class_callback_thunk::block(work.port_thunk().cookie);
                hosted_reverse_class_projection::block_uncertain(work.reverse_owner_id);
                continue;
            }
            work.provider_entered = true;
            trace_connect_live(7, work.source.source_irp_address(), work.reverse_owner_id, 0);
            let phase = {
                let port = &mut (*work_ptr).port;
                let permit = &(*work_ptr).permit;
                let caller = (*work_ptr).caller;
                port.dispatch(permit, caller)
            };
            let work = &mut *work_ptr;
            let (phase_kind, phase_detail) = match phase {
                Ok(hosted_input_connect_dispatch::PortConnectPhase::AwaitingCompletion(irp)) => (1, irp.0),
                Ok(hosted_input_connect_dispatch::PortConnectPhase::Terminal(status)) => (2, status.raw() as u32 as u64),
                Ok(hosted_input_connect_dispatch::PortConnectPhase::Rejected(status)) => (3, status.raw() as u32 as u64),
                Err(status) => (4, status.raw() as u32 as u64),
                _ => (0, 0),
            };
            trace_connect_live(8, work.source.source_irp_address(), phase_kind, phase_detail);
            match phase {
                Ok(hosted_input_connect_dispatch::PortConnectPhase::AwaitingCompletion(_)) => {
                    let _ = work.source.observe_dispatch(ConnectDispatchReturn::Pending);
                }
                Ok(hosted_input_connect_dispatch::PortConnectPhase::Terminal(status)) => {
                    if matches!(work.sequence.phase(), HookForwardPhase::Terminal(_, _)) {
                        if let Some(forward) = work.source.forward_mut() {
                            if work.sequence.observe_connect_terminal(io_manager_mut(), forward, status).is_ok() {
                                work.source.set_terminal_after_hook(status);
                            }
                        }
                    } else if matches!(work.sequence.phase(), HookForwardPhase::AwaitingHook)
                        && status != nt_status::NtStatus::SUCCESS
                    {
                        // A known failed port dispatch before its queued HOOK has no HOOK
                        // completion to wait for. Preserve the provider's actual failure.
                        let _ = work.source.observe_dispatch(ConnectDispatchReturn::Terminal(status));
                    }
                }
                Ok(hosted_input_connect_dispatch::PortConnectPhase::Rejected(status)) | Err(status) => {
                    let _ = work.source.observe_dispatch(ConnectDispatchReturn::Terminal(status));
                }
                _ => {}
            }
            if !work.source.origin_mut().reply_dispatch(HostedForwardDispatchReply::Pending, false) {
                work.blocked = true;
                // The Reply may already have reached the source. Keep the published
                // projection and thunk pinned until its exact arm Call reconciles the wake.
            }
            continue;
        }
        let work = &mut *work_ptr;
        if !work.source.origin_mut().armed() {
            continue;
        }
        if work.source.terminal_status().is_none() {
            let Ok(Some(status)) = work.port.poll_terminal() else { continue; };
            trace_connect_live(9, work.source.source_irp_address(), status.raw() as u32 as u64,
                u64::from(matches!(work.sequence.phase(), HookForwardPhase::Terminal(_, _))));
            if !matches!(work.sequence.phase(), HookForwardPhase::Terminal(_, _)) {
                continue;
            }
            let Some(forward) = work.source.forward_mut() else { continue; };
            if work.sequence.observe_connect_terminal(io_manager_mut(), forward, status).is_err() {
                continue;
            }
            work.source.set_terminal_after_hook(status);
        }
        if !work.source_acknowledged {
            work.source_acknowledged = work.source.complete_terminal();
            trace_connect_live(10, work.source.source_irp_address(), u64::from(work.source_acknowledged), 0);
        }
        if work.source_acknowledged {
            // A nested ACK can finish while this caller is parked in the provider ACK.
            // Preserve the completed ownership transition across the older retry.
            work.port_acknowledged |= match work.port.phase() {
                hosted_input_connect_dispatch::PortConnectPhase::Prepared
                | hosted_input_connect_dispatch::PortConnectPhase::Rejected(_) => true,
                _ => work.port.acknowledge_after_source_completion(&work.source).is_ok(),
            };
            // Published aliases and the callback thunk remain installed for subsequent input.
        }
    }
}

pub(super) fn nested_work_ready() -> bool {
    rows().iter().flatten().any(|work| work.nested_ready())
}

pub(super) unsafe fn redrive_nested_ready() -> bool {
    let progress = || {
        rows().iter().flatten().fold(0usize, |total, work| {
            total
                + usize::from(work.provider_entered)
                + usize::from(work.source_acknowledged)
                + usize::from(work.port_acknowledged)
        })
    };
    let before = progress();
    redrive_inner(true);
    progress() != before
}

impl Work {
    fn nested_ready(&self) -> bool {
        let active = !self.blocked && !self.port_acknowledged;
        let source_prepared = active && !self.provider_entered
            && unsafe { self.source.nested_preparation_ready() };
        nt_io_manager::source_completion_preparation::nested_connect_ready(
            active, self.provider_entered, source_prepared,
        )
    }

    fn port_thunk(&self) -> hosted_class_callback_thunk::PublishedClassServiceThunk {
        self.port.thunk()
    }
}
