//! Retained foreign lower POWER dispatch. Source and provider IRPs have separate owners.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::{
    CompletionAcknowledgement, ExternalPowerCompletionInvocation, ExternalPowerCompletionReturn,
    ExternalPowerFinishResult,
    ExternalPowerReturn, ExternalPowerTerminalReceipt, PreparedExternalPowerIrp,
    RetainedExternalPower,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};
use nt_io_manager::power_forward_cancel::{
    decision as cancellation_decision, PowerForwardDecision, PowerForwardProgress,
};

const INVALID: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
const HANDLE: i32 = nt_status::NtStatus::INVALID_HANDLE.raw();
const BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();
const RESOURCES: i32 = nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw();

struct Ack {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    reply_entered: bool,
}

struct Work {
    source: hosted_lower_power_capture::CapturedLowerPower,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    provider_index: usize,
    storage_index: usize,
    storage_domain: HostedDomainIdentity,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    prepared: Option<PreparedExternalPowerIrp>,
    returned: Option<ExternalPowerReturn>,
    retained: Option<RetainedExternalPower>,
    completion_return: Option<ExternalPowerCompletionReturn>,
    terminal: Option<ExternalPowerTerminalReceipt>,
    rejection: Option<i32>,
    reply_entered: bool,
    source_published: bool,
    native_completed: bool,
    source_released: bool,
    cancel_requested: bool,
    ack: Option<Ack>,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<(usize, DriverInstance, u64)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn same_instance(a: DriverInstance, b: DriverInstance) -> bool {
    a.pml4 == b.pml4 && a.exec_pool_va == b.exec_pool_va
        && a.hosted_domain_id == b.hosted_domain_id
        && a.hosted_domain_cookie == b.hosted_domain_cookie
}

unsafe fn work_index(instance: DriverInstance, source_irp: u64) -> Option<usize> {
    (&*core::ptr::addr_of!(EXECUTING)).iter()
        .find(|(_, active, address)| same_instance(*active, instance) && *address == source_irp)
        .map(|(index, _, _)| *index)
        .or_else(|| (&*core::ptr::addr_of!(WORK)).iter().position(|row|
            row.as_ref().is_some_and(|work| same_instance(work.source_instance, instance)
                && work.source.source_irp_address() == source_irp)))
}

pub(super) unsafe fn submit(ch: &crate::spawn_hosts::PumpChannel, reply_cap: u64,
    badge: u64, target_address: u64, source_irp: u64) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else { return Some(HANDLE); };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() {
        return Some(HANDLE);
    }
    if work_index(source_instance, source_irp).is_some() { return Some(BUSY); }
    let mut source = match hosted_lower_power_capture::capture(ch, reply_cap,
        source_irp, target_address) {
        Ok(source) => source,
        Err(_) => return Some(INVALID),
    };
    let provider = hosted_driver_device_route_by_device_id(source.lower_device_id().raw());
    let Some((provider_index, provider_instance, _)) = provider else {
        source.release().expect("unentered POWER provider rollback");
        return Some(INVALID);
    };
    let storage_index = hosted_provider_dispatch_route_for_instance(provider_index)
        .map_or(provider_index, |route| route.provider_instance);
    let Some(storage_instance) = instance(storage_index) else {
        source.release().expect("unentered POWER storage rollback");
        return Some(INVALID);
    };
    let Some(storage_domain) = instance_domain_identity(storage_instance) else {
        source.release().expect("unentered POWER storage domain rollback");
        return Some(INVALID);
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        source.release().expect("unentered POWER route rollback");
        return Some(HANDLE);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.release().expect("unentered POWER dispatch rollback");
        return Some(HANDLE);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.release().expect("unentered POWER Reply rollback");
        return Some(HANDLE);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.release().expect("unentered POWER caller rollback");
        return Some(HANDLE);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm|
        pm.reference_native_requestor(caller)) {
        Ok(actor) => actor,
        Err(status) => {
            source.release().expect("unentered POWER actor rollback");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().position(Option::is_none);
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        let mut actor = actor;
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered POWER actor release");
        source.release().expect("unentered POWER allocation rollback");
        return Some(RESOURCES);
    }
    let Ok(token) = runtime::next_service_wait_token() else {
        let mut actor = actor;
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered POWER actor release");
        source.release().expect("unentered POWER token rollback");
        return Some(RESOURCES);
    };
    let work = Work { source, source_instance, provider_instance, provider_index,
        storage_index, storage_domain, caller, actor, route, dispatch, reply, token,
        prepared: None, returned: None, retained: None, completion_return: None,
        terminal: None, rejection: None, reply_entered: false, source_published: false,
        native_completed: false,
        source_released: false, cancel_requested: false, ack: None };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().unwrap();
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked POWER actor release");
        work.source.release().expect("unparked POWER source release");
        return Some(RESOURCES);
    }
    None
}

impl Work {
    unsafe fn provider_exact(&self) -> bool {
        self.source.validate_source().is_ok()
            && hosted_driver_device_route_by_device_id(self.source.lower_device_id().raw())
                .is_some_and(|(index, instance, _)| index == self.provider_index
                    && same_instance(instance, self.provider_instance))
            && instance(self.storage_index)
                .and_then(instance_domain_identity) == Some(self.storage_domain)
    }

    unsafe fn provider_ready(&self) -> bool {
        let Some(route) = hosted_ingress_sources::primary_route(self.provider_index) else {
            return true;
        };
        !matches!(runtime::ready_for_admission(route), Ok(false))
    }

    unsafe fn dispatch_provider(&mut self) {
        if crate::service_sec_image::with_provider_process_manager(|pm|
            self.actor.validate(pm)).is_err() || !self.provider_exact() {
            self.rejection = Some(INVALID);
            return;
        }
        let prepared = match io_manager_mut().prepare_external_power_to_exact_device(
            ClientId(IO_MANAGER_COMPONENT_ID), self.source.lower_device_id(), 0,
            self.source.parameters()) {
            Ok(prepared) => prepared,
            Err(status) => { self.rejection = Some(status.raw()); return; }
        };
        let invocation = match io_manager_mut().begin_prepared_external_power(prepared) {
            Ok(invocation) => invocation,
            Err(rejection) => {
                self.prepared = Some(rejection.into_prepared());
                self.rejection = Some(INVALID);
                return;
            }
        };
        let index = self.provider_index;
        let expected = self.source.lower_device_id();
        let returned = invocation.invoke(|context, projection| {
            if projection.device_id != expected ||
                !instance(index).is_some_and(|instance|
                    instance.ready && instance.driver_id == projection.driver_id.raw()) {
                return PnpBackendDispatch::NotDispatched {
                    status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
                };
            }
            HostedDriverBackend { instance: index }.dispatch_power_irp(context, projection)
        });
        self.returned = Some(returned);
        self.settle_dispatch();
    }

    unsafe fn settle_dispatch(&mut self) {
        let Some(returned) = self.returned.take() else { return; };
        match io_manager_mut().finish_external_power(returned) {
            Ok(ExternalPowerFinishResult::Terminal(receipt)) => self.terminal = Some(receipt),
            Ok(ExternalPowerFinishResult::Retained(retained)) => {
                if let PnpBackendDispatch::NotDispatched { .. } = retained.outcome() {
                    match io_manager_mut().discard_not_dispatched_external_power(retained) {
                        Ok(status) => self.rejection = Some(status.raw()),
                        Err(rejection) => self.retained = Some(rejection.into_owner()),
                    }
                } else {
                    self.retained = Some(retained);
                }
            }
            Err(rejection) => self.returned = Some(rejection.into_owner()),
        }
    }

    unsafe fn poll_provider(&mut self) {
        if let Some(returned) = self.completion_return.take() {
            let returned = if matches!(returned.acknowledgement(),
                CompletionAcknowledgement::NotEntered { .. }) {
                match io_manager_mut().retry_external_power_completion(returned) {
                    Ok(invocation) => self.invoke_provider_ack(invocation),
                    Err(rejection) => {
                        self.completion_return = Some(rejection.into_owner());
                        return;
                    }
                }
            } else { returned };
            match io_manager_mut().finish_external_power_completion(returned) {
                Ok(receipt) => self.terminal = Some(receipt),
                Err(rejection) => self.completion_return = Some(rejection.into_owner()),
            }
            return;
        }
        let Some(retained) = self.retained.take() else { return; };
        if !matches!(retained.outcome(), PnpBackendDispatch::Pending) {
            self.retained = Some(retained);
            return;
        }
        pump_io_manager();
        let invocation = match io_manager_mut().prepare_external_power_completion(retained) {
            Ok(invocation) => invocation,
            Err(rejection) => {
                self.retained = Some(rejection.into_owner());
                return;
            }
        };
        let returned = self.invoke_provider_ack(invocation);
        match io_manager_mut().finish_external_power_completion(returned) {
            Ok(receipt) => self.terminal = Some(receipt),
            Err(rejection) => self.completion_return = Some(rejection.into_owner()),
        }
    }

    unsafe fn invoke_provider_ack(&self,
        invocation: ExternalPowerCompletionInvocation) -> ExternalPowerCompletionReturn {
        let irp = invocation.completion().id;
        let storage = self.storage_index;
        let domain = self.storage_domain;
        invocation.invoke(|_| {
            match hosted_file_dispatch::control_exact_storage(
                storage, domain, irp, FSD_DISPATCH_ACK_COMPLETION, 0, &mut []) {
                HostedIrpTransportResult::NotDispatched { status } =>
                    CompletionAcknowledgement::NotEntered { status },
                HostedIrpTransportResult::Returned {
                    status: nt_status::NtStatus::SUCCESS, information: 0, file_context: 0,
                } => CompletionAcknowledgement::Acknowledged,
                HostedIrpTransportResult::Returned { status, information: 0, file_context: 0 }
                    if status.is_error() => CompletionAcknowledgement::Rejected { status },
                HostedIrpTransportResult::Indeterminate { transport_status } =>
                    CompletionAcknowledgement::Indeterminate { transport_status },
                _ => CompletionAcknowledgement::Indeterminate {
                    transport_status: nt_status::NtStatus::INVALID_PARAMETER,
                },
            }
        })
    }

    unsafe fn release_actor(&mut self) -> bool {
        !self.actor.is_held() ||
            crate::service_sec_image::with_provider_process_manager(|pm|
                self.actor.release(pm)).is_ok()
    }

    unsafe fn advance_ack(&mut self) -> bool {
        let Some(ack) = self.ack.as_ref() else { return false; };
        if ack.reply_entered {
            if !matches!(runtime::reconcile_retained_service_reply(
                ack.route, ack.dispatch, ack.reply, ack.token), Ok(true)) {
                return false;
            }
            return runtime::retire_stopped_acknowledged_retained_service(
                ack.route, ack.dispatch, ack.reply, ack.token).is_ok();
        }
        if !self.source_released {
            if self.source.release_after_native_completion().is_err() { return false; }
            self.source_released = true;
        }
        if !self.release_actor() { return false; }
        let ack = self.ack.as_mut().unwrap();
        if runtime::retained_service_cancelled(ack.route, ack.dispatch, ack.reply, ack.token) {
            return runtime::acknowledge_retained_service_cancellation(
                ack.route, ack.dispatch, ack.reply, ack.token).is_ok();
        }
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(
            ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance_cancelled(&mut self) -> bool {
        if let Some(prepared) = self.prepared.take() {
            if let Err(rejection) = io_manager_mut().discard_prepared_external_power(prepared) {
                self.prepared = Some(rejection.into_prepared());
                return false;
            }
        }
        if self.returned.is_some() { self.settle_dispatch(); }
        if !self.cancel_requested {
            if let Some(retained) = self.retained.as_ref().filter(|retained|
                matches!(retained.outcome(), PnpBackendDispatch::Pending)) {
                let _ = cancel_irp_if_pending(retained.irp_id().raw());
                self.cancel_requested = true;
            }
        }
        if let Some(retained) = self.retained.take() {
            if matches!(retained.outcome(), PnpBackendDispatch::NotDispatched { .. }) {
                match io_manager_mut().discard_not_dispatched_external_power(retained) {
                    Ok(_) => {},
                    Err(rejection) => self.retained = Some(rejection.into_owner()),
                }
            } else {
                self.retained = Some(retained);
                self.poll_provider();
            }
        } else if self.completion_return.is_some() {
            self.poll_provider();
        }
        if self.prepared.is_some() || self.returned.is_some()
            || self.retained.is_some() || self.completion_return.is_some() {
            return false;
        }
        // A stopped origin cannot run its native completion callback. Release only the forward
        // pin; a separate caller or driver owner still controls the source allocation.
        if !self.source_released {
            let released = if self.native_completed {
                self.source.release_after_native_completion()
            } else {
                self.source.release()
            };
            if released.is_err() { return false; }
            self.source_released = true;
        }
        if !self.release_actor() { return false; }
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token).is_ok()
    }

    unsafe fn advance(&mut self) -> bool {
        if self.ack.is_some() { return self.advance_ack(); }
        match self.cancellation_decision() {
            PowerForwardDecision::RetainLiveCallback => return false,
            PowerForwardDecision::RetireStoppedSource
            | PowerForwardDecision::RetireAfterNativeCompletion =>
                return self.advance_cancelled(),
            PowerForwardDecision::MayDispatch => {},
        }
        if !self.reply_entered {
            if self.rejection.is_none() && self.terminal.is_none() {
                if self.prepared.is_some() {
                    let prepared = self.prepared.take().unwrap();
                    match io_manager_mut().discard_prepared_external_power(prepared) {
                        Ok(()) => {},
                        Err(rejection) => self.prepared = Some(rejection.into_prepared()),
                    }
                } else if self.returned.is_some() {
                    self.settle_dispatch();
                } else if self.retained.is_some() || self.completion_return.is_some() {
                    self.poll_provider();
                } else if self.provider_ready() {
                    self.dispatch_provider();
                }
            }
            if let Some(terminal) = self.terminal {
                if !self.source_published {
                    if self.source.publish_terminal(terminal.status(), terminal.information())
                        .is_err() { return false; }
                    self.source_published = true;
                }
                if self.source.arm_callback_free().is_err() { return false; }
                self.reply_entered = true;
                let _ = runtime::wake_hosted_forward_service(
                    self.route, self.dispatch, self.reply, self.token,
                    nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply::InlineTerminal(
                        terminal.status().raw()));
                return false;
            }
            if let Some(status) = self.rejection {
                if self.prepared.is_some() || self.returned.is_some()
                    || self.retained.is_some() || self.completion_return.is_some() {
                    return false;
                }
                self.reply_entered = true;
                let _ = runtime::wake_query_path_rejected_service(
                    self.route, self.dispatch, self.reply, self.token, status);
            }
            return false;
        }
        if self.terminal.is_some() { return false; }
        if !matches!(runtime::reconcile_retained_service_reply(
            self.route, self.dispatch, self.reply, self.token), Ok(true)) {
            return false;
        }
        if !self.source_released {
            if self.source.release().is_err() { return false; }
            self.source_released = true;
        }
        if !self.release_actor() { return false; }
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token).is_ok()
    }

    unsafe fn cancellation_decision(&self) -> PowerForwardDecision {
        cancellation_decision(PowerForwardProgress {
            cancelled: runtime::retained_service_cancelled(
                self.route, self.dispatch, self.reply, self.token),
            reply_entered: self.reply_entered,
            source_published: self.source_published,
            native_completed: self.native_completed,
        })
    }
}

unsafe fn redrive_one(nested_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return false; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index)
            || nested_only && !(&*core::ptr::addr_of!(WORK))[index].as_ref()
                .is_some_and(|work| work.cancellation_decision()
                        != PowerForwardDecision::MayDispatch
                    || !work.reply_entered && work.provider_ready()
                    || work.ack.as_ref().is_some_and(|ack| !ack.reply_entered)) {
            return None;
        }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return false; };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push((index, work.source_instance,
        work.source.source_irp_address()));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance();
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop().map(|row| row.0), Some(index));
    true
}

pub(super) unsafe fn redrive() { let _ = redrive_one(false); }
pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK)).iter().enumerate().any(|(index, row)|
        !(&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index)
            && row.as_ref().is_some_and(|work| work.cancellation_decision()
                    != PowerForwardDecision::MayDispatch
                || !work.reply_entered && work.provider_ready()
                || work.ack.as_ref().is_some_and(|ack| !ack.reply_entered)))
}
pub(super) unsafe fn redrive_nested_ready() -> bool { redrive_one(true) }

pub(super) unsafe fn acknowledge(ch: &crate::spawn_hosts::PumpChannel, reply_cap: u64,
    badge: u64, source_irp: u64, token: u64) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else { return Some(HANDLE); };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() { return Some(HANDLE); }
    let Some(index) = work_index(source_instance, source_irp) else { return Some(INVALID); };
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index) {
        return Some(BUSY);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else { return Some(INVALID); };
    if work.ack.is_some() || work.token != token || !work.reply_entered
        || !work.source_published || !work.native_completed || work.terminal.is_none()
        || crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || work.source.validate_source().is_err() {
        return Some(INVALID);
    }
    if !matches!(runtime::reconcile_retained_service_reply(
        work.route, work.dispatch, work.reply, work.token), Ok(true)) {
        return Some(BUSY);
    }
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if route == work.route => route,
        _ => return Some(HANDLE),
    };
    let Ok(dispatch) = runtime::dispatch(route) else { return Some(HANDLE); };
    let Ok(reply) = runtime::current_reply(route) else { return Some(HANDLE); };
    let Ok(token) = runtime::next_service_wait_token() else { return Some(RESOURCES); };
    runtime::retire_stopped_acknowledged_retained_service(
        work.route, work.dispatch, work.reply, work.token)
        .expect("POWER original Reply retirement");
    runtime::park_retained_service(route, token).expect("POWER ACK Reply admission");
    work.ack = Some(Ack { route, dispatch, reply, token, reply_entered: false });
    None
}

/// Called only by the local IofCallDriver adapter after the native completion walker returns.
/// This evidence is separate from the source-visible token, which a driver can read.
pub(super) unsafe fn mark_native_completion(source_irp: u64, token: u64) -> bool {
    let mut matches = (&*core::ptr::addr_of!(WORK)).iter().enumerate()
        .filter_map(|(index, row)| row.as_ref().filter(|work|
            work.source.source_irp_address() == source_irp && work.token == token)
            .map(|_| index));
    let Some(index) = matches.next() else { return false; };
    if matches.next().is_some() { return false; }
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index) {
        return false;
    }
    let work = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut().unwrap();
    if work.native_completed || !work.reply_entered || !work.source_published
        || work.terminal.is_none() || work.source.validate_source().is_err() {
        return false;
    }
    work.native_completed = true;
    true
}

pub(super) unsafe fn service(ch: &crate::spawn_hosts::PumpChannel, reply_cap: u64,
    badge: u64, operation: u64, address: u64, other: u64) -> Option<(i32, bool)> {
    match operation {
        1 => submit(ch, reply_cap, badge, address, other).map(|status| (status, false)),
        2 => acknowledge(ch, reply_cap, badge, address, other).map(|status| (status, false)),
        _ => Some((INVALID, false)),
    }
}
