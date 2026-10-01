//! Retained PCI-to-ACPI lower-edge PnP START forwarding.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_pnp_manager::{
    DiscardedLowerPnpForward, LowerPnpForwardDiscardResult, LowerPnpForwardResult,
    PreparedLowerPnpForward, RetainedLowerPnpForward, TerminalLowerPnpForward,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INVALID_DEVICE_REQUEST_LOCAL: i32 = 0xc000_0010u32 as i32;
const STATUS_INVALID_PARAMETER_LOCAL: i32 = 0xc000_000du32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xc000_009au32 as i32;
const STATUS_DEVICE_BUSY_LOCAL: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct Work {
    source: hosted_lower_pnp_capture::CapturedLowerPnpStart,
    source_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    prepared: Option<PreparedLowerPnpForward>,
    discarded: Option<DiscardedLowerPnpForward>,
    retained: Option<RetainedLowerPnpForward>,
    terminal: Option<TerminalLowerPnpForward>,
    initial_status: Option<i32>,
    reply_entered: bool,
    ack: Option<RetainedAck>,
    source_released: bool,
    cancel_requested: bool,
}

struct RetainedAck {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    reply_entered: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<(usize, DriverInstance, u64)> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn status_for_capture(error: hosted_lower_pnp_capture::CaptureError) -> i32 {
    use hosted_lower_pnp_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller | CaptureError::InvalidSourceIrp => STATUS_INVALID_HANDLE_LOCAL,
        CaptureError::InvalidTarget => STATUS_INVALID_DEVICE_REQUEST_LOCAL,
        CaptureError::InvalidResources => STATUS_INVALID_PARAMETER_LOCAL,
        CaptureError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES_LOCAL,
    }
}

fn status_for_forward(error: nt_pnp_manager::LowerPnpForwardError) -> i32 {
    use nt_pnp_manager::{AcceptedPdoProviderError, LowerPnpForwardError};
    match error {
        LowerPnpForwardError::Consumer(status)
        | LowerPnpForwardError::Provider(status)
        | LowerPnpForwardError::Prepare(status)
        | LowerPnpForwardError::Dispatch(status) => status.raw(),
        LowerPnpForwardError::Authority(AcceptedPdoProviderError::InsufficientResources) => {
            STATUS_INSUFFICIENT_RESOURCES_LOCAL
        }
        LowerPnpForwardError::InvalidStart => STATUS_INVALID_PARAMETER_LOCAL,
        _ => STATUS_INVALID_DEVICE_REQUEST_LOCAL,
    }
}

fn source_work_index(source_instance: DriverInstance, source_irp_address: u64) -> Option<usize> {
    let active = unsafe { &*core::ptr::addr_of!(EXECUTING) }
        .iter()
        .find(|(_, instance, address)| {
            instance.pml4 == source_instance.pml4
                && instance.hosted_domain_id == source_instance.hosted_domain_id
                && instance.hosted_domain_cookie == source_instance.hosted_domain_cookie
                && *address == source_irp_address
        })
        .map(|(index, _, _)| *index);
    active.or_else(|| {
        unsafe { &*core::ptr::addr_of!(WORK) }
            .iter()
            .position(|slot| {
                slot.as_ref().is_some_and(|work| {
                    work.source_instance.pml4 == source_instance.pml4
                        && work.source_instance.exec_pool_va == source_instance.exec_pool_va
                        && work.source_instance.hosted_domain_id == source_instance.hosted_domain_id
                        && work.source_instance.hosted_domain_cookie
                            == source_instance.hosted_domain_cookie
                        && work.source.source_irp_address() == source_irp_address
                })
            })
    })
}

/// `None` retains the authenticated PCI Call until the ACPI terminal is known.
pub(super) unsafe fn submit(
    ch: &crate::spawn_hosts::PumpChannel,
    source_irp_address: u64,
    target_device_address: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, active_reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    if source_work_index(source_instance, source_irp_address).is_some() {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let mut source = match hosted_lower_pnp_capture::capture(
        ch,
        active_reply_cap,
        source_irp_address,
        target_device_address,
    ) {
        Ok(source) => source,
        Err(error) => return Some(status_for_capture(error)),
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        source
            .release()
            .expect("unentered lower PnP route rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source
            .release()
            .expect("unentered lower PnP dispatch rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source
            .release()
            .expect("unentered lower PnP Reply rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source
            .release()
            .expect("unentered lower PnP caller rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source
                .release()
                .expect("unentered lower PnP actor rollback");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none()
                && !(&*core::ptr::addr_of!(EXECUTING))
                    .iter()
                    .any(|(active, _, _)| *active == index))
            .then_some(index)
        });
    if slot.is_none()
        && (&mut *core::ptr::addr_of_mut!(WORK))
            .try_reserve(1)
            .is_err()
    {
        let mut actor = actor;
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered lower PnP actor release");
        source
            .release()
            .expect("unentered lower PnP allocation rollback");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered lower PnP actor release");
            source
                .release()
                .expect("unentered lower PnP token rollback");
            return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
        }
    };
    let work = Work {
        source,
        source_instance,
        caller,
        actor,
        route,
        dispatch,
        reply,
        token,
        prepared: None,
        discarded: None,
        retained: None,
        terminal: None,
        initial_status: None,
        reply_entered: false,
        ack: None,
        source_released: false,
        cancel_requested: false,
    };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked lower PnP owner");
        work.actor_release().expect("unparked lower PnP actor");
        work.source.release().expect("unparked lower PnP source");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    None
}

pub(super) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    operation: u64,
    address: u64,
    source_irp: u64,
) -> Option<(i32, bool)> {
    match operation {
        0 => Some(
            u8::try_from(source_irp)
                .map(|minor| classify(ch, reply_cap, caller_badge, address, minor))
                .unwrap_or((STATUS_INVALID_PARAMETER_LOCAL, false)),
        ),
        1 => submit(ch, source_irp, address, caller_badge, reply_cap).map(|status| (status, false)),
        2 if source_irp == 0 => {
            acknowledge(ch, reply_cap, caller_badge, address).map(|status| (status, false))
        }
        _ => Some((STATUS_INVALID_PARAMETER_LOCAL, false)),
    }
}

/// Select the lower edge from authenticated broker authority before either service has an effect.
/// `SUCCESS,false` names an executive root PDO; `SUCCESS,true` names an accepted foreign provider.
/// An unknown or ambiguous target is rejected rather than attempted through either path.
unsafe fn classify(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    target_device_address: u64,
    minor: u8,
) -> (i32, bool) {
    if minor != nt_pnp_abi::IRP_MN_START_DEVICE
        || hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none()
    {
        return (STATUS_INVALID_DEVICE_REQUEST_LOCAL, false);
    }
    let (_, instance, device_id) =
        match authenticated_hosted_device(ch, target_device_address, reply_cap) {
            Ok(target) => target,
            Err(status) => return (status.raw(), false),
        };
    let consumer_domain = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId(instance.hosted_domain_id),
        cookie: instance.hosted_domain_cookie,
    };
    if io_manager_mut()
        .hosted_device_pointer_registration(consumer_domain, target_device_address)
        .is_none_or(|registration| registration.device_id() != device_id)
    {
        return (STATUS_INVALID_DEVICE_REQUEST_LOCAL, false);
    }
    if hosted_root_bus_mut().pdo(device_id).is_some() {
        return (STATUS_SUCCESS, false);
    }
    let authority = match hosted_accepted_pdo_provider_catalog().resolve(
        hosted_pnp_manager_mut(),
        hosted_bus_relations(),
        io_manager_mut(),
        device_id.raw(),
    ) {
        Ok(authority) => authority,
        Err(error) => {
            return (
                status_for_forward(nt_pnp_manager::LowerPnpForwardError::Authority(error)),
                false,
            )
        }
    };
    if authority.provider().domain() == consumer_domain {
        return (STATUS_INVALID_DEVICE_REQUEST_LOCAL, false);
    }
    (STATUS_SUCCESS, true)
}

impl Work {
    unsafe fn actor_release(&mut self) -> Result<(), u32> {
        crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
    }

    unsafe fn provider_instance_if_exact(&self) -> Option<usize> {
        self.source.validate_source().ok()?;
        let device_id = io_manager_mut().hosted_device_by_identity(
            self.source.consumer_domain(),
            self.source.target_device_address(),
        )?;
        let authority = hosted_accepted_pdo_provider_catalog()
            .resolve(
                hosted_pnp_manager_mut(),
                hosted_bus_relations(),
                io_manager_mut(),
                device_id.raw(),
            )
            .ok()?;
        driver_instances()?
            .iter()
            .enumerate()
            .find_map(|(index, instance)| {
                (instance.used
                    && instance_domain_identity(*instance) == Some(authority.provider().domain()))
                .then_some(index)
            })
    }

    unsafe fn provider_dispatch_ready(&self) -> bool {
        let Some(index) = self.provider_instance_if_exact() else {
            return true;
        };
        let Some(route) = hosted_ingress_sources::primary_route(index) else {
            return true;
        };
        !matches!(runtime::ready_for_admission(route), Ok(false))
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        if let Some(ack) = &self.ack {
            return !ack.reply_entered;
        }
        if self.reply_entered || self.prepared.is_some() {
            return false;
        }
        if self.initial_status.is_none() {
            return self.provider_dispatch_ready();
        }
        self.terminal.is_some()
            || self.retained.as_ref().is_some_and(|retained| {
                io_manager_mut()
                    .completed_irp(retained.provider_irp())
                    .is_some()
            })
    }

    unsafe fn dispatch_provider(&mut self, handler: *mut ExecNtHandler) {
        assert!(self.prepared.is_none() && self.retained.is_none() && self.terminal.is_none());
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.initial_status = Some(status as i32);
            return;
        }
        let (raw_len, translated_len, payload) = match self.source.take_payload() {
            Ok(payload) => payload,
            Err(error) => {
                self.initial_status = Some(status_for_capture(error));
                return;
            }
        };
        let prepared = match PreparedLowerPnpForward::start(
            hosted_pnp_manager_mut(),
            hosted_bus_relations(),
            hosted_accepted_pdo_provider_catalog(),
            io_manager_mut(),
            self.source.source_ticket(),
            self.source.consumer_domain(),
            self.source.target_device_address(),
            ClientId(IO_MANAGER_COMPONENT_ID),
            u64::from(self.caller.original_thread().thread_id()),
            raw_len,
            translated_len,
            payload,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.initial_status = Some(status_for_forward(error));
                return;
            }
        };
        self.dispatch_prepared(prepared);
    }

    unsafe fn dispatch_prepared(&mut self, prepared: PreparedLowerPnpForward) {
        let identity = prepared.identity();
        let result = prepared.dispatch(
            hosted_pnp_manager_mut(),
            hosted_bus_relations(),
            hosted_accepted_pdo_provider_catalog(),
            io_manager_mut(),
            identity,
        );
        match result {
            LowerPnpForwardResult::Terminal(terminal) => {
                self.initial_status = Some(terminal.status().raw());
                self.terminal = Some(terminal);
            }
            LowerPnpForwardResult::Retained(retained) => {
                self.initial_status = Some(STATUS_PENDING as i32);
                self.retained = Some(retained);
            }
            LowerPnpForwardResult::NotEntered { error, prepared } => {
                self.initial_status = Some(status_for_forward(error));
                self.prepared = Some(prepared);
            }
            LowerPnpForwardResult::Rejected { retained, .. } => {
                self.initial_status = Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
                self.retained = Some(retained);
            }
        }
    }

    unsafe fn poll_provider(&mut self) {
        let Some(retained) = self.retained.take() else {
            return;
        };
        let identity = retained.identity();
        let irp = retained.provider_irp();
        let Some(receipt) = io_manager_mut().take_completed_external_pnp_receipt(irp) else {
            self.retained = Some(retained);
            return;
        };
        match retained.complete(io_manager_mut(), identity, receipt) {
            LowerPnpForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
            LowerPnpForwardResult::Retained(retained)
            | LowerPnpForwardResult::Rejected { retained, .. } => self.retained = Some(retained),
            LowerPnpForwardResult::NotEntered { .. } => {
                panic!("entered lower PnP terminal became unentered")
            }
        }
    }

    unsafe fn publish_source(&self) {
        let terminal = self.terminal.as_ref().expect("lower PnP provider terminal");
        self.source
            .publish_terminal(terminal.status(), terminal.information())
            .expect("lower PnP source packet changed before completion");
    }

    unsafe fn retire_after_source_completion(&mut self) -> bool {
        if let Some(mut terminal) = self.terminal.take() {
            if terminal.acknowledge_provider(io_manager_mut()).is_err() {
                self.terminal = Some(terminal);
                return false;
            }
            match terminal.retire(io_manager_mut()) {
                Ok(_) => {}
                Err((_, terminal)) => {
                    self.terminal = Some(terminal);
                    return false;
                }
            }
        } else {
            return false;
        }
        if !self.source_released {
            if self.source.release().is_err() {
                return false;
            }
            self.source_released = true;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn retire_after_source_stop(&mut self) -> bool {
        if let Some(mut terminal) = self.terminal.take() {
            if terminal.acknowledge_provider(io_manager_mut()).is_err() {
                self.terminal = Some(terminal);
                return false;
            }
            match terminal.retire_after_source_stop(io_manager_mut()) {
                Ok(_) => {}
                Err((_, terminal)) => {
                    self.terminal = Some(terminal);
                    return false;
                }
            }
        } else {
            return false;
        }
        if !self.source_released {
            if self.source.release().is_err() {
                return false;
            }
            self.source_released = true;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn release_unentered_owners(&mut self) -> bool {
        if !self.source_released {
            if self.source.release().is_err() {
                return false;
            }
            self.source_released = true;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn advance_ack(&mut self) -> bool {
        let ack = self.ack.as_ref().expect("retained lower PnP ACK");
        if ack.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("lower PnP ACK Reply identity");
            if !acknowledged {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("lower PnP ACK Reply retirement");
            return true;
        }
        if !self.retire_after_source_completion() {
            return false;
        }
        let ack = self.ack.as_mut().expect("retained lower PnP ACK");
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance_cancelled(&mut self) -> bool {
        if let Some(prepared) = self.prepared.take() {
            match prepared.discard(io_manager_mut()) {
                LowerPnpForwardDiscardResult::Retired => {}
                LowerPnpForwardDiscardResult::NotDiscarded { prepared, .. } => {
                    self.prepared = Some(prepared);
                    return false;
                }
                LowerPnpForwardDiscardResult::Retained { discarded, .. } => {
                    self.discarded = Some(discarded);
                }
            }
        }
        if let Some(discarded) = self.discarded.take() {
            if let Err((_, discarded)) = discarded.retire(io_manager_mut()) {
                self.discarded = Some(discarded);
                return false;
            }
        }
        if !self.cancel_requested {
            if let Some(retained) = self.retained.as_ref() {
                let _ = cancel_irp_if_pending(retained.provider_irp().raw());
            }
            self.cancel_requested = true;
        }
        if self.retained.is_some() {
            self.poll_provider();
        }
        if self.terminal.is_some() && !self.retire_after_source_stop() {
            return false;
        }
        if self.prepared.is_some()
            || self.discarded.is_some()
            || self.retained.is_some()
            || self.terminal.is_some()
        {
            return false;
        }
        if !self.source_released {
            if self.source.release().is_err() {
                return false;
            }
            self.source_released = true;
        }
        if self.actor.is_held() && self.actor_release().is_err() {
            return false;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("cancelled lower PnP Call retirement");
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.ack.is_some() {
            return self.advance_ack();
        }
        if self.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("lower PnP Reply identity");
            if !acknowledged || self.terminal.is_some() {
                return false;
            }
            if !self.release_unentered_owners() {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("rejected lower PnP service retirement");
            return true;
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            return self.advance_cancelled();
        }
        if self.initial_status.is_none() {
            if !self.provider_dispatch_ready() {
                return false;
            }
            self.dispatch_provider(handler);
        }
        if self.prepared.is_some() && self.provider_dispatch_ready() {
            let prepared = self.prepared.take().unwrap();
            self.dispatch_prepared(prepared);
        }
        if self.prepared.is_some() {
            return false;
        }
        if self.retained.is_some() {
            self.poll_provider();
        }
        if self.retained.is_some() || self.terminal.is_none() {
            if self.initial_status.is_some() && self.retained.is_none() {
                self.reply_entered = true;
                let _ = runtime::wake_query_path_rejected_service(
                    self.route,
                    self.dispatch,
                    self.reply,
                    self.token,
                    self.initial_status.unwrap(),
                );
            }
            return false;
        }
        self.publish_source();
        self.reply_entered = true;
        let _ = runtime::wake_query_path_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            self.initial_status.expect("lower PnP initial status"),
        );
        false
    }
}

unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_ready_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 {
        return false;
    }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING))
            .iter()
            .any(|(active, _, _)| *active == index)
        {
            return None;
        }
        if nested_ready_only
            && !(&*core::ptr::addr_of!(WORK))[index]
                .as_ref()
                .is_some_and(|work| work.ready_for_nested_step())
        {
            return None;
        }
        (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .map(|work| (index, work))
    }) else {
        return false;
    };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING))
        .try_reserve(1)
        .is_err()
    {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push((
        index,
        work.source_instance,
        work.source.source_irp_address(),
    ));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    }
    assert_eq!(
        (&mut *core::ptr::addr_of_mut!(EXECUTING))
            .pop()
            .map(|row| row.0),
        Some(index)
    );
    true
}

pub(super) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _ = redrive_one(handler, false);
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .any(|(index, row)| {
            !(&*core::ptr::addr_of!(EXECUTING))
                .iter()
                .any(|(active, _, _)| *active == index)
                && row
                    .as_ref()
                    .is_some_and(|work| work.ready_for_nested_step())
        })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    redrive_one(handler, true)
}

/// A second authenticated Call proves that the source-local completion routine returned.
pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(index) = source_work_index(source_instance, source_irp_address) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _)| *active == index)
    {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || work.ack.is_some()
        || !work.reply_entered
        || work.terminal.is_none()
    {
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    }
    if !matches!(
        runtime::reconcile_retained_service_reply(
            work.route,
            work.dispatch,
            work.reply,
            work.token,
        ),
        Ok(true)
    ) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    work.source
        .validate_source()
        .expect("ACK lower PnP source identity");
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if route == work.route => route,
        _ => return Some(STATUS_INVALID_HANDLE_LOCAL),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        Err(_) => return Some(STATUS_INVALID_HANDLE_LOCAL),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        Err(_) => return Some(STATUS_INVALID_HANDLE_LOCAL),
    };
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) {
        Ok(token) => token,
        Err(_) => return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL),
    };
    runtime::retire_stopped_acknowledged_retained_service(
        work.route,
        work.dispatch,
        work.reply,
        work.token,
    )
    .expect("ACK original lower PnP Reply retirement");
    runtime::park_retained_service(route, token)
        .expect("ACK lower PnP Call admission after original retirement");
    work.ack = Some(RetainedAck {
        route,
        dispatch,
        reply,
        token,
        reply_entered: false,
    });
    None
}
