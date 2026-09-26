//! Retained cross-domain FLUSH forwarded by a hosted file-system driver.
//!
//! The source IRP and completion routine remain in the forwarding driver's address space.
//! The zero-payload provider terminal is written into the source IRP before its completion
//! routine observes IoStatus. A pending provider IRP stays owned until its exact terminal.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    retained_flush_forward::{
        FlushCompletion, FlushForwardOutcome, FlushForwardResult, RetainedFlushForward,
        TerminalFlushForward,
    },
    IoParameters,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INVALID_DEVICE_REQUEST_LOCAL: i32 = 0xc000_0010u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xc000_009au32 as i32;
const STATUS_DEVICE_BUSY_LOCAL: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct Work {
    source: hosted_flush_capture::CapturedSourceFlush,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    retained: Option<RetainedFlushForward>,
    terminal: Option<TerminalFlushForward>,
    canonical_irp: Option<IrpId>,
    completion: Option<FlushCompletion>,
    ack: Option<RetainedAck>,
    source_released: bool,
    initial_status: Option<i32>,
    cancel_requested: bool,
    reply_entered: bool,
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

fn status_for_capture(error: hosted_flush_capture::CaptureError) -> i32 {
    use hosted_flush_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller
        | CaptureError::InvalidSourceIrp
        | CaptureError::InvalidFile => STATUS_INVALID_HANDLE_LOCAL,
        CaptureError::InvalidTarget => STATUS_INVALID_DEVICE_REQUEST_LOCAL,
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
    if active.is_some() {
        return active;
    }
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
}

/// `None` retains the authenticated source Call. A duplicate cannot dispatch again.
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
    let mut source = match hosted_flush_capture::capture(
        ch,
        active_reply_cap,
        source_irp_address,
        target_device_address,
    ) {
        Ok(source) => source,
        Err(error) => {
            return Some(status_for_capture(error));
        }
    };
    let Some((target_index, _, _)) =
        hosted_driver_device_route_by_device_id(source.device_id().raw())
    else {
        source.release().expect("unentered FLUSH route rejection");
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    };
    let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
        .map_or(target_index, |route| route.provider_instance);
    let Some(provider_instance) = instance(provider_index) else {
        source
            .release()
            .expect("unentered FLUSH provider rejection");
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        source.release().expect("unentered FLUSH route rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.release().expect("unentered FLUSH dispatch rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.release().expect("unentered FLUSH reply rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.release().expect("unentered FLUSH caller rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source.release().expect("unentered FLUSH actor rollback");
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
            .expect("unentered FLUSH actor release");
        source
            .release()
            .expect("unentered FLUSH allocation rollback");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered FLUSH actor release");
            source.release().expect("unentered FLUSH token rollback");
            return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
        }
    };
    let work = Work {
        source,
        source_instance,
        provider_instance,
        caller,
        actor,
        route,
        dispatch,
        reply,
        token,
        retained: None,
        terminal: None,
        canonical_irp: None,
        completion: None,
        ack: None,
        source_released: false,
        initial_status: None,
        cancel_requested: false,
        reply_entered: false,
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
            .expect("unparked FLUSH owner");
        work.actor_release().expect("unparked FLUSH actor");
        work.source.release().expect("unparked FLUSH source");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    None
}

impl Work {
    unsafe fn ready_for_nested_step(&self) -> bool {
        if let Some(ack) = &self.ack {
            return !ack.reply_entered;
        }
        if self.reply_entered {
            return false;
        }
        if self.initial_status.is_none() {
            return self.provider_dispatch_ready();
        }
        if self.terminal.is_some() {
            return true;
        }
        self.retained.is_some()
            && self
                .canonical_irp
                .is_some_and(|irp| completed_irp_exact(irp.raw()).is_some())
    }

    unsafe fn actor_release(&mut self) -> Result<(), u32> {
        crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
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

    unsafe fn provider_index_if_exact(&self) -> Option<usize> {
        let Some((target_index, _, _)) =
            hosted_driver_device_route_by_device_id(self.source.device_id().raw())
        else {
            return None;
        };
        let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
            .map_or(target_index, |route| route.provider_instance);
        instance(provider_index)
            .filter(|live| {
                live.pml4 == self.provider_instance.pml4
                    && live.exec_pool_va == self.provider_instance.exec_pool_va
                    && live.hosted_domain_id == self.provider_instance.hosted_domain_id
                    && live.hosted_domain_cookie == self.provider_instance.hosted_domain_cookie
                    && live.driver_id == self.provider_instance.driver_id
            })
            .map(|_| provider_index)
    }

    unsafe fn provider_dispatch_ready(&self) -> bool {
        let Some(index) = self.provider_index_if_exact() else {
            return true;
        };
        let Some(route) = hosted_ingress_sources::primary_route(index) else {
            return true;
        };
        !matches!(runtime::ready_for_admission(route), Ok(false))
    }

    unsafe fn dispatch_provider(&mut self, handler: *mut ExecNtHandler) {
        assert!(self.retained.is_none() && self.terminal.is_none());
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.initial_status = Some(status as i32);
            return;
        }
        if self.source.validate_packet().is_err() || self.provider_index_if_exact().is_none() {
            self.initial_status = Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
            return;
        }
        let request = ExternalFileIrpRequest {
            client: nt_types::ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.source.device_id(),
            file_id: Some(self.source.file_id()),
            user_data: 0,
            requestor_tid: u64::from(self.caller.original_thread().thread_id()),
            major: major::IRP_MJ_FLUSH_BUFFERS,
            parameters: IoParameters::FlushBuffers,
            stack_flags: self.source.stack_flags(),
            initial_information: 0,
        };
        let result = hosted_file_owners::dispatch(
            self.caller,
            request,
            &[],
            &[],
            ExternalFileIrpDispatchPolicy::File,
        );
        let result = match result {
            Ok(result) => result,
            Err(status) if status == nt_status::NtStatus::DEVICE_BUSY => return,
            Err(status) => {
                self.initial_status = Some(status.raw());
                return;
            }
        };
        let prepared = self.source.prepare().expect("entered FLUSH source owner");
        let identity = prepared.identity();
        let invocation = prepared
            .begin(io_manager_mut(), identity)
            .expect("entered FLUSH forward identity");
        let outcome = match result {
            hosted_file_owners::DispatchResult::Returned {
                status,
                information,
                buffers,
                ..
            } => {
                let (input, output) = buffers.into_parts();
                let completion = if status.raw() as u32 == STATUS_PENDING as u32
                    || information != 0
                    || !input.is_empty()
                    || !output.is_empty()
                {
                    self.initial_status = Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
                    FlushCompletion::new(STATUS_INVALID_DEVICE_REQUEST_LOCAL as u32, 0)
                } else {
                    self.initial_status = Some(status.raw());
                    FlushCompletion::new(status.raw() as u32, 0)
                };
                FlushForwardOutcome::Returned(completion)
            }
            hosted_file_owners::DispatchResult::Outstanding { irp_id } => {
                self.initial_status = Some(STATUS_PENDING as i32);
                self.canonical_irp = Some(irp_id);
                FlushForwardOutcome::Pending
            }
        };
        match invocation
            .returned(outcome)
            .finish(io_manager_mut(), identity)
        {
            FlushForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
            FlushForwardResult::Retained(retained) => self.retained = Some(retained),
            FlushForwardResult::Rejected { error, retained } => {
                self.reconcile_rejected_completion(error, retained);
            }
        }
    }

    unsafe fn reconcile_rejected_completion(
        &mut self,
        error: nt_io_manager::retained_flush_forward::FlushForwardError,
        retained: RetainedFlushForward,
    ) {
        self.retained = Some(retained);
        panic!("completed FLUSH result has no reconcilable target identity: {error:?}");
    }

    unsafe fn poll_provider(&mut self) {
        let Some(irp) = self.canonical_irp else {
            return;
        };
        let Some(completion) = completed_irp_exact(irp.raw()) else {
            return;
        };
        assert_eq!(completion.file_id, self.source.file_id().raw());
        assert_eq!(
            completion.requestor_tid,
            u64::from(self.caller.original_thread().thread_id())
        );
        assert_eq!(completion.major, major::IRP_MJ_FLUSH_BUFFERS);
        let protocol_error =
            completion.status == STATUS_PENDING as u32 || completion.information != 0;
        if protocol_error {
            let retained = self.retained.take().expect("pending FLUSH forward owner");
            let identity = retained.identity();
            let invalid = FlushCompletion::new(STATUS_INVALID_DEVICE_REQUEST_LOCAL as u32, 0);
            match retained.complete(io_manager_mut(), identity, invalid) {
                FlushForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
                FlushForwardResult::Retained(retained) => self.retained = Some(retained),
                FlushForwardResult::Rejected { error, retained } => {
                    self.reconcile_rejected_completion(error, retained);
                }
            }
            return;
        }
        let output = FlushCompletion::new(completion.status, 0);
        let retained = self.retained.take().expect("pending FLUSH forward owner");
        let identity = retained.identity();
        match retained.complete(io_manager_mut(), identity, output) {
            FlushForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
            FlushForwardResult::Retained(retained) => self.retained = Some(retained),
            FlushForwardResult::Rejected { error, retained } => {
                self.reconcile_rejected_completion(error, retained);
            }
        }
    }

    unsafe fn publish_source(&mut self) {
        let completion = self
            .terminal
            .as_ref()
            .expect("FLUSH provider terminal")
            .completion();
        let irp = self
            .source
            .source_irp_exec()
            .expect("live source FLUSH IRP");
        self.source
            .validate_packet()
            .expect("source FLUSH packet changed before completion");
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut u32,
            completion.status(),
        );
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
            0,
        );
        self.source
            .arm_callback_free()
            .expect("deferred source FLUSH IRP free");
    }

    unsafe fn retire_after_terminal(&mut self, stopped: bool) -> bool {
        if self.completion.is_none() {
            let Some(terminal) = self.terminal.take() else {
                return false;
            };
            let result = if stopped {
                self.source.retire_target_after_source_stop(terminal)
            } else {
                self.source.retire_target_after_source_completion(terminal)
            };
            match result {
                Ok(completion) => self.completion = Some(completion),
                Err((_, terminal)) => {
                    self.terminal = Some(terminal);
                    return false;
                }
            }
        }
        if let Some(irp) = self.canonical_irp {
            if acknowledge_completed_irp(irp.raw()).is_err() {
                return false;
            }
            self.canonical_irp = None;
        }
        if !self.source_released {
            if self.source.release().is_err() {
                return false;
            }
            self.source_released = true;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn advance_ack(&mut self) -> bool {
        let ack = self.ack.as_ref().expect("retained FLUSH ACK");
        if ack.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("FLUSH ACK Reply identity");
            if !acknowledged {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("FLUSH ACK Reply retirement");
            return true;
        }
        if !self.retire_after_terminal(false) {
            return false;
        }
        let ack = self.ack.as_mut().expect("retained FLUSH ACK");
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance_stopped_source(&mut self) -> bool {
        if !self.cancel_requested {
            if let Some(retained) = self.retained.as_mut() {
                retained.request_cancel();
            }
            if let Some(irp) = self.canonical_irp {
                let _ = cancel_irp_if_pending(irp.raw());
            }
            self.cancel_requested = true;
        }
        if self.retained.is_some() {
            self.poll_provider();
        }
        if !self.retire_after_terminal(true) {
            return false;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("stopped FLUSH Call retirement");
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.ack.is_some() {
            return self.advance_ack();
        }
        if self.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("FLUSH Reply identity");
            if !acked || self.terminal.is_some() {
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
            .expect("rejected FLUSH service retirement");
            return true;
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            if self.retained.is_none() && self.terminal.is_none() && self.canonical_irp.is_none() {
                if !self.release_unentered_owners() {
                    return false;
                }
                runtime::acknowledge_retained_service_cancellation(
                    self.route,
                    self.dispatch,
                    self.reply,
                    self.token,
                )
                .expect("unentered FLUSH cancellation");
                return true;
            }
            return self.advance_stopped_source();
        }
        if self.initial_status.is_none() {
            if !self.provider_dispatch_ready() {
                return false;
            }
            self.dispatch_provider(handler);
            if self.initial_status.is_none() {
                return false;
            }
        }
        if self.retained.is_some() {
            self.poll_provider();
        }
        if self.terminal.is_none() && self.canonical_irp.is_some() {
            return false;
        }
        if self.terminal.is_some() {
            self.publish_source();
        }
        self.reply_entered = true;
        let status = self.initial_status.expect("FLUSH dispatch status");
        let accepted = self.terminal.is_some();
        let _ = if accepted {
            runtime::wake_query_path_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
                status,
            )
        } else {
            runtime::wake_query_path_rejected_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
                status,
            )
        };
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
    let deferred_unentered = !done && work.initial_status.is_none();
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    }
    assert_eq!(
        (&mut *core::ptr::addr_of_mut!(EXECUTING))
            .pop()
            .map(|row| row.0),
        Some(index)
    );
    !deferred_unentered
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

/// A new authenticated Call acknowledges `IoFreeIrp` issued by the source completion routine.
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
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller) {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    if work.ack.is_some()
        || !work.reply_entered
        || work.terminal.is_none()
        || !work.source.callback_requested_free()
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
        .expect("ACK FLUSH IRP and File identity");
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
    .expect("ACK original FLUSH Reply retirement");
    runtime::park_retained_service(route, token)
        .expect("ACK FLUSH Call admission after original retirement");
    work.ack = Some(RetainedAck {
        route,
        dispatch,
        reply,
        token,
        reply_entered: false,
    });
    None
}
