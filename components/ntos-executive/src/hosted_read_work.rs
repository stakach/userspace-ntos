//! Retained cross-domain READ forwarded by a hosted file-system driver.
//!
//! The source IRP and completion routine remain in the forwarding driver's address space.
//! Provider output is owned before its canonical IRP is acknowledged, then copied back into
//! the source domain before the source completion routine observes IoStatus.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_progress::HostedForwardWorkProgress;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    retained_read_forward::{
        RetainedReadForward, TerminalReadForward, ReadCompletion, ReadForwardOutcome,
        ReadForwardResult,
    },
    IoParameters, ReadWriteParameters,
};
use nt_io_manager::source_irp_ledger::SourceIrpForwardIdentity;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INVALID_PARAMETER_LOCAL: i32 = 0xc000_000du32 as i32;
const STATUS_INVALID_DEVICE_REQUEST_LOCAL: i32 = 0xc000_0010u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xc000_009au32 as i32;
const STATUS_DEVICE_BUSY_LOCAL: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct Work {
    source: hosted_read_capture::CapturedSourceRead,
    read_length: u32,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    origin: hosted_forward_origin::HostedForwardOrigin,
    source_published: bool,
    retained: Option<RetainedReadForward>,
    terminal: Option<TerminalReadForward>,
    canonical_irp: Option<IrpId>,
    completion: Option<ReadCompletion>,
    ack: Option<RetainedAck>,
    source_released: bool,
    initial_status: Option<i32>,
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
static mut EXECUTING: Vec<(usize, DriverInstance, SourceIrpForwardIdentity, bool)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn status_for_capture(error: hosted_read_capture::CaptureError) -> i32 {
    use hosted_read_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller | CaptureError::InvalidSourceIrp | CaptureError::InvalidFile => {
            STATUS_INVALID_HANDLE_LOCAL
        }
        CaptureError::InvalidSourceBuffer | CaptureError::UnsupportedBuffer => {
            STATUS_INVALID_PARAMETER_LOCAL
        }
        CaptureError::InvalidTarget => STATUS_INVALID_DEVICE_REQUEST_LOCAL,
    }
}

fn source_work_index(source_instance: DriverInstance, incoming: SourceIrpForwardIdentity) -> Option<usize> {
    let active = unsafe { &*core::ptr::addr_of!(EXECUTING) }
        .iter()
        .find(|(_, instance, identity, source_pin_owned)| {
            instance.pml4 == source_instance.pml4
                && instance.hosted_domain_id == source_instance.hosted_domain_id
                && instance.hosted_domain_cookie == source_instance.hosted_domain_cookie
                && identity.duplicates_owned(incoming, *source_pin_owned)
        })
        .map(|(index, _, _, _)| *index);
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
                    && work.source_instance.hosted_domain_cookie == source_instance.hosted_domain_cookie
                    && work.source.source_identity().duplicates_owned(incoming, work.source.source_pin_owned())
            })
        })
}

fn source_ack_work_index(source_instance: DriverInstance, source_irp_address: u64) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(WORK) }.iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            !work.source_released && work.source.source_pin_owned()
                && work.source_instance.pml4 == source_instance.pml4
                && work.source_instance.exec_pool_va == source_instance.exec_pool_va
                && work.source_instance.hosted_domain_id == source_instance.hosted_domain_id
                && work.source_instance.hosted_domain_cookie == source_instance.hosted_domain_cookie
                && work.source.source_irp_address() == source_irp_address
                && work.source.validate_source().is_ok()
        })
    })
}

unsafe fn reconcile_source_acks(route: nt_component_suspension::peer_registry::PeerRoute) -> bool {
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let Some(work) = rows[index].as_ref() else { continue; };
        let Some(ack) = work.ack.as_ref().filter(|ack| ack.route == route) else { continue; };
        if !work.source_released || work.actor.is_held() || !ack.reply_entered {
            return false;
        }
        match runtime::reconcile_retained_service_reply(
            ack.route, ack.dispatch, ack.reply, ack.token,
        ) {
            Ok(true) => {},
            _ => return false,
        }
        if runtime::retire_stopped_acknowledged_retained_service(
            ack.route, ack.dispatch, ack.reply, ack.token,
        ).is_err() { return false; }
        rows[index] = None;
    }
    true
}

fn source_token_work_index(source_instance: DriverInstance, source_irp_address: u64, token: u64) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(WORK) }.iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            !work.source_released && work.source.source_pin_owned()
                && work.origin.token == token
                && work.source_instance.pml4 == source_instance.pml4
                && work.source_instance.exec_pool_va == source_instance.exec_pool_va
                && work.source_instance.hosted_domain_id == source_instance.hosted_domain_id
                && work.source_instance.hosted_domain_cookie == source_instance.hosted_domain_cookie
                && work.source.source_irp_address() == source_irp_address
                && work.source.validate_source().is_ok()
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
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if !reconcile_source_acks(route) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let mut source = match hosted_read_capture::capture(
        ch, active_reply_cap, source_irp_address, target_device_address,
    ) {
        Ok(source) => source,
        Err(error) => {
            return Some(status_for_capture(error));
        }
    };
    let identity = source.source_identity();
    if source_work_index(source_instance, identity).is_some() {
        source.release().expect("duplicate READ capture rollback");
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some((target_index, _, _)) =
        hosted_driver_device_route_by_device_id(source.device_id().raw())
    else {
        source.release().expect("unentered READ route rejection");
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    };
    let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
        .map_or(target_index, |route| route.provider_instance);
    let Some(provider_instance) = instance(provider_index) else {
        source.release().expect("unentered READ provider rejection");
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.release().expect("unentered READ dispatch rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.release().expect("unentered READ reply rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.release().expect("unentered READ caller rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source.release().expect("unentered READ actor rollback");
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
                    .any(|(active, _, _, _)| *active == index))
            .then_some(index)
        });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        let mut actor = actor;
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered READ actor release");
        source.release().expect("unentered READ allocation rollback");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered READ actor release");
            source.release().expect("unentered READ token rollback");
            return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
        }
    };
    let read_length = source.read().length();
    let work = Work {
        source, read_length, source_instance, provider_instance, caller, actor,
        origin: hosted_forward_origin::HostedForwardOrigin::new(route, dispatch, reply, token),
        source_published: false,
        retained: None, terminal: None, canonical_irp: None, completion: None, ack: None,
        source_released: false, initial_status: None, cancel_requested: false,
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
            .take().expect("unparked READ owner");
        work.actor_release().expect("unparked READ actor");
        work.source.release().expect("unparked READ source");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    None
}

impl Work {
    fn progress(&self) -> HostedForwardWorkProgress {
        HostedForwardWorkProgress {
            initial_status: self.initial_status,
            canonical_irp: self.canonical_irp.map(|irp| irp.raw()),
            retained: self.retained.is_some(),
            terminal: self.terminal.is_some(),
            completion: self.completion.is_some(),
            source_released: self.source_released,
            source_published: self.source_published,
            cancel_requested: self.cancel_requested,
            actor_held: self.actor.is_held(),
            reply_entered: self.origin.reply_entered,
            origin: Some(self.origin.progress()),
            ack: self.ack.as_ref().map(|ack| ack.reply_entered),
        }
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        if self.origin.inline_held() {
            return self.source_released || self.source.completion_finished() || self.origin.stopped();
        }
        if let Some(ack) = &self.ack { return !ack.reply_entered; }
        if self.origin.pending() {
            if self.origin.stopped() { return self.origin.may_discard(); }
            if !self.origin.armed() { return false; }
            if self.origin.completed() { return true; }
            if self.origin.held() && self.source.completion_finished() { return true; }
            return self.source.completion_command(self.origin.token).is_ok_and(|command|
                self.origin.terminal_ready(command)) && (self.terminal.is_some() || self.canonical_irp
                    .is_some_and(|irp| completed_irp_exact(irp.raw()).is_some()));
        }
        if self.origin.reply_entered { return false; }
        if self.initial_status.is_none() {
            return !self.origin.preparation_uncertain() && self.provider_dispatch_ready()
                && self.source.completion_command(self.origin.token).is_ok_and(|command|
                    self.origin.terminal_ready(command));
        }
        if self.initial_status == Some(STATUS_PENDING as i32) {
            return self.source.completion_command(self.origin.token).is_ok_and(|command|
                self.origin.terminal_ready(command));
        }
        if self.terminal.is_some() { return true; }
        self.retained.is_some() && self.canonical_irp
            .is_some_and(|irp| completed_irp_exact(irp.raw()).is_some())
    }

    unsafe fn actor_release(&mut self) -> Result<(), u32> {
        crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
    }

    unsafe fn release_source(&mut self, pending_terminal: bool) -> bool {
        if self.source_released { return true; }
        let released = if pending_terminal {
            self.source.release_pending_terminal()
        } else {
            self.source.release()
        };
        if released.is_err() { return false; }
        self.source_released = true;
        // Publish pin retirement before any reentrant actor or Reply effect.
        let identity = self.source.source_identity();
        for (_, _, active, source_pin_owned) in &mut *core::ptr::addr_of_mut!(EXECUTING) {
            if *active == identity { *source_pin_owned = false; }
        }
        true
    }

    unsafe fn release_unentered_owners(&mut self) -> bool {
        if !self.origin.release_prepared() { return false; }
        if !self.release_source(false) { return false; }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn provider_index_if_exact(&self) -> Option<usize> {
        let Some((target_index, _, _)) =
            hosted_driver_device_route_by_device_id(self.source.device_id().raw())
        else { return None; };
        let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
            .map_or(target_index, |route| route.provider_instance);
        instance(provider_index).filter(|live| {
            live.pml4 == self.provider_instance.pml4
                && live.exec_pool_va == self.provider_instance.exec_pool_va
                && live.hosted_domain_id == self.provider_instance.hosted_domain_id
                && live.hosted_domain_cookie == self.provider_instance.hosted_domain_cookie
                && live.driver_id == self.provider_instance.driver_id
        }).map(|_| provider_index)
    }

    unsafe fn provider_dispatch_ready(&self) -> bool {
        let Some(index) = self.provider_index_if_exact() else { return true; };
        let Some(route) = hosted_ingress_sources::primary_route(index) else { return true; };
        !matches!(runtime::ready_for_admission(route), Ok(false))
    }

    unsafe fn dispatch_provider(&mut self, handler: *mut ExecNtHandler) {
        assert!(self.retained.is_none() && self.terminal.is_none());
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.initial_status = Some(status as i32);
            return;
        }
        if self.source.validate_source().is_err() || self.provider_index_if_exact().is_none() {
            self.initial_status = Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
            return;
        }
        let read = *self.source.read();
        let mut initial_output = Vec::new();
        if initial_output.try_reserve_exact(read.length() as usize).is_err() {
            self.initial_status = Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
            return;
        }
        initial_output.resize(read.length() as usize, 0);
        let request = ExternalFileIrpRequest {
            client: nt_types::ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.source.device_id(),
            file_id: Some(self.source.file_id()),
            user_data: 0,
            requestor_tid: u64::from(self.caller.original_thread().thread_id()),
            major: major::IRP_MJ_READ,
            parameters: IoParameters::Read(ReadWriteParameters {
                length: read.length(), key: read.key(), offset: read.byte_offset(),
            }),
            stack_flags: read.stack_flags(),
            initial_information: 0,
        };
        let result = hosted_file_owners::dispatch(
            self.caller, request, &[], &initial_output, ExternalFileIrpDispatchPolicy::File,
        );
        let result = match result {
            Ok(result) => result,
            Err(status) if status == nt_status::NtStatus::DEVICE_BUSY => return,
            Err(status) => {
                self.initial_status = Some(status.raw());
                return;
            }
        };
        let prepared = self.source.prepare().expect("entered READ source owner");
        let identity = prepared.identity();
        let invocation = prepared.begin(io_manager_mut(), identity)
            .expect("entered READ forward identity");
        let outcome = match result {
            hosted_file_owners::DispatchResult::Returned {
                status, information, buffers, ..
            } => {
                let (_, mut output) = buffers.into_parts();
                let completion = if status.raw() as u32 == STATUS_PENDING as u32
                    || information > u64::from(self.read_length)
                    || information > output.len() as u64
                {
                    self.initial_status = Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
                    ReadCompletion::from_owned(
                        STATUS_INVALID_DEVICE_REQUEST_LOCAL as u32, 0, Vec::new(),
                    )
                } else {
                    self.initial_status = Some(status.raw());
                    output.truncate(information as usize);
                    ReadCompletion::from_owned(status.raw() as u32, information, output)
                };
                ReadForwardOutcome::Returned(completion)
            }
            hosted_file_owners::DispatchResult::Outstanding { irp_id } => {
                self.initial_status = Some(STATUS_PENDING as i32);
                self.canonical_irp = Some(irp_id);
                ReadForwardOutcome::Pending
            }
        };
        match invocation.returned(outcome).finish(io_manager_mut(), identity) {
            ReadForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
            ReadForwardResult::Retained(retained) => self.retained = Some(retained),
            ReadForwardResult::Rejected { error, retained } => {
                self.reconcile_rejected_completion(error, retained);
            }
        }
    }

    unsafe fn reconcile_rejected_completion(
        &mut self,
        error: nt_io_manager::retained_read_forward::ReadForwardError,
        retained: RetainedReadForward,
    ) {
        self.retained = Some(retained);
        panic!("completed READ result has no reconcilable target identity: {error:?}");
    }

    unsafe fn poll_provider(&mut self) {
        let Some(irp) = self.canonical_irp else { return; };
        let Some(completion) = completed_irp_exact(irp.raw()) else { return; };
        assert_eq!(completion.client_id, IO_MANAGER_COMPONENT_ID);
        assert_eq!(completion.file_id, self.source.file_id().raw());
        assert_eq!(completion.device_id, self.source.device_id().raw());
        assert_eq!(completion.requestor_tid, u64::from(self.caller.original_thread().thread_id()));
        assert_eq!(completion.major, major::IRP_MJ_READ);
        let protocol_error = completion.status == STATUS_PENDING as u32
            || completion.information > u64::from(self.read_length);
        if protocol_error {
            let retained = self.retained.take().expect("pending READ forward owner");
            let identity = retained.identity();
            let invalid = ReadCompletion::from_owned(
                STATUS_INVALID_DEVICE_REQUEST_LOCAL as u32, 0, Vec::new(),
            );
            match retained.complete(io_manager_mut(), identity, invalid) {
                ReadForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
                ReadForwardResult::Retained(retained) => self.retained = Some(retained),
                ReadForwardResult::Rejected { error, retained } => {
                    self.reconcile_rejected_completion(error, retained);
                }
            }
            return;
        }
        let length = completion.information as usize;
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() { return; }
        bytes.resize(length, 0);
        if !matches!(copy_completed_irp_output_exact(irp.raw(), 0, &mut bytes), Ok(copied) if copied == length) {
            return;
        }
        let output = ReadCompletion::from_owned(completion.status, completion.information, bytes);
        let retained = self.retained.take().expect("pending READ forward owner");
        let identity = retained.identity();
        match retained.complete(io_manager_mut(), identity, output) {
            ReadForwardResult::Terminal(terminal) => self.terminal = Some(terminal),
            ReadForwardResult::Retained(retained) => self.retained = Some(retained),
            ReadForwardResult::Rejected { error, retained } => {
                self.reconcile_rejected_completion(error, retained);
            }
        }
    }

    unsafe fn publish_source(&mut self) {
        let completion = self.terminal.as_ref().expect("READ provider terminal").completion();
        let irp = self.source.source_irp_exec().expect("live source READ IRP");
        let (status, information) = match self.source.write_output(completion) {
            Ok(()) => (completion.status(), completion.information()),
            Err(error) => {
                let status = status_for_capture(error);
                self.initial_status = Some(status);
                (status as u32, 0)
            }
        };
        write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut u32, status);
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
            information,
        );
        self.source.arm_callback_free().expect("deferred source READ IRP free");
    }

    unsafe fn retire_after_terminal(&mut self, stopped: bool) -> bool {
        if self.completion.is_none() {
            let Some(terminal) = self.terminal.take() else { return false; };
            let result = if stopped {
                self.source.retire_target_after_source_stop(terminal)
            } else if self.origin.pending() {
                self.source.retire_target_after_pending_source_completion(terminal)
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
            if acknowledge_completed_irp(irp.raw()).is_err() { return false; }
            self.canonical_irp = None;
        }
        if !self.release_source((self.origin.pending() || self.origin.inline_held()) && !stopped) {
            return false;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn advance_inline_held(&mut self) -> bool {
        let finished = self.source_released || self.source.completion_finished();
        let stopped = self.origin.stopped();
        if !finished && !stopped { return false; }
        if !self.retire_after_terminal(!finished) || !self.origin.retire_receipt() {
            return false;
        }
        self.origin.retire_inline_held(finished, stopped)
    }

    unsafe fn advance_ack(&mut self) -> bool {
        let ack = self.ack.as_ref().expect("retained READ ACK");
        if ack.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                ack.route, ack.dispatch, ack.reply, ack.token,
            ).expect("READ ACK Reply identity");
            if !acknowledged { return false; }
            runtime::retire_stopped_acknowledged_retained_service(
                ack.route, ack.dispatch, ack.reply, ack.token,
            ).expect("READ ACK Reply retirement");
            return true;
        }
        if !self.retire_after_terminal(false) { return false; }
        let ack = self.ack.as_mut().expect("retained READ ACK");
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance_stopped_source(&mut self) -> bool {
        if !self.origin.release_prepared() { return false; }
        if !self.cancel_requested {
            if let Some(retained) = self.retained.as_mut() { retained.request_cancel(); }
            if let Some(irp) = self.canonical_irp { let _ = cancel_irp_if_pending(irp.raw()); }
            self.cancel_requested = true;
        }
        if self.retained.is_some() { self.poll_provider(); }
        let finished = self.source.completion_finished();
        if !self.retire_after_terminal(!finished) { return false; }
        self.origin.retire_receipt()
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.origin.inline_held() { return self.advance_inline_held(); }
        if self.ack.is_some() { return self.advance_ack(); }
        if self.origin.pending() {
            if self.origin.stopped() {
                if !self.origin.may_discard() { return false; }
                return self.advance_stopped_source();
            }
            if !self.origin.armed() { return false; }
            if self.retained.is_some() { self.poll_provider(); }
            if self.terminal.is_none() && self.completion.is_none() { return false; }
            if !self.source_published {
                self.publish_source();
                self.source_published = true;
            }
            if self.origin.held() && self.source.completion_finished() {
                self.origin.acknowledge_held_completion();
            }
            if !self.origin.completed() {
                let command = self.source.completion_command(self.origin.token)
                    .expect("pending READ exact completion owner");
                if !self.origin.begin_terminal(command) { return false; }
            }
            return self.retire_after_terminal(false) && self.origin.retire_receipt();
        }
        if self.origin.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.origin.route, self.origin.dispatch, self.origin.reply, self.origin.token,
            ).expect("READ Reply identity");
            if !acked || self.terminal.is_some() { return false; }
            if !self.release_unentered_owners() { return false; }
            runtime::retire_stopped_acknowledged_retained_service(
                self.origin.route, self.origin.dispatch, self.origin.reply, self.origin.token,
            ).expect("rejected READ service retirement");
            return true;
        }
        if runtime::retained_service_cancelled(self.origin.route, self.origin.dispatch, self.origin.reply, self.origin.token) {
            if self.retained.is_none() && self.terminal.is_none() && self.canonical_irp.is_none() {
                if !self.release_unentered_owners() { return false; }
                runtime::acknowledge_retained_service_cancellation(
                    self.origin.route, self.origin.dispatch, self.origin.reply, self.origin.token,
                ).expect("unentered READ cancellation");
                return true;
            }
            return self.advance_stopped_source();
        }
        if self.initial_status.is_none() {
            if !self.provider_dispatch_ready() { return false; }
            match self.source.completion_command(self.origin.token) {
                Ok(command) => match self.origin.prepare_lane(command) {
                    hosted_source_completion_lane::SourceCompletionPreparation::Ready => self.dispatch_provider(handler),
                    hosted_source_completion_lane::SourceCompletionPreparation::KnownRejected(status) => self.initial_status = Some(status as i32),
                    hosted_source_completion_lane::SourceCompletionPreparation::RetainedUncertain => return false,
                },
                Err(error) => self.initial_status = Some(status_for_capture(error)),
            }
            if self.initial_status.is_none() { return false; }
        }
        if self.retained.is_some() { self.poll_provider(); }
        let status = self.initial_status.expect("READ dispatch status");
        use nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply;
        let disposition = if status == STATUS_PENDING as i32 {
            HostedForwardDispatchReply::Pending
        } else if self.terminal.is_some() {
            if !self.origin.release_prepared() { return false; }
            self.publish_source();
            self.source_published = true;
            HostedForwardDispatchReply::InlineTerminal(self.initial_status.unwrap())
        } else {
            if !self.origin.release_prepared() { return false; }
            HostedForwardDispatchReply::Rejected(status)
        };
        self.origin.reply_dispatch(disposition, self.source_published);
        false
    }
}

unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_ready_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return false; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _, _)| *active == index) {
            return None;
        }
        if nested_ready_only && !(&*core::ptr::addr_of!(WORK))[index]
            .as_ref().is_some_and(|work| work.ready_for_nested_step()) {
            return None;
        }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return false; };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push((
        index, work.source_instance, work.source.source_identity(),
        work.source.source_pin_owned(),
    ));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let before = work.progress();
    let done = work.advance(handler);
    let progressed = HostedForwardWorkProgress::advanced(before, work.progress(), done);
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop().map(|row| row.0), Some(index));
    progressed
}

pub(super) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _ = redrive_one(handler, false);
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK)).iter().enumerate().any(|(index, row)| {
        !(&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _, _)| *active == index)
            && row.as_ref().is_some_and(|work| work.ready_for_nested_step())
    })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    let attempts = (&*core::ptr::addr_of!(WORK)).len();
    nt_io_manager::hosted_forward_progress::redrive_ready_pass(attempts, || {
        redrive_one(handler, true)
    })
}

/// Arm terminal delivery only after the exact source consumed its pending dispatch Reply.
pub(super) unsafe fn arm_pending(
    ch: &crate::spawn_hosts::PumpChannel, reply_cap: u64, caller_badge: u64,
    source_irp_address: u64, token: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(index) = source_token_work_index(source_instance, source_irp_address, token) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _, _)| *active == index) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || runtime::channel_route(ch).ok().flatten() != Some(work.origin.route)
        || work.source.completion_command(token).is_err()
    { return Some(STATUS_INVALID_HANDLE_LOCAL); }
    Some(work.origin.arm(token).err().unwrap_or(STATUS_SUCCESS))
}

pub(super) unsafe fn acknowledge_held(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    token: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(index) = source_token_work_index(source_instance, source_irp_address, token) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _, _)| *active == index) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if work.ack.is_some() || work.terminal.is_none()
        || crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || runtime::channel_route(ch).ok().flatten() != Some(work.origin.route)
        || work.source.completion_command(token).is_err() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    Some(work.origin.hold_inline(token).err().unwrap_or(STATUS_SUCCESS))
}

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
    let Some(index) = source_ack_work_index(source_instance, source_irp_address) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _, _)| *active == index) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller) {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    if work.ack.is_some() || !work.origin.reply_entered || work.terminal.is_none()
        || !work.source.completion_finished()
    {
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    }
    if !matches!(runtime::reconcile_retained_service_reply(
        work.origin.route, work.origin.dispatch, work.origin.reply, work.origin.token,
    ), Ok(true)) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    work.source.validate_source().expect("ACK READ IRP and File identity");
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if route == work.origin.route => route,
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
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL),
    };
    runtime::retire_stopped_acknowledged_retained_service(
        work.origin.route, work.origin.dispatch, work.origin.reply, work.origin.token,
    ).expect("ACK original READ Reply retirement");
    runtime::park_retained_service(route, token)
        .expect("ACK READ Call admission after original retirement");
    work.ack = Some(RetainedAck { route, dispatch, reply, token, reply_entered: false });
    None
}
