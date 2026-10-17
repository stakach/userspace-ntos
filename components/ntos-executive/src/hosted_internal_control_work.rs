//! Retained file-less internal control dispatch between hosted driver domains.
//!
//! The canonical Device IRP may finish later than the source Call. Both the source IRP pin and
//! physical Reply are retained until the provider terminal and source-local IoCompleteRequest.
//! Opaque eight-byte output is never copied back: a callable pointer needs a typed bridge.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    internal_device_control_forward::{InternalControlOutcome, InternalControlProgress},
    source_irp_ledger::SourceIrpForwardIdentity,
    DeviceControlParameters, IoParameters, StackFlags,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const INVALID_HANDLE: i32 = nt_status::NtStatus::INVALID_HANDLE.raw();
const INVALID_PARAMETER: i32 = nt_status::NtStatus::INVALID_PARAMETER.raw();
const INVALID_DEVICE_REQUEST: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
const DEVICE_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();
const NOT_SUPPORTED: i32 = nt_status::NtStatus::NOT_SUPPORTED.raw();
const INSUFFICIENT_RESOURCES: i32 = nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw();

struct Work {
    source: hosted_internal_control_capture::CapturedSourceInternalControl,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    progress: InternalControlProgress,
    canonical_irp: Option<IrpId>,
    entered_provider: bool,
    terminal_status: Option<i32>,
    source_published: bool,
    source_released: bool,
    reply_entered: bool,
    ack: Option<RetainedAck>,
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
static mut EXECUTING: Vec<(usize, DriverInstance, SourceIrpForwardIdentity)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn capture_status(error: hosted_internal_control_capture::CaptureError) -> i32 {
    use hosted_internal_control_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller | CaptureError::InvalidSourceIrp => INVALID_HANDLE,
        CaptureError::InvalidOutput | CaptureError::Unsupported(_) => INVALID_PARAMETER,
        CaptureError::InvalidTarget => INVALID_DEVICE_REQUEST,
    }
}

fn source_work_index(instance: DriverInstance, incoming: SourceIrpForwardIdentity) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(EXECUTING) }
        .iter()
        .find(|(_, owner, identity)| {
            owner.pml4 == instance.pml4
                && owner.hosted_domain_id == instance.hosted_domain_id
                && owner.hosted_domain_cookie == instance.hosted_domain_cookie
                && *identity == incoming
        })
        .map(|(index, _, _)| *index)
        .or_else(|| {
            unsafe { &*core::ptr::addr_of!(WORK) }.iter().position(|slot| {
                slot.as_ref().is_some_and(|work| {
                    !work.source_released
                        && work.source_instance.pml4 == instance.pml4
                        && work.source_instance.hosted_domain_id == instance.hosted_domain_id
                        && work.source_instance.hosted_domain_cookie == instance.hosted_domain_cookie
                        && work.source.source_identity() == incoming
                })
            })
        })
}

fn source_address_work_index(instance: DriverInstance, address: u64) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(WORK) }.iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            !work.source_released
                && work.source_instance.pml4 == instance.pml4
                && work.source_instance.hosted_domain_id == instance.hosted_domain_id
                && work.source_instance.hosted_domain_cookie == instance.hosted_domain_cookie
                && work.source.source_irp_address() == address
                && work.source.validate_source().is_ok()
        })
    })
}

pub(super) unsafe fn submit(
    ch: &crate::spawn_hosts::PumpChannel,
    source_irp: u64,
    target_device: u64,
    badge: u64,
    reply_cap: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(INVALID_HANDLE);
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        return Some(INVALID_HANDLE);
    };
    let mut source = match hosted_internal_control_capture::capture(
        ch, reply_cap, badge, source_irp, target_device,
    ) {
        Ok(source) => source,
        Err(error) => return Some(capture_status(error)),
    };
    if source_work_index(source_instance, source.source_identity()).is_some() {
        source.release(false).expect("duplicate internal control capture rollback");
        return Some(DEVICE_BUSY);
    }
    let provider = hosted_driver_device_route_by_device_id(source.device_id().raw())
        .map(|(index, _, _)| {
            hosted_provider_dispatch_route_for_instance(index)
                .map_or(index, |route| route.provider_instance)
        });
    let Some(provider_index) = provider else {
        source.release(false).expect("internal control target rollback");
        return Some(INVALID_DEVICE_REQUEST);
    };
    let Some((source_index, _)) = instance_for_pump_channel(ch, reply_cap) else {
        source.release(false).expect("internal control caller rollback");
        return Some(INVALID_HANDLE);
    };
    if provider_index == source_index {
        source.release(false).expect("local internal control has no foreign handler");
        return Some(INVALID_DEVICE_REQUEST);
    }
    let Some(provider_instance) = instance(provider_index) else {
        source.release(false).expect("internal control target rollback");
        return Some(INVALID_DEVICE_REQUEST);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.release(false).expect("internal control dispatch rollback");
        return Some(INVALID_HANDLE);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.release(false).expect("internal control Reply rollback");
        return Some(INVALID_HANDLE);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.release(false).expect("internal control caller rollback");
        return Some(INVALID_HANDLE);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source.release(false).expect("internal control actor rollback");
            return Some(status as i32);
        }
    };
    if (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        source.release(false).expect("internal control work rollback");
        return Some(INSUFFICIENT_RESOURCES);
    }
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
            source.release(false).expect("internal control token rollback");
            return Some(INSUFFICIENT_RESOURCES);
        }
    };
    let work = Work {
        progress: InternalControlProgress::new(source.request()),
        source,
        source_instance,
        provider_instance,
        caller,
        actor,
        route,
        dispatch,
        reply,
        token,
        canonical_irp: None,
        entered_provider: false,
        terminal_status: None,
        source_published: false,
        source_released: false,
        reply_entered: false,
        ack: None,
        cancel_requested: false,
    };
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = if let Some(index) = rows.iter().position(Option::is_none) {
        rows[index] = Some(work);
        index
    } else {
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = rows[index].take().expect("unparked internal control owner");
        let _ = work.actor_release();
        work.source.release(false).expect("unparked internal control source");
        return Some(INSUFFICIENT_RESOURCES);
    }
    None
}

impl Work {
    unsafe fn ready_for_nested_step(&self) -> bool {
        if let Some(ack) = &self.ack { return !ack.reply_entered; }
        if self.reply_entered { return false; }
        if self.terminal_status.is_some() || !self.entered_provider { return true; }
        if !self.cancel_requested
            && runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
        {
            return true;
        }
        self.canonical_irp
            .is_some_and(|irp| completed_irp_exact(irp.raw()).is_some())
    }

    unsafe fn actor_release(&mut self) -> Result<(), u32> {
        crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
    }

    unsafe fn provider_exact(&self) -> bool {
        let Some((index, _, _)) = hosted_driver_device_route_by_device_id(self.source.device_id().raw()) else {
            return false;
        };
        let index = hosted_provider_dispatch_route_for_instance(index)
            .map_or(index, |route| route.provider_instance);
        instance(index).is_some_and(|live| {
            live.pml4 == self.provider_instance.pml4
                && live.exec_pool_va == self.provider_instance.exec_pool_va
                && live.hosted_domain_id == self.provider_instance.hosted_domain_id
                && live.hosted_domain_cookie == self.provider_instance.hosted_domain_cookie
                && live.driver_id == self.provider_instance.driver_id
        })
    }

    unsafe fn dispatch_provider(&mut self, handler: *mut ExecNtHandler) {
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.terminal_status = Some(status as i32);
            return;
        }
        if self.source.validate_output().is_err() || !self.provider_exact() {
            self.terminal_status = Some(INVALID_DEVICE_REQUEST);
            return;
        }
        let control = self.source.request();
        let request = ExternalFileIrpRequest {
            client: nt_types::ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.source.device_id(),
            file_id: None,
            user_data: 0,
            requestor_tid: u64::from(self.caller.original_thread().thread_id()),
            major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            parameters: IoParameters::InternalDeviceControl(DeviceControlParameters {
                ioctl_code: control.code(),
                input_len: 0,
                output_len: 8,
            }),
            stack_flags: StackFlags::empty(),
            initial_information: 0,
        };
        let result = hosted_file_owners::dispatch(
            self.caller,
            request,
            &[],
            &[0; 8],
            ExternalFileIrpDispatchPolicy::DeviceControlAtDevice,
        );
        let result = match result {
            Ok(result) => result,
            Err(status) if status == nt_status::NtStatus::DEVICE_BUSY => return,
            Err(status) => {
                self.terminal_status = Some(status.raw());
                return;
            }
        };
        self.progress.enter().expect("one internal control provider entry");
        self.entered_provider = true;
        match result {
            hosted_file_owners::DispatchResult::Returned {
                status, information, buffers, ..
            } => {
                let (_, output) = buffers.into_parts();
                let mut opaque = [0u8; 8];
                if output.len() != 8 {
                    self.terminal_status = Some(INVALID_DEVICE_REQUEST);
                    return;
                }
                opaque.copy_from_slice(&output);
                self.observe_terminal(status.raw(), information, opaque);
            }
            hosted_file_owners::DispatchResult::Outstanding { irp_id } => {
                self.canonical_irp = Some(irp_id);
                self.progress.observe(InternalControlOutcome::Pending)
                    .expect("retained internal control pending");
            }
        }
    }

    fn observe_terminal(&mut self, status: i32, information: u64, opaque: [u8; 8]) {
        // A completed provider IRP cannot report STATUS_PENDING as its terminal status.
        // Completing the source with it would violate IoCompleteRequest's contract.
        if status as u32 == nt_status::NtStatus::PENDING.raw() as u32 {
            self.terminal_status = Some(INVALID_DEVICE_REQUEST);
            return;
        }
        let observed = self.progress.observe(InternalControlOutcome::Terminal {
            status, information, output: opaque,
        });
        self.terminal_status = Some(match observed {
            Ok(Some(_)) if status >= 0 => NOT_SUPPORTED,
            Ok(Some(_)) => status,
            _ => INVALID_DEVICE_REQUEST,
        });
    }

    unsafe fn poll_provider(&mut self) {
        let Some(irp) = self.canonical_irp else { return; };
        let Some(completion) = completed_irp_exact(irp.raw()) else { return; };
        if completion.client_id != IO_MANAGER_COMPONENT_ID
            || completion.device_id != self.source.device_id().raw()
            || completion.file_id != 0
            || completion.requestor_tid != u64::from(self.caller.original_thread().thread_id())
            || completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            || !self.provider_exact()
        {
            self.progress.observe(InternalControlOutcome::Uncertain).ok();
            return;
        }
        if completion.information > 8 {
            self.observe_terminal(INVALID_DEVICE_REQUEST, 0, [0; 8]);
            return;
        }
        let mut opaque = [0u8; 8];
        if completion.status as i32 >= 0
            && copy_completed_irp_output_exact(irp.raw(), 0, &mut opaque) != Ok(8)
        {
            return;
        }
        self.observe_terminal(completion.status as i32, completion.information, opaque);
    }

    unsafe fn publish_source_failure(&mut self) -> bool {
        if self.source.validate_output().is_err() {
            return false;
        }
        let Ok(irp) = self.source.source_irp_exec() else { return false; };
        let status = self.terminal_status.expect("internal control terminal status");
        // No raw provider pointer is copied to the source output. The source's IOSB/event and
        // completion routine still run with an honest error and zero information.
        write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32, status);
        write_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64, 0);
        self.source.arm_callback_free().is_ok()
    }

    unsafe fn retire_terminal(&mut self, stopped: bool) -> bool {
        if let Some(irp) = self.canonical_irp {
            if acknowledge_completed_irp(irp.raw()).is_err() { return false; }
            self.canonical_irp = None;
        }
        if !self.source_released {
            if self.source.release(!stopped).is_err() { return false; }
            self.source_released = true;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if let Some(ack) = self.ack.as_ref() {
            let (route, dispatch, reply, token, reply_entered) =
                (ack.route, ack.dispatch, ack.reply, ack.token, ack.reply_entered);
            if reply_entered {
                let done = matches!(runtime::reconcile_retained_service_reply(
                    route, dispatch, reply, token,
                ), Ok(true));
                if !done { return false; }
                runtime::retire_stopped_acknowledged_retained_service(
                    route, dispatch, reply, token,
                ).expect("internal control ACK retirement");
                return true;
            }
            if !self.source.completion_finished() || !self.retire_terminal(false) {
                return false;
            }
            self.ack.as_mut().expect("retained internal control ACK").reply_entered = true;
            let _ = runtime::wake_query_path_service(
                route, dispatch, reply, token, STATUS_SUCCESS,
            );
            return false;
        }
        if self.reply_entered {
            if !matches!(runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ), Ok(true)) {
                return false;
            }
            if self.source_published { return false; }
            if !self.retire_terminal(true) { return false; }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("rejected internal control retirement");
            return true;
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            if !self.cancel_requested {
                if let Some(irp) = self.canonical_irp { let _ = cancel_irp_if_pending(irp.raw()); }
                self.cancel_requested = true;
            }
            if self.canonical_irp.is_some() && self.terminal_status.is_none() {
                self.poll_provider();
            }
            if self.entered_provider && self.terminal_status.is_none() { return false; }
            // Once the provider entered, the source IRP cannot be released merely because
            // its Call was cancelled. Keep the whole row until source-local completion has
            // actually requested its deferred free.
            if self.entered_provider && !self.source.completion_finished() { return false; }
            if !self.retire_terminal(!self.entered_provider) { return false; }
            runtime::acknowledge_retained_service_cancellation(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("stopped internal control retirement");
            return true;
        }
        if !self.entered_provider && self.terminal_status.is_none() {
            self.dispatch_provider(handler);
        }
        if self.canonical_irp.is_some() && self.terminal_status.is_none() {
            self.poll_provider();
        }
        let Some(status) = self.terminal_status else { return false; };
        if self.entered_provider {
            if !self.publish_source_failure() { return false; }
            self.source_published = true;
        }
        self.reply_entered = true;
        let _ = if self.source_published {
            runtime::wake_query_path_service(self.route, self.dispatch, self.reply, self.token, status)
        } else {
            runtime::wake_query_path_rejected_service(self.route, self.dispatch, self.reply, self.token, status)
        };
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
        if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index) {
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
    ));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let before = (
        work.progress,
        work.canonical_irp.is_some(),
        work.terminal_status,
        work.source_published,
        work.source_released,
        work.reply_entered,
        work.ack.as_ref().map(|ack| ack.reply_entered),
        work.cancel_requested,
    );
    let done = work.advance(handler);
    let after = (
        work.progress,
        work.canonical_irp.is_some(),
        work.terminal_status,
        work.source_published,
        work.source_released,
        work.reply_entered,
        work.ack.as_ref().map(|ack| ack.reply_entered),
        work.cancel_requested,
    );
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop().map(|row| row.0), Some(index));
    done || before != after
}

pub(super) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _ = redrive_one(handler, false);
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK)).iter().enumerate().any(|(index, row)| {
        !(&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index)
            && row.as_ref().is_some_and(|work| work.ready_for_nested_step())
    })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    let attempts = (&*core::ptr::addr_of!(WORK)).len();
    nt_io_manager::hosted_forward_progress::redrive_ready_pass(attempts, || {
        redrive_one(handler, true)
    })
}

pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(INVALID_HANDLE);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() {
        return Some(INVALID_HANDLE);
    }
    let Some(index) = source_address_work_index(source_instance, source_irp) else {
        return Some(INVALID_HANDLE);
    };
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index) {
        return Some(DEVICE_BUSY);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(INVALID_HANDLE);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || work.ack.is_some()
        || !work.reply_entered
        || !work.source_published
        || !work.source.completion_finished()
    {
        return Some(INVALID_HANDLE);
    }
    if !matches!(runtime::reconcile_retained_service_reply(
        work.route, work.dispatch, work.reply, work.token,
    ), Ok(true)) {
        return Some(DEVICE_BUSY);
    }
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if route == work.route => route,
        _ => return Some(INVALID_HANDLE),
    };
    let Ok(dispatch) = runtime::dispatch(route) else { return Some(INVALID_HANDLE); };
    let Ok(reply) = runtime::current_reply(route) else { return Some(INVALID_HANDLE); };
    let Ok(token) = runtime::next_service_wait_token() else { return Some(INSUFFICIENT_RESOURCES); };
    runtime::retire_stopped_acknowledged_retained_service(
        work.route, work.dispatch, work.reply, work.token,
    ).expect("internal control original Reply retirement");
    runtime::park_retained_service(route, token)
        .expect("internal control ACK admission");
    work.ack = Some(RetainedAck { route, dispatch, reply, token, reply_entered: false });
    None
}
