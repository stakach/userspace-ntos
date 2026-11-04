//! Retained fileless device control and READ dispatch between hosted domains.
//!
//! The canonical Device IRP may finish later than the source Call. Both the source IRP pin and
//! physical Reply are retained until the provider terminal and source-local IoCompleteRequest.
//! Provider bytes return only through the source's exact retained output graph.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    hosted_forward_progress::HostedForwardDispatchReply,
    source_irp_ledger::SourceIrpForwardIdentity,
    DeviceControlParameters, IoParameters, ReadWriteParameters, StackFlags,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const INVALID_HANDLE: i32 = nt_status::NtStatus::INVALID_HANDLE.raw();
const INVALID_DEVICE_REQUEST: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
const DEVICE_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();
const NOT_SUPPORTED: i32 = nt_status::NtStatus::NOT_SUPPORTED.raw();
const INSUFFICIENT_RESOURCES: i32 = nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw();

struct Work {
    source: Source,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    canonical_irp: Option<IrpId>,
    entered_provider: bool,
    terminal_status: Option<i32>,
    terminal_information: u64,
    terminal_output: Vec<u8>,
    source_published: bool,
    source_released: bool,
    reply_entered: bool,
    inline_held: bool,
    ack: Option<RetainedAck>,
    pending_wake: Option<WakeAction>,
    cancel_requested: bool,
    quarantined: bool,
}

enum Source {
    Control(hosted_buffered_control_capture::CapturedBufferedControl),
    Read(hosted_device_read_capture::CapturedDeviceRead),
}

impl Source {
    fn identity(&self) -> SourceIrpForwardIdentity {
        match self {
            Self::Control(source) => source.identity(),
            Self::Read(source) => source.identity(),
        }
    }
    fn address(&self) -> u64 {
        match self {
            Self::Control(source) => source.address(),
            Self::Read(source) => source.address(),
        }
    }
    fn device_id(&self) -> nt_io_manager::DeviceId {
        match self {
            Self::Control(source) => source.device_id(),
            Self::Read(source) => source.device_id(),
        }
    }
    fn output_len(&self) -> u32 {
        match self {
            Self::Control(source) => source.request().output_len,
            Self::Read(source) => source.request().length,
        }
    }
    fn major(&self) -> u8 {
        match self {
            Self::Control(_) => major::IRP_MJ_DEVICE_CONTROL,
            Self::Read(_) => major::IRP_MJ_READ,
        }
    }
    fn label(&self) -> u64 {
        match self {
            Self::Control(_) => FSD_SERVICE_BUFFERED_CONTROL_FORWARD_LABEL,
            Self::Read(_) => FSD_SERVICE_DEVICE_READ_FORWARD_LABEL,
        }
    }
    fn completion_finished(&self) -> bool {
        match self {
            Self::Control(source) => source.completion_finished(),
            Self::Read(source) => source.completion_finished(),
        }
    }
    fn validate(&self) -> bool {
        match self {
            Self::Control(source) => source.validate().is_ok(),
            Self::Read(source) => source.validate().is_ok(),
        }
    }
    unsafe fn validate_before_entry(&self) -> bool {
        match self {
            Self::Control(source) => source.validate_before_entry().is_ok(),
            Self::Read(source) => source.validate_before_entry().is_ok(),
        }
    }
    unsafe fn write_refusal(&self, status: i32) -> bool {
        match self {
            Self::Control(source) => source.write_refusal(status).is_ok(),
            Self::Read(source) => source.write_refusal(status).is_ok(),
        }
    }
    unsafe fn write_result(&self, status: i32, information: u64, output: &[u8]) -> bool {
        match self {
            Self::Control(source) => source.write_result(status, information, output).is_ok(),
            Self::Read(source) => source.write_result(status, information, output).is_ok(),
        }
    }
    fn release(&mut self, pending_terminal: bool) -> bool {
        match self {
            Self::Control(source) => source.release(pending_terminal).is_ok(),
            Self::Read(source) => source.release(pending_terminal).is_ok(),
        }
    }
}

struct RetainedAck {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    reply_entered: bool,
}

#[derive(Clone, Copy)]
enum WakeAction {
    Source {
        route: nt_component_suspension::peer_registry::PeerRoute,
        dispatch: nt_component_suspension::LaneDispatchIdentity,
        reply: u64,
        token: u64,
        disposition: HostedForwardDispatchReply,
    },
    Ack {
        route: nt_component_suspension::peer_registry::PeerRoute,
        dispatch: nt_component_suspension::LaneDispatchIdentity,
        reply: u64,
        token: u64,
    },
}

unsafe fn wake_after_restore(wake: WakeAction) {
    match wake {
        WakeAction::Source { route, dispatch, reply, token, disposition } => {
            let _ = runtime::wake_hosted_forward_service(route, dispatch, reply, token, disposition);
        }
        WakeAction::Ack { route, dispatch, reply, token } => {
            let _ = runtime::wake_query_path_service(route, dispatch, reply, token, STATUS_SUCCESS);
        }
    }
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<(usize, DriverInstance, SourceIrpForwardIdentity)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);
static HOLD_REFUSAL_TRACE: AtomicU64 = AtomicU64::new(0);

fn trace_hold_refusal(stage: u64, source_irp: u64, observed: u64, expected: u64) {
    if HOLD_REFUSAL_TRACE.fetch_add(1, Ordering::Relaxed) >= 8 { return; }
    print_str(b"[buffered-control-hold-refusal] stage/irp/token/expected=");
    print_u64(stage);
    print_str(b"/");
    print_hex_u64(source_irp);
    print_str(b"/");
    print_hex_u64(observed);
    print_str(b"/");
    print_hex_u64(expected);
    print_str(b"\n");
}

fn capture_status(error: hosted_buffered_control_capture::CaptureError) -> i32 {
    use hosted_buffered_control_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller | CaptureError::InvalidSource => INVALID_HANDLE,
        CaptureError::Unsupported => NOT_SUPPORTED,
        CaptureError::InvalidTarget => INVALID_DEVICE_REQUEST,
    }
}

unsafe fn refuse_unentered(
    mut source: Source,
    status: i32,
) -> Option<i32> {
    if !source.write_refusal(status) {
        // A captured source changed while this exact Call was parked. Releasing
        // its pin or returning a value would let classpnp observe stale SUCCESS.
        crate::provider_bugcheck::report(
            0xc4, [source.label(), 10, source.address(), status as u32 as u64],
        );
    }
    assert!(source.release(false), "unentered device forward release");
    Some(status)
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
                    && work.source.identity() == incoming
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
            && work.source.address() == address
            && work.source.validate()
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
    let source = match hosted_buffered_control_capture::capture(
        ch, reply_cap, badge, source_irp, target_device,
    ) {
        Ok(source) => Source::Control(source),
        Err(error) => return Some(capture_status(error)),
    };
    submit_captured(ch, source, reply_cap)
}

pub(super) unsafe fn submit_read(
    ch: &crate::spawn_hosts::PumpChannel,
    source_irp: u64,
    target_device: u64,
    badge: u64,
    reply_cap: u64,
) -> Option<i32> {
    let source = match hosted_device_read_capture::capture(
        ch, reply_cap, badge, source_irp, target_device,
    ) {
        Ok(source) => Source::Read(source),
        Err(hosted_device_read_capture::CaptureError::InvalidCaller
            | hosted_device_read_capture::CaptureError::InvalidSource) => return Some(INVALID_HANDLE),
        Err(hosted_device_read_capture::CaptureError::InvalidTarget) =>
            return Some(INVALID_DEVICE_REQUEST),
        Err(hosted_device_read_capture::CaptureError::Unsupported) => return Some(NOT_SUPPORTED),
    };
    submit_captured(ch, source, reply_cap)
}

unsafe fn submit_captured(
    ch: &crate::spawn_hosts::PumpChannel,
    mut source: Source,
    reply_cap: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        assert!(source.release(false), "captured source channel rollback");
        return Some(INVALID_HANDLE);
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        assert!(source.release(false), "captured source route rollback");
        return Some(INVALID_HANDLE);
    };
    if source_work_index(source_instance, source.identity()).is_some() {
        assert!(source.release(false), "duplicate device forward capture rollback");
        return Some(DEVICE_BUSY);
    }
    let provider = hosted_driver_device_route_by_device_id(source.device_id().raw())
        .map(|(index, _, _)| {
            hosted_provider_dispatch_route_for_instance(index)
                .map_or(index, |route| route.provider_instance)
        });
    let Some(provider_index) = provider else {
        return refuse_unentered(source, INVALID_DEVICE_REQUEST);
    };
    let (source_index, _) = instance_for_pump_channel(ch, reply_cap)
        .expect("captured exact source channel");
    if provider_index == source_index {
        return refuse_unentered(source, INVALID_DEVICE_REQUEST);
    }
    let Some(provider_instance) = instance(provider_index) else {
        return refuse_unentered(source, INVALID_DEVICE_REQUEST);
    };
    if instance_domain_identity(provider_instance).is_none()
        || instance_domain_identity(provider_instance) == instance_domain_identity(source_instance)
    {
        return refuse_unentered(source, INVALID_DEVICE_REQUEST);
    }
    let Ok(dispatch) = runtime::dispatch(route) else {
        return refuse_unentered(source, INVALID_HANDLE);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        return refuse_unentered(source, INVALID_HANDLE);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        return refuse_unentered(source, INVALID_HANDLE);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            return refuse_unentered(source, status as i32);
        }
    };
    let mut terminal_output = Vec::new();
    if terminal_output.try_reserve_exact(source.output_len() as usize).is_err() {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        return refuse_unentered(source, INSUFFICIENT_RESOURCES);
    }
    terminal_output.resize(source.output_len() as usize, 0);
    if (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        return refuse_unentered(source, INSUFFICIENT_RESOURCES);
    }
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
            return refuse_unentered(source, INSUFFICIENT_RESOURCES);
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
        canonical_irp: None,
        entered_provider: false,
        terminal_status: None,
        terminal_information: 0,
        terminal_output,
        source_published: false,
        source_released: false,
        reply_entered: false,
        inline_held: false,
        ack: None,
        pending_wake: None,
        cancel_requested: false,
        quarantined: false,
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
        let mut work = rows[index].take().expect("unparked buffered control owner");
        let _ = work.actor_release();
        return refuse_unentered(work.source, INSUFFICIENT_RESOURCES);
    }
    None
}

impl Work {
    unsafe fn ready_for_nested_step(&self) -> bool {
        if self.quarantined { return false; }
        if let Some(ack) = &self.ack { return !ack.reply_entered; }
        if self.reply_entered { return self.inline_held && self.source.completion_finished(); }
        if self.cancel_requested && self.terminal_status.is_some()
            && !self.source.completion_finished()
        {
            return false;
        }
        if self.terminal_status.is_some() || !self.entered_provider { return true; }
        if !self.cancel_requested
            && runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
        {
            return true;
        }
        self.canonical_irp.is_some_and(|irp| {
            completed_device_irp_exact(irp.raw(), self.source.major()).is_some()
        })
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
        if !self.source.validate_before_entry() || !self.provider_exact() {
            self.terminal_status = Some(INVALID_DEVICE_REQUEST);
            return;
        }
        let (major, parameters, stack_flags, initial_information, policy, input) =
            match &self.source {
                Source::Control(source) => {
                    let control = source.request();
                    (
                        major::IRP_MJ_DEVICE_CONTROL,
                        IoParameters::DeviceControl(DeviceControlParameters {
                            ioctl_code: control.code,
                            input_len: control.input_len,
                            output_len: control.output_len,
                        }),
                        StackFlags::empty(),
                        control.initial_information,
                        if control.output_len == 0 {
                            ExternalFileIrpDispatchPolicy::DeviceControlAtDevice
                        } else {
                            ExternalFileIrpDispatchPolicy::BufferedDeviceControlAtDevice
                        },
                        source.input(),
                    )
                }
                Source::Read(source) => {
                    let read = source.request();
                    (
                        major::IRP_MJ_READ,
                        IoParameters::Read(ReadWriteParameters {
                            length: read.length,
                            key: 0,
                            offset: read.byte_offset,
                        }),
                        StackFlags::from_bits_retain(read.stack_flags),
                        0,
                        ExternalFileIrpDispatchPolicy::ReadAtDevice,
                        &[][..],
                    )
                }
            };
        let request = ExternalFileIrpRequest {
            client: nt_types::ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.source.device_id(),
            file_id: None,
            user_data: 0,
            requestor_tid: u64::from(self.caller.original_thread().thread_id()),
            major,
            parameters,
            stack_flags,
            initial_information,
        };
        let result = hosted_file_owners::dispatch(
            self.caller,
            request,
            input,
            &self.terminal_output,
            policy,
        );
        let result = match result {
            Ok(result) => result,
            Err(status) if status == nt_status::NtStatus::DEVICE_BUSY => return,
            Err(status) => {
                self.terminal_status = Some(status.raw());
                return;
            }
        };
        self.entered_provider = true;
        match result {
            hosted_file_owners::DispatchResult::Returned {
                status, information, buffers, ..
            } => {
                let (_, output) = buffers.into_parts();
                if output.len() != self.source.output_len() as usize {
                    self.terminal_status = Some(INVALID_DEVICE_REQUEST);
                    return;
                }
                self.observe_terminal(status.raw(), information, output);
            }
            hosted_file_owners::DispatchResult::Outstanding { irp_id } => {
                self.canonical_irp = Some(irp_id);
            }
        }
    }

    unsafe fn observe_terminal(&mut self, status: i32, information: u64, output: Vec<u8>) {
        // A completed provider IRP cannot report STATUS_PENDING as its terminal status.
        // Completing the source with it would violate IoCompleteRequest's contract.
        if status as u32 == nt_status::NtStatus::PENDING.raw() as u32
            || output.len() != self.source.output_len() as usize
            || self.source.major() == major::IRP_MJ_READ
                && information > u64::from(self.source.output_len())
        {
            self.terminal_status = Some(INVALID_DEVICE_REQUEST);
            return;
        }
        self.terminal_status = Some(status);
        self.terminal_information = information;
        self.terminal_output = output;
    }

    unsafe fn poll_provider(&mut self) {
        let Some(irp) = self.canonical_irp else { return; };
        let Some(completion) = completed_device_irp_exact(irp.raw(), self.source.major()) else { return; };
        if completion.client_id != IO_MANAGER_COMPONENT_ID
            || completion.driver_id != self.provider_instance.driver_id
            || completion.device_id != self.source.device_id().raw()
            || completion.requestor_tid != u64::from(self.caller.original_thread().thread_id())
            || completion.major != self.source.major()
            || !self.provider_exact()
        {
            self.quarantined = true;
            return;
        }
        if completion.status == nt_status::NtStatus::PENDING.raw() as u32 {
            self.quarantined = true;
            return;
        }
        let output_len = if self.source.major() == major::IRP_MJ_READ {
            let Ok(length) = usize::try_from(completion.information) else {
                self.quarantined = true;
                return;
            };
            if length > self.terminal_output.len() {
                self.quarantined = true;
                return;
            }
            length
        } else {
            self.terminal_output.len()
        };
        if output_len != 0
            && copy_completed_irp_output_exact(irp.raw(), 0, &mut self.terminal_output[..output_len]) != Ok(output_len)
        {
            return;
        }
        self.terminal_status = Some(completion.status as i32);
        self.terminal_information = completion.information;
    }

    unsafe fn publish_source_terminal(&mut self) -> bool {
        let status = self.terminal_status.expect("buffered control terminal status");
        self.source.write_result(status, self.terminal_information, &self.terminal_output)
    }

    unsafe fn retire_terminal(&mut self, stopped: bool) -> bool {
        if let Some(irp) = self.canonical_irp {
            if acknowledge_completed_irp(irp.raw()).is_err() { return false; }
            self.canonical_irp = None;
        }
        if !self.source_released {
            if !self.source.release(!stopped) { return false; }
            self.source_released = true;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.quarantined { return false; }
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
                ).expect("buffered control ACK retirement");
                return true;
            }
            // This ACK follows a terminal local completion. The driver may call
            // IoFreeIrp only after IofCallDriver returns, so release_pending_terminal
            // preserves the exact allocation until that later free.
            if !self.retire_terminal(false) {
                return false;
            }
            self.ack.as_mut().expect("retained buffered control ACK").reply_entered = true;
            self.pending_wake = Some(WakeAction::Ack { route, dispatch, reply, token });
            return false;
        }
        if self.reply_entered {
            if !matches!(runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ), Ok(true)) {
                return false;
            }
            if self.source_published {
                if !self.inline_held || !self.source.completion_finished() {
                    return false;
                }
                if !self.retire_terminal(false) { return false; }
            } else if !self.retire_terminal(true) { return false; }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("buffered control source retirement");
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
            ).expect("stopped buffered control retirement");
            return true;
        }
        if !self.entered_provider && self.terminal_status.is_none() {
            self.dispatch_provider(handler);
        }
        if self.canonical_irp.is_some() && self.terminal_status.is_none() {
            self.poll_provider();
        }
        let Some(status) = self.terminal_status else { return false; };
        if !self.publish_source_terminal() { return false; }
        self.source_published = true;
        self.reply_entered = true;
        self.pending_wake = Some(WakeAction::Source {
            route: self.route,
            dispatch: self.dispatch,
            reply: self.reply,
            token: self.token,
            disposition: HostedForwardDispatchReply::InlineTerminal(status),
        });
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
        index, work.source_instance, work.source.identity(),
    ));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let before = (
        work.inline_held,
        work.canonical_irp.is_some(),
        work.terminal_status,
        work.source_published,
        work.source_released,
        work.reply_entered,
        work.ack.as_ref().map(|ack| ack.reply_entered),
        work.cancel_requested,
        work.quarantined,
    );
    let done = work.advance(handler);
    let wake = work.pending_wake.take();
    let after = (
        work.inline_held,
        work.canonical_irp.is_some(),
        work.terminal_status,
        work.source_published,
        work.source_released,
        work.reply_entered,
        work.ack.as_ref().map(|ack| ack.reply_entered),
        work.cancel_requested,
        work.quarantined,
    );
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    } else {
        assert!(wake.is_none(), "retired buffered control row cannot expose an unowned Reply");
    }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop().map(|row| row.0), Some(index));
    if let Some(wake) = wake {
        wake_after_restore(wake);
    }
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

/// The origin ran its exact source-local completion callback and observed
/// MORE_PROCESSING_REQUIRED. Classpnp then owns the IRP until IoFreeIrp; its
/// deferred-free receipt is required before this work can retire the source pin.
pub(super) unsafe fn hold_inline(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
    token: u64,
    expected_label: u64,
) -> i32 {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        trace_hold_refusal(1, source_irp, token, 0);
        return INVALID_HANDLE;
    };
    if token == 0 || hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() {
        trace_hold_refusal(2, source_irp, token, 0);
        return INVALID_HANDLE;
    }
    let Some(index) = source_address_work_index(source_instance, source_irp) else {
        trace_hold_refusal(3, source_irp, token, 0);
        return INVALID_HANDLE;
    };
    if (&*core::ptr::addr_of!(EXECUTING)).iter().any(|(active, _, _)| *active == index) {
        trace_hold_refusal(4, source_irp, token, 0);
        return DEVICE_BUSY;
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        trace_hold_refusal(5, source_irp, token, 0);
        return INVALID_HANDLE;
    };
    if work.token != token || work.source.label() != expected_label {
        trace_hold_refusal(6, source_irp, token, work.token);
        return INVALID_HANDLE;
    }
    if work.inline_held || work.ack.is_some() {
        trace_hold_refusal(7, source_irp, token, work.token);
        return INVALID_HANDLE;
    }
    if !work.reply_entered || !work.source_published {
        trace_hold_refusal(8, source_irp, token, work.token);
        return INVALID_HANDLE;
    }
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller) {
        trace_hold_refusal(9, source_irp, token, work.token);
        return INVALID_HANDLE;
    }
    if runtime::channel_route(ch).ok().flatten() != Some(work.route) {
        trace_hold_refusal(10, source_irp, token, work.token);
        return INVALID_HANDLE;
    }
    if !matches!(runtime::reconcile_retained_service_reply(
        work.route, work.dispatch, work.reply, work.token,
    ), Ok(true)) {
        trace_hold_refusal(11, source_irp, token, work.token);
        return DEVICE_BUSY;
    }
    work.inline_held = true;
    STATUS_SUCCESS
}

pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
    expected_label: u64,
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
        || work.source.label() != expected_label
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
    ).expect("buffered control original Reply retirement");
    runtime::park_retained_service(route, token)
        .expect("buffered control ACK admission");
    work.ack = Some(RetainedAck { route, dispatch, reply, token, reply_entered: false });
    None
}
