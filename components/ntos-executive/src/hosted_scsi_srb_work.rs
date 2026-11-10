//! Retained cross-domain SCSI SRB dispatch from an exact accepted foreign PDO.
//!
//! The source IRP, SRB, MDL, data and sense children remain pinned through provider terminal,
//! canonical acknowledgement, source-local completion and its physical Reply acknowledgement.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    hosted_forward_progress::HostedForwardDispatchReply,
    scsi_srb_transport::{bounded_scsi_information, ScsiParameters},
    scsi_srb_wire::decode_scsi_completion,
    IoParameters, StackFlags,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};
use super::hosted_source_stack_lease::ScsiStackSource;

const INVALID_HANDLE: i32 = nt_status::NtStatus::INVALID_HANDLE.raw();
const INVALID_PARAMETER: i32 = nt_status::NtStatus::INVALID_PARAMETER.raw();
const INVALID_DEVICE_REQUEST: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
const DEVICE_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();
const INSUFFICIENT_RESOURCES: i32 = nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw();

struct Work {
    source: hosted_scsi_srb_capture::CapturedSourceScsi,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    provider_irp: Option<IrpId>,
    canonical_irp: Option<IrpId>,
    entered_provider: bool,
    provider_terminal: bool,
    provider_acknowledged: bool,
    source_completed: bool,
    terminal_status: Option<i32>,
    terminal_information: u64,
    source_copyback_committed: bool,
    source_published: bool,
    source_publish_failure_traced: bool,
    source_released: bool,
    reply_entered: bool,
    inline_held: bool,
    ack: Option<RetainedAck>,
    pending_wake: Option<WakeAction>,
    cancel_requested: bool,
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
static mut EXECUTING: Vec<(usize, DriverInstance, ScsiStackSource)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);
static CLAIM_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static SCSI_CAPTURE_REFUSAL_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static SCSI_PROGRESS_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static SCSI_PENDING_BOUNDARY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static SCSI_HELD_REFUSAL_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static SCSI_IRQ_BOUNDARY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static mut SCSI_IRQ_BOUNDARY_SEEN: [Option<(u64, u64, u64, bool, bool)>; 128] = [None; 128];
static SCSI_RECEIVE_BOUNDARY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReceiveBoundaryObservation {
    source: u64,
    use_epoch: u64,
    provider_irp: u64,
    terminal: bool,
    ready: bool,
    terminal_status: Option<i32>,
    pending_wake: bool,
    reply_entered: bool,
    cancelled: bool,
    provider_terminal: bool,
    provider_acknowledged: bool,
    route_endpoint: u64,
    route_badge: u64,
    dispatch_epoch: u64,
    dispatch_lane_generation: u64,
    reply: u64,
    token: u64,
}

static mut SCSI_RECEIVE_BOUNDARY_SEEN: [Option<ReceiveBoundaryObservation>; 64] = [None; 64];

fn trace_scsi_held_refusal(stage: u64, source_irp: u64, token: u64, detail: u64) {
    if SCSI_HELD_REFUSAL_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 4 { return; }
    print_str(b"[scsi-held-refusal] stage/irp/token/detail=");
    print_u64(stage);
    print_str(b"/");
    print_hex64(source_irp);
    print_str(b"/");
    print_u64(token);
    print_str(b"/");
    print_u64(detail);
    print_str(b"\n");
}

/// Stages: 1 captured, 2 returned, 3 outstanding, 4 terminal,
/// 5 source published, 6 publication refused, 7 source completed,
/// 8 provider ACK, 9 released. Result is 1 for committed copyback at
/// terminal, 0 for uncommitted copyback, and 0 at other stages.
fn trace_scsi_progress(
    stage: u64,
    source: &hosted_scsi_srb_capture::CapturedSourceScsi,
    provider_irp: Option<IrpId>,
    status: i32,
    information: u64,
    result: u64,
) {
    if SCSI_PROGRESS_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 256 { return; }
    let opcode = source.wire_srb().ok().map_or(0xff, |srb| srb[0x48]);
    print_str(b"[scsi-progress] stage/source/use/cdb/provider/status/info/result=");
    print_u64(stage);
    print_str(b"/");
    print_u64(source.source_irp_address());
    print_str(b"/");
    print_u64(source.scsi_identity().use_ticket().epoch().get());
    print_str(b"/");
    print_hex(u32::from(opcode));
    print_str(b"/");
    print_u64(provider_irp.map_or(0, IrpId::raw));
    print_str(b"/");
    print_hex(status as u32);
    print_str(b"/");
    print_u64(information);
    print_str(b"/");
    print_u64(result);
    print_str(b"\n");
}

/// Observation at provider acceptance and after the first redrive restores its SCSI owner.
/// Neither the canonical completion query nor the ready hint claims or pumps an IRP.
unsafe fn trace_scsi_pending_boundary(phase: u64, work: &Work, irp: IrpId) {
    if SCSI_PENDING_BOUNDARY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 64 { return; }
    let source = work.source.source_irp_address();
    let use_epoch = work.source.scsi_identity().use_ticket().epoch().get();
    let terminal = io_manager_mut().completed_irp(irp).is_some();
    let ready = nested_device_control_completion_ready_exact(irp.raw());
    print_str(b"[scsi-pending-boundary] phase/source/use/provider/terminal/ready/reply/provider-tcb=");
    let values = [
        phase, source, use_epoch, irp.raw(), u64::from(terminal), u64::from(ready),
        work.reply, work.provider_instance.tcb,
    ];
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
    print_str(b"\n");
    hosted_file_owners::trace_scsi_provider_owner(phase, source, use_epoch, irp);
}

fn trace_claim(stage: u64, status: i32, detail: u64) {
    if CLAIM_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    print_str(b"[scsi-claim] stage/status/detail=");
    print_u64(stage);
    print_str(b"/");
    print_hex(status as u32);
    print_str(b"/");
    print_u64(detail);
    print_str(b"\n");
}

fn capture_status(error: hosted_scsi_srb_capture::CaptureError) -> i32 {
    use hosted_scsi_srb_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller | CaptureError::InvalidSource => INVALID_HANDLE,
        CaptureError::InvalidTarget => INVALID_DEVICE_REQUEST,
        CaptureError::InvalidSrb => INVALID_PARAMETER,
    }
}

fn same_instance(a: DriverInstance, b: DriverInstance) -> bool {
    a.pml4 == b.pml4
        && a.exec_pool_va == b.exec_pool_va
        && a.hosted_domain_id == b.hosted_domain_id
        && a.hosted_domain_cookie == b.hosted_domain_cookie
        && a.driver_id == b.driver_id
}

fn work_index(instance: DriverInstance, identity: ScsiStackSource) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(EXECUTING) }
        .iter()
        .find(|(_, live, source)| same_instance(*live, instance) && *source == identity)
        .map(|(index, _, _)| *index)
        .or_else(|| {
            unsafe { &*core::ptr::addr_of!(WORK) }
                .iter()
                .position(|slot| {
                    slot.as_ref().is_some_and(|work| {
                        !work.source_released
                            && same_instance(work.source_instance, instance)
                            && work.source.scsi_identity() == identity
                    })
                })
        })
}

pub(super) unsafe fn classify(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    device: u64,
) -> (i32, bool) {
    match hosted_scsi_srb_capture::accepted_foreign_pdo(ch, reply_cap, badge, device) {
        Ok(accepted) => (STATUS_SUCCESS, accepted),
        Err(error) => (capture_status(error), false),
    }
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
    let captured = hosted_scsi_srb_capture::capture(
        ch, reply_cap, badge, source_irp, target_device,
    );
    if let Ok(source) = &captured {
        if source.srb_function() == Some(1) { trace_claim(1, STATUS_SUCCESS, source_irp); }
    } else if let Err(error) = &captured {
        // Capture has not admitted an SRB yet, so the function byte is unavailable.
        if SCSI_CAPTURE_REFUSAL_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 4 {
            print_str(b"[scsi-capture-refusal] status/irp=");
            print_hex(capture_status(*error) as u32);
            print_str(b"/");
            print_u64(source_irp);
            print_str(b"\n");
        }
    }
    let mut source =
        match captured {
            Ok(source) => source,
            Err(error) => return Some(capture_status(error)),
        };
    trace_scsi_progress(1, &source, None, STATUS_SUCCESS, 0, 0);
    if work_index(source_instance, source.scsi_identity()).is_some() {
        source
            .abandon_unentered()
            .expect("duplicate SCSI source rollback");
        return Some(DEVICE_BUSY);
    }
    let Some((index, _, _)) = hosted_driver_device_route_by_device_id(source.device_id().raw())
    else {
        source
            .abandon_unentered()
            .expect("SCSI provider route rollback");
        return Some(INVALID_DEVICE_REQUEST);
    };
    let provider_index = hosted_provider_dispatch_route_for_instance(index)
        .map_or(index, |route| route.provider_instance);
    let Some(provider_instance) = instance(provider_index) else {
        source
            .abandon_unentered()
            .expect("SCSI provider instance rollback");
        return Some(INVALID_DEVICE_REQUEST);
    };
    if same_instance(source_instance, provider_instance)
        || instance_domain_identity(provider_instance)
            != Some(source.provider_authority().provider().domain())
    {
        source
            .abandon_unentered()
            .expect("SCSI wrong provider rollback");
        return Some(INVALID_DEVICE_REQUEST);
    }
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.abandon_unentered().expect("SCSI dispatch rollback");
        return Some(INVALID_HANDLE);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.abandon_unentered().expect("SCSI Reply rollback");
        return Some(INVALID_HANDLE);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.abandon_unentered().expect("SCSI caller rollback");
        return Some(INVALID_HANDLE);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source.abandon_unentered().expect("SCSI actor rollback");
            return Some(status as i32);
        }
    };
    if (&mut *core::ptr::addr_of_mut!(WORK))
        .try_reserve(1)
        .is_err()
    {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        source.abandon_unentered().expect("SCSI capacity rollback");
        return Some(INSUFFICIENT_RESOURCES);
    }
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
            source.abandon_unentered().expect("SCSI token rollback");
            return Some(INSUFFICIENT_RESOURCES);
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
        provider_irp: None,
        canonical_irp: None,
        entered_provider: false,
        provider_terminal: false,
        provider_acknowledged: false,
        source_completed: false,
        terminal_status: None,
        terminal_information: 0,
        source_copyback_committed: false,
        source_published: false,
        source_publish_failure_traced: false,
        source_released: false,
        reply_entered: false,
        inline_held: false,
        ack: None,
        pending_wake: None,
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
        let mut work = rows[index].take().expect("unparked SCSI owner");
        let _ = work.actor_release();
        work.source
            .abandon_unentered()
            .expect("unparked SCSI source");
        return Some(INSUFFICIENT_RESOURCES);
    }
    None
}

impl Work {
    fn trace_terminal(&self) {
        if let Some(status) = self.terminal_status {
            trace_scsi_progress(
                4, &self.source, self.provider_irp, status,
                self.terminal_information, u64::from(self.source_copyback_committed),
            );
        }
    }

    unsafe fn actor_release(&mut self) -> Result<(), u32> {
        crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
    }

    unsafe fn provider_exact(&self) -> bool {
        if self.source.validate().is_err() {
            return false;
        }
        let Some((index, _, _)) =
            hosted_driver_device_route_by_device_id(self.source.device_id().raw())
        else {
            return false;
        };
        let index = hosted_provider_dispatch_route_for_instance(index)
            .map_or(index, |route| route.provider_instance);
        instance(index).is_some_and(|live| same_instance(live, self.provider_instance))
    }

    unsafe fn dispatch_provider(&mut self, handler: *mut ExecNtHandler) {
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.terminal_status = Some(status as i32);
            return;
        }
        if !self.provider_exact() {
            self.terminal_status = Some(INVALID_DEVICE_REQUEST);
            return;
        }
        let children = self.source.children();
        let Ok(srb) = self.source.wire_srb() else {
            self.terminal_status = Some(INVALID_PARAMETER);
            return;
        };
        let Ok(parameters) = ScsiParameters::from_wire(
            children.route,
            srb,
            children.transfer_length,
            children.sense_length,
        ) else {
            self.terminal_status = Some(INVALID_PARAMETER);
            return;
        };
        let Some(output_len) = 64usize
            .checked_add(nt_io_manager::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE)
            .and_then(|length| length.checked_add(self.source.data().len()))
            .and_then(|length| length.checked_add(self.source.sense().map_or(0, <[u8]>::len)))
        else {
            self.terminal_status = Some(INVALID_PARAMETER);
            return;
        };
        let mut input = Vec::new();
        if input
            .try_reserve_exact(
                output_len - 64 - nt_io_manager::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE,
            )
            .is_err()
        {
            self.terminal_status = Some(INSUFFICIENT_RESOURCES);
            return;
        }
        input.extend_from_slice(self.source.data());
        if let Some(sense) = self.source.sense() {
            input.extend_from_slice(sense);
        }
        let mut output = Vec::new();
        if output.try_reserve_exact(output_len).is_err() {
            self.terminal_status = Some(INSUFFICIENT_RESOURCES);
            return;
        }
        output.resize(output_len, 0);
        let request = ExternalFileIrpRequest {
            client: nt_types::ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.source.device_id(),
            file_id: None,
            user_data: 0,
            requestor_tid: u64::from(self.caller.original_thread().thread_id()),
            major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            parameters: IoParameters::Scsi(parameters),
            stack_flags: StackFlags::empty(),
            initial_information: 0,
        };
        let result = hosted_file_owners::dispatch(
            self.caller,
            request,
            &input,
            &output,
            ExternalFileIrpDispatchPolicy::ScsiAtDevice,
        );
        match result {
            Ok(hosted_file_owners::DispatchResult::Returned {
                irp_id,
                status,
                information,
                buffers,
                ..
            }) => {
                if self.source.srb_function() == Some(1) {
                    trace_claim(2, status.raw(), irp_id.raw());
                }
                self.source
                    .entered(irp_id)
                    .expect("SCSI returned exact entry");
                self.provider_irp = Some(irp_id);
                self.canonical_irp = Some(irp_id);
                self.entered_provider = true;
                trace_scsi_progress(2, &self.source, Some(irp_id), status.raw(), information, 0);
                let (_, output) = buffers.into_parts();
                self.observe_terminal(status.raw(), information, &output);
                self.provider_acknowledged = true;
                self.source
                    .provider_acknowledged(irp_id)
                    .expect("SCSI returned canonical acknowledgement");
                trace_scsi_progress(8, &self.source, Some(irp_id), status.raw(), information, 0);
                self.canonical_irp = None;
            }
            Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
                if self.source.srb_function() == Some(1) {
                    trace_claim(3, STATUS_PENDING as i32, irp_id.raw());
                }
                self.source
                    .entered(irp_id)
                    .expect("SCSI pending exact entry");
                self.source
                    .pending(irp_id)
                    .expect("SCSI pending source retention");
                self.provider_irp = Some(irp_id);
                self.canonical_irp = Some(irp_id);
                self.entered_provider = true;
                trace_scsi_progress(3, &self.source, Some(irp_id), STATUS_PENDING as i32, 0, 0);
                trace_scsi_pending_boundary(1, self, irp_id);
            }
            Err(status) if status == nt_status::NtStatus::DEVICE_BUSY => {}
            Err(status) => {
                if self.source.srb_function() == Some(1) {
                    trace_claim(4, status.raw(), 0);
                }
                self.terminal_status = Some(status.raw());
            }
        }
    }

    unsafe fn observe_terminal(&mut self, status: i32, information: u64, output: &[u8]) {
        if self.source.srb_function() == Some(1) {
            trace_claim(5, status, output.len() as u64);
        }
        let Some(irp) = self.canonical_irp else {
            return;
        };
        self.source
            .terminal(irp)
            .expect("SCSI exact provider terminal");
        self.provider_terminal = true;
        self.source_copyback_committed = false;
        if status as u32 == STATUS_PENDING {
            self.project_invalid_provider_terminal();
            return;
        }
        let Ok(information) = bounded_scsi_information(information, self.source.data().len())
        else {
            self.project_invalid_provider_terminal();
            return;
        };
        self.terminal_information = information;
        let route = self.source.children().route;
        self.terminal_status = Some(match decode_scsi_completion(output, route, irp) {
            Ok(packet) => {
                self.source_copyback_committed = false;
                if self.source.write_completion(
                    packet.srb, packet.data, packet.sense,
                    packet.claim_result, status,
                ).is_ok() {
                    self.source_copyback_committed = true;
                    status
                } else {
                    INVALID_DEVICE_REQUEST
                }
            }
            _ => {
                self.project_invalid_provider_terminal();
                return;
            },
        });
        self.trace_terminal();
    }

    unsafe fn project_invalid_provider_terminal(&mut self) {
        self.terminal_status = Some(INVALID_DEVICE_REQUEST);
        self.terminal_information = 0;
        self.source_copyback_committed = self.source
            .write_error_completion(INVALID_DEVICE_REQUEST).is_ok();
        self.trace_terminal();
    }

    unsafe fn poll_provider(&mut self) {
        let Some(irp) = self.canonical_irp else {
            return;
        };
        let Some(completion) = completed_device_control_irp_exact(irp.raw()) else {
            return;
        };
        if completion.client_id != IO_MANAGER_COMPONENT_ID
            || completion.driver_id != self.provider_instance.driver_id
            || completion.device_id != self.source.device_id().raw()
            || completion.requestor_tid != u64::from(self.caller.original_thread().thread_id())
            || completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            || self.source.validate_retained().is_err()
        {
            return;
        }
        let children = self.source.children();
        let Some(capacity) = 64usize
            .checked_add(nt_io_manager::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE)
            .and_then(|length| length.checked_add(children.transfer_length as usize))
            .and_then(|length| length.checked_add(children.sense_length as usize))
        else {
            return;
        };
        let mut output = Vec::new();
        if output.try_reserve_exact(capacity).is_err() {
            return;
        }
        output.resize(capacity, 0);
        if copy_completed_irp_output_exact(irp.raw(), 0, &mut output) != Ok(capacity) {
            return;
        }
        self.observe_terminal(completion.status as i32, completion.information, &output);
    }

    unsafe fn publish_source_terminal(&mut self) -> bool {
        if !self.source_copyback_committed {
            return false;
        }
        let Ok(irp) = self.source.source_irp_exec() else {
            return false;
        };
        let Some(provider_irp) = self.provider_irp else {
            return false;
        };
        let status = self.terminal_status.expect("SCSI source terminal");
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32,
            status,
        );
        // Information is a separately bounded provider scalar; SRB transfer and sense counts
        // remain authoritative for their own retained children.
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
            self.terminal_information,
        );
        if self.source.arm_callback_free().is_err() {
            return false;
        }
        // The use becomes reusable only after SRB/data/sense copyback, IRP
        // status and information, and deferred-free ownership are published.
        // The terminal Reply has not yet been sent to the source driver.
        hosted_source_irp_ledger::publish_scsi_source(self.source.children(), provider_irp)
    }

    unsafe fn retire_provider_and_source(&mut self) -> bool {
        if self.provider_irp.is_some() && !self.source_completed {
            return false;
        }
        if let Some(irp) = self.canonical_irp {
            if !self.provider_acknowledged {
                if acknowledge_completed_irp_strict(irp.raw()).is_err() {
                    return false;
                }
                self.source
                    .provider_acknowledged(irp)
                    .expect("SCSI acknowledged canonical completion");
                self.provider_acknowledged = true;
                trace_scsi_progress(8, &self.source, Some(irp), STATUS_SUCCESS, 0, 0);
            }
            self.canonical_irp = None;
        }
        if !self.source_released {
            if self.entered_provider {
                if self.source.release_after_completions().is_err() {
                    return false;
                }
            } else if self.source.abandon_unentered().is_err() {
                return false;
            }
            self.source_released = true;
            trace_scsi_progress(9, &self.source, self.provider_irp, STATUS_SUCCESS, 0, 0);
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        if let Some(ack) = &self.ack {
            return !ack.reply_entered;
        }
        if self.reply_entered {
            return self.inline_held && self.source_completed;
        }
        if self.terminal_status.is_some() || !self.entered_provider {
            return true;
        }
        if !self.cancel_requested
            && runtime::retained_service_cancelled(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
        {
            return true;
        }
        self.canonical_irp
            .is_some_and(|irp| completed_device_control_irp_exact(irp.raw()).is_some())
    }

    unsafe fn ready_for_irq_step(&self) -> bool {
        nt_io_manager::hosted_forward_progress::irq_owned_ready(self.entered_provider, || {
            unsafe { self.ready_for_nested_step() }
        })
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if let Some(ack) = self.ack.as_ref() {
            let (route, dispatch, reply, token, reply_entered) = (
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
                ack.reply_entered,
            );
            if reply_entered {
                if !matches!(
                    runtime::reconcile_retained_service_reply(route, dispatch, reply, token),
                    Ok(true)
                ) {
                    return false;
                }
                runtime::retire_stopped_acknowledged_retained_service(
                    route, dispatch, reply, token,
                )
                .expect("SCSI ACK retirement");
                return true;
            }
            if !self.retire_provider_and_source() {
                return false;
            }
            self.ack.as_mut().expect("retained SCSI ACK").reply_entered = true;
            self.pending_wake = Some(WakeAction::Ack { route, dispatch, reply, token });
            return false;
        }
        if self.reply_entered {
            if !matches!(
                runtime::reconcile_retained_service_reply(
                    self.route,
                    self.dispatch,
                    self.reply,
                    self.token,
                ),
                Ok(true)
            ) {
                return false;
            }
            if self.source_published {
                if !self.inline_held || !self.source_completed {
                    return false;
                }
                if !self.retire_provider_and_source() {
                    return false;
                }
                runtime::retire_stopped_acknowledged_retained_service(
                    self.route,
                    self.dispatch,
                    self.reply,
                    self.token,
                )
                .expect("held SCSI source retirement");
                return true;
            }
            if !self.retire_provider_and_source() {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("rejected SCSI retirement");
            return true;
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            if !self.cancel_requested {
                if let Some(irp) = self.canonical_irp {
                    let _ = cancel_irp_if_pending(irp.raw());
                }
                self.cancel_requested = true;
            }
            if self.canonical_irp.is_some() && self.terminal_status.is_none() {
                self.poll_provider();
            }
            if self.entered_provider
                && (self.terminal_status.is_none() || !self.source.completion_finished())
            {
                return false;
            }
            if !self.retire_provider_and_source() {
                return false;
            }
            runtime::acknowledge_retained_service_cancellation(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("stopped SCSI retirement");
            return true;
        }
        if !self.entered_provider && self.terminal_status.is_none() {
            self.dispatch_provider(handler);
        }
        if self.canonical_irp.is_some() && self.terminal_status.is_none() {
            self.poll_provider();
        }
        let Some(status) = self.terminal_status else {
            return false;
        };
        if self.entered_provider {
            if !self.publish_source_terminal() {
                if !self.source_publish_failure_traced {
                    trace_scsi_progress(6, &self.source, self.provider_irp, status,
                        self.terminal_information, 0);
                    self.source_publish_failure_traced = true;
                }
                return false;
            }
            self.source_published = true;
            trace_scsi_progress(5, &self.source, self.provider_irp, status,
                self.terminal_information, 0);
        }
        self.reply_entered = true;
        let disposition = if self.source_published {
            HostedForwardDispatchReply::InlineTerminal(status)
        } else {
            HostedForwardDispatchReply::Rejected(status)
        };
        self.pending_wake = Some(WakeAction::Source {
            route: self.route,
            dispatch: self.dispatch,
            reply: self.reply,
            token: self.token,
            disposition,
        });
        false
    }
}

#[derive(Clone, Copy)]
enum ReadyScope { Any, Nested, IrqOwned }

unsafe fn redrive_one(handler: *mut ExecNtHandler, scope: ReadyScope) -> bool {
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
        let ready = (&*core::ptr::addr_of!(WORK))[index].as_ref().is_some_and(|work| {
            match scope {
                ReadyScope::Any => true,
                ReadyScope::Nested => work.ready_for_nested_step(),
                ReadyScope::IrqOwned => work.ready_for_irq_step(),
            }
        });
        if !ready {
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
        work.source.scsi_identity(),
    ));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let before = (
        work.canonical_irp,
        work.terminal_status,
        work.source_published,
        work.source_released,
        work.reply_entered,
        work.ack.as_ref().map(|ack| ack.reply_entered),
    );
    let done = work.advance(handler);
    let wake = work.pending_wake.take();
    let after = (
        work.canonical_irp,
        work.terminal_status,
        work.source_published,
        work.source_released,
        work.reply_entered,
        work.ack.as_ref().map(|ack| ack.reply_entered),
    );
    let newly_pending = before.0.is_none() && after.0.is_some() && !done;
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    } else {
        assert!(wake.is_none(), "retired SCSI row cannot expose an unowned Reply");
    }
    assert_eq!(
        (&mut *core::ptr::addr_of_mut!(EXECUTING))
            .pop()
            .map(|row| row.0),
        Some(index)
    );
    if newly_pending {
        let restored = (&*core::ptr::addr_of!(WORK))[index]
            .as_ref().expect("pending SCSI owner restored");
        if let Some(irp) = restored.canonical_irp {
            trace_scsi_pending_boundary(2, restored, irp);
        }
    }
    if let Some(wake) = wake {
        wake_after_restore(wake);
    }
    done || before != after
}

pub(super) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _ = redrive_one(handler, ReadyScope::Any);
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
    let attempts = (&*core::ptr::addr_of!(WORK)).len();
    nt_io_manager::hosted_forward_progress::redrive_ready_pass(attempts, || {
        redrive_one(handler, ReadyScope::Nested)
    })
}

unsafe fn redrive_irq_ready_pass(handler: *mut ExecNtHandler) -> bool {
    let attempts = (&*core::ptr::addr_of!(WORK)).len();
    nt_io_manager::hosted_forward_progress::redrive_ready_pass(attempts, || {
        redrive_one(handler, ReadyScope::IrqOwned)
    })
}

/// DPC publication can make several retained SCSI sources ready in one IRQ turn.
/// A nested pass advances at most one row. Its progress snapshot has six monotonic
/// fields plus retirement, so eight rounds per initial owner cover every ready phase.
pub(super) unsafe fn redrive_irq_ready(handler: *mut ExecNtHandler) -> usize {
    let owners = (&*core::ptr::addr_of!(WORK)).len();
    nt_io_manager::hosted_forward_progress::drain_irq_ready_rounds(
        owners.saturating_mul(8),
        || redrive_irq_ready_pass(handler),
    )
}

/// Observation only: inspect the exact retained provider before a post-DPC poll.
/// This does not pump an IRP, claim a pending owner, or change a Reply.
pub(super) unsafe fn trace_irq_boundary() {
    for work in (&*core::ptr::addr_of!(WORK)).iter().flatten() {
        if !work.entered_provider || work.source_published { continue; }
        let Some(irp) = work.canonical_irp else { continue; };
        let terminal = io_manager_mut().completed_irp(irp).is_some();
        let ready = nested_device_control_completion_ready_exact(irp.raw());
        let observation = (
            work.source.source_irp_address(),
            work.source.scsi_identity().use_ticket().epoch().get(),
            irp.raw(), terminal, ready,
        );
        let seen = &mut *core::ptr::addr_of_mut!(SCSI_IRQ_BOUNDARY_SEEN);
        if seen.contains(&Some(observation)) { continue; }
        let sequence = SCSI_IRQ_BOUNDARY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
        seen[sequence as usize % seen.len()] = Some(observation);
        if sequence >= 64 && !sequence.is_power_of_two() { continue; }
        print_str(b"[scsi-irq-boundary] source/use/provider/terminal/ready=");
        print_u64(observation.0);
        print_str(b"/");
        print_u64(observation.1);
        print_str(b"/");
        print_u64(observation.2);
        print_str(b"/");
        print_u64(u64::from(observation.3));
        print_str(b"/");
        print_u64(u64::from(observation.4));
        print_str(b"\n");
        return;
    }
}

/// Observation only, after ordinary redrive and before the root may sleep. A canonical
/// terminal here distinguishes a missed final redrive from a provider that never completed.
/// This never claims a completion, wakes a source, or touches a retained Reply.
pub(super) unsafe fn receive_boundary_probe_due() -> bool {
    SCSI_RECEIVE_BOUNDARY_TRACE_COUNT.load(Ordering::Relaxed) < 64
        && (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work| {
            work.entered_provider && !work.source_published && work.canonical_irp.is_some()
        })
}

pub(super) unsafe fn trace_receive_boundary() {
    if SCSI_RECEIVE_BOUNDARY_TRACE_COUNT.load(Ordering::Relaxed) >= 64 { return; }
    for work in (&*core::ptr::addr_of!(WORK)).iter().flatten() {
        if !work.entered_provider || work.source_published { continue; }
        let Some(irp) = work.canonical_irp else { continue; };
        let observation = ReceiveBoundaryObservation {
            source: work.source.source_irp_address(),
            use_epoch: work.source.scsi_identity().use_ticket().epoch().get(),
            provider_irp: irp.raw(),
            terminal: io_manager_mut().completed_irp(irp).is_some(),
            ready: nested_device_control_completion_ready_exact(irp.raw()),
            terminal_status: work.terminal_status,
            pending_wake: work.pending_wake.is_some(),
            reply_entered: work.reply_entered,
            cancelled: work.cancel_requested,
            provider_terminal: work.provider_terminal,
            provider_acknowledged: work.provider_acknowledged,
            route_endpoint: work.route.endpoint(),
            route_badge: work.route.badge(),
            dispatch_epoch: work.dispatch.epoch(),
            dispatch_lane_generation: work.dispatch.lane().generation,
            reply: work.reply,
            token: work.token,
        };
        let seen = &mut *core::ptr::addr_of_mut!(SCSI_RECEIVE_BOUNDARY_SEEN);
        if seen.contains(&Some(observation)) { continue; }
        let sequence = SCSI_RECEIVE_BOUNDARY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
        if sequence >= 64 { return; }
        seen[sequence as usize % seen.len()] = Some(observation);
        print_str(b"[scsi-receive-boundary] source/use/provider/terminal/ready/status/wake/reply-entered/cancel/provider-terminal/ack/route/badge/dispatch/lane-generation/reply-cap/token=");
        for value in [
            observation.source,
            observation.use_epoch,
            observation.provider_irp,
            u64::from(observation.terminal),
            u64::from(observation.ready),
            observation.terminal_status.map_or(u64::MAX, |status| status as u32 as u64),
            u64::from(observation.pending_wake),
            u64::from(observation.reply_entered),
            u64::from(observation.cancelled),
            u64::from(observation.provider_terminal),
            u64::from(observation.provider_acknowledged),
            observation.route_endpoint,
            observation.route_badge,
            observation.dispatch_epoch,
            observation.dispatch_lane_generation,
            observation.reply,
            observation.token,
        ] {
            print_str(b"/");
            print_u64(value);
        }
        print_str(b"\n");
        return;
    }
}

pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
    source_token: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(INVALID_HANDLE);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() || source_token == 0 {
        return Some(INVALID_HANDLE);
    }
    let Some(index) = (&*core::ptr::addr_of!(WORK)).iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            !work.source_released
                && same_instance(work.source_instance, source_instance)
                && work.source.source_irp_address() == source_irp
                && work.token == source_token
                && work.provider_irp.is_some_and(|provider_irp|
                    work.source.validate_published_source(provider_irp).is_ok())
        })
    }) else {
        return Some(INVALID_HANDLE);
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _)| *active == index)
    {
        return Some(DEVICE_BUSY);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(INVALID_HANDLE);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || work.ack.is_some()
        || !work.reply_entered
        || !work.source_published
        || !work.provider_terminal
    {
        return Some(INVALID_HANDLE);
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
        return Some(DEVICE_BUSY);
    }
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if route == work.route => route,
        _ => return Some(INVALID_HANDLE),
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        return Some(INVALID_HANDLE);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        return Some(INVALID_HANDLE);
    };
    let Ok(token) = runtime::next_service_wait_token() else {
        return Some(INSUFFICIENT_RESOURCES);
    };
    let Some(provider_irp) = work.provider_irp else {
        return Some(INVALID_HANDLE);
    };
    if !work.source_completed {
        if work.source.source_completed(provider_irp).is_err() {
            return Some(DEVICE_BUSY);
        }
        work.source_completed = true;
        trace_scsi_progress(7, &work.source, Some(provider_irp), STATUS_SUCCESS, 0, 0);
    }
    runtime::retire_stopped_acknowledged_retained_service(
        work.route,
        work.dispatch,
        work.reply,
        work.token,
    )
    .expect("SCSI original Reply retirement");
    runtime::park_retained_service(route, token).expect("SCSI ACK admission");
    work.ack = Some(RetainedAck {
        route,
        dispatch,
        reply,
        token,
        reply_entered: false,
    });
    None
}

pub(super) unsafe fn hold_inline(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
    source_token: u64,
) -> i32 {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return INVALID_HANDLE;
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() || source_token == 0 {
        return INVALID_HANDLE;
    }
    let Some(index) = (&*core::ptr::addr_of!(WORK)).iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            !work.source_released
                && same_instance(work.source_instance, source_instance)
                && work.source.source_irp_address() == source_irp
                && work.token == source_token
                && work.provider_irp.is_some_and(|provider_irp|
                    work.source.validate_published_source(provider_irp).is_ok())
        })
    }) else {
        return INVALID_HANDLE;
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _)| *active == index)
    {
        return DEVICE_BUSY;
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return INVALID_HANDLE;
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || !work.reply_entered
        || !work.source_published
        || !work.provider_terminal
        || work.inline_held
        || work.ack.is_some()
    {
        return INVALID_HANDLE;
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
        return DEVICE_BUSY;
    }
    work.inline_held = true;
    STATUS_SUCCESS
}

/// A held completion returned from its later IoCompleteRequest terminal walk. The token is
/// bound to the original physical source, while the source pin prevents address reuse.
pub(super) unsafe fn complete_held(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_irp: u64,
    source_token: u64,
) -> i32 {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        trace_scsi_held_refusal(1, source_irp, source_token, reply_cap);
        return INVALID_HANDLE;
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() || source_token == 0 {
        trace_scsi_held_refusal(2, source_irp, source_token, badge);
        return INVALID_HANDLE;
    }
    let Some(index) = (&*core::ptr::addr_of!(WORK)).iter().position(|slot| {
        slot.as_ref().is_some_and(|work| {
            !work.source_released
                && same_instance(work.source_instance, source_instance)
                && work.source.source_irp_address() == source_irp
                && work.token == source_token
        })
    }) else {
        trace_scsi_held_refusal(3, source_irp, source_token, 0);
        return INVALID_HANDLE;
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _)| *active == index)
    {
        return DEVICE_BUSY;
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        trace_scsi_held_refusal(3, source_irp, source_token, index as u64);
        return INVALID_HANDLE;
    };
    if !work.provider_irp.is_some_and(|provider_irp|
        work.source.validate_published_source(provider_irp).is_ok()) {
        trace_scsi_held_refusal(4, source_irp, source_token,
            work.source.scsi_identity().use_ticket().epoch().get());
        return INVALID_HANDLE;
    }
    if !work.inline_held
        || !work.reply_entered
        || !work.source_published
        || !work.provider_terminal
        || work.source_completed
        || work.ack.is_some()
    {
        let detail = u64::from(work.inline_held)
            | (u64::from(work.reply_entered) << 1)
            | (u64::from(work.source_published) << 2)
            | (u64::from(work.provider_terminal) << 3)
            | (u64::from(work.source_completed) << 4)
            | (u64::from(work.ack.is_some()) << 5);
        trace_scsi_held_refusal(5, source_irp, source_token, detail);
        return INVALID_HANDLE;
    }
    let Some(provider_irp) = work.provider_irp else {
        return INVALID_HANDLE;
    };
    if work.source.source_completed(provider_irp).is_err() {
        return DEVICE_BUSY;
    }
    work.source_completed = true;
    trace_scsi_progress(7, &work.source, Some(provider_irp), STATUS_SUCCESS, 0, 0);
    STATUS_SUCCESS
}
