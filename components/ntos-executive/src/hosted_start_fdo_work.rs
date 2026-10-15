//! Retained upper-FDO to immediate lower-FDO START forwarding.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::{CompletionAcknowledgement, HostedDevicePointerRegistration};
use nt_pnp_manager::{
    DiscardedStartFdoForward, PreparedStartFdoForward, RetainedStartFdoForward,
    StartFdoCompletionReturn, StartFdoDiscardResult, StartFdoForwardResult, StartFdoReturn,
    StartFdoSourceCompletionWitness, StartFdoSourceStopWitness, TerminalStartFdoForward,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const INVALID: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
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
    source: hosted_start_fdo_capture::CapturedStartFdo,
    source_index: usize,
    source_instance: DriverInstance,
    source_irp: IrpId,
    lower: HostedDevicePointerRegistration,
    lower_instance: usize,
    physical: HostedPnpPhysicalProvider,
    devnode: u64,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    prepared: Option<PreparedStartFdoForward>,
    discarded: Option<DiscardedStartFdoForward>,
    returned: Option<StartFdoReturn>,
    retained: Option<RetainedStartFdoForward>,
    ack_return: Option<StartFdoCompletionReturn>,
    terminal: Option<TerminalStartFdoForward>,
    initial_status: Option<i32>,
    reply_entered: bool,
    source_published: bool,
    source_completion_witness: Option<StartFdoSourceCompletionWitness>,
    source_stop_witness: Option<StartFdoSourceStopWitness>,
    source_completion_marked: bool,
    terminal_retired: bool,
    source_released: bool,
    cancel_requested: bool,
    ack: Option<Ack>,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<(usize, DriverInstance, u64)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);
static START_FDO_TRACE_N: AtomicU64 = AtomicU64::new(0);

fn trace_start_fdo(work: &Work, phase: &[u8], provider_irp: IrpId) {
    if START_FDO_TRACE_N.fetch_add(1, Ordering::Relaxed) >= 48 {
        return;
    }
    print_str(b"[start-fdo] phase=");
    print_str(phase);
    print_str(b" source=");
    print_u64(work.source_irp.raw());
    print_str(b" provider=");
    print_u64(provider_irp.raw());
    print_str(b" lower=");
    print_u64(work.lower.device_id().raw());
    print_str(b" devnode=");
    print_u64(work.devnode);
    print_str(b"\n");
}


fn same_instance(left: DriverInstance, right: DriverInstance) -> bool {
    left.pml4 == right.pml4
        && left.exec_pool_va == right.exec_pool_va
        && left.hosted_domain_id == right.hosted_domain_id
        && left.hosted_domain_cookie == right.hosted_domain_cookie
}

unsafe fn work_index(inst: DriverInstance, source_irp: u64) -> Option<usize> {
    (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .find(|(_, source, address)| same_instance(*source, inst) && *address == source_irp)
        .map(|(index, _, _)| *index)
        .or_else(|| {
            (&*core::ptr::addr_of!(WORK)).iter().position(|slot| {
                slot.as_ref().is_some_and(|work| {
                    same_instance(work.source_instance, inst)
                        && work.source.source_irp_address() == source_irp
                })
            })
        })
}

unsafe fn lower_identity(
    source: &hosted_start_fdo_capture::CapturedStartFdo,
) -> Option<(HostedDevicePointerRegistration, usize, u64)> {
    let lower_id = io_manager_mut()
        .hosted_device_by_identity(source.source_domain(), source.target_device_address())?;
    let pdo = io_manager_mut().device(lower_id)?.attached_to?;
    let devnode = hosted_pnp_manager_mut().devnode_for_pdo(pdo.raw())?;
    if hosted_pnp_manager_mut().fdo(devnode) != Some(lower_id.raw()) {
        return None;
    }
    let (instance_index, instance, native_address) =
        hosted_driver_device_route_by_device_id(lower_id.raw())?;
    let provider_domain = instance_domain_identity(instance)?;
    let lower =
        io_manager_mut().hosted_device_pointer_registration(provider_domain, native_address)?;
    (lower.device_id() == lower_id).then_some((lower, instance_index, devnode))
}

pub(super) unsafe fn is_exact_fdo_target(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    target_address: u64,
) -> bool {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return false;
    };
    let Some(domain) = instance_domain_identity(source_instance) else {
        return false;
    };
    let Some(lower) = io_manager_mut().hosted_device_by_identity(domain, target_address) else {
        return false;
    };
    let Some(pdo) = io_manager_mut()
        .device(lower)
        .and_then(|device| device.attached_to)
    else {
        return false;
    };
    let exact = hosted_pnp_manager_mut()
        .devnode_for_pdo(pdo.raw())
        .is_some_and(|node| hosted_pnp_manager_mut().fdo(node) == Some(lower.raw()));
    exact
}

pub(super) unsafe fn submit(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    target_address: u64,
    source_irp_address: u64,
) -> Option<i32> {
    let Some((source_index, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(INVALID);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(INVALID);
    }
    if work_index(source_instance, source_irp_address).is_some() {
        return Some(BUSY);
    }
    let Some(active) = (*core::ptr::addr_of!(ACTIVE_HOSTED_IRP_TRANSFERS))
        .as_ref()
        .and_then(|rows| rows.last())
        .copied()
    else {
        return Some(INVALID);
    };
    let source_irp = IrpId(active.transfer_id);
    let mismatch = u64::from(active.shared_va != ch.shared_va)
        | (u64::from(active.source_instance != source_index) << 1)
        | (u64::from(!hosted_source_irp_ledger::active_caller_projection_matches(
            source_index,
            active.transfer_id,
            source_irp_address,
            nt_pnp_abi::IRP_MN_START_DEVICE,
        )) << 2)
        | (u64::from(io_manager_mut().irp(source_irp).is_none()) << 3);
    if mismatch != 0 {
        return Some(INVALID);
    }
    let mut source = match hosted_start_fdo_capture::capture(
        ch,
        reply_cap,
        source_irp_address,
        target_address,
        source_irp,
    ) {
        Ok(source) => source,
        Err(error) => {
            return Some(status_for_capture(error));
        }
    };
    let Some((lower, lower_instance, devnode)) = lower_identity(&source) else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let Some(driver_id) = io_manager_mut()
        .device(lower.device_id())
        .map(|device| device.driver_id)
    else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let Some(physical) = hosted_pnp_physical_provider(lower_instance, driver_id) else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.release_unentered().expect("unentered START source");
        return Some(INVALID);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source.release_unentered().expect("unentered START source");
            return Some(status as i32);
        }
    };
    let index = (&*core::ptr::addr_of!(WORK))
        .iter()
        .position(Option::is_none);
    if index.is_none()
        && (&mut *core::ptr::addr_of_mut!(WORK))
            .try_reserve(1)
            .is_err()
    {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        source.release_unentered().expect("unentered START source");
        return Some(RESOURCES);
    }
    let Ok(token) = runtime::next_service_wait_token() else {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        source.release_unentered().expect("unentered START source");
        return Some(RESOURCES);
    };
    let work = Work {
        source,
        source_index,
        source_instance,
        source_irp,
        lower,
        lower_instance,
        physical,
        devnode,
        caller,
        actor,
        route,
        dispatch,
        reply,
        token,
        prepared: None,
        discarded: None,
        returned: None,
        retained: None,
        ack_return: None,
        terminal: None,
        initial_status: None,
        reply_entered: false,
        source_published: false,
        source_completion_witness: None,
        source_stop_witness: None,
        source_completion_marked: false,
        terminal_retired: false,
        source_released: false,
        cancel_requested: false,
        ack: None,
    };
    let index = if let Some(index) = index {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().unwrap();
        let _ =
            crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm));
        work.source
            .release_unentered()
            .expect("unparked START source");
        return Some(RESOURCES);
    }
    None
}

fn status_for_capture(error: hosted_start_fdo_capture::CaptureError) -> i32 {
    match error {
        hosted_start_fdo_capture::CaptureError::InsufficientResources => RESOURCES,
        _ => INVALID,
    }
}

fn status_for_forward(error: nt_pnp_manager::StartFdoForwardError) -> i32 {
    match error {
        nt_pnp_manager::StartFdoForwardError::Upper(status)
        | nt_pnp_manager::StartFdoForwardError::Lower(status)
        | nt_pnp_manager::StartFdoForwardError::Prepare(status)
        | nt_pnp_manager::StartFdoForwardError::Dispatch(status) => status.raw(),
        _ => INVALID,
    }
}

impl Work {
    unsafe fn provider_dispatch_ready(&self) -> bool {
        let Some(route) = hosted_ingress_sources::primary_route(self.lower_instance) else {
            return true;
        };
        !matches!(runtime::ready_for_admission(route), Ok(false))
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        if let Some(ack) = &self.ack {
            return !ack.reply_entered;
        }
        if self.reply_entered || self.prepared.is_some() || self.ack_return.is_some() {
            return false;
        }
        if self.initial_status.is_none() {
            return self.provider_dispatch_ready();
        }
        if self.retained.is_some() {
            pump_io_manager();
        }
        self.terminal.is_some()
            || self.retained.as_ref().is_some_and(|retained| {
                io_manager_mut()
                    .completed_irp(retained.provider_irp())
                    .is_some()
            })
    }

    unsafe fn prepare_and_dispatch(&mut self) {
        if let Err(status) = crate::service_sec_image::with_provider_process_manager(|pm| self.actor.validate(pm)) {
            self.initial_status = Some(status as i32);
            return;
        }
        let (raw, translated) = match self.source.take_lists() {
            Ok(lists) => lists,
            Err(error) => {
                self.initial_status = Some(status_for_capture(error));
                return;
            }
        };
        let Some(source_irp) = io_manager_mut().irp_mut(self.source_irp) else {
            self.initial_status = Some(INVALID);
            return;
        };
        let requestor_tid = source_irp.requestor_tid;
        let Some(upper_device) = source_irp.current_stack().map(|stack| stack.device_id) else {
            self.initial_status = Some(INVALID);
            return;
        };
        let Some(next) = source_irp
            .stack
            .get_mut(usize::from(source_irp.current_location) + 1)
        else {
            self.initial_status = Some(INVALID);
            return;
        };
        if (next.minor != 0 && next.minor != nt_pnp_abi::IRP_MN_START_DEVICE)
            || (next.device_id != upper_device && next.device_id != self.lower.device_id())
        {
            self.initial_status = Some(INVALID);
            return;
        }
        next.minor = nt_pnp_abi::IRP_MN_START_DEVICE;
        next.device_id = self.lower.device_id();
        let mut prepared = match PreparedStartFdoForward::prepare(
            hosted_pnp_manager_mut(),
            io_manager_mut(),
            self.source.source_ticket(),
            self.source_irp,
            self.source.upper_device_address(),
            self.lower,
            self.devnode,
            ClientId(IO_MANAGER_COMPONENT_ID),
            requestor_tid,
            raw,
            translated,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.initial_status = Some(status_for_forward(error));
                return;
            }
        };
        if let Err(error) = prepared.bind_native_source_allocation(self.source.source_allocation()) {
            self.initial_status = Some(status_for_forward(error));
            self.prepared = Some(prepared);
            return;
        }
        self.dispatch_prepared(prepared);
    }

    unsafe fn dispatch_prepared(&mut self, prepared: PreparedStartFdoForward) {
        let identity = prepared.identity();
        if !hosted_pnp_physical_provider_current(self.physical) {
            self.initial_status = Some(INVALID);
            self.prepared = Some(prepared);
            return;
        }
        let invocation = match prepared.begin(hosted_pnp_manager_mut(), io_manager_mut(), identity)
        {
            Ok(invocation) => invocation,
            Err((error, prepared)) => {
                self.initial_status = Some(status_for_forward(error));
                self.prepared = Some(prepared);
                return;
            }
        };
        let lower_instance = self.lower_instance;
        let lower = self.lower;
        let physical = self.physical;
        let returned = invocation.invoke(|context, projection| {
            let valid = instance(lower_instance).is_some_and(|inst| {
                inst.ready
                    && instance_domain_identity(inst) == Some(lower.domain())
                    && inst.driver_id == projection.driver_id.raw()
            }) && projection.device_id == lower.device_id();
            if !valid {
                return PnpBackendDispatch::NotDispatched {
                    status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
                };
            }
            let outcome = HostedDriverBackend {
                instance: lower_instance,
            }
            .dispatch_pnp_irp(context, projection);
            if !hosted_pnp_physical_provider_current(physical) {
                return PnpBackendDispatch::Indeterminate {
                    transport_status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
                };
            }
            outcome
        });
        match returned.finish(io_manager_mut()) {
            Ok(StartFdoForwardResult::Terminal(terminal)) => {
                trace_start_fdo(self, b"dispatch-terminal", terminal.provider_irp());
                self.initial_status = Some(terminal.status().raw());
                self.terminal = Some(terminal);
            }
            Ok(StartFdoForwardResult::Retained(retained)) => {
                trace_start_fdo(self, b"dispatch-retained", retained.provider_irp());
                self.initial_status = Some(STATUS_PENDING as i32);
                self.retained = Some(retained);
            }
            Ok(StartFdoForwardResult::Rejected { retained, .. }) => {
                trace_start_fdo(self, b"dispatch-rejected", retained.provider_irp());
                self.initial_status = Some(INVALID);
                self.retained = Some(retained);
            }
            Err(rejection) => {
                trace_start_fdo(self, b"dispatch-error", self.source_irp);
                self.initial_status = Some(status_for_forward(rejection.error()));
                self.returned = Some(rejection.into_return());
            }
        }
    }

    unsafe fn poll_provider(&mut self) {
        let Some(retained) = self.retained.take() else {
            return;
        };
        if retained.is_indeterminate() || retained.has_rejected_terminal() {
            self.retained = Some(retained);
            return;
        }
        pump_io_manager();
        if io_manager_mut()
            .completed_irp(retained.provider_irp())
            .is_none()
        {
            self.retained = Some(retained);
            return;
        }
        trace_start_fdo(self, b"provider-completed", retained.provider_irp());
        let identity = retained.identity();
        let invocation =
            match retained.prepare_completion(hosted_pnp_manager_mut(), io_manager_mut(), identity)
            {
                Ok(invocation) => invocation,
                Err((_, retained)) => {
                    self.retained = Some(retained);
                    return;
                }
            };
        let provider_irp = invocation.completion().id;
        let storage_instance = self.physical.storage_instance;
        let provider_domain = self.physical.storage_domain;
        let returned = invocation.invoke(|_| {
            hosted_file_dispatch::acknowledgement_result(
                hosted_file_dispatch::control_exact_storage(
                    storage_instance,
                    provider_domain,
                    provider_irp,
                    FSD_DISPATCH_ACK_COMPLETION,
                    0,
                    &mut [],
                ),
            )
        });
        match returned.finish(io_manager_mut()) {
            Ok(StartFdoForwardResult::Terminal(terminal)) => {
                trace_start_fdo(self, b"ack-terminal", terminal.provider_irp());
                self.terminal = Some(terminal)
            }
            Ok(StartFdoForwardResult::Retained(retained))
            | Ok(StartFdoForwardResult::Rejected { retained, .. }) => {
                trace_start_fdo(self, b"ack-retained", retained.provider_irp());
                self.retained = Some(retained)
            }
            Err((_, returned)) => {
                trace_start_fdo(self, b"ack-error", provider_irp);
                self.ack_return = Some(returned)
            }
        }
    }

    unsafe fn publish_source(&mut self) -> bool {
        if self.source_published {
            return true;
        }
        let Some(terminal) = self.terminal.as_ref() else {
            return false;
        };
        if self
            .source
            .publish_terminal(terminal.status(), terminal.information())
            .is_err()
        {
            return false;
        }
        let provider_irp = terminal.provider_irp();
        self.source_published = true;
        trace_start_fdo(self, b"source-published", provider_irp);
        true
    }

    unsafe fn retire_after_source_completion(&mut self) -> bool {
        if !self.terminal_retired {
            let Some(mut terminal) = self.terminal.take() else {
                return false;
            };
            if !self.source_completion_marked {
                let Some(witness) = self.source_completion_witness.take() else {
                    self.terminal = Some(terminal);
                    return false;
                };
                if let Err((_, witness)) = terminal.mark_source_completed_from_native_witness(witness) {
                    self.source_completion_witness = Some(witness);
                    trace_start_fdo(self, b"mark-source-refused", terminal.provider_irp());
                    self.terminal = Some(terminal);
                    return false;
                }
                self.source_completion_marked = true;
            }
            if let Err((_, retained)) = terminal.retire(io_manager_mut()) {
                trace_start_fdo(self, b"terminal-retire-refused", retained.provider_irp());
                self.terminal = Some(retained);
                return false;
            }
            self.terminal_retired = true;
            trace_start_fdo(self, b"terminal-retired", self.source_irp);
        }
        if !self.source_released {
            if self.source.release_terminal().is_err() {
                trace_start_fdo(self, b"source-release-refused", self.source_irp);
                return false;
            }
            self.source_released = true;
            trace_start_fdo(self, b"source-released", self.source_irp);
        }
        !self.actor.is_held()
            || crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
                .is_ok()
    }

    unsafe fn advance_cancelled(&mut self) -> bool {
        if let Some(prepared) = self.prepared.take() {
            match prepared.discard(io_manager_mut()) {
                StartFdoDiscardResult::Retired => {}
                StartFdoDiscardResult::NotDiscarded { prepared, .. } => {
                    self.prepared = Some(prepared);
                    return false;
                }
                StartFdoDiscardResult::Retained { discarded, .. } => {
                    self.discarded = Some(discarded)
                }
            }
        }
        if let Some(discarded) = self.discarded.take() {
            if let Err((_, discarded)) = discarded.retire(io_manager_mut()) {
                self.discarded = Some(discarded);
                return false;
            }
        }
        if self.returned.is_some() || self.ack_return.is_some() {
            return false;
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
        if self.retained.is_some() || self.prepared.is_some() || self.discarded.is_some() {
            return false;
        }
        if !self.source_released {
            // The cancelled route is stopped; keep the terminal owner while either exact
            // source-pin release refuses. A failed release never creates stop authority.
            let released = if self.source_published && self.source.caller_terminal_ready() {
                self.source.release_terminal()
            } else {
                self.source.release_unentered()
            };
            if released.is_err() {
                return false;
            }
            self.source_released = true;
        }
        if self.terminal.is_some() && self.source_stop_witness.is_none() {
            self.source_stop_witness = unsafe { StartFdoSourceStopWitness::after_native_source_stop(
                self.source.source_ticket(), self.source_irp, self.source.source_allocation(),
            ) };
            if self.source_stop_witness.is_none() {
                return false;
            }
        }
        if let Some(terminal) = self.terminal.take() {
            let witness = self.source_stop_witness.take()
                .expect("released START terminal retains its source stop witness");
            if let Err((_, retained, witness)) = terminal.retire_after_source_stop(io_manager_mut(), witness) {
                self.terminal = Some(retained);
                self.source_stop_witness = Some(witness);
                return false;
            }
        }
        if self.actor.is_held()
            && crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
                .is_err()
        {
            return false;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .is_ok()
    }

    unsafe fn advance_ack(&mut self) -> bool {
        let ack = self.ack.as_ref().unwrap();
        if ack.reply_entered {
            if !matches!(
                runtime::reconcile_retained_service_reply(
                    ack.route,
                    ack.dispatch,
                    ack.reply,
                    ack.token,
                ),
                Ok(true)
            ) {
                trace_start_fdo(self, b"ack-reconcile-wait", self.source_irp);
                return false;
            }
            trace_start_fdo(self, b"ack-reconciled", self.source_irp);
            runtime::retire_stopped_acknowledged_retained_service(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("START ACK Reply retirement");
            return true;
        }
        if !self.retire_after_source_completion() {
            return false;
        }
        trace_start_fdo(self, b"ack-source-retired", self.source_irp);
        let ack = self.ack.as_mut().unwrap();
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance(&mut self) -> bool {
        if self.ack.is_some() {
            return self.advance_ack();
        }
        if let Some(returned) = self.returned.take() {
            match returned.finish(io_manager_mut()) {
                Ok(StartFdoForwardResult::Terminal(terminal)) => self.terminal = Some(terminal),
                Ok(StartFdoForwardResult::Retained(retained))
                | Ok(StartFdoForwardResult::Rejected { retained, .. }) => {
                    self.retained = Some(retained)
                }
                Err(rejection) => self.returned = Some(rejection.into_return()),
            }
        }
        if let Some(returned) = self.ack_return.take() {
            match returned.finish(io_manager_mut()) {
                Ok(StartFdoForwardResult::Terminal(terminal)) => self.terminal = Some(terminal),
                Ok(StartFdoForwardResult::Retained(retained))
                | Ok(StartFdoForwardResult::Rejected { retained, .. }) => {
                    self.retained = Some(retained)
                }
                Err((_, returned)) => self.ack_return = Some(returned),
            }
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            return self.advance_cancelled();
        }
        if self.returned.is_some() || self.ack_return.is_some() {
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
            ) || self.terminal.is_some()
            {
                return false;
            }
            self.source
                .release_unentered()
                .expect("rejected START source release");
            let _ = crate::service_sec_image::with_provider_process_manager(|pm| {
                self.actor.release(pm)
            });
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("rejected START Reply retirement");
            return true;
        }
        if self.initial_status.is_none() {
            if !self.provider_dispatch_ready() {
                return false;
            }
            self.prepare_and_dispatch();
        }
        if let Some(prepared) = self.prepared.take() {
            match prepared.discard(io_manager_mut()) {
                StartFdoDiscardResult::Retired => {}
                StartFdoDiscardResult::NotDiscarded { prepared, .. } => {
                    self.prepared = Some(prepared);
                    return false;
                }
                StartFdoDiscardResult::Retained { discarded, .. } => {
                    self.discarded = Some(discarded);
                    return false;
                }
            }
        }
        if let Some(discarded) = self.discarded.take() {
            if let Err((_, discarded)) = discarded.retire(io_manager_mut()) {
                self.discarded = Some(discarded);
                return false;
            }
        }
        if self.retained.is_some() {
            self.poll_provider();
        }
        if self.terminal.is_some() {
            if !self.publish_source() {
                return false;
            }
            self.reply_entered = true;
            let _ = runtime::wake_hosted_forward_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
                nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply::InlineTerminal(
                    self.terminal.as_ref().unwrap().status().raw(),
                ),
            );
            return false;
        }
        if self.initial_status.is_some() && self.prepared.is_none() && self.retained.is_none() {
            self.reply_entered = true;
            let _ = runtime::wake_query_path_rejected_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
                self.initial_status.unwrap(),
            );
        }
        false
    }
}

unsafe fn redrive_one(nested_only: bool) -> bool {
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
            || nested_only
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
    let done = work.advance();
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

pub(super) unsafe fn redrive() {
    let _ = redrive_one(false);
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

pub(super) unsafe fn redrive_nested_ready() -> bool {
    redrive_one(true)
}

pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    token: u64,
    held_completion: bool,
) -> Option<i32> {
    let Some((source_index, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(INVALID);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(INVALID);
    }
    let Some(index) = work_index(source_instance, source_irp_address) else {
        return Some(INVALID);
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _)| *active == index)
    {
        return Some(BUSY);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(INVALID);
    };
    if (!held_completion && crate::provider_registry_caller::resolve(ch) != Ok(work.caller))
        || work.source_index != source_index
        || work.ack.is_some()
        || work.token != token
        || !work.reply_entered
        || !work.source_published
        || work.terminal.is_none()
        || work.source.validate_pin().is_err()
        || !work.source.caller_terminal_ready()
        || !start_fdo_terminal_evidence(source_index, source_irp_address, token,
            if held_completion { 8 } else { 7 })
    {
        return Some(INVALID);
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
        return Some(BUSY);
    }
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if held_completion || route == work.route => route,
        _ => return Some(INVALID),
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        return Some(INVALID);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        return Some(INVALID);
    };
    let Ok(token) = runtime::next_service_wait_token() else {
        return Some(RESOURCES);
    };
    // The trusted native completion path has now proved the exact direct or held terminal.
    // The pending-node READY payload alone cannot mint this one-use owner witness.
    let Some(witness) = (unsafe { StartFdoSourceCompletionWitness::after_native_terminal(
        work.source.source_ticket(), work.source_irp, work.source.source_allocation(),
    ) }) else {
        return Some(INVALID);
    };
    runtime::retire_stopped_acknowledged_retained_service(
        work.route,
        work.dispatch,
        work.reply,
        work.token,
    )
    .expect("START original Reply retirement");
    runtime::park_retained_service(route, token).expect("START ACK Reply admission");
    work.ack = Some(Ack {
        route,
        dispatch,
        reply,
        token,
        reply_entered: false,
    });
    work.source_completion_witness = Some(witness);
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
        6 => submit(ch, reply_cap, caller_badge, address, source_irp).map(|status| (status, false)),
        7 => acknowledge(ch, reply_cap, caller_badge, address, source_irp, false)
            .map(|status| (status, false)),
        8 => acknowledge(ch, reply_cap, caller_badge, address, source_irp, true)
            .map(|status| (status, false)),
        _ => Some((INVALID, false)),
    }
}
