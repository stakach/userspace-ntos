//! Retained class FDO to function FDO FILTER forwarding.
//!
//! This module is deliberately independent of the accepted lower PDO proof. A class
//! driver's source IRP and its Reply remain owned here until the immediate lower FDO's
//! exact provider terminal and the class driver's local completion are both observed.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::{
    CompletionAcknowledgement, ExternalPnpFilterOutput, HostedDevicePointerRegistration,
};
use nt_pnp_manager::{
    DiscardedFilterFdoForward, FilterFdoCompletionReturn, FilterFdoDiscardResult,
    FilterFdoForwardResult, FilterFdoReturn, PreparedFilterFdoForward, RetainedFilterFdoForward,
    TerminalFilterFdoForward,
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
    source: hosted_filter_fdo_capture::CapturedFilterFdo,
    source_instance: DriverInstance,
    source_irp: IrpId,
    lower: HostedDevicePointerRegistration,
    lower_instance: usize,
    physical: HostedPnpPhysicalProvider,
    input_receipt: Option<SourcePoolAllocationIdentity>,
    devnode: u64,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    prepared: Option<PreparedFilterFdoForward>,
    discarded: Option<DiscardedFilterFdoForward>,
    returned: Option<FilterFdoReturn>,
    retry_output: Option<(nt_status::NtStatus, u64)>,
    retained: Option<RetainedFilterFdoForward>,
    ack_return: Option<FilterFdoCompletionReturn>,
    terminal: Option<TerminalFilterFdoForward>,
    initial_status: Option<i32>,
    reply_entered: bool,
    source_published: bool,
    published_output: Option<SourcePoolAllocationIdentity>,
    terminal_retired: bool,
    source_released: bool,
    cancel_requested: bool,
    ack: Option<Ack>,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<(usize, DriverInstance, u64)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);


struct ProviderInputRow {
    irp: IrpId,
    instance: usize,
    minimum_capacity: u64,
    allocation: Option<SourcePoolAllocationIdentity>,
}

static mut PROVIDER_INPUTS: Vec<ProviderInputRow> = Vec::new();

unsafe fn reserve_provider_input(irp: IrpId, instance: usize, bytes: usize) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(PROVIDER_INPUTS);
    if rows.iter().any(|row| row.irp == irp) || rows.try_reserve(1).is_err() {
        return false;
    }
    let Ok(minimum_capacity) = u64::try_from(bytes) else {
        return false;
    };
    rows.push(ProviderInputRow {
        irp,
        instance,
        minimum_capacity,
        allocation: None,
    });
    true
}

unsafe fn take_provider_input(irp: IrpId) -> Option<SourcePoolAllocationIdentity> {
    let rows = &mut *core::ptr::addr_of_mut!(PROVIDER_INPUTS);
    let index = rows.iter().position(|row| row.irp == irp)?;
    rows.swap_remove(index).allocation
}

/// Called only after the provider's op 6 source registration succeeded, before its
/// `MajorFunction` can run. The provider's `SH_ACTIVE_DATA` allocation is still live.
pub(super) unsafe fn observe_provider_input(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    canonical_irp_id: u64,
    native_irp: u64,
) {
    let Some((instance_index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return;
    };
    let Some(row) = (&mut *core::ptr::addr_of_mut!(PROVIDER_INPUTS))
        .iter_mut()
        .find(|row| row.irp.raw() == canonical_irp_id && row.instance == instance_index)
    else {
        return;
    };
    let sh = inst.exec_shared_va;
    if read_volatile((sh + SH_ACTIVE_IRP) as *const u64) != native_irp {
        return;
    }
    let pointer = read_volatile((sh + SH_ACTIVE_DATA) as *const u64);
    let capacity = read_volatile((sh + SH_ACTIVE_DATA_CAP) as *const u64);
    if pointer == 0 || capacity < row.minimum_capacity {
        return;
    }
    if let Ok(allocation) = hosted_device_allocations::capture_allocation(inst, pointer) {
        if allocation.capacity >= row.minimum_capacity {
            row.allocation = Some(allocation);
        }
    }
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

/// Resolve the immediate FDO from the exact source projection and the devnode's
/// recorded function device. A projected pointer alone is never authority.
unsafe fn lower_identity(
    source: &hosted_filter_fdo_capture::CapturedFilterFdo,
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

/// `None` parks the exact source Call. Only a checked pre-entry refusal returns inline.
pub(super) unsafe fn submit(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    target_address: u64,
    source_irp_address: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
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
    if active.shared_va != ch.shared_va
        || active.source_instance
            != instance_for_pump_channel(ch, reply_cap)
                .map(|(index, _)| index)
                .unwrap_or(usize::MAX)
        || !hosted_source_irp_ledger::active_caller_projection_matches(
            active.source_instance,
            active.transfer_id,
            source_irp_address,
            nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
        )
        || io_manager_mut().irp(source_irp).is_none()
    {
        return Some(INVALID);
    }
    let mut source = match hosted_filter_fdo_capture::capture(
        ch,
        reply_cap,
        source_irp_address,
        target_address,
        source_irp,
    ) {
        Ok(source) => source,
        Err(error) => {
            return Some(INVALID);
        }
    };
    let Some((lower, lower_instance, devnode)) = lower_identity(&source) else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let Some(driver_id) = io_manager_mut()
        .device(lower.device_id())
        .map(|device| device.driver_id)
    else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let Some(physical) = hosted_pnp_physical_provider(lower_instance, driver_id) else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source.release_unentered().expect("unentered FILTER source");
        return Some(INVALID);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source.release_unentered().expect("unentered FILTER source");
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
        source.release_unentered().expect("unentered FILTER source");
        return Some(RESOURCES);
    }
    let Ok(token) = runtime::next_service_wait_token() else {
        let mut actor = actor;
        let _ = crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm));
        source.release_unentered().expect("unentered FILTER source");
        return Some(RESOURCES);
    };
    let work = Work {
        source,
        source_instance,
        source_irp,
        lower,
        lower_instance,
        physical,
        input_receipt: None,
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
        retry_output: None,
        retained: None,
        ack_return: None,
        terminal: None,
        initial_status: None,
        reply_entered: false,
        source_published: false,
        published_output: None,
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
            .expect("unparked FILTER source");
        return Some(RESOURCES);
    }
    None
}

fn status_for_capture(error: hosted_filter_fdo_capture::CaptureError) -> i32 {
    match error {
        hosted_filter_fdo_capture::CaptureError::InsufficientResources => RESOURCES,
        _ => INVALID,
    }
}

fn status_for_forward(error: nt_pnp_manager::FilterFdoForwardError) -> i32 {
    match error {
        nt_pnp_manager::FilterFdoForwardError::Upper(status)
        | nt_pnp_manager::FilterFdoForwardError::Lower(status)
        | nt_pnp_manager::FilterFdoForwardError::Prepare(status)
        | nt_pnp_manager::FilterFdoForwardError::Dispatch(status) => status.raw(),
        _ => INVALID,
    }
}

/// A changed provider list must be copied while its exact physical allocation is live.
/// A borrowed successful input pointer requires separate native allocation proof; an
/// unproved pointer is left `Original` and the pure contract quarantines the terminal.
unsafe fn capture_output(
    provider_instance: usize,
    status: nt_status::NtStatus,
    information: u64,
    pending: bool,
    input_receipt: Option<SourcePoolAllocationIdentity>,
) -> ExternalPnpFilterOutput {
    if !status.is_success() || information == 0 {
        return ExternalPnpFilterOutput::Original;
    }
    if pending {
        let Some(input) = input_receipt else {
            return ExternalPnpFilterOutput::Original;
        };
        if information == input.component_address {
            let exact = instance(provider_instance).and_then(|inst| {
                hosted_device_allocations::capture_allocation(inst, information).ok()
            });
            return if exact == Some(input) {
                ExternalPnpFilterOutput::BorrowedInput {
                    provider_pointer: information,
                    input_allocation: input,
                }
            } else {
                ExternalPnpFilterOutput::Original
            };
        }
    }
    match copy_hosted_bus_property_result(
        provider_instance,
        information,
        nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
    ) {
        Ok(HostedBusPropertyValue::Blob(bytes)) => ExternalPnpFilterOutput::Copied {
            provider_pointer: information,
            bytes,
        },
        _ => ExternalPnpFilterOutput::Original,
    }
}

impl Work {
    fn bind_retained_input(
        &mut self,
        mut retained: RetainedFilterFdoForward,
    ) -> RetainedFilterFdoForward {
        if let Some(input) = self.input_receipt {
            let _ = retained.bind_provider_filter_input_allocation(input);
        }
        retained
    }

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
            // Completion records arrive through the I/O Manager's completion pump.
            // No I/O Manager reference is held across this call.
            pump_io_manager();
        }
        self.terminal.is_some()
            || self.retained.as_ref().is_some_and(|retained| {
                io_manager_mut()
                    .completed_irp(retained.provider_irp())
                    .is_some()
            })
    }

    unsafe fn prepare_and_dispatch(&mut self, handler: *mut ExecNtHandler) {
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.initial_status = Some(status as i32);
            return;
        }
        let requirements = match self.source.input_copy() {
            Ok(bytes) => bytes,
            Err(error) => {
                self.initial_status = Some(status_for_capture(error));
                return;
            }
        };
        // The native source just proved that the upper driver copied FILTER into its
        // next stack frame. Mirror that observed frame in the canonical source record.
        let Some(source_irp) = io_manager_mut().irp_mut(self.source_irp) else {
            self.initial_status = Some(INVALID);
            return;
        };
        // The canonical source IRP retains the original requestor identity. The
        // pump caller is separately authenticated above and can be a driver worker.
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
        if (next.minor != 0 && next.minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS)
            || (next.device_id != upper_device && next.device_id != self.lower.device_id())
        {
            self.initial_status = Some(INVALID);
            return;
        }
        next.minor = nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS;
        next.device_id = self.lower.device_id();
        let prepared = match PreparedFilterFdoForward::prepare(
            hosted_pnp_manager_mut(),
            io_manager_mut(),
            self.source.source_ticket(),
            self.source_irp,
            self.source.upper_device_address(),
            self.lower,
            self.devnode,
            ClientId(IO_MANAGER_COMPONENT_ID),
            requestor_tid,
            requirements,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.initial_status = Some(status_for_forward(error));
                return;
            }
        };
        self.dispatch_prepared(prepared);
    }

    unsafe fn dispatch_prepared(&mut self, prepared: PreparedFilterFdoForward) {
        let identity = prepared.identity();
        let provider_irp = prepared.provider_irp();
        if !hosted_pnp_physical_provider_current(self.physical)
            || !reserve_provider_input(
                provider_irp,
                self.physical.storage_instance,
                self.source.input_len(),
            )
        {
            self.initial_status = Some(RESOURCES);
            self.prepared = Some(prepared);
            return;
        }
        let accepted_pdo_edge = io_manager_mut()
            .device(self.lower.device_id())
            .and_then(|device| device.attached_to)
            .is_some_and(|pdo| hosted_root_bus_mut().pdo(pdo).is_none());
        if accepted_pdo_edge {
            let Some(requestor_tid) = io_manager_mut()
                .irp(provider_irp)
                .map(|irp| irp.requestor_tid)
            else {
                let _ = take_provider_input(provider_irp);
                self.initial_status = Some(INVALID);
                self.prepared = Some(prepared);
                return;
            };
            if !hosted_accepted_pdo_filter_edge::publish(
                self.source_irp,
                provider_irp,
                self.lower,
                self.source.source_ticket(),
                ClientId(IO_MANAGER_COMPONENT_ID),
                requestor_tid,
            ) {
                let _ = take_provider_input(provider_irp);
                self.initial_status = Some(INVALID);
                self.prepared = Some(prepared);
                return;
            }
        }
        let invocation = match prepared.begin(hosted_pnp_manager_mut(), io_manager_mut(), identity)
        {
            Ok(invocation) => invocation,
            Err((error, prepared)) => {
                hosted_accepted_pdo_filter_edge::retire_unentered(provider_irp);
                let _ = take_provider_input(provider_irp);
                self.initial_status = Some(status_for_forward(error));
                self.prepared = Some(prepared);
                return;
            }
        };
        let lower_instance = self.lower_instance;
        let storage_instance = self.physical.storage_instance;
        let physical = self.physical;
        let lower = self.lower;
        let mut output_retry = None;
        let returned = invocation.invoke_with_output(|context, projection| {
            let valid = instance(lower_instance).is_some_and(|inst| {
                inst.ready
                    && instance_domain_identity(inst) == Some(lower.domain())
                    && inst.driver_id == projection.driver_id.raw()
            }) && projection.device_id == lower.device_id();
            if !valid {
                return (
                    PnpBackendDispatch::NotDispatched {
                        status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
                    },
                    ExternalPnpFilterOutput::Original,
                );
            }
            let outcome = HostedDriverBackend {
                instance: lower_instance,
            }
            .dispatch_pnp_irp(context, projection);
            if !hosted_pnp_physical_provider_current(physical) {
                return (
                    PnpBackendDispatch::Indeterminate {
                        transport_status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
                    },
                    ExternalPnpFilterOutput::Original,
                );
            }
            let output = match outcome {
                PnpBackendDispatch::Returned {
                    status,
                    information,
                } => {
                    let output = capture_output(storage_instance, status, information, false, None);
                    if status.is_success()
                        && information != 0
                        && matches!(output, ExternalPnpFilterOutput::Original)
                    {
                        output_retry = Some((status, information));
                    }
                    output
                }
                _ => ExternalPnpFilterOutput::Original,
            };
            (outcome, output)
        });
        self.retry_output = output_retry;
        self.input_receipt = take_provider_input(provider_irp);
        match returned.finish(io_manager_mut()) {
            Ok(FilterFdoForwardResult::Terminal(terminal)) => {
                self.initial_status = Some(terminal.status().raw());
                self.terminal = Some(terminal);
            }
            Ok(FilterFdoForwardResult::Retained(retained)) => {
                self.initial_status = Some(STATUS_PENDING as i32);
                let retained = self.bind_retained_input(retained);
                self.retained = Some(retained);
            }
            Ok(FilterFdoForwardResult::Rejected { retained, .. }) => {
                self.initial_status = Some(INVALID);
                let retained = self.bind_retained_input(retained);
                self.retained = Some(retained);
            }
            Err(rejection) => {
                // A returned provider effect cannot be invoked again. Retain its exact
                // canonical return and source pin until native output authority is known.
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
        let Some((status, information)) = io_manager_mut()
            .completed_irp(retained.provider_irp())
            .map(|completion| (completion.status, completion.information))
        else {
            self.retained = Some(retained);
            return;
        };
        let output = capture_output(
            self.physical.storage_instance,
            status,
            information,
            true,
            self.input_receipt,
        );
        let identity = retained.identity();
        let invocation = match retained.prepare_completion(
            hosted_pnp_manager_mut(),
            io_manager_mut(),
            identity,
            output,
        ) {
            Ok(invocation) => invocation,
            Err((_, retained, _)) => {
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
            Ok(FilterFdoForwardResult::Terminal(terminal)) => self.terminal = Some(terminal),
            Ok(FilterFdoForwardResult::Retained(retained))
            | Ok(FilterFdoForwardResult::Rejected { retained, .. }) => {
                self.retained = Some(retained)
            }
            Err((_, returned)) => self.ack_return = Some(returned),
        }
    }

    unsafe fn publish_source(&mut self) -> bool {
        if self.source_published {
            return true;
        }
        let Some(terminal) = self.terminal.as_ref() else {
            return false;
        };
        let mut allocated_output = None;
        let information = match terminal.return_action() {
            nt_pnp_manager::FilterRequirementsReturnAction::UseOriginal => {
                self.source.original_information()
            }
            nt_pnp_manager::FilterRequirementsReturnAction::Barrier(_) => 0,
            nt_pnp_manager::FilterRequirementsReturnAction::CopyProviderOutput { .. } => {
                let ExternalPnpFilterOutput::Copied { bytes, .. } = terminal.captured_output()
                else {
                    return false;
                };
                let Some(address) =
                    hosted_instance_pool_alloc(self.source_instance, bytes.len() as u64)
                else {
                    return false;
                };
                let Some(memory) =
                    hosted_source_pool_memory::SourcePoolMemory::new(self.source_instance)
                else {
                    let _ = hosted_instance_pool_free(self.source_instance, address);
                    return false;
                };
                let copied = memory.write(address, bytes);
                drop(memory);
                if !copied {
                    let _ = hosted_instance_pool_free(self.source_instance, address);
                    return false;
                }
                let Ok(allocation) =
                    hosted_device_allocations::capture_allocation(self.source_instance, address)
                else {
                    let _ = hosted_instance_pool_free(self.source_instance, address);
                    return false;
                };
                allocated_output = Some(allocation);
                address
            }
        };
        if self
            .source
            .publish_terminal(terminal.status(), information)
            .is_err()
        {
            if let Some(allocation) = allocated_output {
                let _ =
                    hosted_instance_pool_free(self.source_instance, allocation.component_address);
            }
            // Source identity loss is a barrier; the foreign terminal remains owned.
            return false;
        }
        self.source_published = true;
        self.published_output = allocated_output;
        true
    }

    unsafe fn retire_after_source_completion(&mut self) -> bool {
        if !self.terminal_retired {
            let Some(mut terminal) = self.terminal.take() else {
                return false;
            };
            if terminal.mark_source_completed(terminal.identity()).is_err() {
                self.terminal = Some(terminal);
                return false;
            }
            if let Err((_, retained)) = terminal.retire(io_manager_mut()) {
                self.terminal = Some(retained);
                return false;
            }
            self.terminal_retired = true;
        }
        if !self.source_released {
            if self.source.release_terminal().is_err() {
                return false;
            }
            self.source_released = true;
        }
        !self.actor.is_held()
            || crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
                .is_ok()
    }

    unsafe fn advance_cancelled(&mut self) -> bool {
        let source_completed = self.source.caller_terminal_ready();
        if let Some(prepared) = self.prepared.take() {
            match prepared.discard(io_manager_mut()) {
                FilterFdoDiscardResult::Retired => {}
                FilterFdoDiscardResult::NotDiscarded { prepared, .. } => {
                    self.prepared = Some(prepared);
                    return false;
                }
                FilterFdoDiscardResult::Retained { discarded, .. } => {
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
        if self.returned.is_some() || self.ack_return.is_some() {
            // A provider or ACK effect with an unknown outcome is a replay barrier.
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
            if self.source.release_unentered().is_err() {
                return false;
            }
            self.source_released = true;
        }
        if let Some(mut terminal) = self.terminal.take() {
            if let Err((_, retained)) = terminal.retire_after_source_stop(io_manager_mut()) {
                self.terminal = Some(retained);
                return false;
            }
        }
        if let Some(allocation) = self.published_output.take() {
            if !source_completed
                && hosted_device_allocations::capture_allocation(
                    self.source_instance,
                    allocation.component_address,
                ) == Ok(allocation)
                && !hosted_instance_pool_free(self.source_instance, allocation.component_address)
            {
                self.published_output = Some(allocation);
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
                    ack.token
                ),
                Ok(true)
            ) {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("FILTER ACK Reply retirement");
            return true;
        }
        if !self.retire_after_source_completion() {
            return false;
        }
        let ack = self.ack.as_mut().unwrap();
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.ack.is_some() {
            return self.advance_ack();
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            return self.advance_cancelled();
        }
        if let Some(returned) = self.returned.take() {
            let returned = if let Some((status, information)) = self.retry_output {
                let output = capture_output(
                    self.physical.storage_instance,
                    status,
                    information,
                    false,
                    self.input_receipt,
                );
                if matches!(output, ExternalPnpFilterOutput::Original) {
                    self.returned = Some(returned);
                    return false;
                }
                self.retry_output = None;
                returned.with_output(output)
            } else {
                returned
            };
            match returned.finish(io_manager_mut()) {
                Ok(FilterFdoForwardResult::Terminal(terminal)) => self.terminal = Some(terminal),
                Ok(FilterFdoForwardResult::Retained(retained))
                | Ok(FilterFdoForwardResult::Rejected { retained, .. }) => {
                    let retained = self.bind_retained_input(retained);
                    self.retained = Some(retained);
                }
                Err(rejection) => self.returned = Some(rejection.into_return()),
            }
        }
        if let Some(returned) = self.ack_return.take() {
            match returned.finish(io_manager_mut()) {
                Ok(FilterFdoForwardResult::Terminal(terminal)) => self.terminal = Some(terminal),
                Ok(FilterFdoForwardResult::Retained(retained))
                | Ok(FilterFdoForwardResult::Rejected { retained, .. }) => {
                    self.retained = Some(retained)
                }
                Err((_, returned)) => self.ack_return = Some(returned),
            }
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
                    self.token
                ),
                Ok(true)
            ) || self.terminal.is_some()
            {
                return false;
            }
            self.source
                .release_unentered()
                .expect("rejected FILTER source release");
            let _ = crate::service_sec_image::with_provider_process_manager(|pm| {
                self.actor.release(pm)
            });
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("rejected FILTER Reply retirement");
            return true;
        }
        if self.initial_status.is_none() {
            if !self.provider_dispatch_ready() {
                return false;
            }
            self.prepare_and_dispatch(handler);
        }
        if let Some(prepared) = self.prepared.take() {
            match prepared.discard(io_manager_mut()) {
                FilterFdoDiscardResult::Retired => {}
                FilterFdoDiscardResult::NotDiscarded { prepared, .. } => {
                    self.prepared = Some(prepared);
                    return false;
                }
                FilterFdoDiscardResult::Retained { discarded, .. } => {
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
            hosted_accepted_pdo_filter_edge::retire_unentered(
                self.terminal.as_ref().unwrap().provider_irp(),
            );
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

unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_only: bool) -> bool {
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

/// The second authenticated Call is made only after the class source-local
/// completion routine returns. It releases the first Reply and parks its own ACK Reply.
pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    token: u64,
    held_completion: bool,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
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
        || work.ack.is_some()
        || work.token != token
        || !work.reply_entered
        || !work.source_published
        || work.terminal.is_none()
        || work.source.validate_pin().is_err()
        || !work.source.caller_terminal_ready()
    {
        return Some(INVALID);
    }
    if !matches!(
        runtime::reconcile_retained_service_reply(
            work.route,
            work.dispatch,
            work.reply,
            work.token
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
    runtime::retire_stopped_acknowledged_retained_service(
        work.route,
        work.dispatch,
        work.reply,
        work.token,
    )
    .expect("FILTER original Reply retirement");
    runtime::park_retained_service(route, token).expect("FILTER ACK Reply admission");
    work.ack = Some(Ack {
        route,
        dispatch,
        reply,
        token,
        reply_entered: false,
    });
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
        3 => submit(ch, reply_cap, caller_badge, address, source_irp).map(|status| (status, false)),
        4 => acknowledge(ch, reply_cap, caller_badge, address, source_irp, false)
            .map(|status| (status, false)),
        5 => acknowledge(ch, reply_cap, caller_badge, address, source_irp, true)
            .map(|status| (status, false)),
        _ => Some((INVALID, false)),
    }
}
