//! Command-reserved ordinary execution for a retained source IRP's native completion stack.
//!
//! Work retains the source pin, target completion and original requestor. This module owns only
//! a canonical kernel worker, its transport and the receipt of one entered unwinder invocation.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::peer_registry::PeerRoute;
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_ledger::SourceIrpAllocation;
use nt_io_manager::source_completion_preparation::{
    admit_existing, ExistingLanePhase, ExistingLanePreparation,
};
use nt_component_suspension::{NestedRestoreChain, NestedRestoreResultKey};

const LABEL: u64 = 0x7bc;
const SELECTOR: u64 = u64::MAX - LABEL;
const COMMAND: u64 = 0x100;
const BANK_OFFSET: u64 = FSD_WORKER_KPCR_OFFSET + 0x1000;
const _: () = assert!(BANK_OFFSET + 0x1000 <= FSD_WORKER_STRIDE);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceCompletionCommand {
    pub ticket: SourceIrpTicket,
    pub allocation: SourceIrpAllocation,
    pub token: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Preparing,
    Ready,
    Prepared,
    Entered,
    Suspended,
    NestedRestore,
    Completed,
    Uncertain,
    Retiring,
    Retired,
}

struct SourceCompletionLane {
    instance: usize,
    domain: HostedDomainIdentity,
    pml4: u64,
    ordinal: u64,
    handle: u64,
    route: Option<PeerRoute>,
    component_shared: u64,
    executive_shared: u64,
    phase: Phase,
    command: Option<SourceCompletionCommand>,
    outcome: Option<HostedIrpUnwindOutcome>,
    pump: Option<crate::spawn_hosts::PumpResult>,
    dispatch: Option<nt_component_suspension::LaneDispatchIdentity>,
    startup_dispatch: Option<nt_component_suspension::LaneDispatchIdentity>,
    nested_restore: Option<SourcePendingRestore>,
}

#[derive(Clone, Copy)]
enum SourceResumeResult {
    Pump(crate::spawn_hosts::PumpResult),
    NotReady,
    Failed,
}

struct SourcePendingRestore {
    ticket: runtime::nested::NestedRestoreTicket,
    key: NestedRestoreResultKey,
    chain: NestedRestoreChain<SourceResumeResult>,
    retryable: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SourceCompletionDispatch {
    NotEntered,
    Completed(HostedIrpUnwindOutcome),
    Suspended,
    Uncertain,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SourceCompletionPreparation {
    InProgress,
    Ready,
    KnownRejected(u32),
    RetainedUncertain,
}

static mut LANES: Vec<SourceCompletionLane> = Vec::new();
static STARTUP_FAILURE_TRACE_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

unsafe fn row_for(instance_index: usize, command: SourceCompletionCommand) -> Option<usize> {
    let inst = instance(instance_index)?;
    if instance_domain_identity(inst) != Some(command.allocation.domain) {
        return None;
    }
    (&*core::ptr::addr_of!(LANES)).iter().position(|row| {
        row.instance == instance_index
            && row.domain == command.allocation.domain
            && row.pml4 == inst.pml4
            && row.command == Some(command)
    })
}

unsafe fn command_is_current(instance_index: usize, command: SourceCompletionCommand) -> bool {
    use nt_io_manager::source_irp_ledger::SourceIrpOwner;
    let Some(inst) = instance(instance_index) else {
        return false;
    };
    matches!(command.allocation.owner,
        SourceIrpOwner::HostedDriver(index) | SourceIrpOwner::HostedCaller(index) if index == instance_index)
        && instance_domain_identity(inst) == Some(command.allocation.domain)
        && command.token != 0
        && command.ticket.domain == command.allocation.domain
        && hosted_source_irp_ledger::matches(instance_index, command.allocation, command.ticket)
}

pub(super) unsafe fn worker(
    instance_index: usize,
    ordinal: u64,
) -> Option<HostedDriverThreadRuntime> {
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.instance == instance_index && row.ordinal == ordinal && row.phase != Phase::Retired
    })?;
    let inst = instance(instance_index)?;
    if instance_domain_identity(inst) != Some(row.domain) || inst.pml4 != row.pml4 {
        return None;
    }
    (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES))
        .as_ref()?
        .iter()
        .copied()
        .find(|runtime| {
            runtime.instance == instance_index
                && runtime.domain == row.domain
                && runtime.pml4 == row.pml4
                && runtime.handle == row.handle
        })
}

pub(super) unsafe fn instance_for_shared(shared: u64) -> Option<(usize, DriverInstance)> {
    let row = (&*core::ptr::addr_of!(LANES))
        .iter()
        .find(|row| row.executive_shared == shared && row.phase != Phase::Retired)?;
    let inst = instance(row.instance)?;
    (instance_domain_identity(inst) == Some(row.domain) && inst.pml4 == row.pml4)
        .then_some((row.instance, inst))
}

pub(super) unsafe fn matches_channel(
    instance_index: usize,
    inst: DriverInstance,
    channel: &crate::spawn_hosts::PumpChannel,
) -> bool {
    let Some(domain) = instance_domain_identity(inst) else {
        return false;
    };
    let Some(index) = (&*core::ptr::addr_of!(LANES)).iter().position(|row| {
        row.instance == instance_index
            && row.domain == domain
            && row.pml4 == inst.pml4
            && row.executive_shared == channel.shared_va
            && row.route == channel.ingress_route
    }) else {
        return false;
    };
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    let Some(worker) = worker(instance_index, row.ordinal) else {
        return false;
    };
    row.phase != Phase::Retired
        && channel.physical_domain == Some(domain)
        && channel.pml4 == row.pml4
        && channel.tcb == worker.tcb
        && channel.shared_va == row.executive_shared
        && channel.ingress_route == row.route
        && row
            .route
            .is_some_and(|route| channel.fault_ep == route.endpoint())
}

pub(super) unsafe fn preparation_ready(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> bool {
    let phase = row_for(instance_index, command).map(|index| {
        match (&*core::ptr::addr_of!(LANES))[index].phase {
            Phase::Preparing => ExistingLanePhase::Preparing,
            Phase::Prepared => ExistingLanePhase::Prepared,
            _ => ExistingLanePhase::Other,
        }
    });
    nt_io_manager::source_completion_preparation::nested_source_preparation_ready(
        phase,
        command_is_current(instance_index, command),
        matches!(phase, Some(ExistingLanePhase::Prepared))
            && ready_for_source(instance_index, command),
    )
}

pub(super) unsafe fn prepare(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> SourceCompletionPreparation {
    use SourceCompletionPreparation::{InProgress, KnownRejected, Ready, RetainedUncertain};
    // An old-domain construction remains owned even after current admission has disappeared.
    if let Some(index) = (&*core::ptr::addr_of!(LANES))
        .iter()
        .position(|row| row.instance == instance_index && row.command == Some(command))
    {
        let phase = match (&*core::ptr::addr_of!(LANES))[index].phase {
            Phase::Preparing => ExistingLanePhase::Preparing,
            Phase::Prepared => ExistingLanePhase::Prepared,
            _ => ExistingLanePhase::Other,
        };
        return match admit_existing(phase, command_is_current(instance_index, command)) {
            ExistingLanePreparation::InProgress => InProgress,
            ExistingLanePreparation::Ready => Ready,
            ExistingLanePreparation::RetainedUncertain => RetainedUncertain,
        };
    }
    let domain = command.allocation.domain;
    let Some(inst) = instance(instance_index) else {
        return KnownRejected(STATUS_INVALID_HANDLE as u32);
    };
    if !command_is_current(instance_index, command) {
        return KnownRejected(STATUS_INVALID_HANDLE as u32);
    }
    if let Some(index) = (&*core::ptr::addr_of!(LANES)).iter().position(|row| {
        row.instance == instance_index
            && row.domain == domain
            && row.pml4 == inst.pml4
            && row.phase == Phase::Ready
            && row.command.is_none()
    }) {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        row.command = Some(command);
        row.phase = Phase::Prepared;
        return Ready;
    }
    let _durable = crate::allocator::enter_durable();
    let index = {
        let rows = &mut *core::ptr::addr_of_mut!(LANES);
        if rows.try_reserve(1).is_err() {
            return KnownRejected(STATUS_INSUFFICIENT_RESOURCES as u32);
        }
        let index = rows.len();
        let Some(ordinal) = (index as u64).checked_add(1) else {
            return KnownRejected(STATUS_INSUFFICIENT_RESOURCES as u32);
        };
        rows.push(SourceCompletionLane {
            instance: instance_index,
            domain,
            pml4: inst.pml4,
            ordinal,
            handle: 0,
            route: None,
            component_shared: 0,
            executive_shared: 0,
            phase: Phase::Preparing,
            command: Some(command),
            outcome: None,
            pump: None,
            dispatch: None,
            startup_dispatch: None,
            nested_restore: None,
        });
        index
    };
    // A retained row precedes construction, publication and Resume. Failure never makes it absent.
    let result = construct(index, inst);
    (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = if result.is_ok() {
        Phase::Prepared
    } else {
        Phase::Uncertain
    };
    if result.is_ok() {
        Ready
    } else {
        RetainedUncertain
    }
}

unsafe fn construct(index: usize, inst: DriverInstance) -> Result<(), u32> {
    let (instance_index, domain, ordinal) = {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        (row.instance, row.domain, row.ordinal)
    };
    hosted_driver_thread_runtimes_mut()
        .try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let slot = allocate_hosted_driver_component_slot(instance_index)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let shared = hosted_worker_component_base_for_slot(slot)
        .and_then(|base| base.checked_add(BANK_OFFSET))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let handle = hosted_driver_thread_table_mut(instance_index)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?
        .create(entry as *const () as u64, shared)
        .map_err(|error| hosted_driver_thread_error_status(error) as u32)?;
    (&mut *core::ptr::addr_of_mut!(LANES))[index].handle = handle;
    let spawn = spawn_hosted_driver_worker_thread_with_shared_bank(
        instance_index,
        inst,
        handle,
        slot,
        entry as *const () as u64,
        shared,
        Some(HostedWorkerSharedBankSpec {
            offset: BANK_OFFSET,
            frames: 1,
            arg_offset: None,
        }),
    )
    .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let bank = spawn.shared_bank.ok_or(STATUS_INVALID_HANDLE as u32)?;
    if bank.component != shared {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    let executive_shared = bank.executive;
    hosted_driver_thread_table_mut(instance_index)
        .ok_or(STATUS_INVALID_HANDLE as u32)?
        .attach_tcb(handle, spawn.tcb)
        .map_err(|error| hosted_driver_thread_error_status(error) as u32)?;
    let mut worker = HostedDriverThreadRuntime {
        instance: instance_index,
        domain,
        handle,
        tcb: spawn.tcb,
        pml4: inst.pml4,
        reply_cap: spawn.reply_cap,
        ingress_route: None,
        construction: spawn.construction,
        component_slot: spawn.component_slot,
        exec_alias_slot: spawn.exec_alias_slot,
        component_scratch_va: spawn.component_scratch_va,
        exec_scratch_va: spawn.exec_scratch_va,
        raw_cnode: spawn.raw_cnode,
        cnode: spawn.cnode,
        sched_context: spawn.sched_context,
    };
    hosted_driver_thread_runtimes_mut().push(worker);
    {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        row.component_shared = shared;
        row.executive_shared = executive_shared;
    }
    hosted_thread_resources::enter_shared(spawn.construction, spawn.reply_cap);
    let route = hosted_ingress_sources::enroll_completion(instance_index, ordinal, spawn.reply_cap)
        .map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    (&mut *core::ptr::addr_of_mut!(LANES))[index].route = Some(route);
    hosted_driver_thread_runtimes_mut()
        .iter_mut()
        .find(|runtime| runtime.instance == instance_index && runtime.handle == handle)
        .unwrap()
        .ingress_route = Some(route);
    worker.ingress_route = Some(route);
    // The worker reads only its own bank, not root-private lane storage.
    for (offset, value) in [
        (0x80, ordinal),
        (0x88, domain.domain_id.raw()),
        (0x90, domain.cookie),
        (0x98, handle),
    ] {
        write_volatile((executive_shared + offset) as *mut u64, value);
    }
    let startup_dispatch = runtime::start_bootstrap(route, spawn.cnode, spawn.sched_context)
        .map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    (&mut *core::ptr::addr_of_mut!(LANES))[index].startup_dispatch = Some(startup_dispatch);
    let caller = hosted_thread_resources::registry_caller(worker)?;
    let channel = channel(index, worker, crate::spawn_hosts::InitialAction::RecvFirst)?;
    let pump = component_scheduler::hosted_component_pump_with_caller(&channel, caller);
    (&mut *core::ptr::addr_of_mut!(LANES))[index].pump = Some(pump);
    if !pump.completed
        || pump.status != STATUS_SUCCESS
        || pump.startup_stack_receipt
            != Some([
                ordinal,
                domain.domain_id.raw(),
                domain.cookie,
                shared,
                handle,
            ])
    {
        if STARTUP_FAILURE_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 8 {
            print_str(b"[source-completion-startup] ordinal/completed/status/flags/wall-label/receipt=");
            print_u64(ordinal);
            print_str(b"/");
            print_u64(pump.completed as u64);
            print_str(b"/");
            print_hex(pump.status as u32);
            print_str(b"/");
            let flags = (pump.scheduler_yielded as u64)
                | ((pump.receive_yield().is_some() as u64) << 1)
                | ((pump.service_wait_yield.is_some() as u64) << 2)
                | ((pump.callback_suspended as u64) << 3)
                | ((pump.provider_wait_suspended as u64) << 4)
                | ((pump.lpc_wait_suspended as u64) << 5);
            print_hex(flags as u32);
            print_str(b"/");
            print_u64(pump.wall_label);
            print_str(b"/");
            print_u64(pump.startup_stack_receipt.is_some() as u64);
            print_str(b"\n");
        }
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Ready;
    Ok(())
}

unsafe fn channel(
    index: usize,
    worker: HostedDriverThreadRuntime,
    initial: crate::spawn_hosts::InitialAction,
) -> Result<crate::spawn_hosts::PumpChannel, u32> {
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    let route = row.route.ok_or(STATUS_INVALID_HANDLE as u32)?;
    let inst = instance(row.instance).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let window =
        ExecVaWindow::try_for_instance(row.instance).ok_or(STATUS_INVALID_HANDLE as u32)?;
    Ok(crate::spawn_hosts::PumpChannel {
        initial_root_dispatch: None,
        fault_ep: route.endpoint(),
        pml4: row.pml4,
        physical_domain: Some(row.domain),
        ingress_route: Some(route),
        code_va: 0,
        image_frames: 0,
        exec_code_va: window.code_va,
        root_image_rights: 3,
        root_image_map_owner: inst.map_cap_bank.owner,
        shared_va: row.executive_shared,
        dispatch_label: LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial,
        tcb: worker.tcb,
        reply_cap: runtime::current_reply(route).map_err(|_| STATUS_INVALID_HANDLE as u32)?,
        child_work_capable: false,
        client_pi: 0,
        client_generation: 0,
        logical_caller: None,
        kernel_caller: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    })
}

/// Expected protocol is derived from retained startup ownership, never from received words.
pub(crate) unsafe fn startup_expected(ch: &crate::spawn_hosts::PumpChannel) -> Option<[u64; 5]> {
    if ch.initial != crate::spawn_hosts::InitialAction::RecvFirst
        || ch.caps.kind != crate::spawn_hosts::ReqKind::Irp
        || ch.dispatch_label != LABEL
    {
        return None;
    }
    let route = runtime::channel_route(ch).ok()??;
    let source = runtime::physical_source(route).ok()?;
    let runtime::PhysicalSourceKind::DispatchWorker { ordinal } = source.kind else {
        return None;
    };
    let runtime::PhysicalDomain::Hosted(domain) = source.domain else {
        return None;
    };
    let Some((instance_index, handle, component_shared, startup_dispatch)) =
        (&*core::ptr::addr_of!(LANES))
            .iter()
            .find(|row| {
                row.phase == Phase::Preparing
                    && row.route == Some(route)
                    && row.domain == domain
                    && row.pml4 == source.pml4
                    && row.ordinal == ordinal
                    && row.executive_shared == ch.shared_va
            })
            .map(|row| {
                (
                    row.instance,
                    row.handle,
                    row.component_shared,
                    row.startup_dispatch,
                )
            })
    else {
        return None;
    };
    let startup_dispatch = startup_dispatch?;
    let worker = worker(instance_index, ordinal)?;
    let enrollment = hosted_ingress_sources::enrollment(source)?;
    if worker.tcb != ch.tcb
        || source.tcb != ch.tcb
        || source.pml4 != ch.pml4
        || worker.pml4 != ch.pml4
        || worker.domain != domain
        || ch.physical_domain != Some(domain)
        || worker.handle != handle
        || worker.cnode == 0
        || worker.raw_cnode == 0
        || enrollment.cnode != worker.cnode
        || enrollment.route != Some(route)
        || enrollment.phase != hosted_ingress_sources::EnrollmentPhase::Published
        || !matches!(runtime::dispatch(route), Ok(current) if current == startup_dispatch)
    {
        return None;
    }
    Some([
        ordinal,
        domain.domain_id.raw(),
        domain.cookie,
        component_shared,
        handle,
    ])
}

/// Admit actual READY only under the exact retained startup and rotated Reply ownership.
pub(crate) unsafe fn validate_startup_ready(
    ch: &crate::spawn_hosts::PumpChannel,
    words: [u64; 5],
) -> bool {
    if startup_expected(ch) != Some(words) {
        return false;
    }
    let Ok(Some(route)) = runtime::channel_route(ch) else {
        return false;
    };
    let Ok(current) = runtime::current_reply(route) else {
        return false;
    };
    let Ok(Some((incoming, message))) = runtime::next_message(route) else {
        return false;
    };
    if current == 0
        || incoming == 0
        || current == incoming
        || message.badge() != route.badge()
        || message.info() != (LABEL << 12) | 5
        || words
            .iter()
            .enumerate()
            .any(|(index, word)| message.word(index) != Some(*word))
    {
        return false;
    }
    matches!(
        crate::spawn_hosts::query_component_reply_binding(ch.tcb, current),
        Ok(nt_component_suspension::ReplyBindingObservation::Free)
    ) && matches!(
        crate::spawn_hosts::query_component_reply_binding(ch.tcb, incoming),
        Ok(nt_component_suspension::ReplyBindingObservation::BoundToTarget)
    )
}

pub(super) unsafe fn ready_for_source(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> bool {
    let Some(index) = row_for(instance_index, command) else {
        return false;
    };
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    row.phase == Phase::Prepared
        && row
            .route
            .is_some_and(|route| matches!(runtime::ready_for_admission(route), Ok(true)))
}

pub(super) unsafe fn dispatch(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> SourceCompletionDispatch {
    let Some(index) = row_for(instance_index, command) else {
        return SourceCompletionDispatch::NotEntered;
    };
    let (ordinal, phase, previous, outcome, shared) = {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        (
            row.ordinal,
            row.phase,
            row.command,
            row.outcome,
            row.executive_shared,
        )
    };
    if previous == Some(command) && phase == Phase::Completed {
        return SourceCompletionDispatch::Completed(
            outcome.expect("acknowledged unwinder outcome"),
        );
    }
    if phase == Phase::Suspended {
        return SourceCompletionDispatch::Suspended;
    }
    if phase == Phase::NestedRestore {
        return if (&*core::ptr::addr_of!(LANES))[index]
            .nested_restore.as_ref().is_some_and(|pending| pending.retryable)
        {
            SourceCompletionDispatch::Suspended
        } else {
            SourceCompletionDispatch::Uncertain
        };
    }
    if phase == Phase::Entered || phase == Phase::Uncertain {
        return SourceCompletionDispatch::Uncertain;
    }
    if !ready_for_source(instance_index, command) || !command_is_current(instance_index, command) {
        return SourceCompletionDispatch::NotEntered;
    }
    let Some(worker) = worker(instance_index, ordinal) else {
        return SourceCompletionDispatch::NotEntered;
    };
    let Ok(caller) = hosted_thread_resources::registry_caller(worker) else {
        return SourceCompletionDispatch::NotEntered;
    };
    let Ok(channel) = channel(
        index,
        worker,
        crate::spawn_hosts::InitialAction::ReplyRequest,
    ) else {
        return SourceCompletionDispatch::NotEntered;
    };
    for (offset, value) in [
        (0, command.ticket.id.get()),
        (8, command.ticket.generation.get()),
        (16, command.token),
        (24, command.allocation.component_address),
        (32, command.allocation.pool_generation),
        (40, command.allocation.bytes),
    ] {
        write_volatile((shared + COMMAND + offset) as *mut u64, value);
    }
    write_volatile((shared + SH_REQ_MAJOR) as *mut u64, SELECTOR);
    {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        row.command = Some(command);
        row.phase = Phase::Entered;
    }
    match component_scheduler::hosted_component_pump_with_caller_retained(&channel, caller) {
        component_scheduler::HostedPumpRestore::Restored(pump) => finish_slice(index, pump),
        component_scheduler::HostedPumpRestore::Retained {
            result, key, ticket, retryable,
        } => retain_parent_result(index, ticket, key, SourceResumeResult::Pump(result), retryable),
        component_scheduler::HostedPumpRestore::Unattributed(result) => {
            let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
            row.pump = Some(result);
            row.phase = Phase::Uncertain;
            SourceCompletionDispatch::Uncertain
        }
        component_scheduler::HostedPumpRestore::ChildWorkReady { result, .. }
        | component_scheduler::HostedPumpRestore::ChildWorkQuarantined { result, .. } => {
            // Source completion has no File continuation owner. Fence the retained result;
            // the physical parent row survives the dropped selector/stack handle.
            let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
            row.pump = Some(result);
            row.phase = Phase::Uncertain;
            SourceCompletionDispatch::Uncertain
        }
        component_scheduler::HostedPumpRestore::ChildWorkPending(_) => {
            (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
            SourceCompletionDispatch::Uncertain
        }
    }
}

unsafe fn finish_slice(
    index: usize,
    pump: crate::spawn_hosts::PumpResult,
) -> SourceCompletionDispatch {
    (&mut *core::ptr::addr_of_mut!(LANES))[index].pump = Some(pump);
    if !pump.completed
        && !pump.callback_suspended
        && !pump.scheduler_yielded
        && pump.provider_wait_suspended != pump.lpc_wait_suspended
    {
        let route = (&*core::ptr::addr_of!(LANES))[index].route.unwrap();
        if let Ok(dispatch) = runtime::dispatch(route) {
            let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
            row.dispatch = Some(dispatch);
            row.phase = Phase::Suspended;
            return SourceCompletionDispatch::Suspended;
        }
    }
    if !pump.completed || pump.status != STATUS_SUCCESS {
        (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    }
    let shared = (&*core::ptr::addr_of!(LANES))[index].executive_shared;
    let outcome = match read_volatile((shared + SH_REQ_INFO) as *const u64) {
        1 => HostedIrpUnwindOutcome::Terminal,
        2 => HostedIrpUnwindOutcome::MoreProcessingRequired,
        _ => {
            (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
            return SourceCompletionDispatch::Uncertain;
        }
    };
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    row.outcome = Some(outcome);
    row.phase = Phase::Completed;
    SourceCompletionDispatch::Completed(outcome)
}

unsafe fn finish_resume_result(index: usize, result: SourceResumeResult) -> SourceCompletionDispatch {
    match result {
        SourceResumeResult::Pump(pump) => finish_slice(index, pump),
        SourceResumeResult::NotReady => {
            (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Suspended;
            SourceCompletionDispatch::Suspended
        }
        SourceResumeResult::Failed => {
            (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
            SourceCompletionDispatch::Uncertain
        }
    }
}

unsafe fn retain_parent_result(
    index: usize,
    ticket: runtime::nested::NestedRestoreTicket,
    key: NestedRestoreResultKey,
    result: SourceResumeResult,
    retryable: bool,
) -> SourceCompletionDispatch {
    let Ok(mut chain) = NestedRestoreChain::retain(key, None, result) else {
        (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    };
    if chain.begin_inner(key).is_err() {
        (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    }
    if retryable {
        let _ = chain.refuse_inner_no_effects(key);
    } else {
        let _ = chain.quarantine_inner(key);
    }
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    row.nested_restore = Some(SourcePendingRestore { ticket, key, chain, retryable });
    row.phase = Phase::NestedRestore;
    if retryable { SourceCompletionDispatch::Suspended } else { SourceCompletionDispatch::Uncertain }
}

unsafe fn retry_parent_restore(index: usize) -> SourceCompletionDispatch {
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    let Some(pending) = row.nested_restore.as_mut() else {
        row.phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    };
    if !pending.retryable || pending.chain.begin_inner(pending.key).is_err() {
        row.phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    }
    let ticket = pending.ticket;
    let key = pending.key;
    if runtime::nested::restore_pending_ticket(ticket).is_err() {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        let pending = row.nested_restore.as_mut().unwrap();
        if runtime::nested::pending_ticket(ticket) {
            let _ = pending.chain.refuse_inner_no_effects(key);
            return SourceCompletionDispatch::Suspended;
        }
        let _ = pending.chain.quarantine_inner(key);
        pending.retryable = false;
        return SourceCompletionDispatch::Uncertain;
    }
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    let mut pending = row.nested_restore.take().unwrap();
    if pending.chain.acknowledge_inner(key).is_err() {
        row.nested_restore = Some(pending);
        row.phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    }
    match pending.chain.take(key, None) {
        Ok(result) => finish_resume_result(index, result),
        Err(_) => {
            row.nested_restore = Some(pending);
            row.phase = Phase::Uncertain;
            SourceCompletionDispatch::Uncertain
        }
    }
}

pub(super) unsafe fn acknowledge(instance_index: usize, command: SourceCompletionCommand) -> bool {
    let Some(index) = row_for(instance_index, command) else {
        return false;
    };
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    if row.phase != Phase::Completed || row.command != Some(command) {
        return false;
    }
    row.command = None;
    row.outcome = None;
    row.pump = None;
    row.dispatch = None;
    row.nested_restore = None;
    row.phase = Phase::Ready;
    true
}

pub(super) unsafe fn cancel_prepared(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> bool {
    // Cleanup must still see an entered old-domain row after its catalog admission has stopped.
    let Some(index) = (&*core::ptr::addr_of!(LANES))
        .iter()
        .position(|row| row.instance == instance_index && row.command == Some(command))
    else {
        return true;
    };
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    if row.phase != Phase::Prepared {
        return false;
    }
    row.command = None;
    row.phase = Phase::Ready;
    true
}

pub(super) unsafe fn continuation_ready(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> bool {
    let Some(index) = row_for(instance_index, command) else {
        return false;
    };
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    if row.phase == Phase::NestedRestore {
        return row.nested_restore.as_ref().is_some_and(|pending| {
            pending.retryable && runtime::nested::pending_ticket(pending.ticket)
        });
    }
    if row.phase != Phase::Suspended {
        return false;
    }
    let (Some(route), Some(dispatch)) = (row.route, row.dispatch) else {
        return false;
    };
    matches!(
        runtime::retained_service_resume_ready(route, dispatch),
        Ok(true)
    )
}

/// Resume one retained execution; never rewrite the bank or admit the original command again.
pub(super) unsafe fn poll(
    instance_index: usize,
    command: SourceCompletionCommand,
) -> SourceCompletionDispatch {
    let Some(index) = row_for(instance_index, command) else {
        return SourceCompletionDispatch::NotEntered;
    };
    let (phase, ordinal, route, previous, outcome) = {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        (row.phase, row.ordinal, row.route, row.pump, row.outcome)
    };
    if phase == Phase::Completed {
        return SourceCompletionDispatch::Completed(outcome.unwrap());
    }
    if phase == Phase::NestedRestore {
        return retry_parent_restore(index);
    }
    if phase == Phase::Uncertain || phase == Phase::Entered {
        return SourceCompletionDispatch::Uncertain;
    }
    if !continuation_ready(instance_index, command) {
        return SourceCompletionDispatch::Suspended;
    }
    let (Some(route), Some(previous), Some(worker)) =
        (route, previous, worker(instance_index, ordinal))
    else {
        return SourceCompletionDispatch::Uncertain;
    };
    let Ok(caller) = hosted_thread_resources::registry_caller(worker) else {
        return SourceCompletionDispatch::Uncertain;
    };
    let Ok(mut channel) = channel(index, worker, crate::spawn_hosts::InitialAction::RecvFirst)
    else {
        return SourceCompletionDispatch::Uncertain;
    };
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let Ok(mut parent) = runtime::nested::park_current() else {
        return SourceCompletionDispatch::Suspended;
    };
    (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Entered;
    let resumed = (|| -> Result<Option<crate::spawn_hosts::PumpResult>, ()> {
        if !runtime::resume_service(route).map_err(|_| ())? {
            return Ok(None);
        }
        let _caller =
            crate::provider_registry_caller::Scope::enter(&channel, caller).map_err(|_| ())?;
        let scope = component_scheduler::ComponentSchedulerScope::enter();
        let mut pump = crate::spawn_hosts::component_pump_resume_hosted_wait(&channel, &previous)
            .map_err(|_| ())?;
        while pump.scheduler_yielded {
            scope.service_irq_yield(channel.shared_va);
            channel.reply_cap = runtime::current_reply(route).map_err(|_| ())?;
            pump = crate::spawn_hosts::component_pump_continue_receive_after_scheduler_service(
                &channel, &pump)
                .map_err(|_| ())?;
        }
        if pump.completed {
            let dispatch = runtime::dispatch(route).map_err(|_| ())?;
            runtime::complete(route, dispatch, pump.reply_cap, LABEL).map_err(|_| ())?;
        }
        Ok(Some(pump))
    })();
    let result = match resumed {
        Ok(Some(pump)) => SourceResumeResult::Pump(pump),
        Ok(None) => SourceResumeResult::NotReady,
        Err(()) => SourceResumeResult::Failed,
    };
    let Some(handle) = parent.as_ref() else {
        return finish_resume_result(index, result);
    };
    let ticket = handle.ticket();
    let Some(key) = runtime::nested::result_key(handle) else {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        if let SourceResumeResult::Pump(pump) = result { row.pump = Some(pump); }
        row.phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    };
    let Ok(mut chain) = NestedRestoreChain::retain(key, None, result) else {
        (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    };
    if chain.begin_inner(key).is_err() {
        (&mut *core::ptr::addr_of_mut!(LANES))[index].phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    }
    // Own the result and exact retry selector before entering the physical restore.
    {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        row.nested_restore = Some(SourcePendingRestore { ticket, key, chain, retryable: false });
        row.phase = Phase::NestedRestore;
    }
    if runtime::nested::restore(&mut parent).is_err() {
        let retryable = runtime::nested::pending_ticket(ticket);
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        let pending = row.nested_restore.as_mut().unwrap();
        pending.retryable = retryable;
        if retryable {
            let _ = pending.chain.refuse_inner_no_effects(key);
            return SourceCompletionDispatch::Suspended;
        }
        let _ = pending.chain.quarantine_inner(key);
        return SourceCompletionDispatch::Uncertain;
    }
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    let mut pending = row.nested_restore.take().unwrap();
    if pending.chain.acknowledge_inner(key).is_err() {
        row.nested_restore = Some(pending);
        row.phase = Phase::Uncertain;
        return SourceCompletionDispatch::Uncertain;
    }
    match pending.chain.take(key, None) {
        Ok(result) => finish_resume_result(index, result),
        Err(_) => {
            row.nested_restore = Some(pending);
            row.phase = Phase::Uncertain;
            SourceCompletionDispatch::Uncertain
        }
    }
}

/// An entered or uncertain unwinder still owns execution, even if the driver is being unloaded.
pub(super) unsafe fn begin_worker_retirement(instance_index: usize, handle: u64) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LANES))
        .iter_mut()
        .find(|row| row.instance == instance_index && row.handle == handle)
    else {
        return true;
    };
    if !matches!(row.phase, Phase::Ready | Phase::Retiring) || row.command.is_some() {
        return false;
    }
    row.phase = Phase::Retiring;
    true
}

pub(super) unsafe fn finish_worker_retirement(instance_index: usize, handle: u64) {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LANES))
        .iter_mut()
        .find(|row| row.instance == instance_index && row.handle == handle)
    else {
        return;
    };
    assert!(row.phase == Phase::Retiring && row.command.is_none());
    row.phase = Phase::Retired;
}

unsafe extern "win64" fn entry(shared: u64) {
    let ready = [
        read_volatile((shared + 0x80) as *const u64),
        read_volatile((shared + 0x88) as *const u64),
        read_volatile((shared + 0x90) as *const u64),
        shared,
        read_volatile((shared + 0x98) as *const u64),
    ];
    crate::spawn_hosts::component_dispatch_loop_with_ready(
        shared,
        shared,
        SH_REQ_STATUS,
        LABEL,
        execute,
        Some(ready),
    )
}

unsafe fn execute(request: &crate::spawn_hosts::DispatchReq) -> (i32, u64) {
    if request.sel != SELECTOR {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let shared = request.drv;
    let ticket = read_volatile((shared + COMMAND) as *const u64);
    let generation = read_volatile((shared + COMMAND + 8) as *const u64);
    let token = read_volatile((shared + COMMAND + 16) as *const u64);
    let irp = read_volatile((shared + COMMAND + 24) as *const u64);
    let pool_generation = read_volatile((shared + COMMAND + 32) as *const u64);
    let bytes = read_volatile((shared + COMMAND + 40) as *const u64);
    if ticket == 0
        || generation == 0
        || token == 0
        || pool_generation == 0
        || component_pool_allocation_capacity(irp).is_none_or(|capacity| capacity < bytes)
        || read_unaligned((irp - 8) as *const u64) != pool_generation
        || validate_hosted_irp_packet(irp).is_none()
    {
        return (STATUS_INVALID_HANDLE, 0);
    }
    // The registered root-issued job owns the source pin; no routine address is accepted.
    let outcome = complete_hosted_irp(irp);
    (
        STATUS_SUCCESS,
        match outcome {
            HostedIrpUnwindOutcome::Terminal => 1,
            HostedIrpUnwindOutcome::MoreProcessingRequired => 2,
        },
    )
}
