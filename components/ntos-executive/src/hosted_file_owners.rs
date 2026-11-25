//! Native File IRP ownership across provider IPC and completion delivery.

use super::*;
use hosted_file_dispatch::FileDispatchContinuation;
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpBuffers, ExternalFileIrpCancelPhase, ExternalFileIrpCancelReturn,
    ExternalFileIrpCompletionInvocation, ExternalFileIrpCompletionReturn,
    ExternalFileIrpCopyReturn, ExternalFileIrpDispatchPolicy, ExternalFileIrpOutputCapture,
    ExternalFileIrpNoEntryReceipt, ExternalFileIrpOutcome, ExternalFileIrpRequest,
    ExternalFileIrpPumpKey, ExternalFileIrpResult, ExternalFileIrpReturn, ExternalFileIrpTerminal,
    ExternalFileIrpTerminalReceipt, PreparedExternalFileIrp, RetainedExternalFileIrp,
    SuspendedExternalFileIrpInvocation, ExternalFileIrpInvocation,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flight {
    Preparing,
    QueuedDispatch,
    Dispatch,
    PumpSuspended,
    PumpReturned,
    Copy,
    Cancel,
    Acknowledge,
    Idle,
    Blocked,
}

enum Payload {
    Prepared(PreparedExternalFileIrp),
    NoEntry(ExternalFileIrpNoEntryReceipt),
    Returned(ExternalFileIrpReturn),
    PumpSuspended(SuspendedFilePumpOwner),
    HookReturned(HookReturned),
    Retained(RetainedExternalFileIrp),
    Completion(ExternalFileIrpCompletionInvocation),
    Acknowledgement(ExternalFileIrpCompletionReturn),
    Copy(ExternalFileIrpCopyReturn),
    Cancel(ExternalFileIrpCancelReturn),
    Terminal(ExternalFileIrpTerminal),
}

#[must_use = "retain both the manager invocation and native pump continuation"]
struct SuspendedFilePumpOwner {
    invocation: SuspendedExternalFileIrpInvocation,
    continuation: FileDispatchContinuation,
}

struct HookReturned {
    state: HookReturnedState,
    observed: bool,
}

enum HookReturnedState {
    Terminal(ExternalFileIrpTerminal),
    Retired {
        completion: nt_io_manager::CompletedIrp,
        buffers: ExternalFileIrpBuffers,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HookPumpIdentity {
    owner_id: u64,
    device: nt_io_manager::DeviceId,
    initial_key: ExternalFileIrpPumpKey,
    current_key: ExternalFileIrpPumpKey,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Authority {
    instance: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
    tcb: u64,
    pml4: u64,
    fault_ep: u64,
    shared_va: u64,
}

impl Authority {
    fn capture(index: usize) -> Option<Self> {
        let current = instance(index)?;
        Some(Self {
            instance: index,
            driver_id: current.driver_id,
            domain: instance_domain_identity(current)?,
            tcb: current.tcb,
            pml4: current.pml4,
            fault_ep: current.fault_ep,
            shared_va: current.exec_shared_va,
        })
    }

    fn live(self) -> bool {
        Self::capture(self.instance) == Some(self)
    }
}

/// Value-only lane-availability observation for a queued File IRP. The owner keeps the
/// exact driver instance and hosted-domain generation; foreign lane changes cannot wake it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct AdmissionReceipt {
    owner: Option<Authority>,
    refused: AdmissionEpoch,
    ready: bool,
}

#[derive(Clone, Copy)]
struct QueueHeadTicket {
    id: u64,
    owner: Authority,
}

/// A missing shared-lane registration is distinct from a retired native instance. Neither
/// can borrow an epoch from a replacement instance with the same numeric driver id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionEpoch {
    Retired,
    MissingDomain,
    Ready(u64),
}

impl AdmissionReceipt {
    const EMPTY: Self = Self { owner: None, refused: AdmissionEpoch::Retired, ready: false };

    fn ready_for(owner: Authority) -> bool {
        if !owner.live() { return false; }
        let Some(route) = hosted_ingress_sources::primary_route(owner.instance) else {
            return false;
        };
        let primary_ready = matches!(unsafe {
            crate::spawn_hosts::shared_ingress::owner::runtime::ready_for_admission(route)
        }, Ok(true));
        primary_ready || (unsafe {
            crate::spawn_hosts::shared_ingress::owner::runtime::primary_dispatch_parked(route)
                && hosted_class_irp_lane::ordinary_ready(owner.instance)
        })
    }

    fn became_ready(self) -> bool {
        !self.ready && self.owner.is_some_and(Self::ready_for)
    }

    fn epoch_for(owner: Option<Authority>) -> AdmissionEpoch {
        let Some(owner) = owner.filter(|owner| owner.live()) else {
            return AdmissionEpoch::Retired;
        };
        let Some(worker) = instance(owner.instance).map(|inst| inst.file_worker_epoch) else {
            return AdmissionEpoch::Retired;
        };
        let idle = unsafe {
            crate::spawn_hosts::shared_ingress::owner::runtime::lane_idle_epoch_for_domain(
                owner.domain,
            )
        };
        match idle {
            Some(idle) => AdmissionEpoch::Ready(worker.wrapping_add(idle)),
            None => AdmissionEpoch::MissingDomain,
        }
    }

    fn current_epoch(self) -> AdmissionEpoch {
        Self::epoch_for(self.owner)
    }

    fn refresh(self) -> Self {
        Self { owner: self.owner, refused: self.current_epoch(),
            ready: self.owner.is_some_and(Self::ready_for) }
    }

    fn capture(driver: Option<nt_io_manager::DriverId>) -> Self {
        let owner = driver.and_then(|driver| {
            let (index, _) = instance_by_driver_id(driver.raw())?;
            Authority::capture(index)
                .filter(|authority| authority.driver_id == driver.raw())
        });
        Self { owner, refused: Self::epoch_for(owner),
            ready: owner.is_some_and(Self::ready_for) }
    }
}

struct Row {
    caller: nt_process::native_handle::NativeHandleCaller,
    requestor: nt_process::native_handle::NativeThreadProcessReference,
    id: u64,
    irp_id: Option<IrpId>,
    primary_device: Option<nt_io_manager::DeviceId>,
    primary_driver: Option<nt_io_manager::DriverId>,
    stack: Vec<(nt_io_manager::DeviceId, nt_io_manager::DriverId)>,
    authorities: Vec<Authority>,
    projection_owners: Vec<nt_io_manager::HostedDeviceProjectionReference>,
    /// A completed canonical retirement cannot be replayed if projection release refuses.
    terminal_receipt: Option<ExternalFileIrpTerminalReceipt>,
    settled_buffers: Option<ExternalFileIrpBuffers>,
    completion_storage: Option<(usize, usize)>,
    port_connect_control_storage: Option<usize>,
    hook_pump: Option<HookPumpIdentity>,
    hook_pump_claimed: bool,
    /// An ordinary caller's pump kept in this row (#420): suspended, then its returned
    /// terminal, unretired, until that caller collects it. The root boundary redrives it.
    plain_pump: Option<nt_hosted_runtime::KeptFilePump<ExternalFileIrpPumpKey, ExternalFileIrpTerminal>>,
    /// The scoped SCSI proof authority a kept pump was entered under (#420). Its pump resumes
    /// only with exactly this scope active again, and never outside it.
    proof_scope: Option<ActivePendingScsiProofAuthority>,
    /// The one-use child observation is in the native continuation, even across restore retry.
    recorded_generic_child_ran: Option<bool>,
    flight: Flight,
    payload: Option<Payload>,
    blocked_status: Option<nt_status::NtStatus>,
    completion: Option<nt_io_manager::CompletedIrp>,
    /// Selected once with preparation; retries must not reinterpret the original output contract.
    output_capture: ExternalFileIrpOutputCapture,
    retry_after: u64,
    work_ready: bool,
    /// Observation only; the canonical IRP and Flight still govern every native effect.
    phase_pump_ticks: u64,
    phase_bank_ticks: u64,
    phase_major: u8,
    /// A syscall caller's ordinary IRP that no lane admitted waits in `QueuedDispatch` rather
    /// than failing with a synthetic STATUS_DEVICE_BUSY (#427).
    queue_not_admitted: bool,
    /// Exact instance lifetime and its own lane-availability epoch at last refusal.
    admission_receipt: AdmissionReceipt,
    /// Diagnostic first sighting of this row's queue, independent of later retries.
    queue_trace_emitted: bool,
    nested_pnp_trace: bool,
    nested_pnp_trace_count: u8,
    /// One owned continuation drive after a worker startup yielded at first admission.
    startup_probe_owed: bool,
    /// Stage of the last queued startup attempt; only a changed stage earns another drive.
    startup_probe_phase: Option<component_scheduler::PendingSchedulerProgress>,
    /// An unavailable exact authority may be redriven once for manager disposition.
    retired_probe_consumed: bool,
    missing_domain_probe_consumed: bool,
}

/// Counts dispatches refused admission with nothing entered, for callers that retry them
/// (#427): a nested child refused this way is waiting, not uncertain.
static ADMISSION_REFUSALS: AtomicU64 = AtomicU64::new(0);

pub(super) fn admission_refusals() -> u64 {
    ADMISSION_REFUSALS.load(Ordering::Acquire)
}

/// Advanced when a worker lane frees or a never-admitted queue head retires (#427).
static LANE_EPOCH: AtomicU64 = AtomicU64::new(1);

/// A worker claim ended, so that lane may now admit a queued IRP. A lane returning to Idle
/// advances the lanes' own idle epoch.
pub(super) fn lane_freed(instance_index: usize, domain: HostedDomainIdentity) {
    let table = unsafe { driver_instances_mut() };
    let Some(inst) = table.get_mut(instance_index)
        .filter(|inst| inst.used && instance_domain_identity(**inst) == Some(domain))
    else { return; };
    inst.file_worker_epoch = inst.file_worker_epoch.wrapping_add(1);
    LANE_EPOCH.fetch_add(1, Ordering::AcqRel);
}

/// Changes whenever a hosted lane becomes admissible, a worker claim ends, or a queued
/// head retires without occupying a lane (#427).
pub(super) fn admission_epoch() -> u64 {
    LANE_EPOCH.load(Ordering::Acquire)
        .wrapping_add(unsafe { crate::spawn_hosts::shared_ingress::owner::runtime::lane_idle_epoch() })
}

static mut ROWS: Vec<Row> = Vec::new();
static mut NEXT_ID: u64 = 1;
static mut NEXT_DRAIN_ID: u64 = 1;
static RETRY_READY: AtomicU64 = AtomicU64::new(0);

struct FileRpcTotals {
    calls: AtomicU64,
    prepare: AtomicU64,
    pump: AtomicU64,
    invoke_other: AtomicU64,
    terminal: AtomicU64,
    bank: AtomicU64,
    total: AtomicU64,
}

impl FileRpcTotals {
    const fn new() -> Self {
        Self { calls: AtomicU64::new(0), prepare: AtomicU64::new(0),
            pump: AtomicU64::new(0), invoke_other: AtomicU64::new(0),
            terminal: AtomicU64::new(0), bank: AtomicU64::new(0), total: AtomicU64::new(0) }
    }

    fn add(&self, phase: nt_hosted_runtime::HostedFileRpcDurations) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.prepare.fetch_add(phase.prepare, Ordering::Relaxed);
        self.pump.fetch_add(phase.pump, Ordering::Relaxed);
        self.invoke_other.fetch_add(phase.invoke_other, Ordering::Relaxed);
        self.terminal.fetch_add(phase.terminal, Ordering::Relaxed);
        self.bank.fetch_add(phase.bank, Ordering::Relaxed);
        self.total.fetch_add(phase.total, Ordering::Relaxed);
    }
}

static FILE_RPC_TOTALS: [FileRpcTotals; 2] = [FileRpcTotals::new(), FileRpcTotals::new()];
static FILE_RPC_REJECTED: AtomicU64 = AtomicU64::new(0);

// Mounted FAT uses INTERNAL_DEVICE_CONTROL, which does not enter the File READ/WRITE phase
// census. Keep these three spans exclusive and record early preparation refusals as well.
struct ScsiRpcTotals {
    calls: AtomicU64,
    uninvoked: AtomicU64,
    prepare_ticks: AtomicU64,
    invoke_ticks: AtomicU64,
    finish_ticks: AtomicU64,
}

static SCSI_RPC_TOTALS: ScsiRpcTotals = ScsiRpcTotals {
    calls: AtomicU64::new(0), uninvoked: AtomicU64::new(0),
    prepare_ticks: AtomicU64::new(0), invoke_ticks: AtomicU64::new(0),
    finish_ticks: AtomicU64::new(0),
};

struct ScsiRpcPhaseGuard {
    started: Option<u64>,
    invoked: Option<u64>,
    returned: Option<u64>,
}

impl ScsiRpcPhaseGuard {
    fn new(major: u8, policy: ExternalFileIrpDispatchPolicy) -> Self {
        Self {
            started: (major == major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                && policy == ExternalFileIrpDispatchPolicy::ScsiAtDevice)
                .then(crate::disk_census_ticks),
            invoked: None,
            returned: None,
        }
    }
}

impl Drop for ScsiRpcPhaseGuard {
    fn drop(&mut self) {
        let Some(started) = self.started else { return; };
        SCSI_RPC_TOTALS.calls.fetch_add(1, Ordering::Relaxed);
        let Some(invoked) = self.invoked else {
            SCSI_RPC_TOTALS.uninvoked.fetch_add(1, Ordering::Relaxed);
            SCSI_RPC_TOTALS.prepare_ticks.fetch_add(
                crate::disk_census_ticks().wrapping_sub(started), Ordering::Relaxed);
            return;
        };
        SCSI_RPC_TOTALS.prepare_ticks.fetch_add(
            invoked.wrapping_sub(started), Ordering::Relaxed);
        let Some(returned) = self.returned else { return; };
        SCSI_RPC_TOTALS.invoke_ticks.fetch_add(
            returned.wrapping_sub(invoked), Ordering::Relaxed);
        SCSI_RPC_TOTALS.finish_ticks.fetch_add(
            crate::disk_census_ticks().wrapping_sub(returned), Ordering::Relaxed);
    }
}

struct FileRpcPhaseGuard {
    entered: u64,
    identity: Option<nt_hosted_runtime::HostedFileRpcIdentity>,
    invoked: u64,
    returned: u64,
    pump_ticks: u64,
    bank_ticks: u64,
}

impl FileRpcPhaseGuard {
    fn new(major: u8) -> Self {
        Self { entered: if matches!(major, major::IRP_MJ_READ | major::IRP_MJ_WRITE) {
            crate::disk_census_ticks()
        } else { 0 }, identity: None, invoked: 0, returned: 0,
            pump_ticks: 0, bank_ticks: 0 }
    }
}

impl Drop for FileRpcPhaseGuard {
    fn drop(&mut self) {
        let Some(identity) = self.identity else { return; };
        if self.invoked == 0 || self.returned == 0 { return; }
        let marks = nt_hosted_runtime::HostedFileRpcMarks {
            entered: self.entered, invoked: self.invoked, returned: self.returned,
            terminal: crate::disk_census_ticks(), pump_ticks: self.pump_ticks,
            bank_ticks: self.bank_ticks,
        };
        let mut diagnostic = nt_hosted_runtime::HostedFileRpcDiagnostic::new();
        if let Some(phase) = diagnostic.record(identity, identity, marks) {
            let slot = if identity.major == major::IRP_MJ_READ { 0 } else { 1 };
            FILE_RPC_TOTALS[slot].add(phase);
        } else {
            FILE_RPC_REJECTED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Match only the executing retained File IRP; a numeric ID without its live owner is ignored.
pub(super) fn record_dispatch_pump(
    irp_id: IrpId, major: u8, pump_ticks: u64, bank_ticks: u64,
) {
    if !matches!(major, major::IRP_MJ_READ | major::IRP_MJ_WRITE) { return; }
    let Some(id) = find(irp_id) else { return; };
    let owner = row(id);
    if owner.flight == Flight::Dispatch && owner.irp_id == Some(irp_id)
        && owner.phase_major == major
    {
        owner.phase_pump_ticks = owner.phase_pump_ticks.saturating_add(pump_ticks);
        owner.phase_bank_ticks = owner.phase_bank_ticks.saturating_add(bank_ticks);
    }
}

/// Observation only: the physical dispatch must still own this File READ/WRITE IRP.
pub(super) fn file_read_write_dispatch_for_diagnostic(irp_id: IrpId) -> bool {
    let Some(id) = find(irp_id) else { return false; };
    let owner = row(id);
    owner.flight == Flight::Dispatch
        && owner.irp_id == Some(irp_id)
        && matches!(owner.phase_major, major::IRP_MJ_READ | major::IRP_MJ_WRITE)
}

pub(super) fn print_rpc_phase() {
    let queue: [u64; 4] = core::array::from_fn(|stage| IRP_QUEUE_COUNTS[stage].load(Ordering::Relaxed));
    if queue.iter().any(|count| *count != 0) {
        print_str(b"[irp-queue-census] queued/retried/admitted/refused=");
        for (index, count) in queue.iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(*count);
        }
        print_str(b"\n");
    }
    let scsi_calls = SCSI_RPC_TOTALS.calls.load(Ordering::Relaxed);
    if scsi_calls != 0 {
        print_str(b"[scsi-rpc-phase] calls/uninvoked/prepare/invoke/finish_Mtick=");
        print_u64(scsi_calls);
        print_str(b"/");
        print_u64(SCSI_RPC_TOTALS.uninvoked.load(Ordering::Relaxed));
        for ticks in [&SCSI_RPC_TOTALS.prepare_ticks, &SCSI_RPC_TOTALS.invoke_ticks,
            &SCSI_RPC_TOTALS.finish_ticks] {
            print_str(b"/");
            print_u64(ticks.load(Ordering::Relaxed) / 1_000_000);
        }
        print_str(b"\n");
    }
    for (index, label) in [b"read".as_slice(), b"write".as_slice()].iter().enumerate() {
        let total = &FILE_RPC_TOTALS[index];
        let calls = total.calls.load(Ordering::Relaxed);
        if calls == 0 { continue; }
        print_str(b"[file-rpc-phase] ");
        print_str(label);
        print_str(b" calls/prepare/pump/invoke-other/terminal/bank/total_Mtick=");
        print_u64(calls);
        for field in [&total.prepare, &total.pump, &total.invoke_other,
            &total.terminal, &total.bank, &total.total] {
            print_str(b"/");
            print_u64(field.load(Ordering::Relaxed) / 1_000_000);
        }
        print_str(b"\n");
    }
    let rejected = FILE_RPC_REJECTED.load(Ordering::Relaxed);
    if rejected != 0 {
        print_str(b"[file-rpc-phase] rejected=");
        print_u64(rejected);
        print_str(b"\n");
    }
}

/// Current retained owners, not cumulative outcomes or proof of provider readiness.
#[derive(Clone, Copy, Default)]
pub(crate) struct Stats {
    pub live: usize,
    pub preparing: usize,
    pub queued_dispatch: usize,
    pub dispatching: usize,
    pub pump_suspended: usize,
    pub pump_returned: usize,
    pub copying: usize,
    pub cancelling: usize,
    pub acknowledging: usize,
    pub idle: usize,
    pub blocked: usize,
    pub pending: usize,
    pub indeterminate: usize,
    pub completions: usize,
    pub copy_returns: usize,
    pub ack_returns: usize,
    pub retry_deadlines: usize,
    pub retained_errors: usize,
}

pub(super) fn stats() -> Stats {
    let mut stats = Stats::default();
    // Observe only: do not resolve completions, change deadlines, or invoke a provider.
    for row in unsafe { &*core::ptr::addr_of!(ROWS) } {
        stats.live += 1;
        match row.flight {
            Flight::Preparing => stats.preparing += 1,
            Flight::QueuedDispatch => stats.queued_dispatch += 1,
            Flight::Dispatch => stats.dispatching += 1,
            Flight::PumpSuspended => stats.pump_suspended += 1,
            Flight::PumpReturned => stats.pump_returned += 1,
            Flight::Copy => stats.copying += 1,
            Flight::Cancel => stats.cancelling += 1,
            Flight::Acknowledge => stats.acknowledging += 1,
            Flight::Idle => stats.idle += 1,
            Flight::Blocked => stats.blocked += 1,
        }
        match row.payload.as_ref() {
            Some(Payload::Retained(owner)) if owner.is_indeterminate() => {
                stats.indeterminate += 1;
            }
            Some(Payload::Retained(_)) => stats.pending += 1,
            Some(Payload::Copy(_)) => stats.copy_returns += 1,
            Some(Payload::Acknowledgement(_)) => stats.ack_returns += 1,
            _ => {}
        }
        stats.completions += usize::from(row.completion.is_some());
        stats.retry_deadlines += usize::from(row.flight == Flight::Idle && row.retry_after != 0);
        stats.retained_errors += usize::from(row.blocked_status.is_some());
    }
    stats
}

fn rows() -> &'static mut Vec<Row> {
    // All access is serialized by the executive. References never cross an external call.
    unsafe { &mut *core::ptr::addr_of_mut!(ROWS) }
}

fn row(id: u64) -> &'static mut Row {
    rows()
        .iter_mut()
        .find(|row| row.id == id)
        .expect("File IRP owner missing")
}

fn find(irp_id: IrpId) -> Option<u64> {
    rows()
        .iter()
        .find(|row| row.irp_id == Some(irp_id))
        .map(|row| row.id)
}

/// Bounded by the SCSI caller. Read the exact detached provider owner without advancing it.
/// Flight values follow the existing file-return probe; payload values are listed here so a
/// stalled dispatch can be distinguished from a retained or completed provider.
pub(super) fn trace_scsi_provider_owner(phase: u64, source: u64, use_epoch: u64, irp: IrpId) {
    let owner = rows().iter().find(|row| row.irp_id == Some(irp));
    let (id, flight, payload, ready, blocked, completion, tcb) =
        owner.map_or((0, 0, 0, 0, u64::MAX, 0, 0), |row| {
            let flight = match row.flight {
                Flight::Preparing => 1, Flight::QueuedDispatch => 2, Flight::Dispatch => 3,
                Flight::PumpSuspended => 4, Flight::PumpReturned => 5, Flight::Copy => 6,
                Flight::Cancel => 7, Flight::Acknowledge => 8, Flight::Idle => 9,
                Flight::Blocked => 10,
            };
            let payload = match row.payload.as_ref() {
                None => 0, Some(Payload::Prepared(_)) => 1,
                Some(Payload::NoEntry(_)) => 2, Some(Payload::Returned(_)) => 3,
                Some(Payload::PumpSuspended(_)) => 4,
                Some(Payload::HookReturned(_)) => 5,
                Some(Payload::Retained(_)) => 6,
                Some(Payload::Completion(_)) => 7,
                Some(Payload::Acknowledgement(_)) => 8,
                Some(Payload::Copy(_)) => 9, Some(Payload::Cancel(_)) => 10,
                Some(Payload::Terminal(_)) => 11,
            };
            let authority = row.authorities.iter().find(|authority| {
                row.primary_driver.is_some_and(|driver| driver.raw() == authority.driver_id)
            }).or_else(|| row.authorities.first());
            (row.id, flight, payload, u64::from(row.work_ready),
                row.blocked_status.map_or(u64::MAX, |status| status.raw() as u32 as u64),
                u64::from(row.completion.is_some()),
                authority.map_or(0, |authority| authority.tcb))
        });
    print_str(b"[scsi-provider-owner] phase/source/use/provider/row/flight/payload/work-ready/blocked/completion/tcb=");
    let values = [phase, source, use_epoch, irp.raw(), id, flight, payload,
        ready, blocked, completion, tcb];
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
    print_str(b"\n");
}

/// Bind a port CONNECT's mutable input copy and ACK to its captured physical store before
/// native entry. A synchronous completion may need both controls before dispatch returns.
fn mark_port_connect_control(
    irp: IrpId, device: nt_io_manager::DeviceId,
) -> Result<(), nt_status::NtStatus> {
    let id = find(irp).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let owner = row(id);
    let storage = owner.completion_storage
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?.1;
    if owner.primary_device != Some(device)
        || owner.port_connect_control_storage.is_some()
        || !owner.authorities.iter().all(|authority| authority.live())
    { return Err(nt_status::NtStatus::INVALID_HANDLE); }
    owner.port_connect_control_storage = Some(storage);
    Ok(())
}

/// A matching numeric IRP alone cannot authorize a worker control. The detached owner must be
/// in the corresponding copy/ACK flight and retain the same physical completion store.
pub(super) unsafe fn active_port_connect_control(storage: usize, irp: IrpId, operation: u64) -> bool {
    let Some(id) = find(irp) else { return false; };
    let owner = row(id);
    let matching_flight = match operation {
        FSD_DISPATCH_COPY_MUTABLE_INPUT => matches!(owner.flight, Flight::Copy | Flight::Dispatch),
        FSD_DISPATCH_ACK_COMPLETION => matches!(owner.flight, Flight::Acknowledge | Flight::Dispatch),
        _ => false,
    };
    matching_flight && owner.irp_id == Some(irp)
        && owner.completion_storage.is_some_and(|(_, physical)| physical == storage)
        && owner.port_connect_control_storage == Some(storage)
        && owner.authorities.iter().all(|authority| authority.live())
}

/// Read-only trace discriminator for the exact retained CONNECT dispatch owner.
pub(super) fn port_connect_dispatch_for_trace(irp: IrpId, device: nt_io_manager::DeviceId) -> bool {
    let Some(id) = find(irp) else { return false; };
    let owner = row(id);
    owner.flight == Flight::Dispatch
        && owner.irp_id == Some(irp)
        && owner.primary_device == Some(device)
        && owner.port_connect_control_storage.is_some()
        && owner.authorities.iter().all(|authority| authority.live())
}

fn release_projection_owners(id: u64) -> Result<(), nt_status::NtStatus> {
    for owner in &mut row(id).projection_owners {
        if owner.is_held() {
            io_manager_mut().release_hosted_device_projection_reference(owner)?;
        }
    }
    Ok(())
}

fn quarantine_release(id: u64, status: nt_status::NtStatus) {
    let owner = row(id);
    owner.flight = Flight::Blocked;
    owner.blocked_status = Some(status);
    owner.retry_after = 0;
    owner.work_ready = false;
}

fn remove(id: u64) -> Result<Row, nt_status::NtStatus> {
    let queue_head = queue_head_ticket(id);
    if let Err(status) = release_projection_owners(id) {
        quarantine_release(id, status);
        return Err(status);
    }
    let index = rows()
        .iter()
        .position(|row| row.id == id)
        .expect("File IRP owner missing");
    if let Err(status) =
        unsafe { crate::with_provider_process_manager(|pm| rows()[index].requestor.release(pm)) }
    {
        let status = nt_status::NtStatus(status as i32);
        quarantine_release(id, status);
        return Err(status);
    }
    let retired = rows().swap_remove(index);
    if let Some(ticket) = queue_head { queue_head_retired(ticket); }
    // No later control targets a retired owner's IRP, so the worker lane that entered it is
    // free for the next one, even when its terminal returned with no ACK.
    if let (Some(irp), Some(driver)) = (retired.irp_id, retired.primary_driver) {
        if let Some(authority) = retired.authorities.iter().copied()
            .find(|authority| authority.driver_id == driver.raw() && authority.live()) {
            unsafe { hosted_class_irp_lane::release_irp(authority.instance, irp.raw()) };
        }
        // A caller held on this IRP is released by ordinary completion delivery (#427).
        crate::service_sec_image::hosted_file_dispatch_returned(irp.raw());
    }
    Ok(retired)
}

fn reserve(
    caller: nt_process::native_handle::NativeHandleCaller,
    output_capture: ExternalFileIrpOutputCapture,
) -> Result<u64, nt_status::NtStatus> {
    let id = unsafe { NEXT_ID };
    let next = id
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    rows()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let requestor =
        unsafe { crate::with_provider_process_manager(|pm| pm.reference_native_requestor(caller)) }
            .map_err(|status| nt_status::NtStatus(status as i32))?;
    unsafe { NEXT_ID = next };
    rows().push(Row {
        caller,
        requestor,
        id,
        irp_id: None,
        primary_device: None,
        primary_driver: None,
        stack: Vec::new(),
        authorities: Vec::new(),
        projection_owners: Vec::new(),
        terminal_receipt: None,
        settled_buffers: None,
        completion_storage: None,
        port_connect_control_storage: None,
        hook_pump: None,
        hook_pump_claimed: false,
        plain_pump: None,
        proof_scope: None,
        recorded_generic_child_ran: None,
        flight: Flight::Preparing,
        payload: None,
        blocked_status: None,
        completion: None,
        output_capture,
        retry_after: 0,
        work_ready: false,
        phase_pump_ticks: 0,
        phase_bank_ticks: 0,
        phase_major: 0,
        queue_not_admitted: false,
        admission_receipt: AdmissionReceipt::EMPTY,
        queue_trace_emitted: false,
        nested_pnp_trace: false,
        nested_pnp_trace_count: 0,
        startup_probe_owed: false,
        startup_probe_phase: None,
        retired_probe_consumed: false,
        missing_domain_probe_consumed: false,
    });
    Ok(id)
}

fn add_authority(authorities: &mut Vec<Authority>, authority: Authority) {
    if !authorities.iter().any(|current| *current == authority) {
        // Capacity for the dependent and physical provider of every stack entry was reserved.
        assert!(authorities.len() < authorities.capacity());
        authorities.push(authority);
    }
}

fn capture_route(id: u64, prepared: &PreparedExternalFileIrp) -> Result<(), nt_status::NtStatus> {
    row(id).irp_id = Some(prepared.irp_id());
    row(id).primary_device = Some(prepared.route().device_id());
    row(id).primary_driver = Some(prepared.route().driver_id());
    let mut stack = Vec::new();
    {
        let irp = io_manager_mut()
            .irp(prepared.irp_id())
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        stack
            .try_reserve_exact(irp.stack.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        stack.extend(
            irp.stack
                .iter()
                .map(|entry| (entry.device_id, entry.driver_id)),
        );
    }
    let mut authorities = Vec::new();
    let capacity = stack
        .len()
        .checked_mul(2)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    authorities
        .try_reserve_exact(capacity)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let mut registrations = Vec::new();
    registrations
        .try_reserve_exact(stack.len())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    row(id)
        .projection_owners
        .try_reserve_exact(stack.len())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for (device_id, driver_id) in &stack {
        let Some((index, _)) = instance_by_driver_id(driver_id.raw()) else {
            continue;
        };
        let dependent =
            Authority::capture(index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        add_authority(&mut authorities, dependent);
        let provider_route = unsafe { hosted_provider_dispatch_route_for_instance(index) };
        let physical = if let Some(route) = provider_route {
            let provider = Authority::capture(route.provider_instance)
                .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
            if dependent.domain != route.dependent_domain
                || provider.domain != route.provider_domain
            {
                return Err(nt_status::NtStatus::INVALID_PARAMETER);
            }
            add_authority(&mut authorities, provider);
            provider
        } else {
            dependent
        };
        let registration = capture_projection_registration(
            *device_id,
            *driver_id,
            dependent,
            physical,
            provider_route.is_some(),
            prepared.irp_id(),
        )?;
        if !registrations.contains(&registration) {
            registrations.push(registration);
        }
    }
    if !authorities
        .iter()
        .any(|authority| authority.driver_id == prepared.route().driver_id().raw())
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    row(id).stack = stack;
    row(id).authorities = authorities;
    let (dependent, _) = instance_by_driver_id(prepared.route().driver_id().raw())
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    row(id).completion_storage = Some((dependent, hosted_completion_storage_instance(dependent)));
    // All ownership storage is reserved and every projection resolved before acquiring any pin.
    // These manager calls are outside foreign execution; publish each pin before the next refusal.
    for registration in registrations {
        let owner = io_manager_mut().retain_hosted_device_projection_reference(registration)?;
        row(id).projection_owners.push(owner);
    }
    Ok(())
}

fn capture_projection_registration(
    device: nt_io_manager::DeviceId,
    driver: nt_io_manager::DriverId,
    dependent: Authority,
    physical: Authority,
    provider_hosted: bool,
    exact_irp: IrpId,
) -> Result<nt_io_manager::HostedDevicePointerRegistration, nt_status::NtStatus> {
    if dependent.driver_id != driver.raw()
        || io_manager_mut()
            .device(device)
            .is_none_or(|record| record.driver_id != driver)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let address = if let Some(binding) = hosted_device_binding_by_device_id(device.raw()) {
        if binding.instance != dependent.instance
            || binding.driver_id != driver.raw()
            || binding.projection_instance != physical.instance
            || binding.projection_domain != physical.domain
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        binding.device_object
    } else {
        if provider_hosted {
            // A retained BusRelations query may authorize its exact child PDO before the
            // accepted-provider catalog is committed. The pending query checks its parent,
            // provider domain, physical pointer registration, and current invalidation owner;
            // the allocation check below still pins that same provider object.
            unsafe { hosted_provider_child_registration(device, physical.domain,
                Some(exact_irp)) }
                .filter(|registration| registration.device_id() == device)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?
                .address()
        } else {
            // Direct hosted devices use the canonical domain/address publication, not a guessed PDO.
            io_manager_mut()
                .hosted_device_address_by_identity(physical.domain, device)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?
        }
    };
    let registration = io_manager_mut()
        .hosted_device_pointer_registration(physical.domain, address)
        .filter(|registration| registration.device_id() == device)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let inst = instance(physical.instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if !physical.live()
        || hosted_device_allocations::registration(inst, address) != Ok(Some(registration))
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(registration)
}

fn live_route(id: u64) -> bool {
    !row(id).authorities.is_empty()
        && row(id).authorities.iter().all(|authority| authority.live())
        && row(id)
            .completion_storage
            .is_some_and(|(dependent, physical)| {
                hosted_completion_storage_instance(dependent) == physical
            })
}

fn block(id: u64, payload: Payload, status: nt_status::NtStatus) {
    let row = row(id);
    row.payload = Some(payload);
    row.flight = Flight::Blocked;
    row.blocked_status = Some(status);
    if let Some(irp) = row.irp_id {
        trace_nested_pnp_create_owner(3, id, irp);
    }
}

fn queue_head_ticket(id: u64) -> Option<QueueHeadTicket> {
    let (queued, authority) = {
        let owner = row(id);
        (owner.queue_not_admitted && owner.flight == Flight::QueuedDispatch,
            owner.admission_receipt.owner)
    };
    if !queued || queued_ahead(id) {
        return None;
    }
    let owner = authority.filter(|owner| owner.live())?;
    Some(QueueHeadTicket { id, owner })
}

fn queue_head_retired(ticket: QueueHeadTicket) {
    if !ticket.owner.live() || rows().iter().any(|row| {
        row.id == ticket.id && row.flight == Flight::QueuedDispatch
    }) {
        return;
    }
    // A cancelled preparation never occupied a lane. The next exact queued owner needs
    // its own retry observation even though no physical lane-free event occurred.
    if !rows().iter().any(|row| {
        row.id > ticket.id && row.queue_not_admitted
            && row.flight == Flight::QueuedDispatch
            && row.admission_receipt.owner == Some(ticket.owner)
    }) { return; }
    let Some(inst) = unsafe { driver_instances_mut() }.get_mut(ticket.owner.instance)
        .filter(|inst| inst.used && inst.driver_id == ticket.owner.driver_id
            && instance_domain_identity(**inst) == Some(ticket.owner.domain))
    else { return; };
    inst.file_worker_epoch = inst.file_worker_epoch.wrapping_add(1);
    LANE_EPOCH.fetch_add(1, Ordering::AcqRel);
}

fn keep(id: u64, payload: Payload) {
    let queue_head = queue_head_ticket(id);
    let row = row(id);
    row.payload = Some(payload);
    row.flight = Flight::Idle;
    row.blocked_status = None;
    row.retry_after = 0;
    // A held caller's dispatch has returned: pending (Retained) or completed (#427).
    if let Some(irp) = row.irp_id {
        trace_nested_pnp_create_owner(4, id, irp);
        crate::service_sec_image::hosted_file_dispatch_returned(irp.raw());
    }
    if let Some(ticket) = queue_head { queue_head_retired(ticket); }
}

fn retry_later(id: u64, payload: Payload, status: nt_status::NtStatus) {
    keep(id, payload);
    row(id).blocked_status = Some(status);
    row(id).retry_after = monotonic_time_100ns().saturating_add(1_000_000);
}

/// A definitive transport refusal owns its original preparation until the canonical failure
/// completion is published. Retrying this step never enters a backend or repeats the dispatch.
fn retry_no_entry(id: u64) -> Result<(), nt_status::NtStatus> {
    if row(id).flight != Flight::Idle {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let receipt = match row(id).payload.take() {
        Some(Payload::NoEntry(receipt)) => receipt,
        other => {
            row(id).payload = other;
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
    };
    match io_manager_mut().complete_external_file_irp_not_entered(receipt) {
        Ok(retained) => {
            keep(id, Payload::Retained(retained));
            Ok(())
        }
        Err(rejection) => {
            let (status, receipt) = rejection.into_parts();
            retry_later(id, Payload::NoEntry(receipt), status);
            Err(status)
        }
    }
}

fn discard(id: u64, prepared: PreparedExternalFileIrp) -> Result<(), nt_status::NtStatus> {
    match io_manager_mut().discard_prepared_external_file_irp(prepared) {
        Ok(buffers) => {
            row(id).settled_buffers = Some(buffers);
            remove(id).map(|_| ())
        }
        Err(rejection) => {
            let (status, owner) = rejection.into_parts();
            block(id, Payload::Prepared(owner), status);
            Err(status)
        }
    }
}

/// Move the entered manager invocation into its exact native File owner before the pump stack
/// unwinds. The caller must separately retain the physical pump continuation and Reply.
pub(super) fn suspend_dispatch_for_pump(
    irp_id: IrpId,
    invocation: ExternalFileIrpInvocation,
    key: ExternalFileIrpPumpKey,
    continuation: FileDispatchContinuation,
    hook: Option<(u64, nt_io_manager::DeviceId)>,
) -> Result<(), (nt_status::NtStatus, ExternalFileIrpInvocation,
    FileDispatchContinuation)> {
    let Some(id) = find(irp_id) else {
        return Err((nt_status::NtStatus::INVALID_HANDLE, invocation, continuation));
    };
    if invocation.irp_id() != irp_id || row(id).flight != Flight::Dispatch
        || row(id).payload.is_some()
    {
        return Err((nt_status::NtStatus::INVALID_HANDLE, invocation, continuation));
    }
    let suspended = match invocation.suspend_for_pump(key) {
        Ok(suspended) => suspended,
        Err(invocation) => {
            return Err((nt_status::NtStatus::INVALID_HANDLE, invocation, continuation));
        }
    };
    let owner = row(id);
    owner.payload = Some(Payload::PumpSuspended(SuspendedFilePumpOwner {
        invocation: suspended, continuation,
    }));
    if let Some((owner_id, device)) = hook {
        owner.hook_pump = Some(HookPumpIdentity {
            owner_id, device, initial_key: key, current_key: key,
        });
    } else if let Some(identity) = owner.hook_pump.as_mut() {
        identity.current_key = key;
    }
    owner.flight = Flight::PumpSuspended;
    if owner.hook_pump.is_some() { owner.hook_pump_claimed = false; }
    owner.recorded_generic_child_ran = None;
    crate::driver_launch::trace_port_connect_root_probe(70, irp_id.raw());
    Ok(())
}

/// Only the same manager, IRP, route, and native epoch may recover the invocation. A failed
/// check leaves it in the row; no I/O Manager outcome or provider completion is synthesized.
pub(super) fn resume_dispatch_from_pump(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
) -> Result<(ExternalFileIrpInvocation, FileDispatchContinuation),
    nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row(id).flight != Flight::PumpSuspended || !live_route(id) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let suspended = match row(id).payload.take() {
        Some(Payload::PumpSuspended(suspended)) => suspended,
        other => {
            row(id).payload = other;
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    };
    let SuspendedFilePumpOwner { invocation, continuation } = suspended;
    match invocation.resume(key) {
        Ok(invocation) => {
            row(id).flight = Flight::Dispatch;
            Ok((invocation, continuation))
        }
        Err(invocation) => {
            row(id).payload = Some(Payload::PumpSuspended(SuspendedFilePumpOwner {
                invocation, continuation,
            }));
            Err(nt_status::NtStatus::INVALID_HANDLE)
        }
    }
}

/// An uncertain native effect permanently fences replay while the exact File row keeps the
/// dispatched IRP. A separate, authenticated reconciliation must settle the I/O Manager owner.
pub(super) fn quarantine_dispatch_pump(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    status: nt_status::NtStatus,
) -> Result<(), nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row(id).flight != Flight::PumpSuspended || !status.is_error() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let mut suspended = match row(id).payload.take() {
        Some(Payload::PumpSuspended(suspended)) => suspended,
        other => {
            row(id).payload = other;
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    };
    let outcome = suspended.invocation.quarantine(key);
    row(id).payload = Some(Payload::PumpSuspended(suspended));
    outcome?;
    row(id).flight = Flight::Blocked;
    row(id).blocked_status = Some(status);
    Ok(())
}

pub(super) fn suspended_pump_child_ready(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
) -> bool {
    let Some(id) = find(irp_id) else { return false; };
    if row(id).flight != Flight::PumpSuspended || !live_route(id) {
        return false;
    }
    matches!(row(id).payload.as_ref(), Some(Payload::PumpSuspended(owner))
        if owner.invocation.key() == key && owner.continuation.child_work_ready())
}

pub(super) fn suspended_pump_restore_retryable(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
) -> bool {
    let Some(id) = find(irp_id) else { return false; };
    if row(id).flight != Flight::PumpSuspended { return false; }
    matches!(row(id).payload.as_ref(), Some(Payload::PumpSuspended(owner))
        if owner.invocation.key() == key
            && owner.continuation.retry_without_new_child())
}

pub(super) fn record_suspended_pump_child_step(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    step: crate::service_sec_image::NestedChildStep,
) -> Result<(), crate::service_sec_image::NestedChildStep> {
    let Some(id) = find(irp_id) else { return Err(step); };
    if row(id).flight != Flight::PumpSuspended {
        return Err(step);
    }
    let Some(Payload::PumpSuspended(owner)) = row(id).payload.as_mut() else {
        return Err(step);
    };
    if owner.invocation.key() != key { return Err(step); }
    owner.continuation.record_child_step(step)
}

pub(super) enum PortConnectPumpDrive {
    Returned(DispatchResult),
    Rejected(nt_status::NtStatus),
    Yielded { irp_id: IrpId, key: ExternalFileIrpPumpKey },
    Retained,
    Blocked,
    UnownedYield(PortConnectDispatchFailure),
    UnownedReturned(ExternalFileIrpReturn),
}

/// Resume only the receive half. The child receipt is already in the native continuation;
/// neither this method nor a retry may redispatch the original IRP or run another child.
pub(super) unsafe fn resume_suspended_port_connect_pump(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
) -> PortConnectPumpDrive {
    let (invocation, continuation) = match resume_dispatch_from_pump(irp_id, key) {
        Ok(owners) => owners,
        Err(status) => {
            let _ = quarantine_dispatch_pump(irp_id, key, status);
            return PortConnectPumpDrive::Blocked;
        }
    };
    let progress = continuation.resume_after_child(invocation);
    let yielded = match progress {
        Ok(hosted_file_dispatch::InvokeResult::Returned(returned)) => {
            let Some(id) = find(irp_id) else {
                // The exact File row must remain present until this manager return is settled.
                // A missing row is a fatal owner invariant, never a provider terminal status.
                return PortConnectPumpDrive::UnownedReturned(returned);
            };
            return match settle_returned_dispatch(id, irp_id, returned) {
                Ok(result) => PortConnectPumpDrive::Returned(result),
                Err(status) => PortConnectPumpDrive::Rejected(status),
            };
        }
        Ok(hosted_file_dispatch::InvokeResult::ChildWorkYield {
            invocation, key, continuation,
        }) => (invocation, Some(key), continuation, true, false),
        Ok(hosted_file_dispatch::InvokeResult::UnkeyedChildWorkYield {
            invocation, continuation,
        }) => (invocation, None, continuation, true, false),
        Err((invocation, continuation)) => {
            // A dispatch parked in its own wait again is live: it stays kept (#420, #427 A).
            let retryable = !matches!(nt_component_suspension::kept_dispatch_turn(
                continuation.retry_without_new_child(), continuation.awaiting_own_wake()),
                nt_component_suspension::KeptDispatchTurn::Fence);
            (invocation, Some(key), continuation, false, retryable)
        }
    };
    let (invocation, next_key, continuation, child_ready, retryable) = yielded;
    let Some(next_key) = next_key else {
        return PortConnectPumpDrive::UnownedYield(
            PortConnectDispatchFailure::UnownedYield {
                status: nt_status::NtStatus::INVALID_PARAMETER,
                invocation, continuation,
            },
        );
    };
    match suspend_dispatch_for_pump(irp_id, invocation, next_key, continuation, None) {
        Ok(()) if child_ready => PortConnectPumpDrive::Yielded { irp_id, key: next_key },
        Ok(()) if retryable => PortConnectPumpDrive::Retained,
        Ok(()) => {
            let _ = quarantine_dispatch_pump(
                irp_id, next_key, nt_status::NtStatus::UNSUCCESSFUL,
            );
            PortConnectPumpDrive::Blocked
        }
        Err((status, invocation, continuation)) => {
            PortConnectPumpDrive::UnownedYield(PortConnectDispatchFailure::UnownedYield {
                status, invocation, continuation,
            })
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenericFilePumpSelector {
    pub(super) row_id: u64,
    pub(super) irp_id: IrpId,
    pub(super) key: ExternalFileIrpPumpKey,
    pub(super) hook_owner_id: u64,
    pub(super) device: nt_io_manager::DeviceId,
}

pub(crate) enum GenericFilePumpDrive {
    NoWork,
    Returned,
    Pending,
    Yielded,
    AwaitingLocalChild,
    Retained,
    /// The pump returned with its lane still running after a scheduler yield. Its typed
    /// continuation is the only receiver for that lane; the root drives it again at once.
    SchedulerYielded,
    Blocked,
}

/// A refused post-child handoff still owns the one-use receipt or both physical owners.
enum OrphanedGenericFilePump {
    Step(GenericFilePumpSelector, crate::service_sec_image::NestedChildStep),
    Yield(GenericFilePumpSelector, ExternalFileIrpInvocation, FileDispatchContinuation),
    Return(GenericFilePumpSelector, ExternalFileIrpReturn),
}

static mut ORPHANED_GENERIC_FILE_PUMPS: Vec<OrphanedGenericFilePump> = Vec::new();

fn generic_orphans() -> &'static mut Vec<OrphanedGenericFilePump> {
    unsafe { &mut *core::ptr::addr_of_mut!(ORPHANED_GENERIC_FILE_PUMPS) }
}

fn generic_orphan_after(floor: u64) -> bool {
    generic_orphans().iter().any(|orphan| match orphan {
        OrphanedGenericFilePump::Step(selector, _)
        | OrphanedGenericFilePump::Yield(selector, _, _)
        | OrphanedGenericFilePump::Return(selector, _) => selector.row_id > floor,
    })
}

/// Capped boot probe for the exact Hook File resume. Stages: 1/2/3 recorded
/// entry/before/after; 10/11/12 native resume entry/before/after owner take;
/// 13/14/15 alias invocation entry/return/exit; 16 returned, 17 yielded,
/// 18 retryable refusal, 19 take refusal, 20 uncertain refusal, 21 scheduler yield with the
/// lane still running.
fn trace_generic_file_resume(stage: u64, selector: GenericFilePumpSelector) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 80 { return; }
    print_str(b"[hook-file-resume] stage/row/irp=");
    print_u64(stage); print_str(b"/");
    print_u64(selector.row_id); print_str(b"/0x");
    print_hex_u64(selector.irp_id.raw()); print_str(b"\n");
}

/// Root-only census of the newest Hook File row considered for a child step.
/// Flight: 1 preparing, 2 queued, 3 dispatch, 4 suspended, 5 returned,
/// 6 copy, 7 cancel, 8 acknowledge, 9 idle, 10 blocked.
fn trace_generic_file_selector(
    owner: &Row, orphaned: bool, reserved: bool, authorities_live: bool,
    key_matches: bool, child_ready: bool, retryable: bool, selected: bool,
) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 32 { return; }
    let flight = match owner.flight {
        Flight::Preparing => 1, Flight::QueuedDispatch => 2, Flight::Dispatch => 3,
        Flight::PumpSuspended => 4, Flight::PumpReturned => 5, Flight::Copy => 6,
        Flight::Cancel => 7, Flight::Acknowledge => 8, Flight::Idle => 9,
        Flight::Blocked => 10,
    };
    print_str(b"[hook-file-selector] row/irp/flight/claimed/authority/key/child/retry/orphan/reserve/selected=");
    print_u64(owner.id); print_str(b"/0x");
    print_hex_u64(owner.irp_id.map_or(0, |id| id.raw())); print_str(b"/");
    print_u64(flight); print_str(b"/");
    print_u64(u64::from(owner.hook_pump_claimed)); print_str(b"/");
    print_u64(u64::from(authorities_live)); print_str(b"/");
    print_u64(u64::from(key_matches)); print_str(b"/");
    print_u64(u64::from(child_ready)); print_str(b"/");
    print_u64(u64::from(retryable)); print_str(b"/");
    print_u64(u64::from(orphaned)); print_str(b"/");
    print_u64(u64::from(reserved)); print_str(b"/");
    print_u64(u64::from(selected)); print_str(b"\n");
}

fn trace_generic_file_no_candidate() {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if !hosted_input_hook_live::entered_port_source_unpublished() { return; }
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 256 { return; }
    print_str(b"[hook-file-selector-none] hook-row-count=");
    let count = rows().iter().filter(|owner| owner.hook_pump.is_some()).count();
    print_u64(count as u64); print_str(b"\n");
    for owner in rows().iter().filter(|owner| owner.hook_pump.is_some()).take(8) {
        let flight = match owner.flight {
            Flight::Preparing => 1, Flight::QueuedDispatch => 2, Flight::Dispatch => 3,
            Flight::PumpSuspended => 4, Flight::PumpReturned => 5, Flight::Copy => 6,
            Flight::Cancel => 7, Flight::Acknowledge => 8, Flight::Idle => 9,
            Flight::Blocked => 10,
        };
        print_str(b"[hook-file-selector-row] row/irp/flight/claimed=");
        print_u64(owner.id); print_str(b"/0x");
        print_hex_u64(owner.irp_id.map_or(0, |id| id.raw())); print_str(b"/");
        print_u64(flight); print_str(b"/");
        print_u64(u64::from(owner.hook_pump_claimed)); print_str(b"\n");
    }
}

pub(super) fn generic_file_owner_high_water() -> u64 {
    unsafe { NEXT_ID.saturating_sub(1) }
}

pub(super) fn generic_file_pump_unsettled_after(floor: u64) -> bool {
    generic_orphan_after(floor) || rows().iter().any(|owner| {
        owner.id > floor && owner.hook_pump.is_some()
            && matches!(owner.flight,
                Flight::PumpSuspended | Flight::PumpReturned | Flight::Blocked)
    })
}

pub(super) fn generic_file_pump_unsettled() -> bool {
    generic_file_pump_unsettled_after(0)
}

/// Claim the most recently created ready File child. A claimed parent cannot run a second
/// child; the sealed receipt is kept until any inner File child has settled.
pub(super) fn claim_suspended_generic_file_pump() -> Option<GenericFilePumpSelector> {
    claim_suspended_generic_file_pump_after(0)
}

pub(super) fn claim_suspended_generic_file_pump_after(
    floor: u64,
) -> Option<GenericFilePumpSelector> {
    let orphaned = generic_orphan_after(floor);
    let reserved = !orphaned && generic_orphans().try_reserve(1).is_ok();
    let index = rows().iter().enumerate()
        .filter(|(_, owner)| owner.id > floor && owner.hook_pump.is_some()
            && matches!(owner.flight,
                Flight::PumpSuspended | Flight::PumpReturned | Flight::Blocked))
        .max_by_key(|(_, owner)| owner.id).map(|(index, _)| index);
    let Some(index) = index else {
        trace_generic_file_no_candidate();
        return None;
    };
    let owner = rows().get_mut(index)?;
        let identity = owner.hook_pump?;
        let authorities_live = owner.authorities.iter().all(|a| a.live());
        let (key_matches, child_ready, retryable) =
            match owner.payload.as_ref() {
                Some(Payload::PumpSuspended(pump)) => (
                    pump.invocation.key() == identity.current_key,
                    pump.continuation.child_work_ready(),
                    pump.continuation.retry_without_new_child(),
                ),
                _ => (false, false, false),
            };
        let selected = !orphaned && reserved
            && owner.flight == Flight::PumpSuspended && !owner.hook_pump_claimed
            && owner.irp_id.is_some() && authorities_live && key_matches && child_ready;
        trace_generic_file_selector(owner, orphaned, reserved, authorities_live,
            key_matches, child_ready, retryable, selected);
        if !selected {
            return None;
        }
        owner.hook_pump_claimed = true;
        Some(GenericFilePumpSelector {
            row_id: owner.id,
            irp_id: owner.irp_id?,
            key: identity.current_key,
            hook_owner_id: identity.owner_id,
            device: identity.device,
        })
}

fn exact_generic_pump(selector: GenericFilePumpSelector) -> bool {
    rows().iter().any(|owner| {
        owner.id == selector.row_id && owner.irp_id == Some(selector.irp_id)
            && owner.hook_pump == Some(HookPumpIdentity {
                owner_id: selector.hook_owner_id,
                device: selector.device,
                initial_key: owner.hook_pump.map(|h| h.initial_key).unwrap_or(selector.key),
                current_key: selector.key,
            }) && owner.primary_device == Some(selector.device)
            && owner.flight == Flight::PumpSuspended && owner.hook_pump_claimed
    })
}

unsafe fn resume_generic_file_pump(
    selector: GenericFilePumpSelector,
) -> GenericFilePumpDrive {
    trace_generic_file_resume(10, selector);
    if !exact_generic_pump(selector) { return GenericFilePumpDrive::Blocked; }
    let recorded_child_ran = rows().iter().find(|owner| owner.id == selector.row_id)
        .and_then(|owner| owner.recorded_generic_child_ran);
    trace_generic_file_resume(11, selector);
    let (invocation, continuation) = match resume_dispatch_from_pump(selector.irp_id, selector.key) {
        Ok(owners) => owners,
        Err(status) => {
            trace_generic_file_resume(19, selector);
            let _ = quarantine_dispatch_pump(selector.irp_id, selector.key, status);
            return GenericFilePumpDrive::Blocked;
        }
    };
    trace_generic_file_resume(12, selector);
    if let Some(owner) = rows().iter_mut().find(|owner| owner.id == selector.row_id) {
        owner.recorded_generic_child_ran = None;
    }
    let mut owners = Some((invocation, continuation));
    let mut scheduler_yielded = false;
    let progress = hosted_input_hook_live::with_suspended_hook_alias(
        selector.irp_id,
        row(selector.row_id).hook_pump.map(|h| h.initial_key).unwrap_or(selector.key),
        selector.hook_owner_id, selector.device,
        || {
            trace_generic_file_resume(13, selector);
            let (invocation, continuation) = owners.take().expect("validated Hook pump owners");
            let result = continuation.resume_after_child(invocation);
            trace_generic_file_resume(14, selector);
            result
        },
    );
    trace_generic_file_resume(15, selector);
    let progress = match progress {
        Ok(progress) => progress,
        Err(_) => Err(owners.take().expect("refused alias preserved Hook pump owners")),
    };
    let (invocation, next_key, continuation, child_ready, retryable) = match progress {
        Ok(hosted_file_dispatch::InvokeResult::Returned(returned)) => {
            trace_generic_file_resume(16, selector);
            trace_file_return_probe(60, selector.irp_id);
            let Some(id) = find(selector.irp_id) else {
                generic_orphans().push(OrphanedGenericFilePump::Return(selector, returned));
                trace_file_return_probe(61, selector.irp_id);
                return GenericFilePumpDrive::Blocked;
            };
            let settled = settle_returned_dispatch(id, selector.irp_id, returned);
            trace_file_return_probe(62, selector.irp_id);
            return match settled {
                Ok(DispatchResult::Outstanding { .. }) if row(id).flight == Flight::PumpReturned =>
                    GenericFilePumpDrive::Returned,
                Ok(DispatchResult::Outstanding { .. }) if row(id).flight == Flight::Idle =>
                    GenericFilePumpDrive::Pending,
                Ok(_) | Err(_) => GenericFilePumpDrive::Blocked,
            };
        }
        Ok(hosted_file_dispatch::InvokeResult::ChildWorkYield {
            invocation, key, continuation,
        }) => {
            trace_generic_file_resume(17, selector);
            (invocation, key, continuation, true, false)
        },
        Ok(hosted_file_dispatch::InvokeResult::UnkeyedChildWorkYield {
            invocation, continuation,
        }) => {
            generic_orphans().push(OrphanedGenericFilePump::Yield(
                selector, invocation, continuation,
            ));
            return GenericFilePumpDrive::Blocked;
        }
        Err((invocation, continuation)) => {
            let retryable = continuation.retry_without_new_child();
            scheduler_yielded = continuation.scheduler_yield_pending();
            trace_generic_file_resume(
                if scheduler_yielded { 21 } else if retryable { 18 } else { 20 }, selector,
            );
            (invocation, selector.key, continuation, false, retryable)
        }
    };
    match suspend_dispatch_for_pump(selector.irp_id, invocation, next_key, continuation, None) {
        Ok(()) if child_ready => GenericFilePumpDrive::Yielded,
        Ok(()) if retryable => {
            if let Some(id) = find(selector.irp_id) {
                row(id).hook_pump_claimed = true;
                row(id).recorded_generic_child_ran = recorded_child_ran;
            }
            if scheduler_yielded {
                GenericFilePumpDrive::SchedulerYielded
            } else {
                GenericFilePumpDrive::Retained
            }
        }
        Ok(()) => {
            let _ = quarantine_dispatch_pump(
                selector.irp_id, next_key, nt_status::NtStatus::UNSUCCESSFUL,
            );
            GenericFilePumpDrive::Blocked
        }
        Err((_, invocation, continuation)) => {
            generic_orphans().push(OrphanedGenericFilePump::Yield(
                selector, invocation, continuation,
            ));
            GenericFilePumpDrive::Blocked
        }
    }
}

/// Seal one selected child observation in its exact File continuation before running any
/// dependency that child created. A refused deposit stays in the orphan row and cannot be
/// silently rerun or interpreted as a provider completion.
pub(super) fn record_suspended_generic_file_pump_child_step(
    selector: GenericFilePumpSelector,
    step: crate::service_sec_image::NestedChildStep,
) -> GenericFilePumpDrive {
    let ran_child = step.ran_child();
    generic_orphans().push(OrphanedGenericFilePump::Step(selector, step));
    if !exact_generic_pump(selector) { return GenericFilePumpDrive::Blocked; }
    let Some(index) = generic_orphans().iter().rposition(|orphan|
        matches!(orphan, OrphanedGenericFilePump::Step(key, _) if *key == selector)) else {
        return GenericFilePumpDrive::Blocked;
    };
    let OrphanedGenericFilePump::Step(_, step) = generic_orphans().remove(index) else {
        unreachable!("selected exact generic File child observation changed kind");
    };
    let Some(owner) = rows().iter_mut().find(|owner| owner.id == selector.row_id) else {
        generic_orphans().push(OrphanedGenericFilePump::Step(selector, step));
        return GenericFilePumpDrive::Blocked;
    };
    owner.recorded_generic_child_ran = Some(ran_child);
    if let Err(step) = record_suspended_pump_child_step(selector.irp_id, selector.key, step) {
        if let Some(owner) = rows().iter_mut().find(|owner| owner.id == selector.row_id) {
            owner.recorded_generic_child_ran = None;
        }
        generic_orphans().push(OrphanedGenericFilePump::Step(selector, step));
        return GenericFilePumpDrive::Blocked;
    }
    GenericFilePumpDrive::Retained
}

/// Resume only the already-recorded File child. The root must first settle any queued callback
/// or newer File pump created by that child; no second child selection occurs here.
pub(super) unsafe fn redrive_recorded_generic_file_pump(
    selector: GenericFilePumpSelector,
) -> GenericFilePumpDrive {
    trace_generic_file_resume(1, selector);
    if !exact_generic_pump(selector) { return GenericFilePumpDrive::Blocked; }
    let Some(ran_child) = rows().iter().find(|owner| owner.id == selector.row_id)
        .and_then(|owner| owner.recorded_generic_child_ran) else {
        return GenericFilePumpDrive::Blocked;
    };
    let recorded = rows().iter().find(|owner| owner.id == selector.row_id)
        .and_then(|owner| owner.payload.as_ref())
        .is_some_and(|payload| matches!(payload, Payload::PumpSuspended(pump)
            if pump.invocation.key() == selector.key
                && pump.continuation.retry_without_new_child()));
    if !recorded { return GenericFilePumpDrive::Blocked; }
    if generic_orphan_after(selector.row_id)
        || rows().iter().any(|owner| owner.id > selector.row_id
        && owner.hook_pump.is_some()
        && matches!(owner.flight,
            Flight::PumpSuspended | Flight::PumpReturned | Flight::Blocked))
    {
        return GenericFilePumpDrive::Yielded;
    }
    trace_generic_file_resume(2, selector);
    let result = resume_generic_file_pump(selector);
    trace_generic_file_resume(3, selector);
    match result {
        GenericFilePumpDrive::Yielded if !ran_child =>
            GenericFilePumpDrive::AwaitingLocalChild,
        progress => progress,
    }
}

pub(super) unsafe fn redrive_suspended_generic_file_pump(
    selector: GenericFilePumpSelector,
    step: crate::service_sec_image::NestedChildStep,
) -> GenericFilePumpDrive {
    match record_suspended_generic_file_pump_child_step(selector, step) {
        GenericFilePumpDrive::Retained =>
            redrive_recorded_generic_file_pump(selector),
        other => other,
    }
}

/// Select an already-sealed File receipt above a parked queue callback's owner floor.
/// The saved ran-child bit stays in the row across a no-effects physical restore retry.
pub(super) fn recorded_suspended_generic_file_pump_after(
    floor: u64,
) -> Option<GenericFilePumpSelector> {
    rows().iter().filter_map(|owner| {
        let identity = owner.hook_pump?;
        if owner.id <= floor || owner.flight != Flight::PumpSuspended
            || !owner.hook_pump_claimed || owner.recorded_generic_child_ran.is_none()
            || !owner.authorities.iter().all(|authority| authority.live())
            || generic_orphan_after(owner.id)
            || rows().iter().any(|inner| inner.id > owner.id
                && inner.hook_pump.is_some()
                && matches!(inner.flight,
                    Flight::PumpSuspended | Flight::PumpReturned | Flight::Blocked))
            || !matches!(owner.payload.as_ref(), Some(Payload::PumpSuspended(pump))
                if pump.invocation.key() == identity.current_key
                    && pump.continuation.retry_without_new_child())
        { return None; }
        Some(GenericFilePumpSelector {
            row_id: owner.id, irp_id: owner.irp_id?, key: identity.current_key,
            hook_owner_id: identity.owner_id, device: identity.device,
        })
    }).max_by_key(|selector| selector.row_id)
}

/// Retry only a sealed child receipt or a certified no-effect restore refusal.
pub(super) unsafe fn redrive_retryable_generic_file_pump() -> GenericFilePumpDrive {
    redrive_retryable_generic_file_pump_after(0)
}

pub(super) unsafe fn redrive_retryable_generic_file_pump_after(
    floor: u64,
) -> GenericFilePumpDrive {
    let selected = rows().iter().rev().find_map(|owner| {
        let identity = owner.hook_pump?;
        if owner.id <= floor || owner.flight != Flight::PumpSuspended
            || !owner.hook_pump_claimed
            || generic_orphan_after(owner.id)
            || rows().iter().any(|inner| inner.id > owner.id
                && inner.hook_pump.is_some()
                && matches!(inner.flight,
                    Flight::PumpSuspended | Flight::PumpReturned | Flight::Blocked))
            || !matches!(owner.payload.as_ref(), Some(Payload::PumpSuspended(pump))
                if pump.continuation.retry_without_new_child())
        { return None; }
        Some(GenericFilePumpSelector {
            row_id: owner.id, irp_id: owner.irp_id?, key: identity.current_key,
            hook_owner_id: identity.owner_id, device: identity.device,
        })
    });
    selected.map_or(GenericFilePumpDrive::NoWork, |selector| {
        if rows().iter().any(|owner| owner.id == selector.row_id
            && owner.recorded_generic_child_ran.is_some())
        {
            redrive_recorded_generic_file_pump(selector)
        } else {
            resume_generic_file_pump(selector)
        }
    })
}

pub(super) enum DispatchResult {
    Returned {
        irp_id: IrpId,
        status: nt_status::NtStatus,
        information: u64,
        file_context: Option<u64>,
        buffers: ExternalFileIrpBuffers,
    },
    Outstanding {
        irp_id: IrpId,
    },
}

/// An ordinary caller's dispatch (#420).
#[must_use = "a suspended pump's selector is the only way to collect its return"]
pub(super) enum PlainDispatch {
    Ready(DispatchResult),
    /// The native pump stopped unfinished with no lane to keep it. The row keeps the
    /// continuation; the caller keeps this selector and collects the true return later with
    /// [`collect_pump_returned`]. Nothing has completed yet.
    PumpSuspended {
        irp_id: IrpId,
        key: ExternalFileIrpPumpKey,
    },
}

/// What an ordinary caller's later collection found.
pub(super) enum PumpCollect {
    /// The pump is still unfinished; collect again on a later turn.
    Pending,
    /// The pump returned; this is the dispatch's true result.
    Collected(Result<DispatchResult, nt_status::NtStatus>),
}

enum DispatchFailure<Yield> {
    Status(nt_status::NtStatus),
    Yield(Yield),
}

impl<Yield> From<nt_status::NtStatus> for DispatchFailure<Yield> {
    fn from(status: nt_status::NtStatus) -> Self { Self::Status(status) }
}

enum PortConnectYield {
    Keyed {
        invocation: ExternalFileIrpInvocation,
        key: ExternalFileIrpPumpKey,
        continuation: FileDispatchContinuation,
    },
    Unkeyed {
        invocation: ExternalFileIrpInvocation,
        continuation: FileDispatchContinuation,
    },
}

pub(super) enum PortConnectDispatchResult {
    Returned(DispatchResult),
    PumpSuspended { irp_id: IrpId, key: ExternalFileIrpPumpKey },
}

pub(super) enum HookDispatchResult {
    Returned(DispatchResult),
    PumpSuspended { irp_id: IrpId, key: ExternalFileIrpPumpKey },
}

/// A refusal after native entry still owns both the manager invocation and physical pump.
pub(super) type HookDispatchFailure = PortConnectDispatchFailure;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HookPumpState {
    Suspended,
    Returned,
    Pending,
    Blocked,
}

pub(super) fn hook_pump_state(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    hook_owner_id: u64,
    device: nt_io_manager::DeviceId,
) -> Result<HookPumpState, nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !exact_hook_owner(id, hook_owner_id, device, key) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    if matches!(row(id).payload.as_ref(), Some(Payload::HookReturned(_))) {
        return Ok(HookPumpState::Returned);
    }
    Ok(match row(id).flight {
        Flight::PumpSuspended => HookPumpState::Suspended,
        Flight::PumpReturned => HookPumpState::Returned,
        Flight::Blocked => HookPumpState::Blocked,
        _ => HookPumpState::Pending,
    })
}

/// Retain the monotonic File owner boundary on the exact Hook source before its
/// terminal can retire the File row. Numeric IRP identity alone is insufficient.
pub(super) fn hook_pump_owner_row_id(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    hook_owner_id: u64,
    device: nt_io_manager::DeviceId,
) -> Result<u64, nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !exact_hook_owner(id, hook_owner_id, device, key) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok(id)
}

fn exact_hook_owner(
    id: u64, owner_id: u64, device: nt_io_manager::DeviceId,
    initial_key: ExternalFileIrpPumpKey,
) -> bool {
    row(id).primary_device == Some(device)
        && row(id).hook_pump.is_some_and(|identity| {
            identity.owner_id == owner_id && identity.device == device
                && identity.initial_key == initial_key
        })
}

/// Read the provider's real terminal while its canonical IRP remains available for Hook's
/// separate source observation. No manager owner or File row is consumed by this copy.
pub(super) fn peek_returned_hook_pump(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    hook_owner_id: u64,
    device: nt_io_manager::DeviceId,
    updated: &mut [u8],
) -> Result<Option<(nt_status::NtStatus, u64, Option<u64>)>, nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !exact_hook_owner(id, hook_owner_id, device, key) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let Some(Payload::HookReturned(returned)) = row(id).payload.as_ref() else {
        return Ok(None);
    };
    let HookReturnedState::Terminal(terminal) = &returned.state else {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    };
    let input = terminal.buffers().input();
    if updated.len() != input.len() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    updated.copy_from_slice(input);
    let completion = terminal.completion();
    Ok(Some((completion.status, completion.information, completion.file_context)))
}

/// Hook records this only after it validates the canonical completion against its own source.
pub(super) fn mark_returned_hook_pump_observed(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    hook_owner_id: u64,
    device: nt_io_manager::DeviceId,
) -> Result<(), nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !exact_hook_owner(id, hook_owner_id, device, key) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let Some(Payload::HookReturned(returned)) = row(id).payload.as_mut() else {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    };
    returned.observed = true;
    Ok(())
}

/// Return the actual Type3 input only to its exact Hook source. Failed retirement leaves the
/// terminal and buffers in this File row for a later no-replay retry.
pub(super) fn take_returned_hook_pump(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    hook_owner_id: u64,
    device: nt_io_manager::DeviceId,
) -> Result<Option<DispatchResult>, nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !exact_hook_owner(id, hook_owner_id, device, key) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    if !matches!(row(id).payload.as_ref(), Some(Payload::HookReturned(_))) {
        return Ok(None);
    }
    if !matches!(row(id).payload.as_ref(), Some(Payload::HookReturned(returned)) if returned.observed) {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let Some(Payload::HookReturned(returned)) = row(id).payload.take() else {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    };
    let state = match returned.state {
        HookReturnedState::Terminal(terminal) => {
            let completion = *terminal.completion();
            match io_manager_mut().retire_external_file_irp_terminal(terminal) {
                Ok((receipt, buffers)) => {
                    row(id).terminal_receipt = Some(receipt);
                    HookReturnedState::Retired { completion, buffers }
                }
                Err(rejection) => {
                    let (status, terminal) = rejection.into_parts();
                    row(id).payload = Some(Payload::HookReturned(HookReturned {
                        state: HookReturnedState::Terminal(terminal), observed: returned.observed,
                    }));
                    row(id).blocked_status = Some(status);
                    return Err(status);
                }
            }
        }
        retired @ HookReturnedState::Retired { .. } => retired,
    };
    row(id).payload = Some(Payload::HookReturned(HookReturned {
        state, observed: returned.observed,
    }));
    let mut retired = remove(id)?;
    let Some(Payload::HookReturned(returned)) = retired.payload.take() else {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    };
    let HookReturnedState::Retired { completion, buffers } = returned.state else {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    };
    Ok(Some(DispatchResult::Returned {
        irp_id,
        status: completion.status,
        information: completion.information,
        file_context: completion.file_context,
        buffers,
    }))
}

/// Only the mutable METHOD_NEITHER hook path has a native continuation for nested work.
/// Other File policies keep their existing dispatch contract.
pub(super) fn dispatch_mutable_method_neither_suspend_aware(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    device: nt_io_manager::DeviceId,
    hook_owner_id: u64,
) -> Result<HookDispatchResult, HookDispatchFailure> {
    let result = dispatch_with_port_connect(
        caller, request, input, &[],
        ExternalFileIrpDispatchPolicy::MutableMethodNeitherInputAtDevice,
        None,
        Admission::Refuse,
        |invocation, caller, capture| {
            match hosted_file_dispatch::invoke_suspend_aware(invocation, caller, capture) {
                hosted_file_dispatch::InvokeResult::Returned(returned) => Ok(returned),
                hosted_file_dispatch::InvokeResult::ChildWorkYield {
                    invocation, key, continuation,
                } => Err(PortConnectYield::Keyed { invocation, key, continuation }),
                hosted_file_dispatch::InvokeResult::UnkeyedChildWorkYield {
                    invocation, continuation,
                } => Err(PortConnectYield::Unkeyed { invocation, continuation }),
            }
        },
    );
    match result {
        Ok(returned) => Ok(HookDispatchResult::Returned(returned)),
        Err(DispatchFailure::Status(status)) => Err(HookDispatchFailure::Status(status)),
        Err(DispatchFailure::Yield(PortConnectYield::Keyed {
            invocation, key, continuation,
        })) => {
            let irp_id = invocation.irp_id();
            match suspend_dispatch_for_pump(
                irp_id, invocation, key, continuation, Some((hook_owner_id, device)),
            ) {
                Ok(()) => Ok(HookDispatchResult::PumpSuspended { irp_id, key }),
                Err((status, invocation, continuation)) =>
                    Err(HookDispatchFailure::UnownedYield { status, invocation, continuation }),
            }
        }
        Err(DispatchFailure::Yield(PortConnectYield::Unkeyed {
            invocation, continuation,
        })) => Err(HookDispatchFailure::UnownedYield {
            status: nt_status::NtStatus::INVALID_PARAMETER,
            invocation, continuation,
        }),
    }
}

#[must_use = "retain an unowned native yield; it cannot be mapped to a status"]
pub(super) enum PortConnectDispatchFailure {
    Status(nt_status::NtStatus),
    UnownedYield {
        status: nt_status::NtStatus,
        invocation: ExternalFileIrpInvocation,
        continuation: FileDispatchContinuation,
    },
}

/// Exact-device callers must authenticate and retain their Device and completion recipient.
pub(super) fn dispatch(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
) -> Result<PlainDispatch, nt_status::NtStatus> {
    let result = dispatch_with_port_connect(
        caller, request, input, initial_output, policy, None, Admission::Refuse, invoke_retaining,
    );
    match result {
        Ok(result) => Ok(PlainDispatch::Ready(result)),
        Err(DispatchFailure::Status(status)) => Err(status),
        Err(DispatchFailure::Yield(PortConnectYield::Keyed {
            invocation, key, continuation,
        })) => {
            let irp_id = invocation.irp_id();
            match suspend_dispatch_for_pump(irp_id, invocation, key, continuation, None) {
                Ok(()) => {
                    if let Some(id) = find(irp_id) {
                        row(id).plain_pump = Some(nt_hosted_runtime::KeptFilePump::Suspended(key));
                    }
                    trace_plain_pump(b"suspended", irp_id);
                    Ok(PlainDispatch::PumpSuspended { irp_id, key })
                }
                Err((status, invocation, continuation)) => Ok(PlainDispatch::Ready(
                    orphan_plain_pump(irp_id, status, invocation, continuation))),
            }
        }
        Err(DispatchFailure::Yield(PortConnectYield::Unkeyed {
            invocation, continuation,
        })) => {
            let irp_id = invocation.irp_id();
            Ok(PlainDispatch::Ready(orphan_plain_pump(irp_id,
                nt_status::NtStatus::INVALID_PARAMETER, invocation, continuation)))
        }
    }
}

/// The native dispatch for a caller that keeps an unfinished pump (#420).
fn invoke_retaining(
    invocation: ExternalFileIrpInvocation,
    caller: nt_process::native_handle::NativeHandleCaller,
    capture: ExternalFileIrpOutputCapture,
) -> Result<ExternalFileIrpReturn, PortConnectYield> {
    match hosted_file_dispatch::invoke_retaining(invocation, caller, capture) {
        hosted_file_dispatch::InvokeResult::Returned(returned) => Ok(returned),
        hosted_file_dispatch::InvokeResult::ChildWorkYield { invocation, key, continuation } =>
            Err(PortConnectYield::Keyed { invocation, key, continuation }),
        hosted_file_dispatch::InvokeResult::UnkeyedChildWorkYield { invocation, continuation } =>
            Err(PortConnectYield::Unkeyed { invocation, continuation }),
    }
}

/// A row caller's selector for its kept pump (#420).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct KeptPumpSelector {
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
}

/// What a row caller's turn found for its kept pump.
pub(super) enum KeptCollect {
    /// No pump is kept: the caller dispatches as usual.
    Absent,
    /// The kept pump is still unfinished; the caller's turn ends with no other effect.
    Pending,
    /// The kept pump returned: the dispatch's true result, exactly once.
    Collected(Result<DispatchResult, nt_status::NtStatus>),
}

/// Run first in a row caller's dispatch turn, before any other effect.
pub(super) fn collect_kept(kept: &mut Option<KeptPumpSelector>) -> KeptCollect {
    let Some(selector) = *kept else { return KeptCollect::Absent };
    match collect_pump_returned(selector.irp_id, selector.key) {
        PumpCollect::Pending => KeptCollect::Pending,
        PumpCollect::Collected(result) => {
            *kept = None;
            KeptCollect::Collected(result)
        }
    }
}

/// Keep a suspended dispatch's selector in the caller's row; a ready result passes through.
pub(super) fn keep_or_ready(
    kept: &mut Option<KeptPumpSelector>, dispatched: Result<PlainDispatch, nt_status::NtStatus>,
) -> Option<Result<DispatchResult, nt_status::NtStatus>> {
    match dispatched {
        Ok(PlainDispatch::Ready(result)) => Some(Ok(result)),
        Ok(PlainDispatch::PumpSuspended { irp_id, key }) => {
            *kept = Some(KeptPumpSelector { irp_id, key });
            None
        }
        Err(status) => Some(Err(status)),
    }
}

/// A caller that accepts `STATUS_PENDING` but has no row of its own (#420). A pump that stops
/// unfinished stays in the File row with deferred completion, and the caller gets
/// `Outstanding`: the dispatch is still running. The root boundary resumes the pump, and its
/// return is published as the IRP's ordinary completion, the one the caller's pending owner
/// reads. A dispatch under a scoped SCSI proof authority keeps that exact scope with its pump,
/// which resumes only under it.
pub(super) fn dispatch_deferring(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
) -> Result<DispatchResult, nt_status::NtStatus> {
    dispatch_deferring_with(caller, request, input, initial_output, policy, Admission::Refuse)
}

/// [`dispatch_deferring`] for a syscall caller, whose STATUS_PENDING is published before any
/// provider runs again: an IRP no lane admits waits in this row (#427), never failing busy.
pub(super) fn dispatch_deferring_queued(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
) -> Result<DispatchResult, nt_status::NtStatus> {
    // A scoped SCSI proof authorizes only its own frame; such an IRP is never queued.
    let admission = if unsafe { pending_scsi_proof_slot() }.is_some() {
        Admission::Refuse
    } else {
        Admission::Queue
    };
    dispatch_deferring_with(caller, request, input, initial_output, policy, admission)
}

fn dispatch_deferring_with(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
    admission: Admission,
) -> Result<DispatchResult, nt_status::NtStatus> {
    match dispatch_with_port_connect(
        caller, request, input, initial_output, policy, None, admission, invoke_retaining,
    ) {
        Ok(result) => Ok(result),
        Err(DispatchFailure::Status(status)) => Err(status),
        Err(DispatchFailure::Yield(PortConnectYield::Keyed { invocation, key, continuation })) => {
            let irp_id = invocation.irp_id();
            // The caller's scope is still active here; its guard ends with the caller's frame.
            let scope = unsafe { pending_scsi_proof_slot() };
            if scope.is_some_and(|scope| scope.irp_id != Some(irp_id)) {
                // A scope bound to another IRP cannot authorize this pump's resume.
                return Ok(orphan_plain_pump(irp_id, nt_status::NtStatus::INVALID_PARAMETER,
                    invocation, continuation));
            }
            let _ = defer_pump(irp_id, invocation, key, continuation, scope);
            Ok(DispatchResult::Outstanding { irp_id })
        }
        Err(DispatchFailure::Yield(PortConnectYield::Unkeyed { invocation, continuation })) => {
            let irp_id = invocation.irp_id();
            Ok(orphan_plain_pump(irp_id, nt_status::NtStatus::INVALID_PARAMETER,
                invocation, continuation))
        }
    }
}

/// Keep an unfinished pump for a caller with no row (#420). `Err` is an orphaned owner: the row
/// is fenced and keeps the IRP.
fn defer_pump(
    irp_id: IrpId,
    invocation: ExternalFileIrpInvocation,
    key: ExternalFileIrpPumpKey,
    continuation: FileDispatchContinuation,
    scope: Option<ActivePendingScsiProofAuthority>,
) -> Result<(), nt_status::NtStatus> {
    match suspend_dispatch_for_pump(irp_id, invocation, key, continuation, None) {
        Ok(()) => {
            if let Some(id) = find(irp_id) {
                row(id).plain_pump = Some(nt_hosted_runtime::KeptFilePump::DeferredCompletion);
                row(id).proof_scope = scope;
            }
            trace_plain_pump(b"deferred", irp_id);
            Ok(())
        }
        Err((status, invocation, continuation)) => {
            let _ = orphan_plain_pump(irp_id, status, invocation, continuation);
            Err(status)
        }
    }
}

/// Entered native owners nothing can key or park: an impossible malformed epoch, or a row
/// that no longer accepts the suspension. Both owners are kept and never resumed; the row is
/// fenced as an uncertain native effect is, and its caller keeps waiting on it.
static mut ORPHANED_PLAIN_PUMPS: Vec<(ExternalFileIrpInvocation, FileDispatchContinuation)> =
    Vec::new();

fn orphan_plain_pump(
    irp_id: IrpId, status: nt_status::NtStatus,
    invocation: ExternalFileIrpInvocation, continuation: FileDispatchContinuation,
) -> DispatchResult {
    trace_plain_pump(b"orphaned", irp_id);
    let orphans = unsafe { &mut *core::ptr::addr_of_mut!(ORPHANED_PLAIN_PUMPS) };
    if orphans.try_reserve(1).is_ok() { orphans.push((invocation, continuation)); }
    if let Some(id) = find(irp_id) {
        row(id).flight = Flight::Blocked;
        row(id).blocked_status = Some(status);
    }
    DispatchResult::Outstanding { irp_id }
}

fn trace_plain_pump(stage: &[u8], irp_id: IrpId) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 32 && !n.is_power_of_two() { return; }
    print_str(b"[file-plain-pump] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" irp=0x");
    print_hex_u64(irp_id.raw());
    print_str(b"\n");
}

/// A row's own caller collects its kept pump. A still-unfinished pump is `Pending`; a returned
/// one is retired here, exactly once, and its true result handed over. A return that left the
/// IRP provider-pending (or fenced) is `Outstanding`, the ordinary pending contract.
pub(super) fn collect_pump_returned(irp_id: IrpId, key: ExternalFileIrpPumpKey) -> PumpCollect {
    let Some(id) = find(irp_id) else {
        return PumpCollect::Collected(Err(take_plain_refusal(irp_id)
            .unwrap_or(nt_status::NtStatus::INVALID_HANDLE)));
    };
    let suspended = row(id).flight == Flight::PumpSuspended;
    match nt_hosted_runtime::KeptFilePump::collect(&mut row(id).plain_pump, key) {
        nt_hosted_runtime::FilePumpCollect::Pending if suspended => PumpCollect::Pending,
        // The resumed pump returned provider-pending (or was fenced): the ordinary contract.
        nt_hosted_runtime::FilePumpCollect::Pending => {
            row(id).plain_pump = None;
            PumpCollect::Collected(Ok(DispatchResult::Outstanding { irp_id }))
        }
        nt_hosted_runtime::FilePumpCollect::Collected(terminal) => {
            row(id).flight = Flight::Dispatch;
            PumpCollect::Collected(Ok(retire_returned_terminal(id, irp_id, terminal)))
        }
        nt_hosted_runtime::FilePumpCollect::Mismatch =>
            PumpCollect::Collected(Err(nt_status::NtStatus::INVALID_HANDLE)),
    }
}

/// A resumed pump the manager reported as never entered: its row is gone, so its status waits
/// here for the caller's collection.
static mut PLAIN_REFUSALS: Vec<(IrpId, nt_status::NtStatus)> = Vec::new();

fn take_plain_refusal(irp_id: IrpId) -> Option<nt_status::NtStatus> {
    let refusals = unsafe { &mut *core::ptr::addr_of_mut!(PLAIN_REFUSALS) };
    let index = refusals.iter().position(|(id, _)| *id == irp_id)?;
    Some(refusals.swap_remove(index).1)
}

/// Root boundary only: continue each ordinary row's kept pump once (#420). A return stays in
/// the row for its caller; a no-effect refusal keeps the pump; an uncertain one is fenced.
pub(super) unsafe fn redrive_plain_suspended_pumps() -> usize {
    let count = rows().iter().filter(|owner| owner.flight == Flight::PumpSuspended
        && matches!(owner.plain_pump, Some(nt_hosted_runtime::KeptFilePump::Suspended(_)
            | nt_hosted_runtime::KeptFilePump::DeferredCompletion)))
        .count();
    let mut selected = Vec::new();
    if count == 0 || selected.try_reserve(count).is_err() { return 0; }
    selected.extend(rows().iter().filter_map(|owner| {
        // A kept pump is resumed under its current native key (crate policy).
        let Some(Payload::PumpSuspended(pump)) = owner.payload.as_ref() else { return None };
        let key = owner.plain_pump.as_ref()?.resume_key(pump.invocation.key())?;
        let retryable = owner.flight == Flight::PumpSuspended
            && pump.continuation.retry_without_new_child();
        if retryable { Some((owner.irp_id?, key, owner.proof_scope)) } else { None }
    }));
    let mut progressed = 0;
    for (irp_id, key, scope) in selected {
        // A pump resumes only under the exact scope it was entered with (crate policy).
        let scope_guard = match nt_hosted_runtime::scoped_resume(pending_scsi_proof_slot(), scope) {
            nt_hosted_runtime::ScopedResume::Resume => None,
            nt_hosted_runtime::ScopedResume::RestoreThenResume(scope) =>
                match restore_pending_scsi_proof_scope(scope) {
                    Ok(guard) => Some(guard),
                    Err(_) => continue,
                },
            nt_hosted_runtime::ScopedResume::Wait => continue,
        };
        let drive = resume_suspended_port_connect_pump(irp_id, key);
        if scope_guard.is_some() {
            // A pump that stopped again keeps the scope as it now stands (its one-shot claim).
            if let Some(id) = find(irp_id).filter(|id| row(*id).flight == Flight::PumpSuspended) {
                row(id).proof_scope = pending_scsi_proof_slot();
            }
        }
        drop(scope_guard);
        match drive {
            PortConnectPumpDrive::Returned(_) => {
                trace_plain_pump(b"returned", irp_id);
                progressed += 1;
            }
            PortConnectPumpDrive::Retained | PortConnectPumpDrive::Yielded { .. } => {}
            PortConnectPumpDrive::Blocked => trace_plain_pump(b"fenced", irp_id),
            PortConnectPumpDrive::Rejected(status) => {
                let refusals = &mut *core::ptr::addr_of_mut!(PLAIN_REFUSALS);
                if refusals.try_reserve(1).is_ok() { refusals.push((irp_id, status)); }
                progressed += 1;
            }
            PortConnectPumpDrive::UnownedYield(PortConnectDispatchFailure::UnownedYield {
                status, invocation, continuation,
            }) => { let _ = orphan_plain_pump(irp_id, status, invocation, continuation); }
            PortConnectPumpDrive::UnownedYield(PortConnectDispatchFailure::Status(_))
            | PortConnectPumpDrive::UnownedReturned(_) => trace_plain_pump(b"unowned", irp_id),
        }
    }
    progressed
}

pub(super) fn dispatch_port_connect(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    device: nt_io_manager::DeviceId,
) -> Result<PortConnectDispatchResult, PortConnectDispatchFailure> {
    let result = dispatch_with_port_connect(
        caller, request, input, &[],
        ExternalFileIrpDispatchPolicy::MutableMethodNeitherInputAtDevice,
        Some(device),
        Admission::Refuse,
        |invocation, caller, capture| {
            match hosted_file_dispatch::invoke_suspend_aware(invocation, caller, capture) {
                hosted_file_dispatch::InvokeResult::Returned(returned) => Ok(returned),
                hosted_file_dispatch::InvokeResult::ChildWorkYield {
                    invocation, key, continuation,
                } => Err(PortConnectYield::Keyed { invocation, key, continuation }),
                hosted_file_dispatch::InvokeResult::UnkeyedChildWorkYield {
                    invocation, continuation,
                } => Err(PortConnectYield::Unkeyed { invocation, continuation }),
            }
        },
    );
    match result {
        Ok(returned) => Ok(PortConnectDispatchResult::Returned(returned)),
        Err(DispatchFailure::Status(status)) => Err(PortConnectDispatchFailure::Status(status)),
        Err(DispatchFailure::Yield(PortConnectYield::Keyed {
            invocation, key, continuation,
        })) => {
            let irp_id = invocation.irp_id();
            match suspend_dispatch_for_pump(irp_id, invocation, key, continuation, None) {
                Ok(()) => Ok(PortConnectDispatchResult::PumpSuspended { irp_id, key }),
                Err((status, invocation, continuation)) => {
                    Err(PortConnectDispatchFailure::UnownedYield {
                        status, invocation, continuation,
                    })
                }
            }
        }
        Err(DispatchFailure::Yield(PortConnectYield::Unkeyed {
            invocation, continuation,
        })) => Err(PortConnectDispatchFailure::UnownedYield {
            status: nt_status::NtStatus::INVALID_PARAMETER,
            invocation, continuation,
        }),
    }
}

fn trace_port_connect_dispatch(stage: u64, irp: IrpId, device: nt_io_manager::DeviceId) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    print_str(b"[port-connect-dispatch] stage/irp/device=");
    print_u64(stage);
    print_str(b"/");
    print_hex_u64(irp.raw());
    print_str(b"/");
    print_hex_u64(device.raw());
    print_str(b"\n");
}

/// Bounded, read-only owner transition probe for mutable METHOD_NEITHER returns.
fn trace_file_return_probe(stage: u64, irp: IrpId) {
    trace_file_return_probe_status(stage, irp, None);
}

fn trace_file_return_probe_status(
    stage: u64, irp: IrpId, status: Option<nt_status::NtStatus>,
) {
    let owner = rows().iter().find(|owner| owner.irp_id == Some(irp));
    if owner.is_some_and(|owner| owner.output_capture
        != ExternalFileIrpOutputCapture::MethodNeitherInput) {
        return;
    }
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 512 { return; }
    let (row_id, flight, hook, payload) = owner.map_or((0, u64::MAX, 0, 0), |owner| {
        let flight = match owner.flight {
            Flight::Preparing => 1,
            Flight::QueuedDispatch => 2,
            Flight::Dispatch => 3,
            Flight::PumpSuspended => 4,
            Flight::PumpReturned => 5,
            Flight::Copy => 6,
            Flight::Cancel => 7,
            Flight::Acknowledge => 8,
            Flight::Idle => 9,
            Flight::Blocked => 10,
        };
        let payload = match owner.payload.as_ref() {
            None => 0,
            Some(Payload::Returned(_)) => 1,
            Some(Payload::PumpSuspended(_)) => 2,
            Some(Payload::HookReturned(_)) => 3,
            Some(Payload::Retained(_)) => 4,
            Some(Payload::Terminal(_)) => 5,
            Some(_) => 6,
        };
        (owner.id, flight, u64::from(owner.hook_pump.is_some()), payload)
    });
    print_str(b"[file-return-probe] stage/irp/row/flight/hook/payload/status=");
    print_u64(stage); print_str(b"/");
    print_hex_u64(irp.raw()); print_str(b"/");
    print_u64(row_id); print_str(b"/");
    print_u64(flight); print_str(b"/");
    print_u64(hook); print_str(b"/");
    print_u64(payload); print_str(b"/");
    print_hex_u64(status.map_or(0, |status| status.raw() as u32 as u64));
    print_str(b"\n");
}

/// A root-owned CREATE row is moved through File dispatch while the source PnP START
/// remains entered. Sample only this canonical row at its own transitions, never from
/// the enclosed provider pump or by matching a copied component pointer.
fn trace_nested_pnp_create_owner(stage: u64, id: u64, irp: IrpId) {
    let owner = row(id);
    if !owner.nested_pnp_trace || owner.irp_id != Some(irp)
        || owner.phase_major != major::IRP_MJ_CREATE { return; }
    // Each selected row gets its own bounded receipts, so earlier CREATEs cannot
    // consume the stalled row's entire diagnostic budget.
    if owner.nested_pnp_trace_count >= 8 { return; }
    owner.nested_pnp_trace_count += 1;
    let flight = match owner.flight {
        Flight::Preparing => 1, Flight::QueuedDispatch => 2, Flight::Dispatch => 3,
        Flight::PumpSuspended => 4, Flight::PumpReturned => 5, Flight::Copy => 6,
        Flight::Cancel => 7, Flight::Acknowledge => 8, Flight::Idle => 9,
        Flight::Blocked => 10,
    };
    let payload = match owner.payload.as_ref() {
        None => 0, Some(Payload::Prepared(_)) => 1, Some(Payload::NoEntry(_)) => 2,
        Some(Payload::Returned(_)) => 3, Some(Payload::PumpSuspended(_)) => 4,
        Some(Payload::HookReturned(_)) => 5, Some(Payload::Retained(_)) => 6,
        Some(Payload::Completion(_)) => 7, Some(Payload::Acknowledgement(_)) => 8,
        Some(Payload::Copy(_)) => 9, Some(Payload::Cancel(_)) => 10,
        Some(Payload::Terminal(_)) => 11,
    };
    let pump = match owner.plain_pump.as_ref() {
        None => 0, Some(nt_hosted_runtime::KeptFilePump::Suspended(_)) => 1,
        Some(nt_hosted_runtime::KeptFilePump::Returned(_, _)) => 2,
        Some(nt_hosted_runtime::KeptFilePump::DeferredCompletion) => 3,
    };
    let authority = owner.authorities.iter().find(|authority| {
        owner.primary_driver.is_some_and(|driver| driver.raw() == authority.driver_id)
    }).or_else(|| owner.authorities.first());
    let authority_live = !owner.authorities.is_empty()
        && owner.authorities.iter().all(|authority| authority.live());
    let refused_epoch = match owner.admission_receipt.refused {
        AdmissionEpoch::Ready(epoch) => epoch,
        AdmissionEpoch::Retired | AdmissionEpoch::MissingDomain => 0,
    };
    print_str(b"[nested-pnp-create-owner] stage/row/irp/device/driver/stack/flight/payload/pump/queued/epoch/retry/ready/completion/receipt/blocked=");
    for value in [stage, id, irp.raw(),
        owner.primary_device.map_or(0, |device| device.raw()),
        owner.primary_driver.map_or(0, |driver| driver.raw()),
        owner.stack.len() as u64, flight, payload, pump,
        u64::from(owner.queue_not_admitted), refused_epoch,
        owner.retry_after, u64::from(owner.work_ready),
        u64::from(owner.completion.is_some()),
        u64::from(owner.terminal_receipt.is_some()),
        owner.blocked_status.map_or(0, |status| status.raw() as u32 as u64)] {
        print_str(b"/"); print_u64(value);
    }
    print_str(b" authority-live/instance/domain/cookie/tcb=");
    for value in [u64::from(authority_live),
        authority.map_or(0, |authority| authority.instance as u64),
        authority.map_or(0, |authority| authority.domain.domain_id.raw()),
        authority.map_or(0, |authority| authority.domain.cookie),
        authority.map_or(0, |authority| authority.tcb)] {
        print_str(b"/"); print_u64(value);
    }
    if stage == 0 {
        print_str(b" members=");
        for (index, (device, driver)) in owner.stack.iter().take(8).enumerate() {
            if index != 0 { print_str(b","); }
            print_u64(index as u64); print_str(b":"); print_u64(device.raw());
            print_str(b":"); print_u64(driver.raw());
        }
        if owner.stack.len() > 8 {
            print_str(b" truncated="); print_u64((owner.stack.len() - 8) as u64);
        }
    }
    print_str(b"\n");
}

/// Bounded per-instance observation of ordinary File terminal and ACK ownership (#481).
/// Stages: 1 terminal publish attempt, 2 published, 3 publish refused;
/// 4 synchronous terminal retired, 5 retirement refused; 6 ACK attempt,
/// 7 ACK retired without backend, 8 backend ACK retired, 9 backend ACK retained.
fn trace_file_terminal_ack(stage: u64, id: u64, irp: IrpId,
    status: Option<nt_status::NtStatus>) {
    trace_nested_pnp_create_owner(stage + 10, id, irp);
    let owner = row(id);
    if owner.irp_id != Some(irp) { return; }
    static COUNT: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
    let instance = owner.primary_driver
        .and_then(|driver| instance_by_driver_id(driver.raw()))
        .map_or(usize::MAX, |(index, _)| index);
    let Some(counter) = COUNT.get(instance) else { return; };
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    let flight = match owner.flight {
        Flight::Preparing => 1, Flight::QueuedDispatch => 2, Flight::Dispatch => 3,
        Flight::PumpSuspended => 4, Flight::PumpReturned => 5, Flight::Copy => 6,
        Flight::Cancel => 7, Flight::Acknowledge => 8, Flight::Idle => 9,
        Flight::Blocked => 10,
    };
    print_str(b"[file-terminal-ack] n/instance/row/irp/major/stage/flight/completion/receipt/status=");
    print_u64(n); print_str(b"/"); print_u64(instance as u64); print_str(b"/");
    print_u64(id); print_str(b"/"); print_hex_u64(irp.raw()); print_str(b"/");
    print_hex_u64(owner.phase_major as u64); print_str(b"/"); print_u64(stage);
    print_str(b"/"); print_u64(flight); print_str(b"/");
    print_u64(u64::from(owner.completion.is_some())); print_str(b"/");
    print_u64(u64::from(owner.terminal_receipt.is_some())); print_str(b"/");
    print_hex_u64(status.map_or(0, |status| status.raw() as u32 as u64));
    print_str(b"\n");
}

/// What a dispatch does when no hosted lane can admit its IRP yet (#427).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Return STATUS_DEVICE_BUSY to a caller that re-prepares the request itself.
    Refuse,
    /// Keep the prepared IRP queued in its row and redrive it when a lane frees.
    Queue,
}

/// An older not-admitted IRP for the same driver is still queued.
fn queued_ahead(id: u64) -> bool {
    let driver = row(id).primary_driver;
    rows().iter().any(|other| other.id < id && other.queue_not_admitted
        && other.flight == Flight::QueuedDispatch && other.primary_driver == driver)
}

/// `[irp-queue]` stages: queued, retried, admitted, refused (#427).
const IRP_QUEUE_STAGES: [&[u8]; 4] = [b"queued", b"retried", b"admitted", b"refused"];
static IRP_QUEUE_COUNTS: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Bounded evidence of a not-admitted IRP's queue (#427): every stage's first sightings and
/// then powers of two, with totals in the census. A refusal is always printed.
fn trace_irp_queue(stage: usize, id: u64, major: u8) {
    let n = IRP_QUEUE_COUNTS[stage].fetch_add(1, Ordering::Relaxed) + 1;
    if stage != 3 && n > 16 && !n.is_power_of_two() { return; }
    let owner = row(id);
    let instance = owner.primary_driver
        .and_then(|driver| instance_by_driver_id(driver.raw()))
        .map_or(u64::MAX, |(index, _)| index as u64);
    print_str(b"[irp-queue] stage=");
    print_str(IRP_QUEUE_STAGES[stage]);
    print_str(b" n="); print_u64(n);
    print_str(b" instance/major/irp="); print_u64(instance); print_str(b"/");
    print_hex_u64(u64::from(major)); print_str(b"/");
    print_hex_u64(owner.irp_id.map_or(0, |irp| irp.raw()));
    if let Some(status) = owner.blocked_status.filter(|_| stage == 3) {
        print_str(b" status="); print_hex_u64(status.raw() as u32 as u64);
    }
    print_str(b"\n");
}

/// Retain a not-admitted preparation; nothing was entered, so it may be begun again.
#[repr(u64)]
#[derive(Clone, Copy)]
enum QueueReason {
    OlderQueuedIrp = 1,
    NoLane = 2,
    RedriveNoLane = 3,
}

/// First refusal per exact File row, including the route state that a sparse global queue
/// counter cannot preserve once an unrelated driver has filled its print budget (#481).
fn trace_initial_queue(id: u64, major: u8, reason: QueueReason) {
    let owner = row(id);
    if owner.queue_trace_emitted { return; }
    owner.queue_trace_emitted = true;
    let (driver, irp) = (owner.primary_driver, owner.irp_id);
    let Some(instance) = driver.and_then(|driver| instance_by_driver_id(driver.raw()))
        .map(|(index, _)| index) else { return; };
    static COUNT: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
    let Some(counter) = COUNT.get(instance) else { return; };
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    let (primary_ready, primary_parked) =
        match hosted_ingress_sources::primary_route(instance) {
            Some(route) => {
                let ready = match unsafe { crate::spawn_hosts::shared_ingress::owner::runtime::ready_for_admission(route) } {
                    Ok(true) => 1, Ok(false) => 2, Err(_) => 3,
                };
                (ready, u64::from(unsafe {
                    crate::spawn_hosts::shared_ingress::owner::runtime::primary_dispatch_parked(route)
                }))
            }
            None => (0, 0),
        };
    let (phase, route, claim_idle, worker) = unsafe {
        hosted_class_irp_lane::ordinary_admission_snapshot(instance)
    };
    print_str(b"[file-first-queue] n/instance/row/irp/major/reason/primary-ready/parked/worker-phase/route/claim-idle/worker=");
    print_u64(n); print_str(b"/"); print_u64(instance as u64); print_str(b"/");
    print_u64(id); print_str(b"/"); print_hex_u64(irp.map_or(0, |irp| irp.raw()));
    print_str(b"/"); print_hex_u64(major as u64); print_str(b"/");
    print_u64(reason as u64); print_str(b"/"); print_u64(primary_ready); print_str(b"/");
    print_u64(primary_parked); print_str(b"/"); print_u64(phase); print_str(b"/");
    print_u64(route); print_str(b"/"); print_u64(claim_idle); print_str(b"/");
    print_u64(worker); print_str(b"\n");
}

fn queue_unadmitted(id: u64, prepared: PreparedExternalFileIrp, reason: QueueReason) {
    trace_initial_queue(id, prepared.projection().major, reason);
    trace_irp_queue(0, id, prepared.projection().major);
    let previous = row(id).admission_receipt;
    let admission_receipt = if matches!(reason, QueueReason::RedriveNoLane) {
        previous.refresh()
    } else {
        AdmissionReceipt::capture(row(id).primary_driver)
    };
    let startup_phase = admission_receipt.owner.filter(|owner| owner.live()).and_then(|owner| unsafe {
        hosted_class_irp_lane::startup_retry_progress(owner.instance)
    });
    let startup_probe_owed = match reason {
        QueueReason::NoLane => startup_phase.is_some(),
        QueueReason::RedriveNoLane => startup_phase.is_some()
            && startup_phase != row(id).startup_probe_phase,
        QueueReason::OlderQueuedIrp => false,
    };
    let row = row(id);
    row.payload = Some(Payload::Prepared(prepared));
    row.flight = Flight::QueuedDispatch;
    row.blocked_status = None;
    row.admission_receipt = admission_receipt;
    row.startup_probe_owed = startup_probe_owed;
    row.startup_probe_phase = startup_phase;
    if matches!(admission_receipt.refused, AdmissionEpoch::Ready(_)) {
        row.missing_domain_probe_consumed = false;
    }
    if let Some(irp) = row.irp_id {
        trace_nested_pnp_create_owner(5, id, irp);
    }
}

fn queued_admissions() -> Vec<nt_hosted_runtime::QueuedIrp> {
    rows().iter()
        .filter(|row| row.queue_not_admitted && row.flight == Flight::QueuedDispatch)
        .map(|row| {
            let current_epoch = row.admission_receipt.current_epoch();
            let (refused_at, current) = match (row.admission_receipt.refused, current_epoch) {
                (AdmissionEpoch::Ready(refused), AdmissionEpoch::Ready(now)) =>
                    (refused, Some(now)),
                (_, AdmissionEpoch::Ready(now)) => (now, Some(now)),
                (AdmissionEpoch::Ready(refused), _) => (refused, None),
                _ => (0, None),
            };
            nt_hosted_runtime::QueuedIrp {
                id: row.id,
                driver: row.primary_driver.map_or(0, |driver| driver.raw()),
                refused_at,
                current_epoch: current,
                wake_without_epoch: row.startup_probe_owed
                    || row.admission_receipt.became_ready()
                    || (matches!(row.admission_receipt.refused, AdmissionEpoch::MissingDomain)
                        && matches!(current_epoch, AdmissionEpoch::Ready(_)))
                    || (matches!(current_epoch, AdmissionEpoch::Retired)
                        && !row.retired_probe_consumed)
                    || (matches!(current_epoch, AdmissionEpoch::MissingDomain)
                        && !row.missing_domain_probe_consumed),
                cancel_queued: queued_cancel(row),
            }
        })
        .collect()
}

/// Whether this IRP keeps state in the lane bank it entered: METHOD_NEITHER mutable input, whose
/// copy control reads that bank (#427).
pub(super) fn retains_lane_bank(irp_id: IrpId) -> bool {
    find(irp_id).is_some_and(|id| row(id).output_capture == ExternalFileIrpOutputCapture::MethodNeitherInput)
}

/// How far this IRP's dispatch has got, for its caller (#427): a queued not-admitted or kept
/// (suspended) dispatch has not returned to its caller yet.
pub(super) fn dispatch_progress(irp_id: IrpId) -> Option<nt_hosted_runtime::DispatchProgress> {
    use nt_hosted_runtime::DispatchProgress;
    let id = find(irp_id)?;
    let owner = row(id);
    Some(match owner.flight {
        Flight::Preparing | Flight::QueuedDispatch | Flight::Dispatch | Flight::PumpSuspended =>
            DispatchProgress::InFlight,
        _ if io_manager_mut().completed_irp(irp_id).is_some() => DispatchProgress::Completed,
        Flight::Idle if matches!(owner.payload, Some(Payload::Retained(_))) =>
            DispatchProgress::ReturnedPending,
        // A returned terminal not yet published, or completion delivery under way.
        _ => DispatchProgress::InFlight,
    })
}

/// Queued not-admitted rows an exact lane/readiness change, startup continuation or cancel may move.
pub(super) fn queued_admission_due() -> bool {
    if !rows().iter().any(|row| row.queue_not_admitted && row.flight == Flight::QueuedDispatch) {
        return false;
    }
    let _transient = crate::allocator::enter_transient();
    !nt_hosted_runtime::queued_admission_candidates(&queued_admissions()).is_empty()
}

fn queued_cancel(row: &Row) -> bool {
    row.irp_id.is_some_and(|irp| io_manager_mut()
        .detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp)
        .is_ok_and(|intent| intent.cancel == ExternalFileIrpCancelPhase::Queued))
}

/// Begin queued not-admitted IRPs again, oldest first per driver (see
/// `nt_hosted_runtime::queued_admission_candidates`); a queued cancel or abandon completes its
/// IRP without provider entry. Must run where entering a provider cannot disturb a caller's
/// Reply or received message: the root's global-work pass, after the queuing syscall parked its
/// Reply.
pub(super) fn redrive_queued_dispatches() -> usize {
    let _durable = crate::allocator::enter_durable();
    let candidates = nt_hosted_runtime::queued_admission_candidates(&queued_admissions());
    candidates.into_iter()
        .filter(|id| matches!(redrive_queued(*id), QueuedReadRedriveOutcome::Progressed))
        .count()
}

fn dispatch_with_port_connect<Yield>(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
    port_connect_device: Option<nt_io_manager::DeviceId>,
    admission: Admission,
    invoke: impl FnOnce(
        ExternalFileIrpInvocation,
        nt_process::native_handle::NativeHandleCaller,
        ExternalFileIrpOutputCapture,
    ) -> Result<ExternalFileIrpReturn, Yield>,
) -> Result<DispatchResult, DispatchFailure<Yield>> {
    let major = request.major;
    let mut phase = FileRpcPhaseGuard::new(major);
    let mut scsi_phase = ScsiRpcPhaseGuard::new(major, policy);
    let _durable = crate::allocator::enter_durable();
    let copy = |source: &[u8]| -> Result<Vec<u8>, nt_status::NtStatus> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        bytes.extend_from_slice(source);
        Ok(bytes)
    };
    let buffers = ExternalFileIrpBuffers::new(copy(input)?, copy(initial_output)?);
    let id = reserve(caller, policy.output_capture())?;
    if let Some(device) = port_connect_device {
        trace_port_connect_dispatch(0, IrpId(0), device);
    }
    let preparation = policy.prepare(io_manager_mut(), request, buffers);
    let prepared = match preparation {
        Ok(prepared) => prepared,
        Err(status) => {
            remove(id)?;
            return Err(DispatchFailure::Status(status));
        }
    };
    if let Err(status) = unsafe { bind_pending_scsi_proof_irp(policy, &prepared) } {
        discard(id, prepared)?;
        return Err(DispatchFailure::Status(status));
    }
    if let Err(status) = capture_route(id, &prepared) {
        discard(id, prepared)?;
        return Err(DispatchFailure::Status(status));
    }
    row(id).queue_not_admitted = admission == Admission::Queue
        && port_connect_device.is_none()
        && policy == ExternalFileIrpDispatchPolicy::File;
    if row(id).queue_not_admitted && queued_ahead(id) {
        // An older IRP for this driver still waits for a lane; never overtake it.
        let irp_id = prepared.irp_id();
        queue_unadmitted(id, prepared, QueueReason::OlderQueuedIrp);
        return Ok(DispatchResult::Outstanding { irp_id });
    }
    // This exact retained stack is the last Executive-side point before a disk provider may
    // enter. A possible installed-media mutation permanently disables metadata read-through.
    unsafe { mounted_native_block::before_external_scsi_effect(&prepared, &row(id).stack) };
    let irp_id = prepared.irp_id();
    if let Some(device) = port_connect_device {
        trace_port_connect_dispatch(1, irp_id, device);
    }
    if let Some(device) = port_connect_device {
        if let Err(status) = mark_port_connect_control(irp_id, device) {
            discard(id, prepared)?;
            return Err(DispatchFailure::Status(status));
        }
    }
    let invocation = match io_manager_mut().begin_prepared_external_file_irp(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, prepared) = rejection.into_parts();
            discard(id, prepared)?;
            return Err(DispatchFailure::Status(status));
        }
    };
    row(id).flight = Flight::Dispatch;
    if phase.entered != 0 {
        row(id).phase_major = major;
        phase.identity = Some(nt_hosted_runtime::HostedFileRpcIdentity {
            irp_id: irp_id.raw(), major,
        });
    }
    // Capture the canonical File row at its own entry boundary. `invoke` can reenter
    // the provider pump before this root-owned function returns.
    if major == major::IRP_MJ_CREATE && crate::spawn_hosts::active_pnp_start_receive() {
        static NESTED_PNP_CREATE_ROWS: AtomicU64 = AtomicU64::new(0);
        row(id).nested_pnp_trace = NESTED_PNP_CREATE_ROWS.fetch_update(
            Ordering::AcqRel, Ordering::Acquire,
            |used| (used < 64).then_some(used + 1),
        ).is_ok();
        trace_nested_pnp_create_owner(0, id, irp_id);
    }
    if let Some(device) = port_connect_device {
        trace_port_connect_dispatch(2, irp_id, device);
    }
    if phase.entered != 0 { phase.invoked = crate::disk_census_ticks(); }
    if scsi_phase.started.is_some() { scsi_phase.invoked = Some(crate::disk_census_ticks()); }
    let returned = match invoke(invocation, row(id).caller, policy.output_capture()) {
        Ok(returned) => returned,
        Err(yielded) => {
            trace_nested_pnp_create_owner(2, id, irp_id);
            return Err(DispatchFailure::Yield(yielded));
        }
    };
    trace_nested_pnp_create_owner(1, id, irp_id);
    if scsi_phase.started.is_some() { scsi_phase.returned = Some(crate::disk_census_ticks()); }
    if phase.entered != 0 {
        phase.returned = crate::disk_census_ticks();
        phase.pump_ticks = row(id).phase_pump_ticks;
        phase.bank_ticks = row(id).phase_bank_ticks;
    }
    if let Some(device) = port_connect_device {
        trace_port_connect_dispatch(3, irp_id, device);
    }
    settle_returned_dispatch(id, irp_id, returned).map_err(DispatchFailure::Status)
}

fn settle_returned_dispatch(
    id: u64,
    irp_id: IrpId,
    returned: ExternalFileIrpReturn,
) -> Result<DispatchResult, nt_status::NtStatus> {
    trace_file_return_probe(70, irp_id);
    let result = match io_manager_mut().finish_external_file_irp(returned) {
        Ok(result) => {
            trace_file_return_probe(71, irp_id);
            result
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            take_deferred(id);
            block(id, Payload::Returned(returned), status);
            trace_file_return_probe(72, irp_id);
            return Ok(DispatchResult::Outstanding { irp_id });
        }
    };
    match result {
        ExternalFileIrpResult::NotAdmitted { prepared } => {
            trace_file_return_probe(73, irp_id);
            if take_deferred(id) {
                // A resumed pump had entered its provider; a no-admission return contradicts that.
                block(id, Payload::Prepared(prepared), nt_status::NtStatus::DEVICE_BUSY);
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            if row(id).queue_not_admitted {
                queue_unadmitted(id, prepared, QueueReason::NoLane);
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            // This caller re-prepares a busy refusal itself.
            ADMISSION_REFUSALS.fetch_add(1, Ordering::AcqRel);
            if discard(id, prepared).is_err() {
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            Err(nt_status::NtStatus::DEVICE_BUSY)
        }
        ExternalFileIrpResult::NotEntered { status, prepared } => {
            trace_file_return_probe(73, irp_id);
            if take_deferred(id) {
                // A resumed pump had entered its provider; a no-entry return contradicts that.
                block(id, Payload::Prepared(prepared), status);
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            if discard(id, prepared).is_err() {
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            Err(status)
        }
        ExternalFileIrpResult::Returned(terminal) => {
            trace_file_return_probe(74, irp_id);
            if let Some(kept) = row(id).plain_pump.take() {
                return Ok(match kept.returned(terminal) {
                    // Only this row's own caller may take the return (#420).
                    nt_hosted_runtime::FilePumpReturned::Kept(kept) => {
                        row(id).plain_pump = Some(kept);
                        row(id).flight = Flight::PumpReturned;
                        DispatchResult::Outstanding { irp_id }
                    }
                    // Its caller was told STATUS_PENDING and reads the ordinary completion.
                    nt_hosted_runtime::FilePumpReturned::Publish(terminal) => {
                        let _ = publish_terminal(id, irp_id, terminal);
                        DispatchResult::Outstanding { irp_id }
                    }
                });
            }
            if row(id).hook_pump.is_some() {
                let owner = row(id);
                owner.payload = Some(Payload::HookReturned(HookReturned {
                    state: HookReturnedState::Terminal(terminal), observed: false,
                }));
                owner.flight = Flight::PumpReturned;
                owner.hook_pump_claimed = false;
                trace_file_return_probe(75, irp_id);
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            Ok(retire_returned_terminal(id, irp_id, terminal))
        }
        ExternalFileIrpResult::Pending(retained) => {
            take_deferred(id);
            keep(id, Payload::Retained(retained));
            trace_file_return_probe(76, irp_id);
            Ok(DispatchResult::Outstanding { irp_id })
        }
        ExternalFileIrpResult::Indeterminate {
            transport_status,
            retained,
        } => {
            take_deferred(id);
            keep(id, Payload::Retained(retained));
            row(id).blocked_status = Some(transport_status);
            trace_file_return_probe(77, irp_id);
            Ok(DispatchResult::Outstanding { irp_id })
        }
    }
}

/// A deferred pump that did not return a terminal hands its row to the ordinary contract.
fn take_deferred(id: u64) -> bool {
    let deferred = matches!(row(id).plain_pump,
        Some(nt_hosted_runtime::KeptFilePump::DeferredCompletion));
    if deferred { row(id).plain_pump = None; }
    deferred
}

/// Publish a returned terminal as the IRP's ordinary completion, for a caller that was told
/// `STATUS_PENDING` (#420). Its pending owner reads it as it reads a pended IRP's completion.
fn publish_terminal(
    id: u64, irp_id: IrpId, terminal: ExternalFileIrpTerminal,
) -> Result<(), nt_status::NtStatus> {
    trace_file_terminal_ack(1, id, irp_id, None);
    match io_manager_mut().queue_external_file_irp_terminal(terminal, row(id).output_capture) {
        Ok(completion) => {
            row(id).completion = Some(*completion.completion());
            keep(id, Payload::Completion(completion));
            crate::service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
            trace_plain_pump(b"published", irp_id);
            trace_file_terminal_ack(2, id, irp_id, None);
            Ok(())
        }
        Err(rejection) => {
            let (status, terminal) = rejection.into_parts();
            block(id, Payload::Terminal(terminal), status);
            trace_plain_pump(b"unpublished", irp_id);
            trace_file_terminal_ack(3, id, irp_id, Some(status));
            Err(status)
        }
    }
}

/// Retire a returned terminal and hand its result to the caller that owns it.
fn retire_returned_terminal(
    id: u64, irp_id: IrpId, terminal: ExternalFileIrpTerminal,
) -> DispatchResult {
    let completion = *terminal.completion();
    match io_manager_mut().retire_external_file_irp_terminal(terminal) {
        Ok((receipt, buffers)) => {
            trace_file_return_probe(78, irp_id);
            assert!(io_manager_mut().accepts_external_file_irp_receipt(&receipt));
            row(id).terminal_receipt = Some(receipt);
            row(id).settled_buffers = Some(buffers);
            trace_file_terminal_ack(4, id, irp_id, None);
            let mut retired = match remove(id) {
                Ok(retired) => {
                    trace_file_return_probe(79, irp_id);
                    retired
                }
                Err(status) => {
                    trace_file_return_probe_status(80, irp_id, Some(status));
                    return DispatchResult::Outstanding { irp_id };
                }
            };
            DispatchResult::Returned {
                irp_id,
                status: completion.status,
                information: completion.information,
                file_context: completion.file_context,
                buffers: retired
                    .settled_buffers
                    .take()
                    .expect("retired File buffers missing"),
            }
        }
        Err(rejection) => {
            let (status, terminal) = rejection.into_parts();
            block(id, Payload::Terminal(terminal), status);
            trace_file_return_probe_status(81, irp_id, Some(status));
            trace_file_terminal_ack(5, id, irp_id, Some(status));
            DispatchResult::Outstanding { irp_id }
        }
    }
}

/// Prepare one ordinary hosted READ for a caller whose physical Reply must park before any
/// provider entry. The returned IRP identity is backed by a retained, move-only preparation.
#[must_use = "a retained preparation still owns its requestor and possibly a prepared IRP"]
pub(super) enum QueuedReadPreparation {
    Queued(IrpId),
    RefusedNoOwner(nt_status::NtStatus),
    Retained {
        selector: RetainedQueuedReadSelector,
        status: nt_status::NtStatus,
    },
}

/// Selects the exact native row when cleanup retained an owner, including the case where
/// manager preparation failed before an IRP ID existed. No numeric IRP ID can name that row.
#[must_use = "the selected row remains owned until its cleanup is reconciled"]
pub(super) struct RetainedQueuedReadSelector {
    row_id: u64,
}

/// Retry only the cleanup that refused before the READ was queued. A selector names the native
/// row even if manager preparation failed before an IRP ID existed; it never authorizes dispatch.
pub(super) fn reconcile_retained_queued_read(
    selector: RetainedQueuedReadSelector,
) -> Result<(), (nt_status::NtStatus, RetainedQueuedReadSelector)> {
    let _durable = crate::allocator::enter_durable();
    let id = selector.row_id;
    if !rows().iter().any(|row| row.id == id && row.flight == Flight::Blocked) {
        return Err((nt_status::NtStatus::INVALID_PARAMETER, selector));
    }
    let payload = row(id).payload.take();
    let result = match payload {
        Some(Payload::Prepared(prepared)) => discard(id, prepared),
        None if row(id).irp_id.is_none() || row(id).settled_buffers.is_some() => {
            remove(id).map(|_| ())
        }
        other => {
            row(id).payload = other;
            Err(nt_status::NtStatus::INVALID_PARAMETER)
        }
    };
    result.map_err(|status| (status, selector))
}

pub(super) fn queue_read(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    output_len: usize,
) -> QueuedReadPreparation {
    if request.major != major::IRP_MJ_READ {
        return QueuedReadPreparation::RefusedNoOwner(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let _durable = crate::allocator::enter_durable();
    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return QueuedReadPreparation::RefusedNoOwner(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    output.resize(output_len, 0);
    let id = match reserve(caller, ExternalFileIrpDispatchPolicy::File.output_capture()) {
        Ok(id) => id,
        Err(status) => return QueuedReadPreparation::RefusedNoOwner(status),
    };
    let prepared = match ExternalFileIrpDispatchPolicy::File.prepare(
        io_manager_mut(), request, ExternalFileIrpBuffers::new(Vec::new(), output),
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            return match remove(id) {
                Ok(_) => QueuedReadPreparation::RefusedNoOwner(status),
                Err(cleanup_status) => QueuedReadPreparation::Retained {
                    selector: RetainedQueuedReadSelector { row_id: id },
                    status: cleanup_status,
                },
            };
        }
    };
    if let Err(status) = capture_route(id, &prepared) {
        return match discard(id, prepared) {
            Ok(()) => QueuedReadPreparation::RefusedNoOwner(status),
            Err(cleanup_status) => QueuedReadPreparation::Retained {
                selector: RetainedQueuedReadSelector { row_id: id },
                status: cleanup_status,
            },
        };
    }
    let irp_id = prepared.irp_id();
    row(id).payload = Some(Payload::Prepared(prepared));
    row(id).flight = Flight::QueuedDispatch;
    QueuedReadPreparation::Queued(irp_id)
}

/// Enter the exact queued READ at most once. This must be called only after the parent Reply
/// has a positive restoration receipt. A rejected or uncertain effect remains in this row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QueuedReadRedriveOutcome {
    NoWork,
    Progressed,
    Retained(nt_status::NtStatus),
}

pub(super) fn redrive_queued_read(irp_id: IrpId) -> QueuedReadRedriveOutcome {
    let Some(id) = find(irp_id) else { return QueuedReadRedriveOutcome::NoWork };
    redrive_queued(id)
}

/// Enter the exact queued IRP at most once: a queued READ after its parent Reply was restored,
/// or a not-admitted ordinary IRP after its caller's Reply was parked. A rejected or uncertain
/// effect remains in this row; only a manager-validated no-admission requeues it.
fn redrive_queued(id: u64) -> QueuedReadRedriveOutcome {
    let _durable = crate::allocator::enter_durable();
    if row(id).flight != Flight::QueuedDispatch { return QueuedReadRedriveOutcome::NoWork }
    row(id).startup_probe_owed = false;
    let current_epoch = row(id).admission_receipt.current_epoch();
    match current_epoch {
        AdmissionEpoch::Retired => row(id).retired_probe_consumed = true,
        AdmissionEpoch::MissingDomain => row(id).missing_domain_probe_consumed = true,
        AdmissionEpoch::Ready(_) => {}
    }
    let Some(irp_id) = row(id).irp_id else { return QueuedReadRedriveOutcome::NoWork };
    // A queued caller may be cancelled or abandoned before this explicit redrive. The manager
    // owns that intent; never infer a new provider call merely from a live native route.
    let intent = match io_manager_mut()
        .detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)
    {
        Ok(intent) => intent,
        Err(status) => {
            row(id).flight = Flight::Blocked;
            row(id).blocked_status = Some(status);
            return QueuedReadRedriveOutcome::Retained(status);
        }
    };
    if intent.abandoned
        && intent.cancel != nt_io_manager::detached_file_irp::ExternalFileIrpCancelPhase::Queued
    {
        // Activation gate: abandoned preparation needs a manager-proven no-entry result.
        let status = nt_status::NtStatus::CANCELLED;
        row(id).flight = Flight::Blocked;
        row(id).blocked_status = Some(status);
        return QueuedReadRedriveOutcome::Retained(status);
    }
    let prepared = match row(id).payload.take() {
        Some(Payload::Prepared(prepared)) => prepared,
        other => {
            row(id).payload = other;
            row(id).flight = Flight::Blocked;
            row(id).blocked_status = Some(nt_status::NtStatus::INVALID_PARAMETER);
            return QueuedReadRedriveOutcome::Retained(nt_status::NtStatus::INVALID_PARAMETER);
        }
    };
    let major = prepared.projection().major;
    let queued = row(id).queue_not_admitted;
    if queued { trace_irp_queue(1, id, major); }
    let mut phase = FileRpcPhaseGuard::new(major);
    // The same last point before a disk provider may enter as a first dispatch's.
    unsafe { mounted_native_block::before_external_scsi_effect(&prepared, &row(id).stack) };
    let invocation = match io_manager_mut().begin_prepared_external_file_irp(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, prepared) = rejection.into_parts();
            // A queued cancellation is a proven no-entry terminal; a failed physical or
            // manager route remains retained if its exact cause cannot be terminalized.
            let failure = if status == nt_status::NtStatus::CANCELLED {
                nt_io_manager::detached_file_irp::ExternalFileIrpPreEntryFailure::Cancelled
            } else {
                // A manager route refusal is terminal only when the manager validates its own
                // route fault against this exact preparation. Other refusals remain retained.
                nt_io_manager::detached_file_irp::ExternalFileIrpPreEntryFailure::ManagerRouteUnavailable
            };
            return match io_manager_mut().complete_prepared_external_file_irp_without_entry(
                prepared, failure,
            ) {
                Ok(retained) => {
                    keep(id, Payload::Retained(retained));
                    crate::service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING
                        .store(true, Ordering::Release);
                    QueuedReadRedriveOutcome::Progressed
                }
                Err(rejection) => {
                    let (error, prepared) = rejection.into_parts();
                    let error = if status == nt_status::NtStatus::CANCELLED { error } else { status };
                    block(id, Payload::Prepared(prepared), error);
                    if queued { trace_irp_queue(3, id, major); }
                    QueuedReadRedriveOutcome::Retained(error)
                }
            };
        }
    };
    // The manager has transferred the owner to Dispatched; even an uncertain transport
    // result may never send this invocation again.
    row(id).flight = Flight::Dispatch;
    row(id).phase_major = major;
    phase.identity = Some(nt_hosted_runtime::HostedFileRpcIdentity { irp_id: irp_id.raw(), major });
    let returned = if !live_route(id) {
        // begin_prepared_external_file_irp transferred the exact manager owner, but the
        // captured native authority/generation is no longer live. No provider has entered.
        invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        })
    } else {
        phase.invoked = crate::disk_census_ticks();
        match hosted_file_dispatch::invoke_retaining(
            invocation, row(id).caller, row(id).output_capture,
        ) {
            hosted_file_dispatch::InvokeResult::Returned(returned) => returned,
            // The caller is already parked on its pending owner (#420).
            hosted_file_dispatch::InvokeResult::ChildWorkYield {
                invocation, key, continuation,
            // A queued IRP is never bound to a scoped SCSI proof.
            } => return match defer_pump(irp_id, invocation, key, continuation, None) {
                Ok(()) => QueuedReadRedriveOutcome::Progressed,
                Err(status) => QueuedReadRedriveOutcome::Retained(status),
            },
            hosted_file_dispatch::InvokeResult::UnkeyedChildWorkYield {
                invocation, continuation,
            } => {
                let status = nt_status::NtStatus::INVALID_PARAMETER;
                let _ = orphan_plain_pump(irp_id, status, invocation, continuation);
                return QueuedReadRedriveOutcome::Retained(status);
            }
        }
    };
    phase.returned = crate::disk_census_ticks();
    phase.pump_ticks = row(id).phase_pump_ticks;
    phase.bank_ticks = row(id).phase_bank_ticks;
    let result = match io_manager_mut().finish_external_file_irp(returned) {
        Ok(result) => result,
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            block(id, Payload::Returned(returned), status);
            if queued { trace_irp_queue(3, id, major); }
            return QueuedReadRedriveOutcome::Retained(status);
        }
    };
    if queued && !matches!(result, ExternalFileIrpResult::NotAdmitted { .. }) {
        trace_irp_queue(2, id, major);
    }
    let result = match result.into_no_entry_receipt() {
        Ok(receipt) => {
            keep(id, Payload::NoEntry(receipt));
            return match retry_no_entry(id) {
                Ok(()) => QueuedReadRedriveOutcome::Progressed,
                Err(status) => QueuedReadRedriveOutcome::Retained(status),
            };
        }
        Err(result) => result,
    };
    match result {
        ExternalFileIrpResult::NotEntered { status, prepared } => {
            // An invalid success-shaped refusal has no terminal authority; retain it.
            block(id, Payload::Prepared(prepared), status);
            if queued { trace_irp_queue(3, id, major); }
            QueuedReadRedriveOutcome::Retained(status)
        }
        ExternalFileIrpResult::NotAdmitted { prepared } => {
            // Still no free lane: nothing was entered, so it waits for the next lane change.
            queue_unadmitted(id, prepared, QueueReason::RedriveNoLane);
            QueuedReadRedriveOutcome::Retained(nt_status::NtStatus::DEVICE_BUSY)
        }
        ExternalFileIrpResult::Returned(terminal) => match publish_terminal(id, irp_id, terminal) {
            Ok(()) => QueuedReadRedriveOutcome::Progressed,
            Err(status) => QueuedReadRedriveOutcome::Retained(status),
        },
        ExternalFileIrpResult::Pending(retained) => {
            keep(id, Payload::Retained(retained));
            QueuedReadRedriveOutcome::Progressed
        }
        ExternalFileIrpResult::Indeterminate { transport_status, retained } => {
            keep(id, Payload::Retained(retained));
            row(id).blocked_status = Some(transport_status);
            QueuedReadRedriveOutcome::Progressed
        }
    }
}

pub(super) fn contains(irp_id: IrpId) -> bool {
    find(irp_id).is_some()
}

/// Observe the exact unentered READ owner without advancing its flight or borrowing a provider.
#[allow(dead_code)]
pub(super) fn queued_read_matches(irp_id: IrpId, file_id: FileId, tid: u64) -> bool {
    let Some(id) = find(irp_id) else { return false };
    let owner = row(id);
    owner.flight == Flight::QueuedDispatch
        && matches!(owner.payload.as_ref(), Some(Payload::Prepared(prepared))
            if prepared.projection().major == major::IRP_MJ_READ
                && prepared.projection().file_id == Some(file_id)
                && prepared.projection().requestor_tid == tid)
}

/// The one canonical detached packet currently executing on an exact Device target. A
/// concurrent same-target dispatch is ambiguous to a nested native lower-edge call and is
/// refused until its own source identity can be selected independently.
pub(super) fn unique_executing_device_irp(
    target: nt_io_manager::DeviceId,
) -> Option<IrpId> {
    let mut found = None;
    for row in rows().iter().filter(|row| {
        row.flight == Flight::Dispatch && row.primary_device == Some(target)
    }) {
        let id = row.irp_id?;
        if found.replace(id).is_some() {
            return None;
        }
    }
    found
}

fn ensure_completion(id: u64) -> Result<(), nt_status::NtStatus> {
    if row(id).flight != Flight::Idle {
        return Err(row(id)
            .blocked_status
            .unwrap_or(nt_status::NtStatus::DEVICE_BUSY));
    }
    let payload = row(id)
        .payload
        .take()
        .expect("idle File owner missing payload");
    match payload {
        Payload::Retained(retained) => {
            let capture = row(id).output_capture;
            match io_manager_mut()
                .prepare_external_file_irp_completion_with_capture(retained, capture)
            {
                Ok(completion) => {
                    row(id).completion = Some(*completion.completion());
                    keep(id, Payload::Completion(completion));
                    Ok(())
                }
                Err(rejection) => {
                    let (status, retained) = rejection.into_parts();
                    // Observing a pending IRP must not erase its cancellation backoff.
                    row(id).payload = Some(Payload::Retained(retained));
                    Err(status)
                }
            }
        }
        Payload::NoEntry(receipt) => {
            row(id).payload = Some(Payload::NoEntry(receipt));
            Err(nt_status::NtStatus::DEVICE_BUSY)
        }
        payload @ (Payload::Completion(_) | Payload::Copy(_) | Payload::Acknowledgement(_)) => {
            row(id).payload = Some(payload);
            Ok(())
        }
        other => {
            block(id, other, nt_status::NtStatus::INVALID_PARAMETER);
            Err(nt_status::NtStatus::INVALID_PARAMETER)
        }
    }
}

pub(super) fn completion(
    irp_id: IrpId,
) -> Result<nt_io_manager::CompletedIrp, nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if let Some(Payload::HookReturned(HookReturned {
        state: HookReturnedState::Terminal(terminal), ..
    })) = row(id).payload.as_ref() {
        return Ok(*terminal.completion());
    }
    ensure_completion(id)?;
    row(id)
        .completion
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)
}

fn copy_chunk(id: u64) -> Result<(), nt_status::NtStatus> {
    if monotonic_time_100ns() < row(id).retry_after {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if !live_route(id) {
        row(id).flight = Flight::Blocked;
        row(id).blocked_status = Some(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    let payload = row(id)
        .payload
        .take()
        .expect("File completion owner missing");
    let invocation = match payload {
        Payload::Completion(completion) => {
            match io_manager_mut().begin_external_file_irp_copy(completion, 4096) {
                Ok(invocation) => invocation,
                Err(rejection) => {
                    let (status, completion) = rejection.into_parts();
                    keep(id, Payload::Completion(completion));
                    return Err(status);
                }
            }
        }
        Payload::Copy(returned) => returned.retry(),
        other => {
            keep(id, other);
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    };
    row(id).flight = Flight::Copy;
    let returned = hosted_file_dispatch::copy(invocation);
    match io_manager_mut().finish_external_file_irp_copy(returned) {
        Ok(completion) => {
            keep(id, Payload::Completion(completion));
            Ok(())
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retry_later(id, Payload::Copy(returned), status);
            Err(status)
        }
    }
}

pub(super) fn copy_output(
    irp_id: IrpId,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, nt_status::NtStatus> {
    copy_captured(irp_id, offset, output, false)
}

/// Read the terminal Type3InputBuffer snapshot before ACK. Only the mutable METHOD_NEITHER
/// policy can expose this range; an ordinary output copy must never index the input owner.
pub(super) fn copy_mutable_input(
    irp_id: IrpId,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, nt_status::NtStatus> {
    copy_captured(irp_id, offset, output, true)
}

fn copy_captured(
    irp_id: IrpId,
    offset: u64,
    output: &mut [u8],
    mutable_input: bool,
) -> Result<usize, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if (row(id).output_capture
        == nt_io_manager::detached_file_irp::ExternalFileIrpOutputCapture::MethodNeitherInput)
        != mutable_input
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    ensure_completion(id)?;
    let offset = usize::try_from(offset).map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    loop {
        match row(id).payload.as_ref() {
            Some(Payload::Completion(completion)) => {
                if offset > completion.capture_len() {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                let length = output.len().min(completion.capture_len() - offset);
                let end = offset + length;
                if end <= completion.captured_len() || length == 0 {
                    let captured = if mutable_input {
                        completion.buffers().input()
                    } else {
                        completion.buffers().output()
                    };
                    output[..length].copy_from_slice(&captured[offset..end]);
                    return Ok(length);
                }
            }
            Some(Payload::Copy(_)) => {}
            _ => return Err(nt_status::NtStatus::DEVICE_BUSY),
        }
        copy_chunk(id)?;
    }
}

pub(super) fn acknowledge(irp_id: IrpId) -> Result<(), nt_status::NtStatus> {
    acknowledge_with_buffers(irp_id).map(|_| ())
}

/// The port CONNECT caller retains the actual 16-byte Type3InputBuffer returned by its provider.
pub(super) fn acknowledge_port_connect(irp_id: IrpId) -> Result<[u8; 16], nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row(id).port_connect_control_storage.is_none() {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let buffers = acknowledge_with_buffers(irp_id)?;
    let mut input = [0u8; 16];
    assert_eq!(buffers.input().len(), input.len(), "validated CONNECT input length changed");
    input.copy_from_slice(buffers.input());
    Ok(input)
}

fn acknowledge_with_buffers(irp_id: IrpId) -> Result<ExternalFileIrpBuffers, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    trace_file_terminal_ack(6, id, irp_id, None);
    ensure_completion(id)?;
    if monotonic_time_100ns() < row(id).retry_after {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let abandoned = io_manager_mut()
        .detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)?
        .abandoned;
    if abandoned {
        match row(id).payload.take() {
            Some(Payload::Copy(returned)) => {
                keep(id, Payload::Completion(returned.into_completion()))
            }
            other => row(id).payload = other,
        }
    }
    loop {
        let needs_copy = match row(id).payload.as_ref() {
            Some(Payload::Completion(completion)) => !abandoned && !completion.capture_complete(),
            Some(Payload::Copy(_)) => true,
            Some(Payload::Acknowledgement(_)) => false,
            _ => return Err(nt_status::NtStatus::DEVICE_BUSY),
        };
        if !needs_copy {
            break;
        }
        copy_chunk(id)?;
    }
    if matches!(row(id).payload.as_ref(), Some(Payload::Completion(completion))
        if !completion.owes_backend_acknowledgement())
    {
        let completion = match row(id).payload.take() {
            Some(Payload::Completion(completion)) => completion,
            other => {
                row(id).payload = other;
                return Err(nt_status::NtStatus::DEVICE_BUSY);
            }
        };
        match io_manager_mut().retire_external_file_irp_completion_without_backend(completion) {
            Ok((receipt, buffers)) => {
                if receipt.backend_acknowledged() {
                    row(id).terminal_receipt = Some(receipt);
                    row(id).settled_buffers = Some(buffers);
                    quarantine_release(id, nt_status::NtStatus::INVALID_PARAMETER);
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                row(id).terminal_receipt = Some(receipt);
                row(id).settled_buffers = Some(buffers);
                trace_file_terminal_ack(7, id, irp_id, None);
                let mut retired = remove(id)?;
                return retired.settled_buffers.take()
                    .ok_or(nt_status::NtStatus::INVALID_PARAMETER);
            }
            Err(rejection) => {
                let (status, completion) = rejection.into_parts();
                block(id, Payload::Completion(completion), status);
                return Err(status);
            }
        }
    }
    if row(id).port_connect_control_storage.is_some() {
        if let Some(Payload::Completion(completion)) = row(id).payload.as_ref() {
            if completion.buffers().input().len() != 16 {
                return Err(nt_status::NtStatus::INVALID_PARAMETER);
            }
        }
    }
    let payload = row(id).payload.take().expect("File ACK owner missing");
    let invocation = match payload {
        Payload::Completion(completion) => {
            match io_manager_mut().begin_external_file_irp_acknowledgement(completion) {
                Ok(invocation) => invocation,
                Err(rejection) => {
                    let (status, completion) = rejection.into_parts();
                    keep(id, Payload::Completion(completion));
                    return Err(status);
                }
            }
        }
        Payload::Acknowledgement(returned) => {
            match io_manager_mut().finish_external_file_irp_completion(returned) {
                Ok((receipt, buffers)) => {
                    assert!(receipt.backend_acknowledged());
                    row(id).terminal_receipt = Some(receipt);
                    row(id).settled_buffers = Some(buffers);
                    trace_file_terminal_ack(8, id, irp_id, None);
                    let mut retired = remove(id)?;
                    return Ok(retired.settled_buffers.take()
                        .expect("acknowledged File buffers missing"));
                }
                Err(rejection) => {
                    let (status, returned) = rejection.into_parts();
                    match returned.retry() {
                        Ok(invocation) => invocation,
                        Err(returned) => {
                            block(id, Payload::Acknowledgement(returned), status);
                            return Err(status);
                        }
                    }
                }
            }
        }
        other => {
            keep(id, other);
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    };
    row(id).flight = Flight::Acknowledge;
    if !live_route(id) {
        let status = nt_status::NtStatus::DEVICE_NOT_CONNECTED;
        let returned = invocation.acknowledged(
            nt_io_manager::detached_file_irp::ExternalFileIrpAcknowledgement::NotEntered { status },
        );
        block(id, Payload::Acknowledgement(returned), status);
        return Err(status);
    }
    let returned = hosted_file_dispatch::acknowledge(invocation);
    match io_manager_mut().finish_external_file_irp_completion(returned) {
        Ok((receipt, buffers)) => {
            assert!(receipt.backend_acknowledged());
            assert!(io_manager_mut().accepts_external_file_irp_receipt(&receipt));
            row(id).terminal_receipt = Some(receipt);
            row(id).settled_buffers = Some(buffers);
            trace_file_terminal_ack(8, id, irp_id, None);
            let mut retired = remove(id)?;
            Ok(retired.settled_buffers.take()
                .expect("acknowledged File buffers missing"))
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retry_later(id, Payload::Acknowledgement(returned), status);
            trace_file_terminal_ack(9, id, irp_id, Some(status));
            Err(status)
        }
    }
}

fn cancel_queued(id: u64) -> bool {
    if row(id).flight != Flight::Idle {
        return false;
    }
    if !live_route(id) {
        row(id).flight = Flight::Blocked;
        row(id).blocked_status = Some(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        return false;
    }
    let payload = row(id).payload.take().expect("File cancel owner missing");
    let retained = match payload {
        Payload::Retained(retained) => retained,
        other => {
            keep(id, other);
            return false;
        }
    };
    let invocation = match io_manager_mut().begin_external_file_irp_cancel(retained) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, retained) = rejection.into_parts();
            retry_later(id, Payload::Retained(retained), status);
            return false;
        }
    };
    row(id).flight = Flight::Cancel;
    let returned = hosted_file_dispatch::cancel(invocation);
    match io_manager_mut().finish_external_file_irp_cancel(returned) {
        Ok(result) => {
            let (retained, outcome) = result.into_parts();
            keep(id, Payload::Retained(retained));
            if matches!(
                outcome,
                nt_io_manager::detached_file_irp::ExternalFileIrpCancelOutcome::NotEntered { .. }
                    | nt_io_manager::detached_file_irp::ExternalFileIrpCancelOutcome::Rejected { .. }
            ) {
                row(id).retry_after = monotonic_time_100ns().saturating_add(1_000_000);
            }
            true
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            block(id, Payload::Cancel(returned), status);
            false
        }
    }
}

pub(super) fn drain() -> usize {
    let _durable = crate::allocator::enter_durable();
    let mut selected = [0u64; 32];
    let now = monotonic_time_100ns();
    RETRY_READY.store(0, Ordering::Relaxed);
    for entry in rows().iter_mut() {
        entry.work_ready = false;
        // Activation gate: a queued READ is owned by the parent-restore checkpoint, not this
        // ordinary drain. Its cancel/abandon intent must be settled by redrive_queued_read before
        // the service loop resumes unrestricted provider or maintenance work.
        if entry.flight != Flight::Idle {
            continue;
        }
        let Some(irp_id) = entry.irp_id else { continue };
        let Ok(intent) =
            io_manager_mut().detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)
        else {
            continue;
        };
        entry.work_ready = matches!(entry.payload, Some(Payload::NoEntry(_)))
            || intent.cancel == ExternalFileIrpCancelPhase::Queued
            && matches!(entry.payload, Some(Payload::Retained(_)))
            || intent.abandoned && io_manager_mut().completed_irp(irp_id).is_some();
        if !entry.work_ready
            && entry.retry_after != 0
            && entry.retry_after <= now
            && matches!(entry.payload, Some(Payload::Copy(_)
                | Payload::Acknowledgement(_) | Payload::NoEntry(_)))
        {
            // Transfer a due retry to its delivery owner once, rather than rearming
            // an overdue timer while that owner is waiting for the outer loop.
            entry.retry_after = 0;
            crate::service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
        }
        if entry.work_ready && entry.retry_after == 0 {
            entry.retry_after = now;
        }
    }
    let cursor = unsafe { NEXT_DRAIN_ID };
    let selection = nt_kernel_exec::select_cyclic_ids(
        rows()
            .iter()
            .filter(|row| row.work_ready && row.flight == Flight::Idle && row.retry_after <= now)
            .map(|row| row.id),
        cursor,
        &mut selected,
    );
    let count = selection.count;
    unsafe { NEXT_DRAIN_ID = selection.next_cursor };
    let mut progress = 0;
    for id in &selected[..count] {
        let Some(irp_id) = rows()
            .iter()
            .find(|row| row.id == *id)
            .and_then(|row| row.irp_id)
        else {
            continue;
        };
        let Ok(intent) =
            io_manager_mut().detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)
        else {
            continue;
        };
        if matches!(row(*id).payload.as_ref(), Some(Payload::NoEntry(_))) {
            progress += usize::from(retry_no_entry(*id).is_ok());
        } else if intent.abandoned && io_manager_mut().completed_irp(irp_id).is_some() {
            progress += usize::from(acknowledge(irp_id).is_ok());
        } else if intent.cancel == ExternalFileIrpCancelPhase::Queued {
            progress += usize::from(cancel_queued(*id));
        }
    }
    progress
}

pub(super) fn retry_deadline() -> Option<u64> {
    if RETRY_READY.load(Ordering::Relaxed) != 0 {
        return None;
    }
    rows()
        .iter()
        .filter(|row| row.flight == Flight::Idle && row.retry_after != 0)
        .map(|row| row.retry_after)
        .min()
}

pub(super) fn retry_wake_due(now: u64) -> u64 {
    if retry_deadline().is_some_and(|deadline| now >= deadline) {
        return u64::from(RETRY_READY.swap(1, Ordering::Relaxed) == 0);
    }
    0
}

pub(super) fn device_quiesced(device_id: u64) -> bool {
    rows().iter().all(|row| {
        row.primary_device
            .is_none_or(|device| device.raw() != device_id)
            && row
                .stack
                .iter()
                .all(|(device, _)| device.raw() != device_id)
    })
}

pub(super) fn instance_quiesced(index: usize) -> bool {
    let driver = instance(index).map(|instance| instance.driver_id);
    rows().iter().all(|row| {
        row.authorities
            .iter()
            .all(|authority| authority.instance != index)
            && row
                .primary_driver
                .map(|id| id.raw())
                .is_none_or(|id| Some(id) != driver)
            && row.stack.iter().all(|(_, id)| Some(id.raw()) != driver)
    })
}

pub(super) fn domain_quiesced(domain: HostedDomainIdentity) -> bool {
    rows().iter().all(|row| {
        row.authorities
            .iter()
            .all(|authority| authority.domain != domain)
    })
}

pub(super) fn lifetime_quiesced(
    index: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
) -> bool {
    instance_quiesced(index)
        && domain_quiesced(domain)
        && rows().iter().all(|row| {
            row.primary_driver.is_none_or(|id| id.raw() != driver_id)
                && row
                    .stack
                    .iter()
                    .all(|(_, driver)| driver.raw() != driver_id)
        })
}
