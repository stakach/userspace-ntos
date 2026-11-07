//! Native File IRP ownership across provider IPC and completion delivery.

use super::*;
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpBuffers, ExternalFileIrpCancelPhase, ExternalFileIrpCancelReturn,
    ExternalFileIrpCompletionInvocation, ExternalFileIrpCompletionReturn,
    ExternalFileIrpCopyReturn, ExternalFileIrpDispatchPolicy, ExternalFileIrpOutputCapture,
    ExternalFileIrpNoEntryReceipt, ExternalFileIrpOutcome, ExternalFileIrpRequest,
    ExternalFileIrpResult, ExternalFileIrpReturn, ExternalFileIrpTerminal,
    ExternalFileIrpTerminalReceipt, PreparedExternalFileIrp, RetainedExternalFileIrp,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flight {
    Preparing,
    QueuedDispatch,
    Dispatch,
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
    Retained(RetainedExternalFileIrp),
    Completion(ExternalFileIrpCompletionInvocation),
    Acknowledgement(ExternalFileIrpCompletionReturn),
    Copy(ExternalFileIrpCopyReturn),
    Cancel(ExternalFileIrpCancelReturn),
    Terminal(ExternalFileIrpTerminal),
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
    Ok(rows().swap_remove(index))
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
}

fn keep(id: u64, payload: Payload) {
    let row = row(id);
    row.payload = Some(payload);
    row.flight = Flight::Idle;
    row.blocked_status = None;
    row.retry_after = 0;
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

/// Exact-device callers must authenticate and retain their Device and completion recipient.
pub(super) fn dispatch(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
) -> Result<DispatchResult, nt_status::NtStatus> {
    dispatch_with_port_connect(caller, request, input, initial_output, policy, None)
}

pub(super) fn dispatch_port_connect(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    device: nt_io_manager::DeviceId,
) -> Result<DispatchResult, nt_status::NtStatus> {
    dispatch_with_port_connect(
        caller, request, input, &[],
        ExternalFileIrpDispatchPolicy::MutableMethodNeitherInputAtDevice,
        Some(device),
    )
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

fn dispatch_with_port_connect(
    caller: nt_process::native_handle::NativeHandleCaller,
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
    policy: ExternalFileIrpDispatchPolicy,
    port_connect_device: Option<nt_io_manager::DeviceId>,
) -> Result<DispatchResult, nt_status::NtStatus> {
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
            return Err(status);
        }
    };
    if let Err(status) = unsafe { bind_pending_scsi_proof_irp(policy, &prepared) } {
        discard(id, prepared)?;
        return Err(status);
    }
    if let Err(status) = capture_route(id, &prepared) {
        discard(id, prepared)?;
        return Err(status);
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
            return Err(status);
        }
    }
    let invocation = match io_manager_mut().begin_prepared_external_file_irp(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, prepared) = rejection.into_parts();
            discard(id, prepared)?;
            return Err(status);
        }
    };
    row(id).flight = Flight::Dispatch;
    if phase.entered != 0 {
        row(id).phase_major = major;
        phase.identity = Some(nt_hosted_runtime::HostedFileRpcIdentity {
            irp_id: irp_id.raw(), major,
        });
    }
    if let Some(device) = port_connect_device {
        trace_port_connect_dispatch(2, irp_id, device);
    }
    if phase.entered != 0 { phase.invoked = crate::disk_census_ticks(); }
    if scsi_phase.started.is_some() { scsi_phase.invoked = Some(crate::disk_census_ticks()); }
    let returned =
        hosted_file_dispatch::invoke(invocation, row(id).caller, policy.output_capture());
    if scsi_phase.started.is_some() { scsi_phase.returned = Some(crate::disk_census_ticks()); }
    if phase.entered != 0 {
        phase.returned = crate::disk_census_ticks();
        phase.pump_ticks = row(id).phase_pump_ticks;
        phase.bank_ticks = row(id).phase_bank_ticks;
    }
    if let Some(device) = port_connect_device {
        trace_port_connect_dispatch(3, irp_id, device);
    }
    let result = match io_manager_mut().finish_external_file_irp(returned) {
        Ok(result) => result,
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            block(id, Payload::Returned(returned), status);
            return Ok(DispatchResult::Outstanding { irp_id });
        }
    };
    match result {
        ExternalFileIrpResult::NotEntered { status, prepared } => {
            if discard(id, prepared).is_err() {
                return Ok(DispatchResult::Outstanding { irp_id });
            }
            Err(status)
        }
        ExternalFileIrpResult::Returned(terminal) => {
            let completion = *terminal.completion();
            match io_manager_mut().retire_external_file_irp_terminal(terminal) {
                Ok((receipt, buffers)) => {
                    assert!(io_manager_mut().accepts_external_file_irp_receipt(&receipt));
                    row(id).terminal_receipt = Some(receipt);
                    row(id).settled_buffers = Some(buffers);
                    let mut retired = match remove(id) {
                        Ok(retired) => retired,
                        Err(_) => return Ok(DispatchResult::Outstanding { irp_id }),
                    };
                    Ok(DispatchResult::Returned {
                        irp_id,
                        status: completion.status,
                        information: completion.information,
                        file_context: completion.file_context,
                        buffers: retired
                            .settled_buffers
                            .take()
                            .expect("retired File buffers missing"),
                    })
                }
                Err(rejection) => {
                    let (status, terminal) = rejection.into_parts();
                    block(id, Payload::Terminal(terminal), status);
                    Ok(DispatchResult::Outstanding { irp_id })
                }
            }
        }
        ExternalFileIrpResult::Pending(retained) => {
            keep(id, Payload::Retained(retained));
            Ok(DispatchResult::Outstanding { irp_id })
        }
        ExternalFileIrpResult::Indeterminate {
            transport_status,
            retained,
        } => {
            keep(id, Payload::Retained(retained));
            row(id).blocked_status = Some(transport_status);
            Ok(DispatchResult::Outstanding { irp_id })
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
    let _durable = crate::allocator::enter_durable();
    let Some(id) = find(irp_id) else { return QueuedReadRedriveOutcome::NoWork };
    if row(id).flight != Flight::QueuedDispatch { return QueuedReadRedriveOutcome::NoWork }
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
    let mut phase = FileRpcPhaseGuard::new(major::IRP_MJ_READ);
    let invocation = match io_manager_mut().begin_prepared_external_file_irp(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, prepared) = rejection.into_parts();
            // A queued cancellation is a proven no-entry terminal; a failed physical or
            // manager route remains retained if its exact cause cannot be terminalized.
            if status == nt_status::NtStatus::CANCELLED {
                match io_manager_mut().complete_prepared_external_file_irp_without_entry(
                    prepared,
                    nt_io_manager::detached_file_irp::ExternalFileIrpPreEntryFailure::Cancelled,
                ) {
                    Ok(retained) => {
                        keep(id, Payload::Retained(retained));
                        return QueuedReadRedriveOutcome::Progressed;
                    }
                    Err(rejection) => {
                        let (error, prepared) = rejection.into_parts();
                        block(id, Payload::Prepared(prepared), error);
                        return QueuedReadRedriveOutcome::Retained(error);
                    }
                }
            }
            // A manager route refusal is terminal only when the manager validates its own
            // route fault against this exact preparation. Other refusals remain retained.
            let failure = nt_io_manager::detached_file_irp::ExternalFileIrpPreEntryFailure::ManagerRouteUnavailable;
            match io_manager_mut().complete_prepared_external_file_irp_without_entry(prepared, failure) {
                Ok(retained) => {
                    keep(id, Payload::Retained(retained));
                    return QueuedReadRedriveOutcome::Progressed;
                }
                Err(rejection) => {
                    let (_, prepared) = rejection.into_parts();
                    block(id, Payload::Prepared(prepared), status);
                    return QueuedReadRedriveOutcome::Retained(status);
                }
            }
        }
    };
    // The manager has transferred the owner to Dispatched; even an uncertain transport
    // result may never send this invocation again.
    row(id).flight = Flight::Dispatch;
    row(id).phase_major = major::IRP_MJ_READ;
    phase.identity = Some(nt_hosted_runtime::HostedFileRpcIdentity {
        irp_id: irp_id.raw(), major: major::IRP_MJ_READ,
    });
    let returned = if !live_route(id) {
        // begin_prepared_external_file_irp transferred the exact manager owner, but the
        // captured native authority/generation is no longer live. No provider has entered.
        invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        })
    } else {
        phase.invoked = crate::disk_census_ticks();
        hosted_file_dispatch::invoke(
            invocation, row(id).caller, ExternalFileIrpDispatchPolicy::File.output_capture(),
        )
    };
    phase.returned = crate::disk_census_ticks();
    phase.pump_ticks = row(id).phase_pump_ticks;
    phase.bank_ticks = row(id).phase_bank_ticks;
    let result = match io_manager_mut().finish_external_file_irp(returned) {
        Ok(result) => result,
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            block(id, Payload::Returned(returned), status);
            return QueuedReadRedriveOutcome::Retained(status);
        }
    };
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
            QueuedReadRedriveOutcome::Retained(status)
        }
        ExternalFileIrpResult::Returned(terminal) => {
            row(id).completion = Some(*terminal.completion());
            keep(id, Payload::Terminal(terminal));
            QueuedReadRedriveOutcome::Progressed
        }
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
        payload @ (Payload::Terminal(_) | Payload::Completion(_) | Payload::Copy(_)
            | Payload::Acknowledgement(_)) => {
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
            Some(Payload::Terminal(terminal)) => {
                let captured = if mutable_input {
                    terminal.buffers().input()
                } else {
                    terminal.buffers().output()
                };
                let length = output.len();
                let end = offset.checked_add(length)
                    .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
                let capture_len = usize::try_from(terminal.completion().information)
                    .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
                if capture_len > captured.len() || end > capture_len {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                output.copy_from_slice(&captured[offset..end]);
                return Ok(length);
            }
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
    ensure_completion(id)?;
    if matches!(row(id).payload.as_ref(), Some(Payload::Terminal(_))) {
        let terminal = match row(id).payload.take() {
            Some(Payload::Terminal(terminal)) => terminal,
            other => {
                row(id).payload = other;
                return Err(nt_status::NtStatus::DEVICE_BUSY);
            }
        };
        match io_manager_mut().retire_external_file_irp_terminal(terminal) {
            Ok((receipt, buffers)) => {
                if receipt.backend_acknowledged()
                    || !io_manager_mut().accepts_external_file_irp_receipt(&receipt)
                {
                    row(id).terminal_receipt = Some(receipt);
                    row(id).settled_buffers = Some(buffers);
                    quarantine_release(id, nt_status::NtStatus::INVALID_PARAMETER);
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                row(id).terminal_receipt = Some(receipt);
                row(id).settled_buffers = Some(buffers);
                let mut retired = remove(id)?;
                return retired.settled_buffers.take()
                    .ok_or(nt_status::NtStatus::INVALID_PARAMETER);
            }
            Err(rejection) => {
                let (status, terminal) = rejection.into_parts();
                block(id, Payload::Terminal(terminal), status);
                return Err(status);
            }
        }
    }
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
        if completion.completion().completion_origin == nt_io_manager::IrpCompletionOrigin::NoBackendEntry)
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
            let mut retired = remove(id)?;
            Ok(retired.settled_buffers.take()
                .expect("acknowledged File buffers missing"))
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retry_later(id, Payload::Acknowledgement(returned), status);
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
