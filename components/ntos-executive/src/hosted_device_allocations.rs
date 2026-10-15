//! Physical allocation ownership for hosted-pool Device projections, independent of IoManager.
use super::*;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::{
    HostedDevicePointerRegistration, ProjectionAllocationLedger, ProjectionAllocationOwner,
};

#[path = "hosted_dma_adapter_pair.rs"]
mod dma_adapter_pair;
#[path = "hosted_dma_private_graph.rs"]
mod dma_private_graph;
pub(super) use dma_private_graph::Kind as DmaPrivateKind;
#[path = "hosted_interrupt_projection.rs"]
mod interrupt_projection;

pub(super) unsafe fn provision_interrupt_projection(
    inst: DriverInstance, binding: HostedDeviceBinding,
) -> Result<(u64, u64), nt_status::NtStatus> {
    interrupt_projection::provision(inst, binding)
}

pub(super) unsafe fn validate_interrupt_projection(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::validate(inst, binding, address)
}

pub(super) unsafe fn bind_interrupt_projection(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
    interrupt_id: u64, grant_generation: u64,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::bind(inst, binding, address, interrupt_id, grant_generation)
}

pub(super) unsafe fn mark_interrupt_projection_effect_started(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::mark_effect_started(inst, binding, address)
}

pub(super) fn admit_interrupt_projection_canonical_retirement(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
    connection: (u64, u64),
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::admits_canonical_retirement(inst, binding, address, connection)
}

pub(super) unsafe fn interrupt_projection_connection_for_retirement(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
) -> Result<Option<(u64, u64)>, nt_status::NtStatus> {
    interrupt_projection::connection_for_retirement(inst, binding, address)
}

pub(super) fn mark_interrupt_projection_canonical_retired(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
    connection: (u64, u64),
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::mark_canonical_retired(inst, binding, address, connection)
}

pub(super) unsafe fn retire_interrupt_projection_physical(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::retire_physical(inst, binding, address)
}

pub(super) unsafe fn cancel_prepared_interrupt_projection(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::cancel_prepared(inst, binding, address)
}

pub(super) unsafe fn cancel_interrupt_projection_after_proven_no_effect(
    inst: DriverInstance, binding: HostedDeviceBinding, address: u64,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::cancel_after_proven_no_effect(inst, binding, address)
}

pub(super) unsafe fn drain_interrupt_projection_tombstones(
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    interrupt_projection::drain_tombstones(inst)
}

pub(super) unsafe fn provision_dma_adapter_pair(
    inst: DriverInstance, lease_id: u64,
) -> Result<(u64, u64), nt_status::NtStatus> {
    dma_adapter_pair::provision_dma_adapter_pair(inst, lease_id)
}

pub(super) unsafe fn retire_dma_adapter_pair(
    inst: DriverInstance, lease_id: u64, adapter_address: u64,
    put: impl FnOnce() -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    dma_adapter_pair::retire_dma_adapter_pair(inst, lease_id, adapter_address, put)
}

pub(super) fn has_dma_adapter_pair(lease_id: u64) -> bool {
    let _catalog = lock();
    dma_adapter_pair::has_lease(lease_id)
}

pub(super) unsafe fn drain_dma_adapter_tombstones(
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    dma_adapter_pair::drain_dma_adapter_tombstones(inst)
}

pub(super) unsafe fn provision_dma_private_graph(
    inst: DriverInstance, lease_id: u64, request_id: u64, kind: DmaPrivateKind,
    borrowed_list: u64,
) -> Result<(u64, u64, u64), nt_status::NtStatus> {
    dma_private_graph::provision(inst, lease_id, request_id, kind, borrowed_list)
}

pub(super) unsafe fn record_dma_private_mapping(
    inst: DriverInstance, lease_id: u64, map: u64, logical: u64,
    backing: u64, length: u64,
    register: impl FnOnce() -> Result<u64, nt_status::NtStatus>,
) -> Result<u64, nt_status::NtStatus> {
    dma_private_graph::record_mapping(inst, lease_id, map, logical, backing, length, register)
}

pub(super) unsafe fn dma_private_mapping_receipt(
    inst: DriverInstance, map: u64, logical: u64, backing: u64, length: u64,
) -> Option<(u64, u64)> {
    dma_private_graph::mapping_receipt(inst, map, logical, backing, length)
}

pub(super) unsafe fn retire_dma_private_graph(
    inst: DriverInstance, lease_id: u64, address: u64, whole_graph: bool,
    release: impl FnMut(u64) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    dma_private_graph::retire(inst, lease_id, address, whole_graph, release)
}

pub(super) unsafe fn dma_private_sg_members(
    inst: DriverInstance, lease_id: u64, list: u64,
) -> Result<(u64, u64), nt_status::NtStatus> {
    dma_private_graph::sg_members(inst, lease_id, list)
}

pub(super) unsafe fn retire_dma_private_lease(
    inst: DriverInstance, lease_id: u64,
    release: impl FnMut(u64) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    dma_private_graph::retire_lease(inst, lease_id, release)
}

pub(super) unsafe fn drain_dma_private_tombstones(
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    dma_private_graph::drain_tombstones(inst)
}

struct Row {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    allocation: SourcePoolAllocationIdentity,
    staged_driver_object: Option<u64>,
    accepted: Option<HostedDevicePointerRegistration>,
    accepted_driver_object: Option<u64>,
    registration: Option<HostedDevicePointerRegistration>,
    owner: ProjectionAllocationOwner,
    retirement_pending: bool,
}
static LOCK: AtomicU64 = AtomicU64::new(0);
static mut LEDGER: ProjectionAllocationLedger = ProjectionAllocationLedger::new();
static mut ROWS: Vec<Row> = Vec::new();
// Short-lived foreign callback input/output ranges. A pin protects the whole exact pool
// allocation, including interior pointers passed to the callback. A lost effect is quarantined.
struct TemporaryPinRow {
    id: u64,
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    allocation: SourcePoolAllocationIdentity,
    uncertain: bool,
}
static mut TEMPORARY_PINS: Vec<TemporaryPinRow> = Vec::new();
static mut NEXT_TEMPORARY_PIN_ID: u64 = 1;

fn temporary_pins() -> &'static mut Vec<TemporaryPinRow> {
    unsafe { &mut *core::ptr::addr_of_mut!(TEMPORARY_PINS) }
}

/// Exact physical pin receipt. Dropping this value does not release its pool exclusion.
#[must_use = "retain through callback acknowledgement; quarantine uncertain effects"]
pub(super) struct TemporaryPoolPin {
    id: u64,
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    allocation: SourcePoolAllocationIdentity,
    held: bool,
}

impl TemporaryPoolPin {
    pub(super) fn allocation(&self) -> SourcePoolAllocationIdentity {
        self.allocation
    }
}
// FILE_OBJECT storage has the same pool exclusion requirement as Device projections. Its
// constructor name is captured before the driver's CREATE callback can mutate FileName.Buffer.
struct FileStorageRow {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    file_id: u64,
    file: SourcePoolAllocationIdentity,
    name: SourcePoolAllocationIdentity,
    publishing: bool,
    binding_generation: u64,
    canonical_unbound: bool,
    name_freed: bool,
    file_freed: bool,
}
static mut FILE_ROWS: Vec<FileStorageRow> = Vec::new();
#[derive(Clone, Copy)]
struct FileStorageAck {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    file_id: u64,
    file: SourcePoolAllocationIdentity,
    name: SourcePoolAllocationIdentity,
}
static mut FILE_ACKS: Vec<FileStorageAck> = Vec::new();
fn file_rows() -> &'static mut Vec<FileStorageRow> {
    unsafe { &mut *core::ptr::addr_of_mut!(FILE_ROWS) }
}
fn file_acks() -> &'static mut Vec<FileStorageAck> {
    unsafe { &mut *core::ptr::addr_of_mut!(FILE_ACKS) }
}
fn contains_allocation(identity: SourcePoolAllocationIdentity, address: u64) -> bool {
    address >= identity.component_address
        && address < identity.component_address.saturating_add(identity.capacity)
}
fn protects_file_member(row: &FileStorageRow, address: u64) -> bool {
    (!row.file_freed && contains_allocation(row.file, address))
        || (!row.name_freed && contains_allocation(row.name, address))
}

pub(super) struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(0, Ordering::Release);
    }
}
fn lock() -> Guard {
    while LOCK
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        crate::yield_now();
    }
    Guard
}
fn rows() -> &'static mut Vec<Row> {
    unsafe { &mut *core::ptr::addr_of_mut!(ROWS) }
}
fn ledger() -> &'static mut ProjectionAllocationLedger {
    unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) }
}
fn same_arena(a: DriverInstance, b: DriverInstance) -> bool {
    instance_domain_identity(a) == instance_domain_identity(b)
        && a.exec_pool_va == b.exec_pool_va
        && a.pool_frame_base == b.pool_frame_base
        && a.pml4 == b.pml4
}
fn same_pool(a: DriverInstance, b: DriverInstance) -> bool {
    a.exec_pool_va != 0
        && a.exec_pool_va == b.exec_pool_va
        && a.pool_frame_base == b.pool_frame_base
}
fn validate_arena(inst: DriverInstance) -> Result<HostedDomainIdentity, nt_status::NtStatus> {
    if !inst.used || inst.exec_pool_va == 0 || inst.pool_frame_base == 0 || inst.pml4 == 0 {
        return Err(nt_status::NtStatus::ACCESS_DENIED);
    }
    instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)
}
unsafe fn allocation(
    inst: DriverInstance,
    address: u64,
) -> Result<SourcePoolAllocationIdentity, nt_status::NtStatus> {
    validate_arena(inst)?;
    let used = hosted_pool_used(inst.exec_pool_va);
    if used < POOL_DATA_OFF || used > FSD_POOL_FRAMES * 0x1000 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let offset = address
        .checked_sub(FSD_POOL_VADDR)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    if offset >= FSD_POOL_FRAMES * 0x1000 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let found = nt_io_manager::hosted_pool_range::walk_hosted_pool_allocation(
        FSD_POOL_FRAMES * 0x1000,
        used,
        POOL_DATA_OFF,
        offset,
        1,
        |header| {
            if header.checked_add(8)? > used {
                return None;
            }
            Some(read_volatile(
                inst.exec_pool_va.checked_add(header)? as *const u64
            ))
        },
    )
    .filter(|found| found.base == offset)
    .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let exec = inst
        .exec_pool_va
        .checked_add(found.base)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    if hosted_instance_pool_allocation_is_free_unlocked(inst, address) != Some(false) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let pool_generation = read_volatile((exec - 8) as *const u64);
    if pool_generation == 0 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    Ok(SourcePoolAllocationIdentity {
        component_address: address,
        capacity: found.capacity,
        pool_generation,
    })
}

/// Resolve an interior byte range to one live allocation while the caller holds the allocator
/// lock. `allocation` itself deliberately accepts only a base address.
unsafe fn allocation_containing(
    inst: DriverInstance,
    address: u64,
    bytes: u64,
) -> Result<SourcePoolAllocationIdentity, nt_status::NtStatus> {
    validate_arena(inst)?;
    if bytes == 0 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let used = hosted_pool_used(inst.exec_pool_va);
    if used < POOL_DATA_OFF || used > FSD_POOL_FRAMES * 0x1000 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let offset = address
        .checked_sub(FSD_POOL_VADDR)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let found = nt_io_manager::hosted_pool_range::walk_hosted_pool_allocation(
        FSD_POOL_FRAMES * 0x1000,
        used,
        POOL_DATA_OFF,
        offset,
        bytes,
        |header| {
            if header.checked_add(8)? > used {
                return None;
            }
            Some(read_volatile(
                inst.exec_pool_va.checked_add(header)? as *const u64
            ))
        },
    )
    .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let base = FSD_POOL_VADDR
        .checked_add(found.base)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let exact = allocation(inst, base)?;
    if exact.capacity != found.capacity {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    Ok(exact)
}

/// Pin the exact live pool allocation containing a callback byte range before provider entry.
/// The catalog lock is taken before the pool lock, matching all generic free admissions, so a
/// successful capture cannot race the physical free. Multiple callbacks may pin one allocation;
/// each receipt must be acknowledged separately before generic free is admitted again.
pub(super) unsafe fn pin_temporary_pool_range(
    inst: DriverInstance,
    address: u64,
    bytes: u64,
) -> Result<TemporaryPoolPin, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _guard = lock();
    let domain = validate_arena(inst)?;
    let _pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let exact = allocation_containing(inst, address, bytes)?;
    if ledger().protects_address(domain, exact.component_address)
        || dma_adapter_pair::protects(inst, exact.component_address)
        || dma_private_graph::protects(inst, exact.component_address)
        || interrupt_projection::protects(inst, exact.component_address)
        || rows().iter().any(|row| {
            same_pool(row.instance, inst)
                && row.allocation.component_address == exact.component_address
        })
        || file_rows().iter().any(|row| {
            same_pool(row.instance, inst) && protects_file_member(row, exact.component_address)
        })
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    temporary_pins()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let id = unsafe { NEXT_TEMPORARY_PIN_ID };
    let next = id
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    temporary_pins().push(TemporaryPinRow {
        id,
        instance: inst,
        domain,
        allocation: exact,
        uncertain: false,
    });
    unsafe {
        NEXT_TEMPORARY_PIN_ID = next;
    }
    Ok(TemporaryPoolPin {
        id,
        instance: inst,
        domain,
        allocation: exact,
        held: true,
    })
}

/// A lost or ambiguous callback effect never permits pool reuse, even if a later address and
/// contents appear unchanged. Keep this row until a separately proven terminal path exists.
pub(super) fn retain_temporary_pool_pin_uncertain(pin: &TemporaryPoolPin) -> bool {
    let _guard = lock();
    let Some(row) = temporary_pins().iter_mut().find(|row| row.id == pin.id) else {
        return false;
    };
    if !pin.held
        || !same_arena(row.instance, pin.instance)
        || row.domain != pin.domain
        || row.allocation != pin.allocation
    {
        return false;
    }
    row.uncertain = true;
    true
}

/// True also when the exact row has disappeared: callers must treat lost ownership as uncertain.
pub(super) fn temporary_pool_pin_uncertain(pin: &TemporaryPoolPin) -> bool {
    let _guard = lock();
    !pin.held
        || temporary_pins()
            .iter()
            .find(|row| {
                row.id == pin.id
                    && same_arena(row.instance, pin.instance)
                    && row.domain == pin.domain
                    && row.allocation == pin.allocation
            })
            .is_none_or(|row| row.uncertain)
}

/// Call only after the callback owner's real completion and reply acknowledgement have both
/// succeeded. This primitive verifies the pin's exact allocation generation; it does not prove
/// callback acknowledgement by itself. Failure retains the row and the caller's receipt.
pub(super) unsafe fn release_temporary_pool_pin(
    pin: &mut TemporaryPoolPin,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    if !pin.held {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let index = temporary_pins()
        .iter()
        .position(|row| {
            row.id == pin.id
                && same_arena(row.instance, pin.instance)
                && row.domain == pin.domain
                && row.allocation == pin.allocation
        })
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if temporary_pins()[index].uncertain {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let _pool = hosted_instance_pool_lock(pin.instance.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    if allocation(pin.instance, pin.allocation.component_address)? != pin.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    temporary_pins().swap_remove(index);
    pin.held = false;
    Ok(())
}

/// Copy root-owned bytes into the pinned allocation before publishing it to a foreign class
/// callback. The row is marked uncertain before the write, then restored only after its exact
/// physical generation is revalidated under the same pool lock.
pub(super) unsafe fn write_temporary_pool_pin(
    pin: &TemporaryPoolPin,
    offset: u64,
    bytes: &[u8],
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    if !pin.held
        || bytes.is_empty()
        || offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > pin.allocation.capacity)
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let index = temporary_pins()
        .iter()
        .position(|row| {
            row.id == pin.id
                && same_arena(row.instance, pin.instance)
                && row.domain == pin.domain
                && row.allocation == pin.allocation
        })
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if temporary_pins()[index].uncertain {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let _pool = hosted_instance_pool_lock(pin.instance.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    if allocation(pin.instance, pin.allocation.component_address)? != pin.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let exec = pin
        .instance
        .exec_pool_va
        .checked_add(pin.allocation.component_address - FSD_POOL_VADDR)
        .and_then(|base| base.checked_add(offset))
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    temporary_pins()[index].uncertain = true;
    core::ptr::copy(bytes.as_ptr(), exec as *mut u8, bytes.len());
    if allocation(pin.instance, pin.allocation.component_address)? != pin.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    temporary_pins()[index].uncertain = false;
    Ok(())
}

/// Copy a live interior range while the exact pool generation and generic-free exclusion are
/// held under the same catalog to pool lock order. The parked IRQ worker owns concurrent writes
/// to callback records; this lease prevents physical reuse during the copy.
pub(super) unsafe fn copy_temporary_pool_pin(
    pin: &TemporaryPoolPin,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    if !pin.held
        || destination.is_empty()
        || offset
            .checked_add(destination.len() as u64)
            .is_none_or(|end| end > pin.allocation.capacity)
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let row = temporary_pins()
        .iter()
        .find(|row| {
            row.id == pin.id
                && same_arena(row.instance, pin.instance)
                && row.domain == pin.domain
                && row.allocation == pin.allocation
                && !row.uncertain
        })
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let _ = row;
    let _pool = hosted_instance_pool_lock(pin.instance.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    if allocation(pin.instance, pin.allocation.component_address)? != pin.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let exec = pin
        .instance
        .exec_pool_va
        .checked_add(pin.allocation.component_address - FSD_POOL_VADDR)
        .and_then(|base| base.checked_add(offset))
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    core::ptr::copy_nonoverlapping(exec as *const u8, destination.as_mut_ptr(), destination.len());
    if allocation(pin.instance, pin.allocation.component_address)? != pin.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok(())
}

/// Free an allocation that root itself created and kept pinned for its entire lifetime. The
/// owner must first finish every callback ACK. No other temporary pin may still refer to the
/// allocation. An uncertain physical free leaves the row blocked and cannot be retried.
pub(super) unsafe fn retire_owned_temporary_pool_allocation(
    pin: &mut TemporaryPoolPin,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    if !pin.held {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let index = temporary_pins()
        .iter()
        .position(|row| {
            row.id == pin.id
                && same_arena(row.instance, pin.instance)
                && row.domain == pin.domain
                && row.allocation == pin.allocation
        })
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if temporary_pins()[index].uncertain
        || temporary_pins().iter().any(|row| {
            row.id != pin.id
                && same_pool(row.instance, pin.instance)
                && row.allocation == pin.allocation
        })
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let _pool = hosted_instance_pool_lock(pin.instance.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    if allocation(pin.instance, pin.allocation.component_address)? != pin.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    temporary_pins()[index].uncertain = true;
    if !hosted_instance_pool_free_unlocked(pin.instance, pin.allocation.component_address) {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    temporary_pins().swap_remove(index);
    pin.held = false;
    Ok(())
}

/// The returned lock spans the subsequent generic free, preventing publication in between.
pub(super) fn generic_free_admission(
    inst: DriverInstance,
    address: u64,
) -> Result<Guard, nt_status::NtStatus> {
    let guard = lock();
    let domain = validate_arena(inst)?;
    if ledger().protects_address(domain, address)
        || dma_adapter_pair::protects(inst, address)
        || dma_private_graph::protects(inst, address)
        || interrupt_projection::protects(inst, address)
        || rows().iter().any(|row| {
            same_pool(row.instance, inst)
                && address >= row.allocation.component_address
                && address < row.allocation.component_address + row.allocation.capacity
        })
        || file_rows()
            .iter()
            .any(|row| same_pool(row.instance, inst) && protects_file_member(row, address))
        || temporary_pins().iter().any(|row| {
            same_pool(row.instance, inst) && contains_allocation(row.allocation, address)
        })
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(guard)
}

/// Capture both exact physical allocations while CREATE still owns the unentered driver call.
#[derive(Debug)]
pub(super) struct FileStorageCaptureError {
    pub(super) status: nt_status::NtStatus,
    /// The failed operation did not install an owner and no other physical row owns either member.
    pub(super) no_root_owner: bool,
}

pub(super) unsafe fn protect_file_storage(
    inst: DriverInstance,
    file_id: u64,
    address: u64,
) -> Result<(), FileStorageCaptureError> {
    let _durable = crate::allocator::enter_durable();
    let _guard = lock();
    let mut name_address = 0;
    let result = (|| -> Result<(), nt_status::NtStatus> {
        let domain = validate_arena(inst)?;
        let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
            .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
        let file = allocation(inst, address)?;
        if file.capacity < WDM_X64_FILE_OBJECT_SIZE as u64 {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let exec = inst.exec_pool_va + address - FSD_POOL_VADDR;
        name_address = read_unaligned((exec + 0x60) as *const u64);
        if name_address == 0 || name_address == address {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let name = allocation(inst, name_address)?;
        if dma_adapter_pair::protects(inst, address)
            || dma_private_graph::protects(inst, address)
            || interrupt_projection::protects(inst, address)
            || dma_adapter_pair::protects(inst, name_address)
            || dma_private_graph::protects(inst, name_address)
            || interrupt_projection::protects(inst, name_address)
            || file_rows().iter().any(|row| {
            (row.domain == domain || same_pool(row.instance, inst))
                && (protects_file_member(row, address)
                    || protects_file_member(row, name_address))
        }) || rows().iter().any(|row| {
            same_pool(row.instance, inst)
                && (contains_allocation(row.allocation, address)
                    || contains_allocation(row.allocation, name_address))
        }) || temporary_pins().iter().any(|row| {
            same_pool(row.instance, inst)
                && (contains_allocation(row.allocation, address)
                    || contains_allocation(row.allocation, name_address))
        }) {
            return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
        }
        file_rows().try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        file_rows().push(FileStorageRow {
            instance: inst, domain, file_id, file, name,
            publishing: true, binding_generation: 0,
            canonical_unbound: false, name_freed: false, file_freed: false,
        });
        Ok(())
    })();
    result.map_err(|status| {
        let owned = file_rows().iter().any(|row| {
            same_pool(row.instance, inst)
                && (protects_file_member(row, address)
                    || name_address != 0 && protects_file_member(row, name_address))
        }) || rows().iter().any(|row| {
            same_pool(row.instance, inst)
                && (contains_allocation(row.allocation, address)
                    || name_address != 0 && contains_allocation(row.allocation, name_address))
        }) || interrupt_projection::protects(inst, address)
            || dma_private_graph::protects(inst, address)
            || name_address != 0 && interrupt_projection::protects(inst, name_address)
            || name_address != 0 && dma_private_graph::protects(inst, name_address)
            || temporary_pins().iter().any(|row| {
            same_pool(row.instance, inst)
                && (contains_allocation(row.allocation, address)
                    || name_address != 0 && contains_allocation(row.allocation, name_address))
        });
        FileStorageCaptureError {
            status,
            no_root_owner: !owned,
        }
    })
}

pub(super) fn mark_file_unbound_exact(
    inst: DriverInstance, file_id: u64, address: u64, generation: u64,
) -> bool {
    let _guard = lock();
    let Some(row) = file_rows().iter_mut().find(|row| {
        same_arena(row.instance, inst) && row.file_id == file_id
            && row.file.component_address == address
            && !row.publishing && row.binding_generation == generation && generation != 0
    }) else { return false; };
    row.canonical_unbound = true;
    true
}

/// A QUERY may mark absent only the physical row observed before consulting IoManager.
/// Zero/no row and publishing rows have no retirement authority.
pub(super) fn file_storage_bound_generation(
    inst: DriverInstance, file_id: u64, address: u64,
) -> Option<u64> {
    let _guard = lock();
    file_rows().iter().find(|row| {
        same_arena(row.instance, inst) && row.file_id == file_id
            && row.file.component_address == address && !row.publishing
            && row.binding_generation != 0
    }).map(|row| row.binding_generation)
}

pub(super) fn mark_file_bound(
    inst: DriverInstance, file_id: u64, address: u64, generation: u64,
) -> bool {
    if generation == 0 { return false; }
    let _guard = lock();
    let Some(row) = file_rows().iter_mut().find(|row| {
        same_arena(row.instance, inst) && row.file_id == file_id
            && row.file.component_address == address && row.publishing
    }) else { return false; };
    row.publishing = false;
    row.binding_generation = generation;
    true
}

/// Undo a just-captured row only after synchronous canonical bind returned a definite error.
/// The driver has not entered and no File publication exists for this attempt.
pub(super) fn cancel_unpublished_file_capture(
    inst: DriverInstance,
    file_id: u64,
    address: u64,
) -> bool {
    let _guard = lock();
    let Some(index) = file_rows().iter().position(|row| {
        same_arena(row.instance, inst) && row.file_id == file_id
            && row.file.component_address == address
            && row.publishing && !row.canonical_unbound && !row.name_freed && !row.file_freed
    }) else {
        return false;
    };
    file_rows().swap_remove(index);
    true
}

/// The single authenticated physical free attempt; each member is acknowledged independently.
/// A failed or uncertain attempt retains its row, barring address reuse and generic free.
pub(super) unsafe fn retire_file_storage(
    inst: DriverInstance,
    file_id: u64,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = file_rows().iter().position(|row| {
        same_arena(row.instance, inst) && row.domain == domain
            && row.file_id == file_id && row.file.component_address == address
    }).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut file_rows()[index];
    if row.publishing || !row.canonical_unbound {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if !row.name_freed {
        if allocation(inst, row.name.component_address)? != row.name
            || !hosted_instance_pool_free_unlocked(inst, row.name.component_address)
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        row.name_freed = true;
    }
    if !row.file_freed {
        if allocation(inst, row.file.component_address)? != row.file
            || !hosted_instance_pool_free_unlocked(inst, row.file.component_address)
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        row.file_freed = true;
    }
    // Keep the exact physical receipt until the component has observed this result. A lost
    // op9 reply cannot be interpreted as permission to issue another physical free.
    Ok(())
}

pub(super) fn file_storage_retirement_disposition(
    inst: DriverInstance, file_id: u64, address: u64, file_generation: u64,
) -> Result<u64, nt_status::NtStatus> {
    let _guard = lock();
    let domain = validate_arena(inst)?;
    let row = file_rows().iter().find(|row| {
        same_arena(row.instance, inst) && row.domain == domain
            && row.file_id == file_id && row.file.component_address == address
            && row.file.pool_generation == file_generation && row.canonical_unbound
    }).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    Ok(u64::from(row.name_freed) | (u64::from(row.file_freed) << 1))
}

pub(super) fn acknowledge_file_storage_retirement(
    inst: DriverInstance, file_id: u64, address: u64, file_generation: u64,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _guard = lock();
    let domain = validate_arena(inst)?;
    let Some(index) = file_rows().iter().position(|row| {
        same_arena(row.instance, inst) && row.domain == domain
            && row.file_id == file_id && row.file.component_address == address
            && row.file.pool_generation == file_generation && row.canonical_unbound
            && row.name_freed && row.file_freed
    }) else {
        return if file_acks().iter().any(|ack| {
            same_arena(ack.instance, inst) && ack.domain == domain
                && ack.file_id == file_id && ack.file.component_address == address
                && ack.file.pool_generation == file_generation
        }) { Ok(()) } else { Err(nt_status::NtStatus::INVALID_HANDLE) };
    };
    let row = &file_rows()[index];
    file_acks().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    file_acks().push(FileStorageAck {
        instance: row.instance, domain: row.domain, file_id: row.file_id,
        file: row.file, name: row.name,
    });
    file_rows().swap_remove(index);
    Ok(())
}

pub(super) fn drain_file_storage_acknowledgements(
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    if file_rows().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst)) {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    file_acks().retain(|ack| !same_arena(ack.instance, inst));
    Ok(())
}

pub(super) unsafe fn protect_allocation(
    inst: DriverInstance,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    protect_allocation_exact(inst, address, None)
}

pub(super) unsafe fn protect_allocation_exact(
    inst: DriverInstance,
    address: u64,
    expected: Option<SourcePoolAllocationIdentity>,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _guard = lock();
    let domain = validate_arena(inst)?;
    let _pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let current = allocation(inst, address)?;
    if expected.is_some_and(|expected| expected != current) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if dma_adapter_pair::protects(inst, address)
        || dma_private_graph::protects(inst, address)
        || interrupt_projection::protects(inst, address) {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if rows().iter().any(|row| {
        (row.domain == domain || same_pool(row.instance, inst)) && !same_arena(row.instance, inst)
    }) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if file_rows()
        .iter()
        .any(|row| same_pool(row.instance, inst) && protects_file_member(row, address))
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if temporary_pins()
        .iter()
        .any(|row| same_pool(row.instance, inst) && contains_allocation(row.allocation, address))
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if let Some(row) = rows()
        .iter()
        .find(|row| row.domain == domain && row.allocation.component_address == address)
    {
        return if same_arena(row.instance, inst)
            && row.allocation == current
            && !row.retirement_pending
        {
            Ok(())
        } else {
            Err(nt_status::NtStatus::INVALID_PARAMETER)
        };
    }
    rows()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let owner = ledger().stage(domain, current)?;
    rows().push(Row {
        instance: inst,
        domain,
        allocation: current,
        staged_driver_object: None,
        accepted: None,
        accepted_driver_object: None,
        registration: None,
        owner,
        retirement_pending: false,
    });
    Ok(())
}

pub(super) fn publish_registration(
    inst: DriverInstance,
    registration: HostedDevicePointerRegistration,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    let row = rows()
        .iter_mut()
        .find(|row| {
            same_arena(row.instance, inst)
                && row.allocation.component_address == registration.address()
        })
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.retirement_pending {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if row.accepted != Some(registration) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    if row.registration == Some(registration) {
        return Ok(());
    }
    ledger().attach_registration(&row.owner, registration)?;
    row.registration = Some(registration);
    Ok(())
}

/// Capture the constructor's list owner under both physical locks before canonical bind.
/// A later provider mutation of DEVICE_OBJECT.DriverObject cannot redirect native unlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeviceListOwner {
    Linked,
    Unlinked,
}

pub(super) unsafe fn stage_driver_object(
    inst: DriverInstance, address: u64, list_owner: DeviceListOwner,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let current = allocation(inst, address)?;
    let row = rows()
        .iter_mut()
        .find(|row| same_arena(row.instance, inst)
            && row.allocation.component_address == address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.retirement_pending || row.accepted.is_some() || row.allocation != current
        || current.capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64 {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let offset = address.checked_sub(FSD_POOL_VADDR)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let exec = inst.exec_pool_va.checked_add(offset)
        .and_then(|base| base.checked_add(0x08))
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let driver_object = read_unaligned(exec as *const u64);
    let next_device = read_unaligned((exec + 8) as *const u64);
    if (list_owner == DeviceListOwner::Linked && driver_object == 0)
        || (list_owner == DeviceListOwner::Unlinked
            && (driver_object != 0 || next_device != 0)) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    row.staged_driver_object = Some(driver_object);
    Ok(())
}

/// Retain the minted canonical token before fallible physical catalog publication. A failed
/// later attach still leaves exact provenance for canonical cleanup and physical retirement.
pub(super) fn record_accepted_registration(
    inst: DriverInstance,
    registration: HostedDevicePointerRegistration,
) -> Result<(), nt_status::NtStatus> {
    let _guard = lock();
    let row = rows()
        .iter_mut()
        .find(|row| same_arena(row.instance, inst)
            && row.allocation.component_address == registration.address())
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.retirement_pending || row.accepted.is_some_and(|accepted| accepted != registration) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let driver_object = row.staged_driver_object
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    row.accepted_driver_object = Some(driver_object);
    row.accepted = Some(registration);
    Ok(())
}

#[must_use = "retain physical retirement across failed or uncertain effects"]
pub(super) struct Retirement {
    domain: HostedDomainIdentity,
    allocation: SourcePoolAllocationIdentity,
}

#[must_use = "keep allocation exclusion through the native free and acknowledgement"]
pub(super) struct LocalRetirement {
    receipt: Retirement,
    _pool: ExecutivePoolLockGuard,
    _guard: Guard,
}

/// Read-only validation while the exact physical catalog and allocator are both excluded.
/// The caller must perform no native effect until checked admission returns successfully.
pub(super) struct RetirementPreflight {
    domain: HostedDomainIdentity,
    accepted_driver_object: Option<u64>,
}

impl RetirementPreflight {
    pub(super) fn accepted_driver_object(&self) -> Option<u64> {
        self.accepted_driver_object
    }
    pub(super) unsafe fn related_allocation_exec(
        &self,
        address: u64,
    ) -> Result<u64, nt_status::NtStatus> {
        let row = rows()
            .iter()
            .find(|row| row.domain == self.domain && row.allocation.component_address == address)
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        if row.allocation.capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64
            || allocation(row.instance, address)? != row.allocation
        {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        row.instance
            .exec_pool_va
            .checked_add(address - FSD_POOL_VADDR)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)
    }
}

pub(super) unsafe fn admit_retirement(
    inst: DriverInstance,
    address: u64,
    registration: Option<HostedDevicePointerRegistration>,
) -> Result<LocalRetirement, nt_status::NtStatus> {
    admit_retirement_checked(inst, address, registration, |_| Ok(())).map(|(receipt, ())| receipt)
}

/// Structural refusals are known to have no native effect and leave the exact owner available.
/// Once this returns, callers must retain the pending row through every uncertain native effect.
pub(super) unsafe fn admit_retirement_checked<T>(
    inst: DriverInstance,
    address: u64,
    registration: Option<HostedDevicePointerRegistration>,
    check: impl FnOnce(&RetirementPreflight) -> Result<T, nt_status::NtStatus>,
) -> Result<(LocalRetirement, T), nt_status::NtStatus> {
    let guard = lock();
    let domain = validate_arena(inst)?;
    let pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let current = allocation(inst, address)?;
    let index = rows()
        .iter()
        .position(|row| {
            same_arena(row.instance, inst) && row.allocation.component_address == address
        })
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if rows()[index].retirement_pending {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if rows()[index].accepted != registration {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let checked = check(&RetirementPreflight {
        domain,
        accepted_driver_object: rows()[index].accepted_driver_object,
    })?;
    let row = &mut rows()[index];
    if row.registration.is_none() && registration.is_some() {
        ledger().attach_registration(&row.owner, registration.unwrap())?;
        row.registration = registration;
    }
    ledger().begin_retirement(&row.owner, domain, current, registration)?;
    row.retirement_pending = true;
    Ok((LocalRetirement {
        receipt: Retirement {
            domain,
            allocation: current,
        },
        _pool: pool,
        _guard: guard,
        },
        checked,
    ))
}

/// Called only by the exact native free owner after an acknowledged physical free.
pub(super) fn finish_retirement(retirement: LocalRetirement) -> Result<(), nt_status::NtStatus> {
    acknowledge(&retirement.receipt)
}

fn acknowledge(receipt: &Retirement) -> Result<(), nt_status::NtStatus> {
    let index = rows()
        .iter()
        .position(|row| row.domain == receipt.domain && row.allocation == receipt.allocation)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    ledger().acknowledge_free(&mut rows()[index].owner)?;
    rows().swap_remove(index);
    Ok(())
}

pub(super) unsafe fn capture_allocation(
    inst: DriverInstance,
    address: u64,
) -> Result<SourcePoolAllocationIdentity, nt_status::NtStatus> {
    validate_arena(inst)?;
    let _pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    allocation(inst, address)
}

/// Free one row-owned graph member only when its original physical allocation is still live.
/// The caller clears its ownership bit only after this exact free acknowledges success.
pub(super) unsafe fn free_captured_allocation(
    inst: DriverInstance,
    expected: SourcePoolAllocationIdentity,
) -> bool {
    let Ok(_projection) = generic_free_admission(inst, expected.component_address) else {
        return false;
    };
    let Some(_pool) = hosted_instance_pool_lock(inst.exec_pool_va) else {
        return false;
    };
    if allocation(inst, expected.component_address) != Ok(expected) {
        return false;
    }
    hosted_instance_pool_free_unlocked(inst, expected.component_address)
}

/// Root rollback may free only the exact captured constructor set, not another chain.
pub(super) unsafe fn validate_rollback_allocations(
    inst: DriverInstance,
    driver: u64,
    pdo: u64,
    previous_head: u64,
    delete_pdo: bool,
    expected: &[u64],
) -> Result<(), nt_status::NtStatus> {
    validate_arena(inst)?;
    let _guard = lock();
    let _pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    for (index, address) in expected.iter().enumerate() {
        if expected[..index].contains(address) {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let row = rows()
            .iter()
            .find(|row| {
                same_arena(row.instance, inst) && row.allocation.component_address == *address
            })
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        if row.retirement_pending || allocation(inst, *address)? != row.allocation {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
    }
    let mut count = usize::from(delete_pdo);
    if delete_pdo && !expected.contains(&pdo) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let mut current = if driver == 0 {
        0
    } else {
        let (exec, capacity) = hosted_pool_allocation_exec_range(inst.exec_pool_va, driver)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        if capacity < WDM_X64_DRIVER_OBJECT_SIZE as u64 {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        read_unaligned((exec + 0x08) as *const u64)
    };
    while current != previous_head {
        if count >= expected.len() || current == 0 || current == pdo || !expected.contains(&current)
        {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        allocation(inst, current)?;
        let (exec, capacity) = hosted_pool_allocation_exec_range(inst.exec_pool_va, current)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        if capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64 {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        current = read_unaligned((exec + 0x10) as *const u64);
        count += 1;
    }
    if count != expected.len() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    Ok(())
}

pub(super) fn registration(
    inst: DriverInstance,
    address: u64,
) -> Result<Option<HostedDevicePointerRegistration>, nt_status::NtStatus> {
    let _guard = lock();
    rows()
        .iter()
        .find(|row| same_arena(row.instance, inst) && row.allocation.component_address == address)
        .map(|row| row.registration)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)
}

/// Cleanup provenance includes a canonical bind accepted before a later physical publication
/// refusal. Live callers use `registration`, which exposes only fully published rows.
pub(super) fn accepted_registration(
    inst: DriverInstance,
    address: u64,
) -> Result<Option<HostedDevicePointerRegistration>, nt_status::NtStatus> {
    let _guard = lock();
    rows()
        .iter()
        .find(|row| same_arena(row.instance, inst) && row.allocation.component_address == address)
        .map(|row| row.accepted)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)
}

pub(super) fn instance_quiesced(inst: DriverInstance) -> bool {
    let _guard = lock();
    !dma_adapter_pair::owns_pool(inst)
        && !dma_private_graph::owns_pool(inst)
        && !interrupt_projection::owns_pool(inst)
        && !file_rows().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
        && !rows()
            .iter()
            .any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
        && !temporary_pins()
        .iter()
        .any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
}

pub(super) fn instance_ready_to_drain_dma_tombstones(inst: DriverInstance) -> bool {
    let _guard = lock();
    !dma_adapter_pair::has_live_pair(inst)
        && !dma_private_graph::has_live_graph(inst)
        && !interrupt_projection::has_live(inst)
        && !file_rows().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
        && !rows().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
        && !temporary_pins().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
}

pub(super) fn protects_allocation(inst: DriverInstance, address: u64) -> bool {
    let _guard = lock();
    dma_adapter_pair::protects(inst, address)
        || dma_private_graph::protects(inst, address)
        || interrupt_projection::protects(inst, address)
        || rows().iter().any(|row| {
        (same_arena(row.instance, inst) || same_pool(row.instance, inst))
            && address >= row.allocation.component_address
            && address < row.allocation.component_address + row.allocation.capacity
    })
}
