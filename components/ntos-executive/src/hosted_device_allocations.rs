//! Physical allocation ownership for hosted-pool Device projections, independent of IoManager.
use super::*;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::{
    HostedDevicePointerRegistration, ProjectionAllocationLedger, ProjectionAllocationOwner,
};

struct Row {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    allocation: SourcePoolAllocationIdentity,
    registration: Option<HostedDevicePointerRegistration>,
    owner: ProjectionAllocationOwner,
    retirement_pending: bool,
}
static LOCK: AtomicU64 = AtomicU64::new(0);
static mut LEDGER: ProjectionAllocationLedger = ProjectionAllocationLedger::new();
static mut ROWS: Vec<Row> = Vec::new();
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
fn file_rows() -> &'static mut Vec<FileStorageRow> {
    unsafe { &mut *core::ptr::addr_of_mut!(FILE_ROWS) }
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
    let used = read_volatile(inst.exec_pool_va as *const u64);
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

/// The returned lock spans the subsequent generic free, preventing publication in between.
pub(super) fn generic_free_admission(
    inst: DriverInstance,
    address: u64,
) -> Result<Guard, nt_status::NtStatus> {
    let guard = lock();
    let domain = validate_arena(inst)?;
    if ledger().protects_address(domain, address)
        || rows().iter().any(|row| {
            same_pool(row.instance, inst)
                && address >= row.allocation.component_address
                && address < row.allocation.component_address + row.allocation.capacity
        })
        || file_rows().iter().any(|row| {
            same_pool(row.instance, inst) && protects_file_member(row, address)
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
        if file_rows().iter().any(|row| {
            (row.domain == domain || same_pool(row.instance, inst))
                && (protects_file_member(row, address)
                    || protects_file_member(row, name_address))
        }) || rows().iter().any(|row| {
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
        });
        FileStorageCaptureError { status, no_root_owner: !owned }
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
    file_rows().swap_remove(index);
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
    if rows().iter().any(|row| {
        (row.domain == domain || same_pool(row.instance, inst)) && !same_arena(row.instance, inst)
    }) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if file_rows().iter().any(|row| {
        same_pool(row.instance, inst) && protects_file_member(row, address)
    }) {
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
    if row.registration == Some(registration) {
        return Ok(());
    }
    ledger().attach_registration(&row.owner, registration)?;
    row.registration = Some(registration);
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
}

impl RetirementPreflight {
    pub(super) unsafe fn related_allocation_exec(
        &self,
        address: u64,
    ) -> Result<u64, nt_status::NtStatus> {
        let row = rows()
            .iter()
            .find(|row| {
                row.domain == self.domain && row.allocation.component_address == address
            })
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
        .position(|row| same_arena(row.instance, inst) && row.allocation.component_address == address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if rows()[index].retirement_pending {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let checked = check(&RetirementPreflight { domain })?;
    let row = &mut rows()[index];
    ledger().begin_retirement(&row.owner, domain, current, registration)?;
    row.retirement_pending = true;
    Ok((LocalRetirement {
        receipt: Retirement {
            domain,
            allocation: current,
        },
        _pool: pool,
        _guard: guard,
    }, checked))
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

pub(super) fn instance_quiesced(inst: DriverInstance) -> bool {
    let _guard = lock();
    !file_rows().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
        && !rows()
        .iter()
        .any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
}

pub(super) fn protects_allocation(inst: DriverInstance, address: u64) -> bool {
    let _guard = lock();
    rows().iter().any(|row| {
        (same_arena(row.instance, inst) || same_pool(row.instance, inst))
            && address >= row.allocation.component_address
            && address < row.allocation.component_address + row.allocation.capacity
    })
}
