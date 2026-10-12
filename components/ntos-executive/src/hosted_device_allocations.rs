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
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(guard)
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

pub(super) unsafe fn admit_retirement(
    inst: DriverInstance,
    address: u64,
    registration: Option<HostedDevicePointerRegistration>,
) -> Result<LocalRetirement, nt_status::NtStatus> {
    let guard = lock();
    let domain = validate_arena(inst)?;
    let pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let current = allocation(inst, address)?;
    let row = rows()
        .iter_mut()
        .find(|row| same_arena(row.instance, inst) && row.allocation.component_address == address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    ledger().begin_retirement(&row.owner, domain, current, registration)?;
    row.retirement_pending = true;
    Ok(LocalRetirement {
        receipt: Retirement {
            domain,
            allocation: current,
        },
        _pool: pool,
        _guard: guard,
    })
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

impl LocalRetirement {
    pub(super) unsafe fn related_allocation_exec(
        &self,
        address: u64,
    ) -> Result<u64, nt_status::NtStatus> {
        let row = rows()
            .iter()
            .find(|row| {
                row.domain == self.receipt.domain && row.allocation.component_address == address
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

pub(super) unsafe fn capture_allocation(
    inst: DriverInstance,
    address: u64,
) -> Result<SourcePoolAllocationIdentity, nt_status::NtStatus> {
    validate_arena(inst)?;
    let _pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    allocation(inst, address)
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
    !rows()
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
