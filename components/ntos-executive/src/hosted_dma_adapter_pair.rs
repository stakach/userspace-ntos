//! Root-owned physical storage for a hosted DMA adapter and its operations table.
//! All row access is serialized by the enclosing allocation catalog lock.
use super::*;

struct Pair {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    lease_id: u64,
    adapter: Option<SourcePoolAllocationIdentity>,
    ops: Option<SourcePoolAllocationIdentity>,
    logical_put_done: bool,
    ops_freed: bool,
}

static mut PAIRS: Vec<Pair> = Vec::new();
struct Tombstone {
    instance: DriverInstance,
    adapter: SourcePoolAllocationIdentity,
}
static mut TOMBSTONES: Vec<Tombstone> = Vec::new();

fn pairs() -> &'static mut Vec<Pair> {
    unsafe { &mut *core::ptr::addr_of_mut!(PAIRS) }
}
fn tombstones() -> &'static mut Vec<Tombstone> {
    unsafe { &mut *core::ptr::addr_of_mut!(TOMBSTONES) }
}

fn live(identity: Option<SourcePoolAllocationIdentity>, freed: bool, address: u64) -> bool {
    !freed && identity.is_some_and(|identity| contains_allocation(identity, address))
}

pub(super) fn protects(inst: DriverInstance, address: u64) -> bool {
    pairs().iter().any(|row| same_pool(row.instance, inst)
        && (live(row.adapter, false, address)
            || live(row.ops, row.ops_freed, address)))
        || tombstones().iter().any(|row| same_pool(row.instance, inst)
            && contains_allocation(row.adapter, address))
}

pub(super) fn owns_pool(inst: DriverInstance) -> bool {
    pairs().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
        || tombstones().iter().any(|row| same_arena(row.instance, inst)
            || same_pool(row.instance, inst))
}

pub(super) fn has_live_pair(inst: DriverInstance) -> bool {
    pairs().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
}

pub(super) fn has_lease(lease_id: u64) -> bool {
    pairs().iter().any(|row| row.lease_id == lease_id)
}

/// Allocate under catalog then pool exclusion and record both physical generations before
/// either pointer can be published. A partially constructed row is retained for exact retry.
pub(super) unsafe fn provision_dma_adapter_pair(
    inst: DriverInstance,
    lease_id: u64,
) -> Result<(u64, u64), nt_status::NtStatus> {
    if lease_id == 0 { return Err(nt_status::NtStatus::INVALID_PARAMETER); }
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = if let Some(index) = pairs().iter().position(|row| row.lease_id == lease_id) {
        if !same_arena(pairs()[index].instance, inst)
            || pairs()[index].domain != domain || pairs()[index].logical_put_done {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        index
    } else {
        pairs().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        pairs().push(Pair {
            instance: inst, domain, lease_id, adapter: None, ops: None,
            logical_put_done: false, ops_freed: false,
        });
        pairs().len() - 1
    };
    if pairs()[index].ops.is_none() {
        let Some(address) = hosted_instance_pool_alloc_unlocked(inst, 0x100) else {
            pairs().swap_remove(index);
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        };
        let identity = allocation(inst, address)
            .expect("newly allocated DMA operations require exact pool identity");
        pairs()[index].ops = Some(identity);
    }
    if pairs()[index].adapter.is_none() {
        let Some(address) = hosted_instance_pool_alloc_unlocked(inst, HOSTED_DMA_ADAPTER_SIZE) else {
            let ops = pairs()[index].ops.unwrap();
            if allocation(inst, ops.component_address) == Ok(ops)
                && hosted_instance_pool_free_unlocked(inst, ops.component_address) {
                pairs().swap_remove(index);
            }
            // If physical free refused, the row and lease remain owned for exact retry.
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        };
        let identity = allocation(inst, address)
            .expect("newly allocated DMA adapter requires exact pool identity");
        pairs()[index].adapter = Some(identity);
    }
    let row = &pairs()[index];
    let ops = row.ops.unwrap();
    let adapter = row.adapter.unwrap();
    if allocation(inst, ops.component_address)? != ops
        || allocation(inst, adapter.component_address)? != adapter {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok((adapter.component_address, ops.component_address))
}

/// The callback is the exact logical put. It runs once, before the ops free, with both locks
/// held and no provider RPC. The adapter remains physically reserved until instance teardown.
pub(super) unsafe fn retire_dma_adapter_pair(
    inst: DriverInstance,
    lease_id: u64,
    adapter_address: u64,
    put: impl FnOnce() -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = pairs().iter().position(|row| row.lease_id == lease_id
        && row.domain == domain && same_arena(row.instance, inst)
        && (row.adapter.is_some_and(|member| member.component_address == adapter_address)
            || adapter_address == 0 && row.adapter.is_none()))
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &pairs()[index];
    let Some(ops) = row.ops else {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    };
    let adapter = row.adapter;
    if (!row.ops_freed && allocation(inst, ops.component_address)? != ops)
        || adapter.is_some_and(|adapter|
            allocation(inst, adapter.component_address) != Ok(adapter)) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    if adapter.is_some() {
        tombstones().try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    }
    if !pairs()[index].logical_put_done {
        put()?;
        pairs()[index].logical_put_done = true;
    }
    if let Some(adapter) = adapter {
        let exec = inst.exec_pool_va
            .checked_add(adapter.component_address - FSD_POOL_VADDR)
            .and_then(|base| base.checked_add(HOSTED_DMA_ADAPTER_SIGNATURE_OFFSET))
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        write_unaligned(exec as *mut u64, 0);
    }
    if !pairs()[index].ops_freed {
        if !hosted_instance_pool_free_unlocked(inst, ops.component_address) {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        pairs()[index].ops_freed = true;
    }
    if let Some(adapter) = adapter {
        tombstones().push(Tombstone { instance: inst, adapter });
    }
    pairs().swap_remove(index);
    Ok(())
}

/// The raw adapter pointer cannot be reused until this driver generation has stopped every
/// callback. Drain only at instance teardown, after its lanes have quiesced.
pub(super) unsafe fn drain_dma_adapter_tombstones(
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let mut index = 0;
    while index < tombstones().len() {
        let row = &tombstones()[index];
        if !same_arena(row.instance, inst) {
            index += 1;
            continue;
        }
        if allocation(inst, row.adapter.component_address)? != row.adapter
            || !hosted_instance_pool_free_unlocked(inst, row.adapter.component_address) {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        tombstones().swap_remove(index);
    }
    Ok(())
}
