//! Exact root ownership of hosted KINTERRUPT projections.
//! The enclosing allocation catalog lock serializes every row access.
use super::*;

struct Projection {
    instance: DriverInstance,
    binding: HostedDeviceBinding,
    allocation: SourcePoolAllocationIdentity,
    phase: ProjectionPhase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProjectionPhase {
    Prepared,
    EffectStarted,
    Bound(u64, u64),
    Tombstone,
}

static mut PROJECTIONS: Vec<Projection> = Vec::new();

fn projections() -> &'static mut Vec<Projection> {
    unsafe { &mut *core::ptr::addr_of_mut!(PROJECTIONS) }
}

pub(super) fn protects(inst: DriverInstance, address: u64) -> bool {
    projections().iter().any(|row| {
        same_pool(row.instance, inst) && contains_allocation(row.allocation, address)
    })
}

pub(super) fn owns_pool(inst: DriverInstance) -> bool {
    projections().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
}

fn row_index(inst: DriverInstance, binding: HostedDeviceBinding, address: u64) -> Option<usize> {
    projections().iter().position(|row| {
        same_arena(row.instance, inst)
            && row.binding == binding
            && row.allocation.component_address == address
    })
}

/// The row and physical generation exist before the component receives the pointer.
pub(super) unsafe fn provision(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
) -> Result<(u64, u64), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    if let Some(row) = projections().iter().find(|row| {
        row.binding == binding && row.phase != ProjectionPhase::Tombstone
    }) {
        if !same_arena(row.instance, inst) {
            return Err(nt_status::NtStatus::ACCESS_DENIED);
        }
        return if row.phase == ProjectionPhase::Prepared
            && allocation(inst, row.allocation.component_address)? == row.allocation {
            Ok((row.allocation.component_address, row.allocation.pool_generation))
        } else {
            Err(nt_status::NtStatus::DEVICE_BUSY)
        };
    }
    projections().try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let address = hosted_instance_pool_alloc_unlocked(inst, HOSTED_KINTERRUPT_SIZE)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let identity = allocation(inst, address)
        .expect("new interrupt projection has an exact pool identity");
    let exec = inst.exec_pool_va + address - FSD_POOL_VADDR;
    core::ptr::write_bytes(exec as *mut u8, 0, HOSTED_KINTERRUPT_SIZE as usize);
    projections().push(Projection {
        instance: inst, binding, allocation: identity,
        phase: ProjectionPhase::Prepared,
    });
    Ok((address, identity.pool_generation))
}

/// Shared bytes can describe the callback, but never prove this projection's ownership.
pub(super) unsafe fn validate(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &projections()[index];
    if row.phase == ProjectionPhase::Tombstone || allocation(inst, address)? != row.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok(())
}

/// Record the first uncertain canonical effect before invoking the resource manager or IRQ
/// installer. A replayed PROVISION can return only a still-Prepared row.
pub(super) unsafe fn mark_effect_started(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut projections()[index];
    if row.phase == ProjectionPhase::Tombstone
        || allocation(inst, address)? != row.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    if row.phase == ProjectionPhase::Prepared {
        row.phase = ProjectionPhase::EffectStarted;
    }
    Ok(())
}

pub(super) unsafe fn bind(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
    interrupt_id: u64,
    grant_generation: u64,
) -> Result<(), nt_status::NtStatus> {
    if interrupt_id == 0 || grant_generation == 0 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut projections()[index];
    let matches_connection = match row.phase {
        ProjectionPhase::EffectStarted => true,
        ProjectionPhase::Bound(id, generation) =>
            id == interrupt_id && generation == grant_generation,
        _ => false,
    };
    if allocation(inst, address)? != row.allocation || !matches_connection {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    row.phase = ProjectionPhase::Bound(interrupt_id, grant_generation);
    Ok(())
}

/// A pre-effect CONNECT refusal is definitive. The pointer has already escaped to the
/// component, so retain its physical allocation as a tombstone until instance teardown.
pub(super) unsafe fn cancel_prepared(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut projections()[index];
    if row.phase != ProjectionPhase::Prepared
        || allocation(inst, address)? != row.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    row.phase = ProjectionPhase::Tombstone;
    Ok(())
}

/// The caller must possess a definitive no-effect result from the canonical connect attempt,
/// or an acknowledged rollback with no installed root connection. Keep the escaped address as
/// a tombstone even though that effect is absent.
pub(super) unsafe fn cancel_after_proven_no_effect(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut projections()[index];
    if row.phase != ProjectionPhase::EffectStarted
        || allocation(inst, address)? != row.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    row.phase = ProjectionPhase::Tombstone;
    Ok(())
}

/// A successful canonical disconnect is recorded independently of physical free. If freeing
/// fails, a later retry can complete that exact free without replaying canonical teardown.
pub(super) unsafe fn connection_for_retirement(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
) -> Result<Option<(u64, u64)>, nt_status::NtStatus> {
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &projections()[index];
    if allocation(inst, address)? != row.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    match row.phase {
        ProjectionPhase::Bound(id, generation) => Ok(Some((id, generation))),
        _ => Err(nt_status::NtStatus::INVALID_HANDLE),
    }
}

/// The native connection record is root-owned evidence when publication installed a route
/// before the final catalog bind. Its captured pointer and tokens may reconcile that row.
pub(super) fn admits_canonical_retirement(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
    connection: (u64, u64),
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    match projections()[index].phase {
        ProjectionPhase::EffectStarted => Ok(()),
        ProjectionPhase::Bound(id, generation) if (id, generation) == connection => Ok(()),
        _ => Err(nt_status::NtStatus::INVALID_HANDLE),
    }
}

pub(super) fn mark_canonical_retired(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
    connection: (u64, u64),
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut projections()[index];
    let matches_connection = match row.phase {
        ProjectionPhase::EffectStarted => true,
        ProjectionPhase::Bound(id, generation) => (id, generation) == connection,
        _ => false,
    };
    if !matches_connection {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    row.phase = ProjectionPhase::Tombstone;
    Ok(())
}

pub(super) unsafe fn retire_physical(
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = row_index(inst, binding, address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &projections()[index];
    if row.phase != ProjectionPhase::Tombstone || allocation(inst, address)? != row.allocation {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    if !hosted_instance_pool_free_unlocked(inst, row.allocation.component_address) {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    projections().swap_remove(index);
    Ok(())
}

pub(super) fn has_live(inst: DriverInstance) -> bool {
    projections().iter().any(|row| {
        (same_arena(row.instance, inst) || same_pool(row.instance, inst))
            && row.phase != ProjectionPhase::Tombstone
    })
}

/// Drain tombstones only after all interrupt callbacks, DPCs and lanes have quiesced.
pub(super) unsafe fn drain_tombstones(
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    loop {
        let retired = {
            let _catalog = lock();
            projections().iter()
                .find(|row| same_arena(row.instance, inst)
                    && row.phase == ProjectionPhase::Tombstone)
                .map(|row| (row.binding, row.allocation.component_address))
        };
        let Some((binding, address)) = retired else { return Ok(()); };
        retire_physical(inst, binding, address)?;
    }
}
