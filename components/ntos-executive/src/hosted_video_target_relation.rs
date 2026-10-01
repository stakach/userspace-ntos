//! VideoPort-owned TargetDeviceRelation response for a hosted video device.

use super::*;
use core::sync::atomic::{AtomicBool, Ordering};

struct RelationOwner {
    driver: DriverId,
    allocation_index: usize,
    allocation: u64,
    generation: u64,
    reference: nt_io_manager::HostedDevicePointerReference,
}

static mut OWNERS: Vec<RelationOwner> = Vec::new();
static OWNERS_LOCK: AtomicBool = AtomicBool::new(false);

struct OwnersGuard;

impl OwnersGuard {
    fn acquire() -> Self {
        while OWNERS_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::yield_now();
        }
        Self
    }
}

impl Drop for OwnersGuard {
    fn drop(&mut self) {
        OWNERS_LOCK.store(false, Ordering::Release);
    }
}

pub(super) struct SourceReference {
    reference: nt_io_manager::HostedDevicePointerReference,
}

impl SourceReference {
    pub(super) unsafe fn release(mut self) -> bool {
        self.reference.release(io_manager_mut()).is_ok()
    }
}

pub(super) unsafe fn claim(
    driver: DriverId,
    allocation_index: usize,
    allocation: u64,
    generation: u64,
) -> Option<SourceReference> {
    let _guard = OwnersGuard::acquire();
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    let index = owners.iter().position(|owner| {
        owner.driver == driver
            && owner.allocation_index == allocation_index
            && owner.allocation == allocation
            && owner.generation == generation
    })?;
    Some(SourceReference {
        reference: owners.swap_remove(index).reference,
    })
}

pub(super) unsafe fn claim_allocation(
    allocation_index: usize,
    allocation: u64,
    generation: u64,
) -> Option<SourceReference> {
    let _guard = OwnersGuard::acquire();
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    let index = owners.iter().position(|owner| {
        owner.allocation_index == allocation_index
            && owner.allocation == allocation
            && owner.generation == generation
    })?;
    Some(SourceReference {
        reference: owners.swap_remove(index).reference,
    })
}

pub(super) unsafe fn dispatch(
    binding: HostedDeviceBinding,
    irp: &IrpProjection,
) -> PnpBackendDispatch {
    let IoParameters::Pnp(parameters) = &irp.parameters else {
        return rejected(nt_status::NtStatus::INVALID_PARAMETER);
    };
    if irp.device_id.raw() != binding.device_id
        || parameters.minor != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
        || parameters.relation_type() != Some(nt_pnp_abi::TARGET_DEVICE_RELATION)
    {
        return rejected(nt_status::NtStatus::INVALID_PARAMETER);
    }

    // The VideoPort FDO, not the lower bus PDO, is the object returned by
    // ReactOS VideoPort's TargetDeviceRelation handler.
    let Some(allocation_index) = hosted_relation_allocation_instance(DriverId(binding.driver_id))
    else {
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Some(allocation_inst) = instance(allocation_index) else {
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Some(domain) = instance_domain_identity(allocation_inst) else {
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Some(registration) = io_manager_mut()
        .hosted_device_pointer_registration(domain, binding.device_object)
        .filter(|registration| registration.device_id().raw() == binding.device_id)
    else {
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Ok(mut reference) = io_manager_mut().take_hosted_device_pointer_reference(registration)
    else {
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };

    let bytes = nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES;
    let Some(relation) = hosted_instance_pool_alloc(allocation_inst, bytes as u64) else {
        reference
            .release(io_manager_mut())
            .expect("unpublished video relation reference");
        return rejected(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    let generation = hosted_pool_allocation_exec_range(allocation_inst.exec_pool_va, relation)
        .map(|(mapped, _)| read_volatile((mapped - 8) as *const u64))
        .unwrap_or(0);
    let written = hosted_pool_allocation_exec_range(allocation_inst.exec_pool_va, relation)
        .filter(|(_, capacity)| *capacity >= bytes as u64)
        .and_then(|(mapped, _)| {
            nt_pnp_manager::write_device_relations_x64(
                core::slice::from_raw_parts_mut(mapped as *mut u8, bytes),
                &[binding.device_object],
            )
            .ok()
        });
    if generation == 0 || written != Some(bytes) {
        if !free_hosted_instance_pool_allocation_exact(allocation_inst, relation) {
            crate::provider_bugcheck::report(0xc4, [binding.device_object, relation, 0, 63]);
        }
        reference
            .release(io_manager_mut())
            .expect("unpublished video relation reference");
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let mut reference = Some(reference);
    let recorded = {
        let _guard = OwnersGuard::acquire();
        let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
        if owners.try_reserve(1).is_err() {
            false
        } else {
            owners.push(RelationOwner {
                driver: DriverId(binding.driver_id),
                allocation_index,
                allocation: relation,
                generation,
                reference: reference.take().expect("reserved video relation reference"),
            });
            true
        }
    };
    if !recorded {
        if !free_hosted_instance_pool_allocation_exact(allocation_inst, relation) {
            crate::provider_bugcheck::report(0xc4, [binding.device_object, relation, 0, 65]);
        }
        reference
            .as_mut()
            .expect("unpublished video relation reference")
            .release(io_manager_mut())
            .expect("unpublished video relation reference");
        return rejected(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    PnpBackendDispatch::Returned {
        status: nt_status::NtStatus::SUCCESS,
        information: relation,
    }
}

fn rejected(status: nt_status::NtStatus) -> PnpBackendDispatch {
    PnpBackendDispatch::NotDispatched { status }
}
