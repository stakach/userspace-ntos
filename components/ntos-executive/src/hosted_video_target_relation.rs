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
    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.reference.device_id()
    }

    pub(super) fn into_reference(self) -> nt_io_manager::HostedDevicePointerReference {
        self.reference
    }

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
        trace_rejection(b"allocation-owner", binding, None, None);
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Some(allocation_inst) = instance(allocation_index) else {
        trace_rejection(b"allocation-instance", binding, Some(allocation_index), None);
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Some(domain) = instance_domain_identity(allocation_inst) else {
        trace_rejection(b"allocation-domain", binding, Some(allocation_index), None);
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Some(registration) = io_manager_mut()
        .hosted_device_pointer_registration(domain, binding.device_object)
        .filter(|registration| registration.device_id().raw() == binding.device_id)
    else {
        trace_rejection(b"device-registration", binding, Some(allocation_index), Some(domain));
        return rejected(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let Ok(mut reference) = io_manager_mut().retain_hosted_device_pointer_reference(registration)
    else {
        trace_rejection(b"device-reference", binding, Some(allocation_index), Some(domain));
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
        trace_rejection(b"relation-backing", binding, Some(allocation_index), Some(domain));
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

fn trace_rejection(
    reason: &[u8],
    binding: HostedDeviceBinding,
    allocation_index: Option<usize>,
    allocation_domain: Option<HostedDomainIdentity>,
) {
    print_str(b"[video-target-relation] rejected reason="); print_str(reason);
    print_str(b" device="); print_u64(binding.device_id);
    print_str(b" driver="); print_u64(binding.driver_id);
    print_str(b" address="); print_u64(binding.device_object);
    print_str(b" projection-instance="); print_u64(binding.projection_instance as u64);
    print_str(b" projection-domain="); print_u64(binding.projection_domain.domain_id.raw());
    print_str(b" projection-cookie="); print_u64(binding.projection_domain.cookie);
    print_str(b" allocation-instance=");
    match allocation_index {
        Some(index) => print_u64(index as u64),
        None => print_str(b"none"),
    }
    print_str(b" allocation-domain=");
    match allocation_domain {
        Some(domain) => {
            print_u64(domain.domain_id.raw());
            print_str(b" allocation-cookie="); print_u64(domain.cookie);
        }
        None => print_str(b"none"),
    }
    print_str(b"\n");
}

fn rejected(status: nt_status::NtStatus) -> PnpBackendDispatch {
    PnpBackendDispatch::NotDispatched { status }
}
