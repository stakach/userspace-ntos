//! Exact physical Device retirement after canonical cleanup.
use super::*;

/// Row-owned cleanup provenance. The caller retains the actual constructor/retirement owner;
/// these observations do not themselves grant canonical deletion or physical free authority.
pub(super) enum CanonicalRetirement {
    ConfirmedUnbound { domain: HostedDomainIdentity },
    Retired { registration: nt_io_manager::HostedDevicePointerRegistration },
}

pub(super) fn validate_canonical_retirement(
    device_object: u64, canonical: &CanonicalRetirement,
) -> Result<(), nt_status::NtStatus> {
    let domain = match canonical {
        CanonicalRetirement::ConfirmedUnbound { domain } => *domain,
        CanonicalRetirement::Retired { registration } => {
            if registration.address() != device_object { return Err(nt_status::NtStatus::INVALID_PARAMETER); }
            registration.domain()
        }
    };
    if io_manager_mut().hosted_domain_identity(domain.domain_id) != Some(domain) {
        return Err(nt_status::NtStatus::ACCESS_DENIED);
    }
    // A prior canonical ACK does not exclude a reminted registration or a bare new binding.
    // Original logical identity is independent of the physical allocator's domain.
    if io_manager_mut().hosted_device_by_identity(domain, device_object).is_some()
        || io_manager_mut().hosted_device_pointer_registration(domain, device_object).is_some() {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(())
}

pub(super) unsafe fn retire_hosted_device_projection(
    inst: DriverInstance,
    device_object: u64,
    canonical: CanonicalRetirement,
    rollback_pdo: Option<u64>,
) -> Result<(), nt_status::NtStatus> {
    validate_canonical_retirement(device_object, &canonical)?;
    let registration = match canonical {
        CanonicalRetirement::ConfirmedUnbound { .. } => None,
        CanonicalRetirement::Retired { registration } => Some(registration),
    };
    let physical_registration = hosted_device_allocations::accepted_registration(inst, device_object)?;
    if physical_registration != registration {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let (retirement, (device_exec, next_device, target_link, rollback_pdo_exec)) =
        hosted_device_allocations::admit_retirement_checked(
            inst, device_object, physical_registration, |preflight| {
                let (device_exec, capacity) =
                    hosted_pool_allocation_exec_range(inst.exec_pool_va, device_object)
                        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
                if capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64
                    || hosted_instance_pool_allocation_is_free_unlocked(inst, device_object) != Some(false)
                {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                let projected_size = read_unaligned((device_exec + 2) as *const u16) as u64;
                if read_unaligned(device_exec as *const i16) != WDM_X64_IO_TYPE_DEVICE
                    || projected_size < WDM_X64_DEVICE_OBJECT_SIZE as u64
                    || projected_size > capacity
                {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                let rollback_pdo_exec = match rollback_pdo {
                    Some(pdo) => Some(preflight.related_allocation_exec(pdo)?),
                    None => None,
                };
                let driver_object = read_unaligned((device_exec + 0x08) as *const u64);
                // The projected header is writable by the provider. It cannot erase or
                // redirect the list owner captured when its canonical bind was accepted.
                if physical_registration.is_some()
                    && preflight.accepted_driver_object() != Some(driver_object) {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                let next_device = read_unaligned((device_exec + 0x10) as *const u64);
                // An unlinked PDO has no driver list owner. Its provider-writable
                // NextDevice field cannot introduce a link after publication.
                if driver_object == 0 && next_device != 0 {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                let mut target_link = None;
                if driver_object != 0 {
                    let (driver_exec, driver_capacity) =
                        hosted_pool_allocation_exec_range(inst.exec_pool_va, driver_object)
                            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
                    if driver_capacity < WDM_X64_DRIVER_OBJECT_SIZE as u64
                        || hosted_instance_pool_allocation_is_free_unlocked(inst, driver_object) != Some(false)
                        || read_unaligned(driver_exec as *const i16) != WDM_X64_IO_TYPE_DRIVER
                    {
                        return Err(nt_status::NtStatus::INVALID_PARAMETER);
                    }
                    let mut link_exec = driver_exec + 0x08;
                    let mut current = read_unaligned(link_exec as *const u64);
                    let mut traversed = 0u64;
                    while current != 0 {
                        if traversed >= POOL_FREE_LIST_MAX {
                            return Err(nt_status::NtStatus::INVALID_PARAMETER);
                        }
                        let (current_exec, current_capacity) =
                            hosted_pool_allocation_exec_range(inst.exec_pool_va, current)
                                .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
                        if current_capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64
                            || hosted_instance_pool_allocation_is_free_unlocked(inst, current) != Some(false)
                            || read_unaligned(current_exec as *const i16) != WDM_X64_IO_TYPE_DEVICE
                            || read_unaligned((current_exec + 0x08) as *const u64) != driver_object
                        {
                            return Err(nt_status::NtStatus::INVALID_PARAMETER);
                        }
                        if current == device_object {
                            if target_link.is_some() {
                                return Err(nt_status::NtStatus::INVALID_PARAMETER);
                            }
                            target_link = Some(link_exec);
                        }
                        link_exec = current_exec + 0x10;
                        current = read_unaligned(link_exec as *const u64);
                        traversed += 1;
                    }
                    if target_link.is_none() {
                        return Err(nt_status::NtStatus::INVALID_PARAMETER);
                    }
                }
                Ok((device_exec, next_device, target_link, rollback_pdo_exec))
            },
        )?;
    let attached_pdo = rollback_pdo_exec.and_then(|pdo_exec| {
        (read_unaligned((pdo_exec + 0x18) as *const u64) == device_object)
            .then(|| (pdo_exec, read_unaligned((device_exec + 0x4c) as *const u8)))
    });
    if let Some(target_link) = target_link {
        write_unaligned(target_link as *mut u64, next_device);
    }
    if let Some((pdo_exec, _)) = attached_pdo {
        write_unaligned((pdo_exec + 0x18) as *mut u64, 0);
        write_unaligned((device_exec + 0x4c) as *mut u8, 1);
    }
    write_unaligned(device_exec as *mut u16, 0);
    if !hosted_instance_pool_free_unlocked(inst, device_object) {
        // The allocator returns false before touching the free list. Keep the physical
        // retirement pending, but restore every native link and header changed above so
        // a refused free cannot strand a live Device in a half-retired projection.
        write_unaligned(device_exec as *mut u16, WDM_X64_IO_TYPE_DEVICE as u16);
        if let Some((pdo_exec, prior_flag)) = attached_pdo {
            write_unaligned((device_exec + 0x4c) as *mut u8, prior_flag);
            write_unaligned((pdo_exec + 0x18) as *mut u64, device_object);
        }
        if let Some(target_link) = target_link {
            write_unaligned(target_link as *mut u64, device_object);
        }
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    hosted_device_allocations::finish_retirement(retirement)?;
    Ok(())
}
