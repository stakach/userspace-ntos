//! Provenance-checked copies from win32k-owned stack, pool, or admitted image bytes.

use super::*;
use nt_provider_wait::{ProviderAllocationPin, ProviderAllocationSnapshot, ProviderStackLanePin};

pub(super) enum PinnedInput {
    None,
    Stack(ProviderStackLanePin),
    Pool {
        snapshot: ProviderAllocationSnapshot,
        pin: ProviderAllocationPin,
        native: shared_pool::AllocationIdentity,
    },
    Image { map_owner: u64 },
}

pub(super) unsafe fn pin_input(
    activation: ProviderStackEventActivation,
    address: u64,
    length: u64,
) -> Result<PinnedInput, i32> {
    if length == 0 {
        return Ok(PinnedInput::None);
    }
    let end = address.checked_add(length).ok_or(STATUS_ACCESS_VIOLATION_I32)?;
    if address == 0 {
        return Err(STATUS_ACCESS_VIOLATION_I32);
    }
    if let Some(catalog) = stack_catalog_mut() {
        if catalog.resolve(address, length).is_ok() {
            return catalog
                .pin_active_range(activation, address, length)
                .map(|(_, pin)| PinnedInput::Stack(pin))
                .map_err(|_| STATUS_ACCESS_VIOLATION_I32);
        }
    }
    if provider_pool_contains(address) {
        let (snapshot, pin) = with_provider_allocations(|catalog| catalog.pin_containing(address, length))
            .ok_or(STATUS_NOT_SUPPORTED_I32)?
            .map_err(|_| STATUS_ACCESS_VIOLATION_I32)?;
        let native = provider_pool_lock().and_then(|_pool| {
            shared_pool::containing_allocation(
                &ProviderPoolMemory,
                address - WIN32K_POOL_VADDR,
                length,
            )
            .ok()
            .filter(|location| {
                location.payload_offset == snapshot.base - WIN32K_POOL_VADDR
                    && location.capacity == snapshot.capacity
            })
            .map(|location| location.identity)
        });
        let Some(native) = native else {
            if with_provider_allocations(|catalog| catalog.release_pin(pin).is_ok()) != Some(true) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, address, length, 26]);
            }
            return Err(STATUS_ACCESS_VIOLATION_I32);
        };
        return Ok(PinnedInput::Pool { snapshot, pin, native });
    }
    if address >= WIN32K_CODE_VA
        && end <= WIN32K_CODE_VA + WIN32K_IMAGE_BYTES
        && registered_provider_wait_domain().is_some()
    {
        let owner = WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire);
        let first = ((address - WIN32K_CODE_VA) / 0x1000) as usize;
        let last = ((end - 1 - WIN32K_CODE_VA) / 0x1000) as usize;
        if owner != 0
            && code_rights()[first..=last]
                .iter()
                .all(|&rights| rights == RW_NX || rights == 2)
        {
            return Ok(PinnedInput::Image { map_owner: owner });
        }
    }
    Err(STATUS_ACCESS_VIOLATION_I32)
}

pub(super) unsafe fn release_input(pin: PinnedInput, label: u64) {
    match pin {
        PinnedInput::None | PinnedInput::Image { .. } => {}
        PinnedInput::Stack(pin) => release_stack_pin(pin, label),
        PinnedInput::Pool { pin, .. } => {
            if with_provider_allocations(|catalog| catalog.release_pin(pin).is_ok()) != Some(true) {
                crate::provider_bugcheck::report(0xc4, [label, pin.identity().allocation_id, 0, 9]);
            }
        }
    }
}

pub(super) unsafe fn input_live(
    pin: &PinnedInput,
    address: u64,
    length: u64,
) -> bool {
    match pin {
        PinnedInput::None => length == 0,
        PinnedInput::Stack(pin) => {
            pin.range() == (address, length)
                && stack_catalog_mut().is_some_and(|catalog| catalog.validate_pin(*pin).is_ok())
        }
        PinnedInput::Pool { snapshot, pin, native } => {
            let catalog_live = with_provider_allocations(|catalog| {
                catalog.snapshot_active(pin.identity()) == Ok(*snapshot)
                    && snapshot.offset_of(address).is_some_and(|offset| {
                        offset.checked_add(length).is_some_and(|end| end <= snapshot.capacity)
                    })
            }) == Some(true);
            catalog_live
                && provider_pool_lock().is_some_and(|_pool| {
                    shared_pool::containing_allocation(
                        &ProviderPoolMemory,
                        address - WIN32K_POOL_VADDR,
                        length,
                    )
                    .is_ok_and(|location| {
                        location.identity == *native
                            && location.payload_offset == snapshot.base - WIN32K_POOL_VADDR
                            && location.capacity == snapshot.capacity
                    })
                })
        }
        PinnedInput::Image { map_owner } => {
            let Some(end) = address.checked_add(length) else { return false };
            if address < WIN32K_CODE_VA
                || end > WIN32K_CODE_VA + WIN32K_IMAGE_BYTES
                || WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) != *map_owner
            {
                return false;
            }
            let first = ((address - WIN32K_CODE_VA) / 0x1000) as usize;
            let last = ((end - 1 - WIN32K_CODE_VA) / 0x1000) as usize;
            code_rights()[first..=last]
                .iter()
                .all(|&rights| rights == RW_NX || rights == 2)
        }
    }
}

pub(super) unsafe fn stack_catalog_mut(
) -> Option<&'static mut nt_provider_wait::ProviderStackActivationCatalog> {
    (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS)).as_mut()
}

pub(super) unsafe fn release_stack_pin(pin: ProviderStackLanePin, label: u64) {
    if stack_catalog_mut().is_none_or(|catalog| catalog.release_pin(pin).is_err()) {
        crate::provider_bugcheck::report(0xc4, [label, pin.range().0, pin.range().1, 1]);
    }
}

pub(super) unsafe fn copy_validated_input(
    activation: ProviderStackEventActivation,
    address: u64,
    length: u32,
    destination: &mut [u8],
    label: u64,
) -> Result<(), i32> {
    if length == 0 {
        return Ok(());
    }
    let length = length as u64;
    let end = address
        .checked_add(length)
        .ok_or(STATUS_ACCESS_VIOLATION_I32)?;
    if address == 0 || destination.len() != length as usize {
        return Err(STATUS_ACCESS_VIOLATION_I32);
    }
    if let Some(catalog) = stack_catalog_mut() {
        if catalog.resolve(address, length).is_ok() {
            let (_, pin) = catalog
                .pin_active_range(activation, address, length)
                .map_err(|_| STATUS_ACCESS_VIOLATION_I32)?;
            destination.copy_from_slice(core::slice::from_raw_parts(
                address as *const u8,
                length as usize,
            ));
            release_stack_pin(pin, label);
            return Ok(());
        }
    }
    if provider_pool_contains(address) {
        let (_, pin) = with_provider_allocations(|catalog| catalog.pin_containing(address, length))
            .ok_or(STATUS_NOT_SUPPORTED_I32)?
            .map_err(|_| STATUS_ACCESS_VIOLATION_I32)?;
        destination.copy_from_slice(core::slice::from_raw_parts(
            address as *const u8,
            length as usize,
        ));
        if with_provider_allocations(|catalog| catalog.release_pin(pin).is_ok()) != Some(true) {
            crate::provider_bugcheck::report(0xc4, [label, address, length, 8]);
        }
        return Ok(());
    }
    if address >= WIN32K_CODE_VA
        && end <= WIN32K_CODE_VA + WIN32K_IMAGE_BYTES
        && WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) != 0
        && registered_provider_wait_domain().is_some()
    {
        let first = ((address - WIN32K_CODE_VA) / 0x1000) as usize;
        let last = ((end - 1 - WIN32K_CODE_VA) / 0x1000) as usize;
        if !code_rights()[first..=last]
            .iter()
            .all(|&rights| rights == RW_NX || rights == 2)
        {
            return Err(STATUS_ACCESS_VIOLATION_I32);
        }
        destination.copy_from_slice(core::slice::from_raw_parts(
            address as *const u8,
            length as usize,
        ));
        return Ok(());
    }
    Err(STATUS_ACCESS_VIOLATION_I32)
}
