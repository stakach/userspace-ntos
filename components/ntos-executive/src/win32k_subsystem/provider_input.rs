//! Provenance-checked copies from win32k-owned stack, pool, or admitted image bytes.

use super::*;
use nt_provider_wait::ProviderStackLanePin;

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
