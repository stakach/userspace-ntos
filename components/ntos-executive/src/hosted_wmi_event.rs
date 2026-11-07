//! Exact source-pool ownership for driver-emitted WNODE events.
//! There are no WMI event subscribers yet. A validated event is consumed after
//! capture; a traced event keeps the caller's pool allocation.

use super::*;
use nt_wmi::{event::parse_event_header, WmiEventOwnership};

pub(super) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    pointer: u64,
    badge: u64,
    reply_cap: u64,
) -> i32 {
    if pointer == 0 { return STATUS_INVALID_PARAMETER; }
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return STATUS_ACCESS_DENIED;
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return STATUS_ACCESS_DENIED;
    }
    let Some(domain) = instance_domain_identity(inst) else {
        return STATUS_ACCESS_DENIED;
    };
    let mut pin = match unsafe {
        hosted_device_allocations::pin_temporary_pool_range(inst, pointer, 48)
    } {
        Ok(pin) => pin,
        Err(status) => return status.raw(),
    };
    let allocation = pin.allocation();
    if allocation.component_address != pointer {
        return reject(&mut pin, STATUS_INVALID_PARAMETER);
    }
    let mut header_bytes = [0u8; 48];
    if let Err(status) = unsafe {
        hosted_device_allocations::copy_temporary_pool_pin(&pin, 0, &mut header_bytes)
    } {
        return reject(&mut pin, status.raw());
    }
    let header = match parse_event_header(&header_bytes, allocation.capacity as usize) {
        Ok(header) => header,
        Err(_) => return reject(&mut pin, STATUS_INVALID_PARAMETER),
    };
    let (identity, ownership) = match hosted_driver_wmi::plan_device_event(
        header.provider_id, header.guid, header.flags,
    ) {
        Ok(plan) => plan,
        Err(status) => return reject(&mut pin, status as i32),
    };
    if identity.domain != domain.domain_id.raw() {
        return reject(&mut pin, STATUS_ACCESS_DENIED);
    }
    let physical = hosted_device_allocations::registration(inst, identity.device_object);
    if !physical.is_ok_and(|registration| registration.is_some_and(|registration| {
        registration.domain() == domain
            && registration.generation() == identity.generation
            && registration.address() == identity.device_object
    })) {
        return reject(&mut pin, STATUS_INVALID_HANDLE);
    }

    // The current broker has zero event subscribers. Capturing the header and
    // exact pool generation before this point makes consumption a real event
    // submission, with no fabricated delivery receipt.
    match ownership {
        WmiEventOwnership::TransferPoolOnSuccess => {
            match unsafe { hosted_device_allocations::retire_owned_temporary_pool_allocation(&mut pin) } {
                Ok(()) => STATUS_SUCCESS,
                Err(status) => {
                    if !hosted_device_allocations::retain_temporary_pool_pin_uncertain(&pin) {
                        unsafe { crate::provider_bugcheck::report(0xc4, [pointer, 8, 0, 0]); }
                    }
                    status.raw()
                }
            }
        }
        WmiEventOwnership::RetainCaller => {
            match unsafe { hosted_device_allocations::release_temporary_pool_pin(&mut pin) } {
                Ok(()) => STATUS_SUCCESS,
                Err(status) => status.raw(),
            }
        }
    }
}

fn reject(pin: &mut hosted_device_allocations::TemporaryPoolPin, status: i32) -> i32 {
    if unsafe { hosted_device_allocations::release_temporary_pool_pin(pin) }.is_err() {
        unsafe { crate::provider_bugcheck::report(0xc4, [pin.allocation().component_address, 8, status as u32 as u64, 0]); }
    }
    status
}
