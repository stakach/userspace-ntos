//! Exact process-primary token references for isolated hosted drivers.
//!
//! The native pointer is a provider-local projection. The canonical token, its reference, and
//! the process identity stay in the executive. Failed pool frees remain owned until a retry or
//! the stopped provider's retirement drain acknowledges them.

use super::*;

use super::driver_hosted_token_projection::{
    self as projections, ReservedTokenProjection, RetiringPrimaryTokenProjection,
};

pub(super) const REFERENCE: u64 = 1;
pub(super) const DEREFERENCE: u64 = 2;

const INVALID_HANDLE: i32 = nt_process::STATUS_INVALID_HANDLE as i32;
const INVALID_PARAMETER: i32 = nt_process::STATUS_INVALID_PARAMETER as i32;
const RESOURCES: i32 = nt_process::STATUS_INSUFFICIENT_RESOURCES as i32;
const DEVICE_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct PendingReserved {
    provider: DriverInstance,
    receipt: ReservedTokenProjection,
}

struct PendingRetired {
    provider: DriverInstance,
    receipt: RetiringPrimaryTokenProjection,
}

static mut PENDING_RESERVED: Vec<PendingReserved> = Vec::new();
static mut PENDING_RETIRED: Vec<PendingRetired> = Vec::new();

fn same_provider(left: DriverInstance, right: DriverInstance) -> bool {
    left.hosted_domain_id == right.hosted_domain_id
        && left.hosted_domain_cookie == right.hosted_domain_cookie
        && left.pml4 == right.pml4
        && left.exec_pool_va == right.exec_pool_va
        && left.driver_id == right.driver_id
}

/// The enclosing pump has selected the active physical Reply. Recheck its exact driver and
/// caller before reserving any provider-local storage; neither a badge nor a pointer authorizes
/// a token operation by itself.
pub(super) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    op: u64,
    value: u64,
) -> (i32, u64) {
    let Some((_, provider)) = instance_for_pump_channel(ch, reply_cap) else {
        return (INVALID_HANDLE, 0);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return (INVALID_HANDLE, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(ch) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    if value == 0 {
        return (INVALID_PARAMETER, 0);
    }
    match op {
        REFERENCE => reference(provider, caller, value),
        DEREFERENCE => dereference(provider, caller, value),
        _ => (INVALID_PARAMETER, 0),
    }
}

fn reference(
    provider: DriverInstance,
    caller: nt_process::native_handle::NativeHandleCaller,
    process_body: u64,
) -> (i32, u64) {
    // Reserve one failure receipt before any pool operation. Allocation failure here has no
    // effect; after this point an uncertain pool free always has a durable owner.
    let pending = unsafe { &mut *core::ptr::addr_of_mut!(PENDING_RESERVED) };
    if pending.try_reserve(1).is_err() {
        return (RESOURCES, 0);
    }
    let mut reserved = match unsafe { projections::reserve(provider) } {
        Ok(reserved) => Some(reserved),
        Err((status, maybe_reserved)) => {
            if let Some(receipt) = maybe_reserved {
                if let Err(receipt) = unsafe { projections::release_reserved(receipt) } {
                    pending.push(PendingReserved { provider, receipt });
                }
            }
            return (status, 0);
        }
    };
    let result = unsafe {
        crate::with_provider_security_managers(|pm, tokens| {
            let (pid, sequence) = hosted_driver_process_identity::authorized_process(
                pm, caller, provider, process_body,
            )?;
            let token = pm.process_primary_token(pid)
                .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
            let receipt = reserved.take().expect("unbound primary reservation is retained");
            match projections::bind_primary(receipt, process_body, sequence, token, tokens) {
                Ok(projection) => Ok(projection.address),
                Err((status, receipt)) => {
                    reserved = Some(receipt);
                    Err(status as u32)
                }
            }
        })
    };
    match result {
        Ok(address) => (STATUS_SUCCESS, address),
        Err(status) => {
            if let Some(receipt) = reserved {
                if let Err(receipt) = unsafe { projections::release_reserved(receipt) } {
                    pending.push(PendingReserved { provider, receipt });
                }
            }
            (status as i32, 0)
        }
    }
}

fn dereference(
    provider: DriverInstance,
    caller: nt_process::native_handle::NativeHandleCaller,
    address: u64,
) -> (i32, u64) {
    let pending = unsafe { &mut *core::ptr::addr_of_mut!(PENDING_RETIRED) };
    if pending.try_reserve(1).is_err() {
        return (RESOURCES, 0);
    }
    let result = unsafe {
        crate::with_provider_security_managers(|pm, tokens| {
            pm.validate_native_handle_caller(caller)?;
            projections::retire_primary(provider, address, tokens).map_err(|status| status as u32)
        })
    };
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(status) => return (status as i32, 0),
    };
    match unsafe { projections::free_retired_primary(receipt) } {
        Ok(()) => (STATUS_SUCCESS, 0),
        Err((_status, receipt)) => {
            pending.push(PendingRetired { provider, receipt });
            // The canonical reference is already retired. Pool cleanup remains owned and is
            // retried at provider retirement; a void native dereference cannot replay it.
            (STATUS_SUCCESS, 0)
        }
    }
}

/// Called only after native execution, callbacks, and worker threads have stopped. It drains
/// failed frees first, then any token references left by that provider. A failed effect leaves
/// its exact receipt in place and blocks provider retirement or identity reuse.
pub(super) fn retire(provider: DriverInstance) -> Result<(), u32> {
    let reserved = unsafe { &mut *core::ptr::addr_of_mut!(PENDING_RESERVED) };
    let mut index = 0;
    while index < reserved.len() {
        if !same_provider(reserved[index].provider, provider) {
            index += 1;
            continue;
        }
        let row = reserved.swap_remove(index);
        if let Err(receipt) = unsafe { projections::release_reserved(row.receipt) } {
            reserved.push(PendingReserved { provider: row.provider, receipt });
            return Err(DEVICE_BUSY as u32);
        }
    }

    let retired = unsafe { &mut *core::ptr::addr_of_mut!(PENDING_RETIRED) };
    let mut index = 0;
    while index < retired.len() {
        if !same_provider(retired[index].provider, provider) {
            index += 1;
            continue;
        }
        let row = retired.swap_remove(index);
        if let Err((status, receipt)) = unsafe { projections::free_retired_primary(row.receipt) } {
            retired.push(PendingRetired { provider: row.provider, receipt });
            return Err(status as u32);
        }
    }

    loop {
        let Some((address, retiring)) = projections::next_primary_for_provider(provider)
            .map_err(|status| status as u32)? else { break; };
        retired.try_reserve(1).map_err(|_| RESOURCES as u32)?;
        let receipt = if retiring {
            projections::retiring_primary_receipt(provider, address)
                .map_err(|status| status as u32)?
        } else {
            unsafe {
                crate::with_provider_security_managers(|_, tokens| {
                    projections::retire_primary(provider, address, tokens)
                        .map_err(|status| status as u32)
                })
            }?
        };
        if let Err((status, receipt)) = unsafe { projections::free_retired_primary(receipt) } {
            retired.push(PendingRetired { provider, receipt });
            return Err(status as u32);
        }
    }
    Ok(())
}
