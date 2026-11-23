//! Root-owned DriverObject identity before a hosted image enters foreign DriverEntry code.

use super::*;

/// The root's pre-PE claim remains authoritative when the live instance is reconstructed.
pub(super) fn published_identity(provisional: u64, published: u64) -> Option<u64> {
    (provisional != 0 && provisional == published).then_some(provisional)
}

/// The shared harness calls this immediately after allocating and publishing `SH_DRVOBJ`.
/// A refused or malformed acknowledgement prevents the image from executing; it is never retried.
pub(super) unsafe fn claim_before_entry(_shared_va: u64, driver_object: u64) -> i32 {
    let (words, raw, first, second, third) = call_on4_raw(
        (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
        HOSTED_DEVICE_OP_CLAIM_DRIVER_OBJECT,
        driver_object,
        0,
        0,
    );
    if words != 4 || first != 0 || second != 0 || third != 0
        || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    raw as u32 as i32
}

/// Authenticate the exact primary physical source and its current Reply. Only the harness can
/// make the first claim: it runs before the foreign DriverEntry call, and the claim is one-shot.
pub(super) fn service_claim(
    ch: &crate::spawn_hosts::PumpChannel,
    driver_object: u64,
    active_reply_cap: u64,
) -> i32 {
    let Some((index, inst)) = physical_instance_for_pump_channel(ch) else {
        return STATUS_ACCESS_DENIED;
    };
    if instance_for_pump_channel(ch, active_reply_cap).map(|(source, _)| source) != Some(index)
        || inst.driver_id == 0
        || !inst.used
        || inst.driver_object != 0
        || inst.provisional_driver_object != 0
        || inst.ready
        || ch.tcb != inst.tcb
        || ch.pml4 != inst.pml4
        || ch.fault_ep != inst.fault_ep
        || ch.shared_va != inst.exec_shared_va
        || driver_object == 0
        || unsafe { read_volatile((ch.shared_va + SH_DRVOBJ) as *const u64) } != driver_object
    {
        return STATUS_ACCESS_DENIED;
    }
    let valid_driver = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, driver_object)
            .is_some_and(|(exec, capacity)| {
                capacity >= WDM_X64_DRIVER_OBJECT_SIZE as u64
                    && hosted_instance_pool_allocation_is_free_unlocked(inst, driver_object)
                        == Some(false)
                    && read_unaligned(exec as *const i16) == WDM_X64_IO_TYPE_DRIVER
                    && read_unaligned((exec + 2) as *const u16)
                        == WDM_X64_DRIVER_OBJECT_SIZE as u16
            })
    };
    if !valid_driver {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { driver_instances_mut()[index].provisional_driver_object = driver_object; }
    STATUS_SUCCESS
}
