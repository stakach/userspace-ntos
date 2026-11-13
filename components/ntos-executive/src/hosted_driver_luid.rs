//! Kernel `ZwAllocateLocallyUniqueId` shares the root's `ExpLuid` namespace.

use super::*;

pub(super) const LABEL: u64 = 0x7D2;

/// `NTSTATUS ZwAllocateLocallyUniqueId(PLUID)` (one 8-byte output).
pub(super) extern "win64" fn allocate(luid_out: u64) -> i32 {
    if luid_out == 0 || luid_out.checked_add(8).is_none() {
        return STATUS_ACCESS_VIOLATION;
    }
    let (label, status, value, _, _) = unsafe { call_on4(LABEL << 12, 0, 0, 0, 0) };
    if label != 0 {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let status = status as u32 as i32;
    if status == 0 {
        unsafe { write_unaligned(luid_out as *mut u64, value); }
    }
    status
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return (STATUS_ACCESS_DENIED, 0);
    }
    match EXP_LUID.allocate() {
        Some(value) => (0, value),
        None => (0xC000_0095u32 as i32, 0), // STATUS_INTEGER_OVERFLOW
    }
}
