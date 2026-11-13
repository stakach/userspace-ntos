//! Named IoCreateDriver lookup for a hosted image's already published canonical driver.
//!
//! A fresh secondary driver needs its own DRIVER_OBJECT, callback transaction and teardown
//! ledger. This adapter explicitly refuses that operation until those owners exist.

use super::*;

const NAME_CAP: usize = 128;
const NAME_BYTES_OFFSET: u64 = 8;

/// NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE Init).
pub(super) extern "win64" fn create(name: u64, initialize: u64) -> i32 {
    if name == 0 || initialize == 0 { return STATUS_INVALID_PARAMETER; }
    unsafe {
        let length = read_unaligned(name as *const u16) as usize;
        let capacity = read_unaligned((name + 2) as *const u16) as usize;
        let source = read_unaligned((name + 8) as *const u64);
        if length == 0 || length % 2 != 0 || length > NAME_CAP * 2
            || capacity < length || source == 0
        { return STATUS_INVALID_PARAMETER; }
        let Some(callback_rva) = initialize.checked_sub(FSD_CODE_VA) else {
            return STATUS_INVALID_PARAMETER;
        };
        let _guard = component_device_reply_lock();
        write_volatile(FSD_ARG_VADDR as *mut u16, length as u16);
        for index in 0..length / 2 {
            let unit = read_unaligned((source + index as u64 * 2) as *const u16);
            write_volatile((FSD_ARG_VADDR + NAME_BYTES_OFFSET + index as u64 * 2) as *mut u16, unit);
        }
        let (info, status, _, _, _) = call_on4_raw(
            (FSD_SERVICE_CREATE_DRIVER_LABEL << 12) | 1,
            callback_rva, 0, 0, 0,
        );
        if info != 1 {
            crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_CREATE_DRIVER_LABEL, callback_rva, info, status]);
        }
        status as u32 as i32
    }
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    callback_rva: u64,
    badge: u64,
    reply_cap: u64,
) -> i32 {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return STATUS_ACCESS_DENIED;
    };
    if hosted_driver_caller(index, inst, badge).is_none()
        || callback_rva >= inst.image_frames.saturating_mul(0x1000)
        || inst.exec_arg_va == 0
    { return STATUS_ACCESS_DENIED; }
    let len = unsafe { read_volatile(inst.exec_arg_va as *const u16) as usize };
    if len == 0 || len % 2 != 0 || len > NAME_CAP * 2 { return STATUS_INVALID_PARAMETER; }
    let mut path = String::new();
    if path.try_reserve_exact(len / 2).is_err() { return STATUS_INSUFFICIENT_RESOURCES; }
    for offset in (0..len).step_by(2) {
        let unit = unsafe { read_volatile((inst.exec_arg_va + NAME_BYTES_OFFSET + offset as u64) as *const u16) };
        if unit == 0 || unit > 0x7f { return STATUS_NOT_SUPPORTED; }
        path.push(char::from(unit as u8));
    }
    if path.len() <= 8 || !path[..8].eq_ignore_ascii_case("\\Driver\\")
        || parse_nt_path(&path).is_none()
    { return STATUS_INVALID_PARAMETER; }
    if driver_id_by_name(&path).is_some() {
        nt_status::NtStatus::OBJECT_NAME_COLLISION.raw()
    } else {
        // No new object is published and the initialization callback is never invoked.
        STATUS_NOT_SUPPORTED
    }
}
