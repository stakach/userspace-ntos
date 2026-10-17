//! Typed PDO property publication through the exact hosted PDO and CM authority.

use super::*;

const PROPERTY_DATA_OFFSET: u64 = 32;
const MAX_PROPERTY_BYTES: usize = 1024;
const DEVICE_FMTID: [u8; 16] = [
    0x4e, 0x25, 0x5c, 0xa4, 0x1c, 0xdf, 0xfd, 0x4e,
    0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0,
];
// LiberNT ACPI buspdo.c publishes these properties on its own child PDOs.
const DEVPKEY_DEVICE_FRIENDLY_NAME: u32 = 14;
const DEVPKEY_DEVICE_BUS_NUMBER: u32 = 23;
const DEVPKEY_DEVICE_ADDRESS: u32 = 30;

/// NTSTATUS IoSetDevicePropertyData(PDO, DEVPROPKEY*, LCID, Flags, Type, Size, Data).
pub(super) extern "win64" fn set(
    pdo: u64,
    key: u64,
    lcid: u32,
    flags: u32,
    property_type: u32,
    size: u32,
    data: u64,
) -> i32 {
    if pdo == 0 || key == 0 || data == 0 || size == 0 || size as usize > MAX_PROPERTY_BYTES {
        return STATUS_INVALID_PARAMETER;
    }
    if lcid != 0 || flags != 0 { return STATUS_NOT_SUPPORTED; }
    unsafe {
        if hosted_current_irql() != 0 { return STATUS_INVALID_DEVICE_REQUEST; }
        let key_bytes = read_unaligned(key as *const [u8; 20]);
        let pid = u32::from_le_bytes(key_bytes[16..20].try_into().unwrap());
        if key_bytes[..16] != DEVICE_FMTID
            || !matches!(pid, DEVPKEY_DEVICE_BUS_NUMBER | DEVPKEY_DEVICE_ADDRESS | DEVPKEY_DEVICE_FRIENDLY_NAME)
        { return STATUS_NOT_SUPPORTED; }
        let valid = match pid {
            DEVPKEY_DEVICE_BUS_NUMBER | DEVPKEY_DEVICE_ADDRESS =>
                property_type == nt_config_manager::devprop_type::UINT32 && size == 4,
            DEVPKEY_DEVICE_FRIENDLY_NAME =>
                property_type == nt_config_manager::devprop_type::STRING && size >= 2 && size % 2 == 0,
            _ => false,
        };
        if !valid { return STATUS_INVALID_PARAMETER; }
        let _guard = component_device_reply_lock();
        core::ptr::copy_nonoverlapping(key_bytes.as_ptr(), FSD_ARG_VADDR as *mut u8, 20);
        copy_bytes_unchecked(FSD_ARG_VADDR + PROPERTY_DATA_OFFSET, data, size as u64);
        let (info, status, _, _, _) = call_on4_raw(
            (FSD_SERVICE_PROPERTY_WRITE_LABEL << 12) | 4,
            pdo, (u64::from(lcid) << 32) | u64::from(flags),
            u64::from(property_type), u64::from(size),
        );
        if info != 1 {
            // The CM write may already have committed; never report a retryable result.
            crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_PROPERTY_WRITE_LABEL, pdo, info, status]);
        }
        status as u32 as i32
    }
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    pdo: u64,
    locale_flags: u64,
    property_type: u64,
    size: u64,
    badge: u64,
    reply_cap: u64,
) -> i32 {
    if locale_flags != 0 || size == 0 || size > MAX_PROPERTY_BYTES as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    let Ok((index, inst, device_id)) = authenticated_hosted_pdo(ch, pdo, reply_cap)
    else { return STATUS_ACCESS_DENIED; };
    if hosted_driver_caller(index, inst, badge).is_none() || inst.exec_arg_va == 0 {
        return STATUS_ACCESS_DENIED;
    }
    let key = unsafe { read_unaligned(inst.exec_arg_va as *const [u8; 20]) };
    if key[..16] != DEVICE_FMTID { return STATUS_NOT_SUPPORTED; }
    let pid = u32::from_le_bytes(key[16..20].try_into().unwrap());
    let Ok(property_type) = u32::try_from(property_type) else { return STATUS_INVALID_PARAMETER; };
    let valid = match pid {
        DEVPKEY_DEVICE_BUS_NUMBER | DEVPKEY_DEVICE_ADDRESS =>
            property_type == nt_config_manager::devprop_type::UINT32 && size == 4,
        DEVPKEY_DEVICE_FRIENDLY_NAME =>
            property_type == nt_config_manager::devprop_type::STRING && size >= 2 && size % 2 == 0,
        _ => return STATUS_NOT_SUPPORTED,
    };
    if !valid { return STATUS_INVALID_PARAMETER; }
    let path = unsafe {
        let pnp = hosted_pnp_manager_mut();
        let Some(node) = pnp.devnode_for_pdo(device_id.raw()) else { return STATUS_INVALID_DEVICE_REQUEST; };
        let Some(source) = pnp.instance_id(node) else { return STATUS_INVALID_DEVICE_REQUEST; };
        String::from(source)
    };
    let bytes = unsafe {
        core::slice::from_raw_parts((inst.exec_arg_va + PROPERTY_DATA_OFFSET) as *const u8, size as usize)
    };
    unsafe { crate::config_manager_set_device_devprop(&path, DEVICE_FMTID, pid, property_type, bytes) }
        .map(|()| STATUS_SUCCESS)
        .unwrap_or_else(|status| status)
}
