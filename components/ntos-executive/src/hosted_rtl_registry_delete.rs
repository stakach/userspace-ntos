//! Kernel `RtlDeleteRegistryValue` over the existing authenticated Zw registry transport.

use super::*;
use nt_config_client::{plan_rtl_registry_delete, RtlRegistryDeleteTarget};

const GENERIC_WRITE: u32 = 0x4000_0000;
const OBJ_CASE_INSENSITIVE_KERNEL_HANDLE: u64 = 0x240;

pub(super) unsafe fn open_target(
    relative_to: u32,
    path: u64,
) -> Result<(u64, bool), i32> {
    let path_ascii = if relative_to & 0x4000_0000 != 0 {
        None
    } else {
        match wide_cstr_to_hosted_ascii::<HOSTED_REGISTRY_PATH_MAX>(path) {
            Some(value) => Some(value),
            None if path == 0 => None,
            None => return Err(STATUS_INVALID_PARAMETER),
        }
    };
    let target = plan_rtl_registry_delete(
        relative_to,
        path_ascii.as_ref().map(HostedAscii::as_str),
    )?;
    open_planned_target(target, path)
}

pub(super) unsafe fn open_planned_target(
    target: RtlRegistryDeleteTarget,
    borrowed_handle: u64,
) -> Result<(u64, bool), i32> {
    match target {
        RtlRegistryDeleteTarget::BorrowedHandle => Ok((borrowed_handle, false)),
        RtlRegistryDeleteTarget::CreateKey(key_path) => {
            let mut key_wide = [0u16; HOSTED_REGISTRY_PATH_MAX];
            let mut key_len = 0usize;
            for unit in key_path.encode_utf16() {
                if key_len >= key_wide.len() - 1 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                key_wide[key_len] = unit;
                key_len += 1;
            }
            let key_bytes = (key_len * 2) as u64;
            let key_unicode = [
                key_bytes | ((key_bytes + 2) << 16),
                key_wide.as_ptr() as u64,
            ];
            let object_attributes = [
                48u64,
                0,
                key_unicode.as_ptr() as u64,
                OBJ_CASE_INSENSITIVE_KERNEL_HANDLE,
                0,
                0,
            ];
            let mut handle = 0u64;
            let status = s_zw_create_key(
                (&mut handle as *mut u64) as u64,
                GENERIC_WRITE,
                object_attributes.as_ptr() as u64,
                0,
                0,
                0,
                0,
            );
            if status != STATUS_SUCCESS {
                return Err(status);
            }
            if handle == 0 {
                return Err(STATUS_INVALID_HANDLE);
            }
            Ok((handle, true))
        }
    }
}

/// ReactOS' helper creates/opens the selected key with write access, deletes one named value,
/// then closes only the handle it opened. `RTL_REGISTRY_HANDLE` borrows the caller's handle.
pub(super) extern "win64" fn delete_registry_value(
    relative_to: u32,
    path: u64,
    value_name: u64,
) -> i32 {
    unsafe {
        let value_ascii = if value_name == 0 {
            HostedAscii::<HOSTED_REGISTRY_PATH_MAX>::empty()
        } else {
            match wide_cstr_to_hosted_ascii::<HOSTED_REGISTRY_PATH_MAX>(value_name) {
                Some(value) => value,
                None => return STATUS_INVALID_PARAMETER,
            }
        };
        let mut value_wide = [0u16; HOSTED_REGISTRY_PATH_MAX];
        for (index, byte) in value_ascii.as_bytes().iter().enumerate() {
            value_wide[index] = u16::from(*byte);
        }
        let value_bytes = value_ascii.len.checked_mul(2).unwrap() as u64;
        let value_unicode = [
            value_bytes | ((value_bytes + 2) << 16),
            value_wide.as_ptr() as u64,
        ];
        let (handle, owned) = match open_target(relative_to, path) {
            Ok(target) => target,
            Err(status) => return status,
        };
        let status = s_zw_delete_value_key(handle, value_unicode.as_ptr() as u64);
        if owned {
            let _ = s_zw_close(handle);
        }
        status
    }
}
