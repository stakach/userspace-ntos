//! Object-manager boot policy from the composed SYSTEM authority.

use crate::{CurrentControlSetError, Hive, HiveDecodeError, RegistryValueType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootObjectPolicyError {
    Image(HiveDecodeError),
    Selection(CurrentControlSetError),
    InvalidProtectionMode,
}

/// Read the selected control set. Only an absent policy uses ObpProtectionMode's zero initial
/// value; malformed present data and invalid selection are not defaults.
pub fn boot_object_protection_mode(hive: &Hive) -> Result<u32, BootObjectPolicyError> {
    let selected = hive
        .current_control_set()
        .map_err(BootObjectPolicyError::Selection)?;
    let path = alloc::format!("{}\\Control\\Session Manager", selected.as_str());
    let Some(key) = hive.open_key(&path) else {
        return Ok(0);
    };
    let Some((kind, bytes)) = hive.query_value(key, "ProtectionMode") else {
        return Ok(0);
    };
    if kind != RegistryValueType::Dword || bytes.len() != 4 {
        return Err(BootObjectPolicyError::InvalidProtectionMode);
    }
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Decode the actual composed transport, not a Windows REGF image. The temporary decoded Hive
/// is released before returning; this does not retain another SYSTEM snapshot authority.
pub fn boot_object_protection_mode_from_image(bytes: &[u8]) -> Result<u32, BootObjectPolicyError> {
    let hive = crate::decode_image(bytes).map_err(BootObjectPolicyError::Image)?;
    boot_object_protection_mode(&hive)
}
