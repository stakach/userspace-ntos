//! Pure target selection for the kernel `RtlDeleteRegistryValue` helper.

use alloc::string::String;

const STATUS_INVALID_PARAMETER: i32 = 0xc000_000d_u32 as i32;
const STATUS_OBJECT_PATH_SYNTAX_BAD: i32 = 0xc000_003b_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xc000_0023_u32 as i32;
const RTL_REGISTRY_HANDLE: u32 = 0x4000_0000;
const RTL_REGISTRY_OPTIONAL: u32 = 0x8000_0000;
const MAX_PATH_UNITS_WITH_NUL: usize = 260;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtlRegistryDeleteTarget {
    BorrowedHandle,
    CreateKey(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtlRegistryWritePlan {
    pub target: RtlRegistryDeleteTarget,
    pub value_type: u32,
    pub value_length: u32,
}

/// Preserve the caller's exact type and byte length; the broker copies exactly this many bytes.
/// A nonzero length without storage is rejected before creating the registry key.
pub fn plan_rtl_registry_write(
    relative_to: u32,
    path: Option<&str>,
    value_type: u32,
    data_present: bool,
    value_length: u32,
) -> Result<RtlRegistryWritePlan, i32> {
    if value_length != 0 && !data_present {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(RtlRegistryWritePlan {
        target: plan_rtl_registry_delete(relative_to, path)?,
        value_type,
        value_length,
    })
}

/// ReactOS `RtlpGetRegistryHandle(..., Create=TRUE)` target selection. A borrowed HANDLE is
/// never closed by the helper; all path modes create or open the selected key before deletion.
pub fn plan_rtl_registry_delete(
    relative_to: u32,
    path: Option<&str>,
) -> Result<RtlRegistryDeleteTarget, i32> {
    if relative_to & RTL_REGISTRY_HANDLE != 0 {
        return Ok(RtlRegistryDeleteTarget::BorrowedHandle);
    }
    let base = relative_to & !RTL_REGISTRY_OPTIONAL;
    let prefix = match base {
        0 => "",
        1 => r"\Registry\Machine\System\CurrentControlSet\Services",
        2 => r"\Registry\Machine\System\CurrentControlSet\Control",
        3 => r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion",
        4 => r"\Registry\Machine\Hardware\DeviceMap",
        5 => r"\Registry\User\.Default",
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    let path = path.unwrap_or("");
    let mut resolved = String::from(prefix);
    if base != 0 {
        resolved.push('\\');
        resolved.push_str(path.strip_prefix('\\').unwrap_or(path));
    } else {
        resolved.push_str(path);
        if !resolved.starts_with('\\') {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
    }
    if resolved.is_empty() || resolved.encode_utf16().count() >= MAX_PATH_UNITS_WITH_NUL {
        return Err(if resolved.is_empty() {
            STATUS_OBJECT_PATH_SYNTAX_BAD
        } else {
            STATUS_BUFFER_TOO_SMALL
        });
    }
    Ok(RtlRegistryDeleteTarget::CreateKey(resolved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_device_map_delete_creates_the_reactos_target_key() {
        assert_eq!(
            plan_rtl_registry_delete(4, Some("KeyboardClass")),
            Ok(RtlRegistryDeleteTarget::CreateKey(String::from(
                r"\Registry\Machine\Hardware\DeviceMap\KeyboardClass"
            ))),
        );
        assert_eq!(
            plan_rtl_registry_delete(4, Some("\\MouseClass")),
            Ok(RtlRegistryDeleteTarget::CreateKey(String::from(
                r"\Registry\Machine\Hardware\DeviceMap\MouseClass"
            ))),
        );
    }

    #[test]
    fn handle_mode_borrows_the_supplied_handle() {
        assert_eq!(
            plan_rtl_registry_delete(0x4000_0000, None),
            Ok(RtlRegistryDeleteTarget::BorrowedHandle),
        );
    }

    #[test]
    fn invalid_base_and_missing_absolute_path_fail_closed() {
        assert_eq!(plan_rtl_registry_delete(6, Some("Child")), Err(0xc000_000d_u32 as i32));
        assert_eq!(plan_rtl_registry_delete(0, None), Err(0xc000_003b_u32 as i32));
    }

    #[test]
    fn class_device_map_write_preserves_the_actual_value_type_and_byte_length() {
        assert_eq!(
            plan_rtl_registry_write(4, Some("KeyboardClass"), 1, true, 76),
            Ok(RtlRegistryWritePlan {
                target: RtlRegistryDeleteTarget::CreateKey(String::from(
                    r"\Registry\Machine\Hardware\DeviceMap\KeyboardClass"
                )),
                value_type: 1,
                value_length: 76,
            }),
        );
        assert_eq!(
            plan_rtl_registry_write(4, Some("MouseClass"), 1, false, 76),
            Err(0xc000_000d_u32 as i32),
        );
    }

    #[test]
    fn handle_mode_write_borrows_handle_and_accepts_empty_data() {
        assert_eq!(
            plan_rtl_registry_write(0x4000_0000, None, 3, false, 0),
            Ok(RtlRegistryWritePlan {
                target: RtlRegistryDeleteTarget::BorrowedHandle,
                value_type: 3,
                value_length: 0,
            }),
        );
    }
}
