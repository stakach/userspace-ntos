//! Pure path policy shared by the `Rtl*Registry*` exports.

use alloc::vec::Vec;

pub const RTL_REGISTRY_ABSOLUTE: u32 = 0;
pub const RTL_REGISTRY_SERVICES: u32 = 1;
pub const RTL_REGISTRY_CONTROL: u32 = 2;
pub const RTL_REGISTRY_WINDOWS_NT: u32 = 3;
pub const RTL_REGISTRY_DEVICEMAP: u32 = 4;
pub const RTL_REGISTRY_USER: u32 = 5;
pub const RTL_REGISTRY_MAXIMUM: u32 = 6;
pub const RTL_REGISTRY_HANDLE: u32 = 0x4000_0000;
pub const RTL_REGISTRY_OPTIONAL: u32 = 0x8000_0000;

pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_MULTI_SZ: u32 = 7;

const MAX_PATH_UNITS_WITH_NUL: usize = 260;

const SERVICES: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
const CONTROL: &str = r"\Registry\Machine\System\CurrentControlSet\Control";
const WINDOWS_NT: &str = r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion";
const DEVICEMAP: &str = r"\Registry\Machine\Hardware\DeviceMap";
const USER_DEFAULT: &str = r"\Registry\User\.Default";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectDestination {
    UnicodeString {
        buffer_present: bool,
        maximum_length: u16,
    },
    Raw {
        first_long: i32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectCopyPlan {
    UnicodeString {
        copy_length: u16,
        string_length: u16,
        allocate: bool,
    },
    Raw {
        copy_length: u32,
    },
    Typed {
        copy_length: u32,
        value_type: u32,
    },
}

/// Plan ReactOS `RtlpQueryRegistryDirect` without touching caller memory.
pub fn direct_copy_plan(
    value_type: u32,
    value_length: u32,
    destination: DirectDestination,
) -> Result<DirectCopyPlan, u32> {
    if matches!(value_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) {
        let actual_length = value_length.min(u16::MAX as u32) as u16;
        let DirectDestination::UnicodeString {
            buffer_present,
            maximum_length,
        } = destination
        else {
            return Err(STATUS_BUFFER_TOO_SMALL);
        };
        if buffer_present && actual_length > maximum_length {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        return Ok(DirectCopyPlan::UnicodeString {
            copy_length: actual_length,
            string_length: actual_length.wrapping_sub(2),
            allocate: !buffer_present,
        });
    }
    if value_length <= 4 {
        return Ok(DirectCopyPlan::Raw {
            copy_length: value_length,
        });
    }
    let DirectDestination::Raw { first_long } = destination else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    if first_long < 0 {
        let capacity = first_long.wrapping_neg() as u32;
        if capacity < value_length {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        return Ok(DirectCopyPlan::Raw {
            copy_length: value_length,
        });
    }
    if value_type == REG_BINARY {
        return Ok(DirectCopyPlan::Raw {
            copy_length: value_length,
        });
    }
    let required = value_length.checked_add(8).ok_or(STATUS_BUFFER_TOO_SMALL)?;
    if (first_long as u32) < required {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(DirectCopyPlan::Typed {
        copy_length: value_length,
        value_type,
    })
}

/// Normalize the non-handle `RelativeTo` selector, removing `RTL_REGISTRY_OPTIONAL`.
pub fn base_kind(relative_to: u32) -> Result<u32, u32> {
    let base = relative_to & !RTL_REGISTRY_OPTIONAL;
    if base >= RTL_REGISTRY_MAXIMUM {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(base)
    }
}

/// Resolve a registry helper path exactly as ReactOS `RtlpGetRegistryHandle` does.
///
/// `current_user` is the result of `RtlFormatCurrentUserKeyPath`; `None` selects the native
/// `\Registry\User\.Default` fallback. The returned UTF-16 path has no trailing NUL.
pub fn resolve_path(
    relative_to: u32,
    path: Option<&[u16]>,
    current_user: Option<&[u16]>,
) -> Result<Vec<u16>, u32> {
    let base = base_kind(relative_to)?;
    let mut resolved = Vec::new();
    if base != RTL_REGISTRY_ABSOLUTE {
        let prefix = match base {
            RTL_REGISTRY_SERVICES => SERVICES.encode_utf16().collect::<Vec<_>>(),
            RTL_REGISTRY_CONTROL => CONTROL.encode_utf16().collect(),
            RTL_REGISTRY_WINDOWS_NT => WINDOWS_NT.encode_utf16().collect(),
            RTL_REGISTRY_DEVICEMAP => DEVICEMAP.encode_utf16().collect(),
            RTL_REGISTRY_USER => current_user
                .map(Vec::from)
                .unwrap_or_else(|| USER_DEFAULT.encode_utf16().collect()),
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        resolved.extend_from_slice(&prefix);
        resolved.push(b'\\' as u16);
    }
    if let Some(mut suffix) = path {
        if base != RTL_REGISTRY_ABSOLUTE && suffix.first() == Some(&(b'\\' as u16)) {
            suffix = &suffix[1..];
        }
        resolved.extend_from_slice(suffix);
    }
    if resolved.len() >= MAX_PATH_UNITS_WITH_NUL {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn text(value: &[u16]) -> alloc::string::String {
        alloc::string::String::from_utf16(value).unwrap()
    }

    #[test]
    fn resolves_every_native_base() {
        let cases = [
            (RTL_REGISTRY_SERVICES, SERVICES),
            (RTL_REGISTRY_CONTROL, CONTROL),
            (RTL_REGISTRY_WINDOWS_NT, WINDOWS_NT),
            (RTL_REGISTRY_DEVICEMAP, DEVICEMAP),
            (RTL_REGISTRY_USER, USER_DEFAULT),
        ];
        for (base, prefix) in cases {
            let resolved = resolve_path(base, Some(&wide("Child")), None).unwrap();
            assert_eq!(text(&resolved), alloc::format!("{prefix}\\Child"));
        }
    }

    #[test]
    fn absolute_and_optional_paths_are_preserved() {
        let path = wide(r"\Registry\Machine\System");
        assert_eq!(
            resolve_path(
                RTL_REGISTRY_ABSOLUTE | RTL_REGISTRY_OPTIONAL,
                Some(&path),
                None,
            ),
            Ok(path)
        );
    }

    #[test]
    fn relative_path_strips_exactly_one_leading_separator() {
        let resolved = resolve_path(
            RTL_REGISTRY_CONTROL,
            Some(&wide(r"\\Session Manager")),
            None,
        )
        .unwrap();
        assert_eq!(
            text(&resolved),
            r"\Registry\Machine\System\CurrentControlSet\Control\\Session Manager"
        );
    }

    #[test]
    fn current_user_overrides_default_user_path() {
        let user = wide(r"\Registry\User\S-1-5-21");
        let resolved = resolve_path(RTL_REGISTRY_USER, None, Some(&user)).unwrap();
        assert_eq!(text(&resolved), r"\Registry\User\S-1-5-21\");
    }

    #[test]
    fn rejects_handle_and_unknown_selectors() {
        assert_eq!(
            resolve_path(RTL_REGISTRY_HANDLE, None, None),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            resolve_path(RTL_REGISTRY_MAXIMUM, None, None),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn enforces_reactos_fixed_key_buffer() {
        assert_eq!(
            resolve_path(RTL_REGISTRY_ABSOLUTE, Some(&vec![b'A' as u16; 260]), None),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(
            resolve_path(RTL_REGISTRY_ABSOLUTE, Some(&vec![b'A' as u16; 259]), None)
                .unwrap()
                .len(),
            259
        );
    }

    #[test]
    fn direct_strings_use_unicode_string_capacity() {
        assert_eq!(
            direct_copy_plan(
                REG_SZ,
                12,
                DirectDestination::UnicodeString {
                    buffer_present: true,
                    maximum_length: 12,
                },
            ),
            Ok(DirectCopyPlan::UnicodeString {
                copy_length: 12,
                string_length: 10,
                allocate: false,
            })
        );
        assert_eq!(
            direct_copy_plan(
                REG_EXPAND_SZ,
                14,
                DirectDestination::UnicodeString {
                    buffer_present: true,
                    maximum_length: 12,
                },
            ),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(
            direct_copy_plan(
                REG_MULTI_SZ,
                u16::MAX as u32 + 10,
                DirectDestination::UnicodeString {
                    buffer_present: false,
                    maximum_length: 0,
                },
            ),
            Ok(DirectCopyPlan::UnicodeString {
                copy_length: u16::MAX,
                string_length: u16::MAX.wrapping_sub(2),
                allocate: true,
            })
        );
    }

    #[test]
    fn direct_scalars_and_binary_copy_raw() {
        assert_eq!(
            direct_copy_plan(REG_BINARY, 4, DirectDestination::Raw { first_long: 0 }),
            Ok(DirectCopyPlan::Raw { copy_length: 4 })
        );
        assert_eq!(
            direct_copy_plan(REG_BINARY, 16, DirectDestination::Raw { first_long: 0 }),
            Ok(DirectCopyPlan::Raw { copy_length: 16 })
        );
    }

    #[test]
    fn direct_negative_length_is_raw_capacity() {
        assert_eq!(
            direct_copy_plan(8, 12, DirectDestination::Raw { first_long: -12 }),
            Ok(DirectCopyPlan::Raw { copy_length: 12 })
        );
        assert_eq!(
            direct_copy_plan(8, 13, DirectDestination::Raw { first_long: -12 }),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
    }

    #[test]
    fn direct_nonbinary_large_values_include_length_and_type() {
        assert_eq!(
            direct_copy_plan(8, 12, DirectDestination::Raw { first_long: 20 }),
            Ok(DirectCopyPlan::Typed {
                copy_length: 12,
                value_type: 8,
            })
        );
        assert_eq!(
            direct_copy_plan(8, 12, DirectDestination::Raw { first_long: 19 }),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
    }
}
