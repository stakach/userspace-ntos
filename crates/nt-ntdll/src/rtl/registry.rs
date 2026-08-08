//! Pure path policy shared by the `Rtl*Registry*` exports.

use alloc::format;
use alloc::vec::Vec;
use core::ops::Range;

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
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_MULTI_SZ: u32 = 7;

/// `OBJ_PERMANENT` / `OBJ_EXCLUSIVE` — the two attribute bits `RtlpNtOpenKey`/`RtlpNtCreateKey`
/// strip before issuing the syscall (`references/reactos/sdk/lib/rtl/registry.c:913`).
pub const OBJ_PERMANENT: u32 = 0x0000_0010;
pub const OBJ_EXCLUSIVE: u32 = 0x0000_0020;

/// **x64** `OBJECT_ATTRIBUTES` field byte offsets. The struct is
/// `{ ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes;
/// PVOID SecurityDescriptor; PVOID SecurityQualityOfService; }` — with 8-byte pointer alignment
/// `Length` is followed by 4 bytes of padding, so `RootDirectory` is at 0x08, `ObjectName` at
/// 0x10 and **`Attributes` at 0x18** (the 32-bit layout's 0x0C/0x10 do NOT apply). Getting this
/// wrong writes the masked flags over the low half of the `ObjectName` POINTER, which silently
/// corrupts every name the callee then reads.
pub const OA_OFFSET_LENGTH: u64 = 0x00;
pub const OA_OFFSET_ROOT_DIRECTORY: u64 = 0x08;
pub const OA_OFFSET_OBJECT_NAME: u64 = 0x10;
pub const OA_OFFSET_ATTRIBUTES: u64 = 0x18;
pub const OA_OFFSET_SECURITY_DESCRIPTOR: u64 = 0x20;
pub const OA_OFFSET_SECURITY_QOS: u64 = 0x28;
/// `sizeof(OBJECT_ATTRIBUTES)` on x64.
pub const OA_SIZE: u64 = 0x30;

/// The `RtlpNt*Key` attribute sanitiser: drop `OBJ_PERMANENT | OBJ_EXCLUSIVE`, keep the rest
/// (`references/reactos/sdk/lib/rtl/registry.c:913`, `:947`).
#[must_use]
pub const fn sanitize_key_object_attributes(attributes: u32) -> u32 {
    attributes & !(OBJ_PERMANENT | OBJ_EXCLUSIVE)
}

const MAX_PATH_UNITS_WITH_NUL: usize = 260;

const SERVICES: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
const CONTROL: &str = r"\Registry\Machine\System\CurrentControlSet\Control";
const WINDOWS_NT: &str = r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion";
const DEVICEMAP: &str = r"\Registry\Machine\Hardware\DeviceMap";
const USER_DEFAULT: &str = r"\Registry\User\.Default";
const USER_PREFIX: &str = r"\Registry\User";

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

/// Split a UTF-16LE `REG_MULTI_SZ` the way ReactOS' `RtlpCallQueryRegistryRoutine` walks it:
/// each returned byte range includes that string's NUL, and the last two UTF-16 code units in the
/// caller-supplied length are treated as the terminating empty-string area.
///
/// This deliberately uses the value's explicit byte length instead of requiring the buffer to end in
/// a perfectly formed double-NUL. Native callers encounter malformed single-NUL registry data, and
/// ReactOS/NT skip the trailing unterminated tail instead of failing the whole query.
pub fn multi_sz_ranges(value: &[u8]) -> Result<Vec<Range<usize>>, u32> {
    if value.len() < 4 || value.len() & 1 != 0 {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let units = value.len() / 2;
    let value_end = units - 2;
    let unit = |index: usize| {
        let offset = index * 2;
        u16::from_le_bytes([value[offset], value[offset + 1]])
    };
    let mut ranges = Vec::new();
    let mut start = 0usize;
    while start < value_end {
        let mut end = start;
        while end < units && unit(end) != 0 {
            end += 1;
        }
        if end >= units {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        ranges.try_reserve(1).map_err(|_| STATUS_NO_MEMORY)?;
        ranges.push(start * 2..(end + 1) * 2);
        start = end + 1;
    }
    Ok(ranges)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyValueFullInformation<'a> {
    pub value_type: u32,
    pub name: &'a [u8],
    pub data: &'a [u8],
}

/// Validate and borrow a native `KEY_VALUE_FULL_INFORMATION` record.
pub fn parse_key_value_full_information(
    information: &[u8],
) -> Result<KeyValueFullInformation<'_>, u32> {
    if information.len() < 0x14 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let value_type = u32::from_le_bytes(information[4..8].try_into().unwrap());
    let data_offset = u32::from_le_bytes(information[8..12].try_into().unwrap()) as usize;
    let data_length = u32::from_le_bytes(information[12..16].try_into().unwrap()) as usize;
    let name_length = u32::from_le_bytes(information[16..20].try_into().unwrap()) as usize;
    let name_end = 0x14usize
        .checked_add(name_length)
        .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
    let data_end = data_offset
        .checked_add(data_length)
        .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
    if name_length & 1 != 0
        || name_end > information.len()
        || data_offset < 0x14
        || data_end > information.len()
    {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(KeyValueFullInformation {
        value_type,
        name: &information[0x14..name_end],
        data: &information[data_offset..data_end],
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

/// Build the `RtlFormatCurrentUserKeyPath` result from the caller's token-user SID.
pub fn current_user_key_path_from_native_sid(sid: &[u8]) -> Result<Vec<u16>, u32> {
    let sid = nt_security::Sid::from_native_bytes(sid)?;
    Ok(format!("{USER_PREFIX}\\{}", sid.to_sddl())
        .encode_utf16()
        .collect())
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
    fn current_user_path_formats_native_token_sid() {
        let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1325974280, 164944053, 1780406144, 500] {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        let path = current_user_key_path_from_native_sid(&sid).unwrap();
        assert_eq!(
            text(&path),
            r"\Registry\User\S-1-5-21-1325974280-164944053-1780406144-500"
        );
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

    #[test]
    fn splits_multi_sz_with_each_terminator() {
        let mut value = Vec::new();
        for unit in ['A' as u16, 0, 'B' as u16, 'C' as u16, 0, 0] {
            value.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(multi_sz_ranges(&value), Ok(vec![0..4, 4..10]));
        assert_eq!(multi_sz_ranges(&[0, 0, 0, 0]), Ok(Vec::new()));
    }

    #[test]
    fn multi_sz_split_uses_reactos_length_bound_for_malformed_tails() {
        let mut single_nul_tail = Vec::new();
        for unit in ['A' as u16, 0, 'B' as u16, 0, 'C' as u16] {
            single_nul_tail.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(multi_sz_ranges(&single_nul_tail), Ok(vec![0..4, 4..8]));
    }

    #[test]
    fn rejects_multi_sz_shapes_that_cannot_be_walked() {
        assert_eq!(multi_sz_ranges(&[]), Err(STATUS_OBJECT_TYPE_MISMATCH));
        assert_eq!(
            multi_sz_ranges(&[b'A', 0, 0]),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            multi_sz_ranges(&[b'A', 0, b'B', 0, b'C', 0, b'D', 0]),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
    }

    #[test]
    fn parses_bounded_full_value_information() {
        let mut information = vec![0u8; 32];
        information[4..8].copy_from_slice(&4u32.to_le_bytes());
        information[8..12].copy_from_slice(&24u32.to_le_bytes());
        information[12..16].copy_from_slice(&4u32.to_le_bytes());
        information[16..20].copy_from_slice(&2u32.to_le_bytes());
        information[20..22].copy_from_slice(&[b'X', 0]);
        information[24..28].copy_from_slice(&42u32.to_le_bytes());
        assert_eq!(
            parse_key_value_full_information(&information),
            Ok(KeyValueFullInformation {
                value_type: 4,
                name: &[b'X', 0],
                data: &42u32.to_le_bytes(),
            })
        );
    }

    #[test]
    fn rejects_out_of_bounds_full_value_information() {
        for (data_offset, data_length, name_length) in
            [(24u32, 16u32, 2u32), (8, 4, 2), (24, 4, 13), (24, 4, 3)]
        {
            let mut information = vec![0u8; 32];
            information[8..12].copy_from_slice(&data_offset.to_le_bytes());
            information[12..16].copy_from_slice(&data_length.to_le_bytes());
            information[16..20].copy_from_slice(&name_length.to_le_bytes());
            assert_eq!(
                parse_key_value_full_information(&information),
                Err(STATUS_INFO_LENGTH_MISMATCH)
            );
        }
        assert_eq!(
            parse_key_value_full_information(&[0; 19]),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
    }

    /// The x64 `OBJECT_ATTRIBUTES` field offsets must match the C struct's natural layout. The
    /// `Attributes` ULONG sits at 0x18 — NOT 0x10, which is the `ObjectName` POINTER. (The
    /// `RtlpNt*Key` shims used 0x10 and so masked the low dword of the name pointer, which made
    /// lsasrv's `\Registry\Machine\SECURITY` open read a garbage `UNICODE_STRING`.)
    #[test]
    fn x64_object_attributes_field_offsets() {
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: u64,
            object_name: u64,
            attributes: u32,
            security_descriptor: u64,
            security_qos: u64,
        }
        let oa = ObjectAttributes {
            length: 0,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_qos: 0,
        };
        let base = core::ptr::addr_of!(oa) as u64;
        let at = |field: u64| field - base;
        assert_eq!(at(core::ptr::addr_of!(oa.length) as u64), OA_OFFSET_LENGTH);
        assert_eq!(
            at(core::ptr::addr_of!(oa.root_directory) as u64),
            OA_OFFSET_ROOT_DIRECTORY
        );
        assert_eq!(
            at(core::ptr::addr_of!(oa.object_name) as u64),
            OA_OFFSET_OBJECT_NAME
        );
        assert_eq!(
            at(core::ptr::addr_of!(oa.attributes) as u64),
            OA_OFFSET_ATTRIBUTES
        );
        assert_eq!(
            at(core::ptr::addr_of!(oa.security_descriptor) as u64),
            OA_OFFSET_SECURITY_DESCRIPTOR
        );
        assert_eq!(
            at(core::ptr::addr_of!(oa.security_qos) as u64),
            OA_OFFSET_SECURITY_QOS
        );
        assert_eq!(core::mem::size_of::<ObjectAttributes>() as u64, OA_SIZE);
        assert_ne!(OA_OFFSET_ATTRIBUTES, OA_OFFSET_OBJECT_NAME);
    }

    /// The sanitiser drops only `OBJ_PERMANENT|OBJ_EXCLUSIVE`, never any other attribute bit.
    #[test]
    fn key_object_attributes_sanitiser_drops_only_permanent_and_exclusive() {
        const OBJ_INHERIT: u32 = 0x0000_0002;
        const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
        const OBJ_OPENIF: u32 = 0x0000_0080;
        assert_eq!(sanitize_key_object_attributes(0), 0);
        assert_eq!(sanitize_key_object_attributes(OBJ_PERMANENT), 0);
        assert_eq!(sanitize_key_object_attributes(OBJ_EXCLUSIVE), 0);
        assert_eq!(
            sanitize_key_object_attributes(OBJ_PERMANENT | OBJ_EXCLUSIVE),
            0
        );
        assert_eq!(
            sanitize_key_object_attributes(
                OBJ_INHERIT | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_EXCLUSIVE | OBJ_OPENIF
            ),
            OBJ_INHERIT | OBJ_CASE_INSENSITIVE | OBJ_OPENIF
        );
        assert_eq!(sanitize_key_object_attributes(0xFFFF_FFFF), 0xFFFF_FFCF);
    }
}
