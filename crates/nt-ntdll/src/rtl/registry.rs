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

const MAX_PATH_UNITS_WITH_NUL: usize = 260;

const SERVICES: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
const CONTROL: &str = r"\Registry\Machine\System\CurrentControlSet\Control";
const WINDOWS_NT: &str = r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion";
const DEVICEMAP: &str = r"\Registry\Machine\Hardware\DeviceMap";
const USER_DEFAULT: &str = r"\Registry\User\.Default";

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
}
