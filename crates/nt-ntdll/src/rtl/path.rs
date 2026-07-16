//! `Rtl*` DOS-path parsing (the pure part).
//!
//! `RtlDetermineDosPathNameType_U` classifies a path (UNC / drive-absolute / drive-relative / root
//! / relative / device); `RtlDosPathNameToNtPathName_U` prefixes a fully-qualified DOS path with
//! the NT `\??\` object-manager prefix; `RtlIsDosDeviceName_U` recognises the reserved device names
//! (CON/PRN/AUX/NUL/COMn/LPTn). The parts that touch the current directory or the environment
//! (`RtlGetFullPathName_U`, `RtlDosSearchPath_U`) need process state (Step 3); only the pure
//! parsing/classification lives here.
//!
//! Category A. Host-tested.

use alloc::vec::Vec;

/// `RTL_PATH_TYPE` (`RtlDetermineDosPathNameType_U`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DosPathType {
    /// Unknown / empty.
    Unknown,
    /// UNC absolute: `\\server\share`.
    UncAbsolute,
    /// Drive + `\` : `C:\dir`.
    DriveAbsolute,
    /// Drive, no `\` : `C:dir` (relative to that drive's current dir).
    DriveRelative,
    /// Rooted (no drive): `\dir`.
    Rooted,
    /// Plain relative: `dir\file`.
    Relative,
    /// Device path: `\\.\` or `\\?\`.
    LocalDevice,
    /// Root local device: `\\.` or `\\?`.
    RootLocalDevice,
}

#[inline]
fn is_sep(c: u16) -> bool {
    c == b'\\' as u16 || c == b'/' as u16
}

/// `RtlDetermineDosPathNameType_U`: classify a DOS path.
pub fn determine_dos_path_name_type(path: &[u16]) -> DosPathType {
    let n = path.len();
    if n == 0 {
        return DosPathType::Unknown;
    }
    if is_sep(path[0]) {
        if n >= 2 && is_sep(path[1]) {
            // `\\?` `\\.` `\\?\` `\\.\` or UNC.
            if n >= 3 && (path[2] == b'.' as u16 || path[2] == b'?' as u16) {
                if n == 3 {
                    return DosPathType::RootLocalDevice;
                }
                if is_sep(path[3]) {
                    return DosPathType::LocalDevice;
                }
            }
            return DosPathType::UncAbsolute;
        }
        return DosPathType::Rooted;
    }
    // Drive-letter forms: `X:`
    if n >= 2 && path[1] == b':' as u16 {
        let d = path[0];
        let is_letter = (b'A' as u16..=b'Z' as u16).contains(&d) || (b'a' as u16..=b'z' as u16).contains(&d);
        if is_letter {
            if n >= 3 && is_sep(path[2]) {
                return DosPathType::DriveAbsolute;
            }
            return DosPathType::DriveRelative;
        }
    }
    DosPathType::Relative
}

/// `RtlDosPathNameToNtPathName_U` (the pure prefix step): prepend the NT object-manager DOS-devices
/// prefix `\??\` to a drive-absolute or UNC path. For UNC, Windows produces `\??\UNC\server\...`.
/// Relative/drive-relative paths need the current directory (Step 3) and return `None` here.
pub fn dos_path_name_to_nt_path_name(path: &[u16]) -> Option<Vec<u16>> {
    let ty = determine_dos_path_name_type(path);
    let mut out: Vec<u16> = Vec::new();
    let push = |o: &mut Vec<u16>, s: &str| o.extend(s.encode_utf16());
    match ty {
        DosPathType::DriveAbsolute => {
            push(&mut out, "\\??\\");
            out.extend_from_slice(path);
        }
        DosPathType::UncAbsolute => {
            push(&mut out, "\\??\\UNC\\");
            // Skip the leading `\\`.
            out.extend_from_slice(&path[2..]);
        }
        DosPathType::LocalDevice => {
            // `\\?\X:\..` / `\\.\X:\..` → `\??\X:\..`
            push(&mut out, "\\??\\");
            out.extend_from_slice(&path[4..]);
        }
        _ => return None,
    }
    // Normalise forward slashes to backslashes (NT paths use `\`).
    for c in out.iter_mut() {
        if *c == b'/' as u16 {
            *c = b'\\' as u16;
        }
    }
    Some(out)
}

/// `RtlIsDosDeviceName_U`: recognise a reserved DOS device name (case-insensitive, with an optional
/// extension, e.g. `CON`, `NUL.txt`, `COM1`, `LPT3`). Returns `true` if the path names a device.
pub fn is_dos_device_name(path: &[u16]) -> bool {
    // Take the final path component, strip any extension.
    let start = path
        .iter()
        .rposition(|&c| is_sep(c) || c == b':' as u16)
        .map(|i| i + 1)
        .unwrap_or(0);
    let comp = &path[start..];
    let dot = comp.iter().position(|&c| c == b'.' as u16).unwrap_or(comp.len());
    let stem = &comp[..dot];
    if stem.is_empty() {
        return false;
    }
    let up: Vec<u8> = stem
        .iter()
        .map(|&c| {
            let c = c as u8;
            if c.is_ascii_lowercase() {
                c - 0x20
            } else {
                c
            }
        })
        .collect();
    matches!(up.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
        || (up.len() == 4
            && (up.starts_with(b"COM") || up.starts_with(b"LPT"))
            && up[3].is_ascii_digit()
            && up[3] != b'0')
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    fn s(v: &[u16]) -> std::string::String {
        std::string::String::from_utf16(v).unwrap()
    }

    #[test]
    fn classify() {
        assert_eq!(determine_dos_path_name_type(&u("C:\\Windows")), DosPathType::DriveAbsolute);
        assert_eq!(determine_dos_path_name_type(&u("C:temp")), DosPathType::DriveRelative);
        assert_eq!(determine_dos_path_name_type(&u("\\Device")), DosPathType::Rooted);
        assert_eq!(determine_dos_path_name_type(&u("\\\\srv\\share")), DosPathType::UncAbsolute);
        assert_eq!(determine_dos_path_name_type(&u("\\\\.\\C:")), DosPathType::LocalDevice);
        assert_eq!(determine_dos_path_name_type(&u("\\\\?\\C:\\x")), DosPathType::LocalDevice);
        assert_eq!(determine_dos_path_name_type(&u("\\\\.")), DosPathType::RootLocalDevice);
        assert_eq!(determine_dos_path_name_type(&u("dir\\file")), DosPathType::Relative);
        assert_eq!(determine_dos_path_name_type(&u("")), DosPathType::Unknown);
    }

    #[test]
    fn nt_path_prefix() {
        assert_eq!(s(&dos_path_name_to_nt_path_name(&u("C:\\Windows\\notepad.exe")).unwrap()),
                   "\\??\\C:\\Windows\\notepad.exe");
        assert_eq!(s(&dos_path_name_to_nt_path_name(&u("\\\\srv\\share\\f")).unwrap()),
                   "\\??\\UNC\\srv\\share\\f");
        assert_eq!(s(&dos_path_name_to_nt_path_name(&u("\\\\?\\C:\\x")).unwrap()),
                   "\\??\\C:\\x");
        // Relative can't be resolved without the CWD → None.
        assert!(dos_path_name_to_nt_path_name(&u("rel\\path")).is_none());
    }

    #[test]
    fn dos_devices() {
        assert!(is_dos_device_name(&u("CON")));
        assert!(is_dos_device_name(&u("nul.txt")));
        assert!(is_dos_device_name(&u("C:\\path\\COM1")));
        assert!(is_dos_device_name(&u("LPT3")));
        assert!(!is_dos_device_name(&u("COM0")));
        assert!(!is_dos_device_name(&u("README")));
        assert!(!is_dos_device_name(&u("CONSOLE")));
    }
}
