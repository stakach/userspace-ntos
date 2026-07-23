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

const UNICODE_STRING_MAX_UNITS_WITH_NUL: usize = (u16::MAX as usize) / 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchPathError {
    NameTooLong,
}

fn file_leaf_has_dot(file_name: &[u16]) -> bool {
    file_name
        .iter()
        .rev()
        .take_while(|unit| **unit != b'\\' as u16 && **unit != b'/' as u16)
        .any(|unit| *unit == b'.' as u16)
}

fn checked_candidate(parts: &[&[u16]]) -> Result<Vec<u16>, SearchPathError> {
    let length = parts
        .iter()
        .try_fold(0usize, |length, part| length.checked_add(part.len()));
    let length = length.ok_or(SearchPathError::NameTooLong)?;
    if length + 1 > UNICODE_STRING_MAX_UNITS_WITH_NUL {
        return Err(SearchPathError::NameTooLong);
    }
    let mut candidate = Vec::new();
    candidate
        .try_reserve_exact(length)
        .map_err(|_| SearchPathError::NameTooLong)?;
    for part in parts {
        candidate.extend_from_slice(part);
    }
    Ok(candidate)
}

/// Build the ordered DOS filenames probed by `RtlDosSearchPath_Ustr`. File existence and full-path
/// expansion remain target concerns; this core handles path segmentation and extension rules.
pub fn dos_search_path_candidates(
    flags: u32,
    path: &[u16],
    file_name: &[u16],
    extension: Option<&[u16]>,
) -> Result<Vec<Vec<u16>>, SearchPathError> {
    let mut candidates = Vec::new();
    let path_type = determine_dos_path_name_type(file_name);
    if path_type == DosPathType::Relative {
        if flags & 2 != 0
            && (file_name.starts_with(&[b'.' as u16, b'\\' as u16])
                || file_name.starts_with(&[b'.' as u16, b'/' as u16])
                || file_name.starts_with(&[b'.' as u16, b'.' as u16, b'\\' as u16])
                || file_name.starts_with(&[b'.' as u16, b'.' as u16, b'/' as u16]))
        {
            return Ok(candidates);
        }
        let extension =
            extension.filter(|extension| !extension.is_empty() && !file_leaf_has_dot(file_name));
        let mut start = 0usize;
        while start < path.len() {
            let end = path[start..]
                .iter()
                .position(|unit| *unit == b';' as u16)
                .map_or(path.len(), |offset| start + offset);
            let segment = &path[start..end];
            let separator = if segment.is_empty()
                || segment
                    .last()
                    .is_some_and(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
            {
                &[][..]
            } else {
                &[b'\\' as u16][..]
            };
            candidates.push(checked_candidate(&[
                segment,
                separator,
                file_name,
                extension.unwrap_or(&[]),
            ])?);
            if end == path.len() {
                break;
            }
            start = end + 1;
        }
        return Ok(candidates);
    }

    candidates.push(checked_candidate(&[file_name])?);
    if let Some(extension) = extension.filter(|extension| !extension.is_empty()) {
        if flags & 4 != 0 || !file_leaf_has_dot(file_name) {
            candidates.push(checked_candidate(&[file_name, extension])?);
        }
    }
    Ok(candidates)
}

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

/// Largest byte count an NT `UNICODE_STRING` buffer may describe, including its terminal NUL.
pub const MAX_UNICODE_STRING_BUFFER_BYTES: usize = 0xfffe;

/// Compute the byte capacity required to append counted UTF-16 strings and a terminal NUL.
pub fn multi_append_required_bytes(
    original_length: u16,
    source_lengths: impl IntoIterator<Item = u16>,
) -> Option<u16> {
    let mut required = original_length as usize;
    for length in source_lengths {
        required = required.checked_add(length as usize)?;
    }
    required = required.checked_add(core::mem::size_of::<u16>())?;
    (required <= MAX_UNICODE_STRING_BUFFER_BYTES).then_some(required as u16)
}

/// Separator edits needed by `RtlAppendPathElement` around the supplied element.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AppendPathElementPlan {
    /// Separator to insert before the element.
    pub before: Option<u16>,
    /// Whether to omit the element's leading separator because the path already ends in one.
    pub skip_element_leading: bool,
    /// Separator to append after the element to preserve a trailing separator from the path.
    pub after: Option<u16>,
}

/// Fully composed names returned by `RtlComputePrivatizedDllName_U`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatizedDllNames {
    /// Image-directory-relative DLL name.
    pub real: Vec<u16>,
    /// `<full image path>.Local\<dll>` redirection candidate.
    pub local: Vec<u16>,
}

/// The composed names cannot be represented by native `UNICODE_STRING` descriptors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrivatizedDllNameTooLong;

/// Compose the two paths used by `RtlComputePrivatizedDllName_U`.
pub fn compute_privatized_dll_names(
    image_path: &[u16],
    dll_name: &[u16],
) -> Result<PrivatizedDllNames, PrivatizedDllNameTooLong> {
    let basename_start = dll_name
        .iter()
        .rposition(|&unit| is_sep(unit))
        .map_or(0, |position| position + 1);
    let basename = &dll_name[basename_start..];
    let has_extension = basename
        .iter()
        .rposition(|&unit| unit == b'.' as u16)
        .is_some_and(|position| position > 0);
    let default_extension: &[u16] = if has_extension {
        &[]
    } else {
        &[b'.' as u16, b'D' as u16, b'L' as u16, b'L' as u16]
    };

    let image_directory_length = image_path
        .iter()
        .rposition(|&unit| is_sep(unit))
        .map_or(image_path.len(), |position| position + 1);
    let real_length = image_directory_length
        .checked_add(basename.len())
        .and_then(|length| length.checked_add(default_extension.len()))
        .ok_or(PrivatizedDllNameTooLong)?;
    let local_suffix = [
        b'.' as u16,
        b'L' as u16,
        b'o' as u16,
        b'c' as u16,
        b'a' as u16,
        b'l' as u16,
        b'\\' as u16,
    ];
    let local_length = image_path
        .len()
        .checked_add(local_suffix.len())
        .and_then(|length| length.checked_add(basename.len()))
        .and_then(|length| length.checked_add(default_extension.len()))
        .ok_or(PrivatizedDllNameTooLong)?;

    // ReactOS uses `>` for LocalName and `>=` for RealName against the 65534-byte limit.
    if local_length > 32_766 || real_length >= 32_766 {
        return Err(PrivatizedDllNameTooLong);
    }

    let mut real = Vec::with_capacity(real_length);
    real.extend_from_slice(&image_path[..image_directory_length]);
    real.extend_from_slice(basename);
    real.extend_from_slice(default_extension);

    let mut local = Vec::with_capacity(local_length);
    local.extend_from_slice(image_path);
    local.extend_from_slice(&local_suffix);
    local.extend_from_slice(basename);
    local.extend_from_slice(default_extension);
    Ok(PrivatizedDllNames { real, local })
}

/// Plan the separator handling performed by `RtlAppendPathElement`.
pub fn append_path_element_plan(
    path: &[u16],
    element: &[u16],
    only_backslash_is_separator: bool,
) -> AppendPathElementPlan {
    if element.is_empty() {
        return AppendPathElementPlan::default();
    }

    let separator =
        |unit: u16| unit == b'\\' as u16 || (!only_backslash_is_separator && unit == b'/' as u16);
    let path_style = path.iter().take(3).copied().find(|&unit| separator(unit));
    let path_trailing = path.last().copied().filter(|&unit| separator(unit));
    let element_leading = element.first().copied().filter(|&unit| separator(unit));
    let element_trailing = element.last().copied().filter(|&unit| separator(unit));

    let before = if path_trailing.is_none() && element_leading.is_none() {
        Some(if only_backslash_is_separator {
            b'\\' as u16
        } else {
            element_trailing.or(path_style).unwrap_or(b'\\' as u16)
        })
    } else {
        None
    };
    let after = if path_trailing.is_some() && element_trailing.is_none() {
        Some(if only_backslash_is_separator {
            b'\\' as u16
        } else {
            path_trailing.unwrap()
        })
    } else {
        None
    };

    AppendPathElementPlan {
        before,
        skip_element_leading: path_trailing.is_some() && element_leading.is_some(),
        after,
    }
}

/// `RtlDetermineDosPathNameType_U`: classify a DOS path.
pub fn determine_dos_path_name_type(path: &[u16]) -> DosPathType {
    let n = path.len();
    if n == 0 {
        return DosPathType::Relative;
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
        let is_letter =
            (b'A' as u16..=b'Z' as u16).contains(&d) || (b'a' as u16..=b'z' as u16).contains(&d);
        if is_letter {
            if n >= 3 && is_sep(path[2]) {
                return DosPathType::DriveAbsolute;
            }
            return DosPathType::DriveRelative;
        }
    }
    DosPathType::Relative
}

/// `RtlGetLengthWithoutTrailingPathSeperators`: return the character count after trimming trailing
/// DOS path separators (`\` and `/`).
pub fn length_without_trailing_path_separators(path: &[u16]) -> u32 {
    let mut n = path.len();
    while n > 0 && is_sep(path[n - 1]) {
        n -= 1;
    }
    n as u32
}

/// `RtlGetLengthWithoutLastFullDosOrNtPathElement`: return the character count through the path
/// separator before the last full element.
pub fn length_without_last_full_dos_or_nt_path_element(path: &[u16]) -> Result<u32, ()> {
    if path.is_empty() {
        return Ok(0);
    }

    match determine_dos_path_name_type(path) {
        DosPathType::LocalDevice => {
            if path.len() < 7 || path[5] != b':' as u16 || !is_sep(path[6]) {
                return Err(());
            }
        }
        DosPathType::Rooted | DosPathType::UncAbsolute | DosPathType::DriveAbsolute => {}
        _ => return Err(()),
    }

    let mut end = path.len();
    while end > 0 && is_sep(path[end - 1]) {
        end -= 1;
    }
    let Some(mut position) = path[..end].iter().rposition(|&unit| is_sep(unit)) else {
        return Ok(0);
    };
    while position > 1 && is_sep(path[position - 1]) {
        position -= 1;
    }
    Ok((position + 1) as u32)
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

/// Resolve a possibly-relative DOS `name` to an absolute NT path, using `cwd` (a fully-qualified DOS
/// directory, e.g. `C:\Windows`) as the base for relative / rooted forms. This is the CWD-aware
/// cousin of [`dos_path_name_to_nt_path_name`]: real ntdll's `RtlDosPathNameToRelativeNtPathName_U`
/// first canonicalises the DOS name against `PEB->ProcessParameters->CurrentDirectory.DosPath`
/// (via `RtlGetFullPathName_Ustr`) THEN prefixes `\??\`. Without this a relative image name like
/// `services.exe` (winlogon's `CreateProcessW("services.exe")`) yields `None` and CreateProcessInternalW
/// bails with `ERROR_PATH_NOT_FOUND` before ever issuing `NtOpenFile`.
///
/// Handled forms:
/// - already-absolute (drive-absolute / UNC / local-device) → delegate to
///   [`dos_path_name_to_nt_path_name`] (CWD unused).
/// - plain relative (`services.exe`, `sub\file`) → `cwd \ name`, then `\??\` prefix.
/// - rooted (`\dir\file`, no drive) → take the drive from `cwd`, then `drive\dir\file`.
/// - drive-relative (`C:file`) → not resolvable without a per-drive CWD table → `None`.
///
/// `cwd` must itself be drive-absolute (`X:\...`); otherwise `None`.
pub fn dos_path_name_to_nt_path_name_rel(name: &[u16], cwd: &[u16]) -> Option<Vec<u16>> {
    match determine_dos_path_name_type(name) {
        DosPathType::DriveAbsolute | DosPathType::UncAbsolute | DosPathType::LocalDevice => {
            dos_path_name_to_nt_path_name(name)
        }
        DosPathType::Relative => {
            // Require an absolute CWD to anchor against.
            if determine_dos_path_name_type(cwd) != DosPathType::DriveAbsolute {
                return None;
            }
            let mut dos: Vec<u16> = cwd.to_vec();
            // Ensure a single separator between cwd and name.
            if !dos.last().is_some_and(|&c| is_sep(c)) {
                dos.push(b'\\' as u16);
            }
            dos.extend_from_slice(name);
            dos_path_name_to_nt_path_name(&dos)
        }
        DosPathType::Rooted => {
            // `\dir\file` inherits the drive from cwd (e.g. `C:`), giving `C:\dir\file`.
            if determine_dos_path_name_type(cwd) != DosPathType::DriveAbsolute {
                return None;
            }
            let mut dos: Vec<u16> = cwd[..2].to_vec(); // "X:"
            dos.extend_from_slice(name); // name starts with '\'
            dos_path_name_to_nt_path_name(&dos)
        }
        _ => None,
    }
}

/// A canonical NT path and, when the original input was relative to the current directory, the
/// UTF-16 offset of the handle-relative subspan within `nt_path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelativeNtPathPlan {
    pub nt_path: Vec<u16>,
    pub relative_offset: Option<usize>,
}

/// Plan `RtlDosPathNameToRelativeNtPathName_U`. The relative result is valid only when a current
/// directory handle exists and the canonical result remains under that directory on a component
/// boundary. The full NT path is always returned for supported DOS path forms.
pub fn relative_nt_path_plan(
    name: &[u16],
    cwd: &[u16],
    has_current_directory_handle: bool,
) -> Option<RelativeNtPathPlan> {
    let input_type = determine_dos_path_name_type(name);
    let full_dos = super::environment::full_path_units(name, cwd);
    let nt_path = dos_path_name_to_nt_path_name(&full_dos)?;
    let relative_offset = if input_type == DosPathType::Relative && has_current_directory_handle {
        let canonical_cwd = super::environment::full_path_units(&[b'.' as u16], cwd);
        let cwd_end = canonical_cwd
            .iter()
            .rposition(|unit| !is_sep(*unit))
            .map_or(0, |index| index + 1);
        let prefix_matches = full_dos.len() >= cwd_end
            && full_dos[..cwd_end]
                .iter()
                .zip(&canonical_cwd[..cwd_end])
                .all(|(&left, &right)| fold_ascii(left) == fold_ascii(right));
        let dos_offset = if !prefix_matches {
            None
        } else if full_dos.len() == cwd_end {
            Some(cwd_end)
        } else if is_sep(full_dos[cwd_end]) {
            Some(cwd_end + 1)
        } else {
            None
        };
        dos_offset.map(|offset| nt_path.len() - full_dos.len() + offset)
    } else {
        None
    };
    Some(RelativeNtPathPlan {
        nt_path,
        relative_offset,
    })
}

fn fold_ascii(unit: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&unit) {
        unit - 32
    } else {
        unit
    }
}

/// `RtlIsDosDeviceName_U`: recognise a reserved DOS device name (case-insensitive, with an optional
/// extension, e.g. `CON`, `NUL.txt`, `COM1`, `LPT3`). Returns `true` if the path names a device.
pub fn is_dos_device_name(path: &[u16]) -> bool {
    let path_type = determine_dos_path_name_type(path);
    if matches!(path_type, DosPathType::Unknown | DosPathType::UncAbsolute) {
        return false;
    }
    if path_type == DosPathType::LocalDevice {
        return path.len() == 7
            && path[0] == b'\\' as u16
            && path[1] == b'\\' as u16
            && path[2] == b'.' as u16
            && path[3] == b'\\' as u16
            && eq_ascii_ci(&path[4..], b"CON");
    }

    let mut end = path.len();
    if end != 0 && path[end - 1] == b':' as u16 {
        end -= 1;
    }
    while end != 0 && matches!(path[end - 1], 0x20 | 0x2e) {
        end -= 1;
    }
    if end == 0 {
        return false;
    }
    let start = path[..end]
        .iter()
        .rposition(|&c| is_sep(c))
        .map_or(0, |position| position + 1)
        .max(if end >= 2 && path[1] == b':' as u16 {
            2
        } else {
            0
        });
    let component = &path[start..end];
    let stem_end = component
        .iter()
        .position(|&c| c == b'.' as u16 || c == b':' as u16)
        .unwrap_or(component.len());
    let mut stem = &component[..stem_end];
    while stem.last() == Some(&(b' ' as u16)) {
        stem = &stem[..stem.len() - 1];
    }
    matches!(stem.len(), 3 | 4)
        && (eq_ascii_ci(stem, b"CON")
            || eq_ascii_ci(stem, b"PRN")
            || eq_ascii_ci(stem, b"AUX")
            || eq_ascii_ci(stem, b"NUL")
            || (stem.len() == 4
                && (eq_ascii_ci(&stem[..3], b"COM") || eq_ascii_ci(&stem[..3], b"LPT"))
                && matches!(stem[3], 0x31..=0x39)))
}

fn eq_ascii_ci(value: &[u16], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value.iter().zip(expected).all(|(&unit, &byte)| {
            unit <= u8::MAX as u16 && (unit as u8).to_ascii_uppercase() == byte
        })
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

    fn append_element(path: &str, element: &str, only_backslash: bool) -> std::string::String {
        let mut path = u(path);
        let element = u(element);
        let plan = append_path_element_plan(&path, &element, only_backslash);
        path.extend(plan.before);
        path.extend_from_slice(&element[usize::from(plan.skip_element_leading)..]);
        path.extend(plan.after);
        s(&path)
    }

    #[test]
    fn multi_append_capacity_includes_terminal_nul() {
        assert_eq!(multi_append_required_bytes(4, [6, 8]), Some(20));
        assert_eq!(multi_append_required_bytes(0, []), Some(2));
        assert_eq!(multi_append_required_bytes(0xfffc, []), Some(0xfffe));
        assert_eq!(multi_append_required_bytes(0xfffe, []), None);
        assert_eq!(multi_append_required_bytes(0xff00, [0x100]), None);
    }

    #[test]
    fn append_path_element_separator_matrix() {
        let cases = [
            ("a", "bar", "a\\bar"),
            ("/a", "bar", "/a/bar"),
            ("a/", "bar", "a/bar/"),
            ("a", "/b", "a/b"),
            ("a", "bar/", "a/bar/"),
            ("/a/", "bar", "/a/bar/"),
            ("/a", "/b", "/a/b"),
            ("/a", "bar/", "/a/bar/"),
            ("a/", "/b", "a/b/"),
            ("a/", "bar/", "a/bar/"),
            ("a", "/b/", "a/b/"),
            ("/a/", "/b", "/a/b/"),
            ("/a/", "bar/", "/a/bar/"),
            ("/a", "/b/", "/a/b/"),
            ("a/", "/b/", "a/b/"),
            ("/a/", "/b/", "/a/b/"),
        ];
        for (path, element, expected) in cases {
            assert_eq!(append_element(path, element, false), expected);
        }
    }

    #[test]
    fn append_path_element_preserves_separator_style() {
        assert_eq!(append_element("C:\\dir", "leaf", false), "C:\\dir\\leaf");
        assert_eq!(append_element("C:/dir", "leaf", false), "C:/dir/leaf");
        assert_eq!(append_element("/root", "leaf\\", false), "/root\\leaf\\");
        assert_eq!(append_element("/root", "leaf", true), "/root\\leaf");
        assert_eq!(append_element("unchanged", "", false), "unchanged");
    }

    #[test]
    fn privatized_dll_names_match_reactos_cases() {
        let image = u("C:\\Windows\\System32\\app.exe");
        let cases = [
            ("kernel32.dll", "kernel32.dll"),
            ("kernel32", "kernel32.DLL"),
            ("kernel32.dll.dll", "kernel32.dll.dll"),
            ("kernel32.", "kernel32."),
            (".kernel32", ".kernel32.DLL"),
            ("..kernel32", "..kernel32"),
            ("test\\kernel32.dll", "kernel32.dll"),
            ("test.dll/kernel32", "kernel32.DLL"),
            ("//", ".DLL"),
            ("\\", ".DLL"),
            ("", ".DLL"),
        ];
        for (input, expected) in cases {
            let names = compute_privatized_dll_names(&image, &u(input)).unwrap();
            assert_eq!(
                s(&names.real),
                alloc::format!("C:\\Windows\\System32\\{expected}")
            );
            assert_eq!(
                s(&names.local),
                alloc::format!("C:\\Windows\\System32\\app.exe.Local\\{expected}")
            );
        }
    }

    #[test]
    fn privatized_dll_name_limits_match_descriptor_rules() {
        let local_limit_image = alloc::vec![b'a' as u16; 32_761];
        assert!(compute_privatized_dll_names(&local_limit_image, &[]).is_err());

        let real_limit_image = alloc::vec![b'a' as u16; 32_762];
        assert!(compute_privatized_dll_names(&real_limit_image, &[]).is_err());
    }

    #[test]
    fn classify() {
        assert_eq!(
            determine_dos_path_name_type(&u("C:\\Windows")),
            DosPathType::DriveAbsolute
        );
        assert_eq!(
            determine_dos_path_name_type(&u("C:temp")),
            DosPathType::DriveRelative
        );
        assert_eq!(
            determine_dos_path_name_type(&u("\\Device")),
            DosPathType::Rooted
        );
        assert_eq!(
            determine_dos_path_name_type(&u("\\\\srv\\share")),
            DosPathType::UncAbsolute
        );
        assert_eq!(
            determine_dos_path_name_type(&u("\\\\.\\C:")),
            DosPathType::LocalDevice
        );
        assert_eq!(
            determine_dos_path_name_type(&u("\\\\?\\C:\\x")),
            DosPathType::LocalDevice
        );
        assert_eq!(
            determine_dos_path_name_type(&u("\\\\.")),
            DosPathType::RootLocalDevice
        );
        assert_eq!(
            determine_dos_path_name_type(&u("dir\\file")),
            DosPathType::Relative
        );
        assert_eq!(determine_dos_path_name_type(&u("")), DosPathType::Relative);
    }

    #[test]
    fn trims_trailing_path_separators() {
        assert_eq!(length_without_trailing_path_separators(&u("")), 0);
        assert_eq!(length_without_trailing_path_separators(&u("Test")), 4);
        assert_eq!(
            length_without_trailing_path_separators(&u("\\??\\Test\\String\\\\\\")),
            15
        );
        assert_eq!(length_without_trailing_path_separators(&u("\\")), 0);
        assert_eq!(
            length_without_trailing_path_separators(&u("/Test/String/")),
            12
        );
    }

    #[test]
    fn trims_last_full_path_element() {
        assert_eq!(
            length_without_last_full_dos_or_nt_path_element(&u("C:\\foo\\bar")).unwrap(),
            7
        );
        assert_eq!(
            length_without_last_full_dos_or_nt_path_element(&u("C:\\foo\\")).unwrap(),
            3
        );
        assert_eq!(
            length_without_last_full_dos_or_nt_path_element(&u("\\\\server\\share\\dir\\file"))
                .unwrap(),
            19
        );
        assert_eq!(
            length_without_last_full_dos_or_nt_path_element(&u("")).unwrap(),
            0
        );
        assert!(length_without_last_full_dos_or_nt_path_element(&u("relative\\file")).is_err());
        assert!(length_without_last_full_dos_or_nt_path_element(&u("C:relative")).is_err());
    }

    #[test]
    fn nt_path_prefix() {
        assert_eq!(
            s(&dos_path_name_to_nt_path_name(&u("C:\\Windows\\notepad.exe")).unwrap()),
            "\\??\\C:\\Windows\\notepad.exe"
        );
        assert_eq!(
            s(&dos_path_name_to_nt_path_name(&u("\\\\srv\\share\\f")).unwrap()),
            "\\??\\UNC\\srv\\share\\f"
        );
        assert_eq!(
            s(&dos_path_name_to_nt_path_name(&u("\\\\?\\C:\\x")).unwrap()),
            "\\??\\C:\\x"
        );
        // Relative can't be resolved without the CWD → None.
        assert!(dos_path_name_to_nt_path_name(&u("rel\\path")).is_none());
    }

    #[test]
    fn nt_path_rel() {
        // The winlogon → services.exe case: relative name + CWD C:\Windows.
        assert_eq!(
            s(&dos_path_name_to_nt_path_name_rel(&u("services.exe"), &u("C:\\Windows")).unwrap()),
            "\\??\\C:\\Windows\\services.exe"
        );
        // CWD with a trailing separator → no double backslash.
        assert_eq!(
            s(
                &dos_path_name_to_nt_path_name_rel(&u("services.exe"), &u("C:\\Windows\\"))
                    .unwrap()
            ),
            "\\??\\C:\\Windows\\services.exe"
        );
        // Nested relative.
        assert_eq!(
            s(&dos_path_name_to_nt_path_name_rel(&u("sub\\a.exe"), &u("C:\\Windows")).unwrap()),
            "\\??\\C:\\Windows\\sub\\a.exe"
        );
        // Already-absolute → CWD ignored.
        assert_eq!(
            s(&dos_path_name_to_nt_path_name_rel(&u("D:\\x\\y.exe"), &u("C:\\Windows")).unwrap()),
            "\\??\\D:\\x\\y.exe"
        );
        // Rooted (no drive) inherits the CWD drive.
        assert_eq!(
            s(&dos_path_name_to_nt_path_name_rel(&u("\\dir\\f.exe"), &u("C:\\Windows")).unwrap()),
            "\\??\\C:\\dir\\f.exe"
        );
        // A non-absolute CWD can't anchor a relative name.
        assert!(dos_path_name_to_nt_path_name_rel(&u("services.exe"), &u("Windows")).is_none());
        // Drive-relative (per-drive CWD) is unsupported → None.
        assert!(
            dos_path_name_to_nt_path_name_rel(&u("C:services.exe"), &u("C:\\Windows")).is_none()
        );
    }

    #[test]
    fn relative_nt_plan_uses_canonical_current_directory_subspan() {
        let plan = relative_nt_path_plan(&u("foo\\bar"), &u("C:\\Windows\\"), true).unwrap();
        assert_eq!(s(&plan.nt_path), "\\??\\C:\\Windows\\foo\\bar");
        assert_eq!(s(&plan.nt_path[plan.relative_offset.unwrap()..]), "foo\\bar");

        let plan = relative_nt_path_plan(
            &u("sub\\..\\foo"),
            &u("c:\\WINDOWS"),
            true,
        )
        .unwrap();
        assert_eq!(s(&plan.nt_path), "\\??\\c:\\WINDOWS\\foo");
        assert_eq!(s(&plan.nt_path[plan.relative_offset.unwrap()..]), "foo");
    }

    #[test]
    fn relative_nt_plan_rejects_unsafe_handle_relative_cases() {
        let escaped = relative_nt_path_plan(&u("..\\outside"), &u("C:\\Windows"), true).unwrap();
        assert_eq!(escaped.relative_offset, None);
        let no_handle = relative_nt_path_plan(&u("foo"), &u("C:\\Windows"), false).unwrap();
        assert_eq!(no_handle.relative_offset, None);
        for absolute in ["C:\\Windows2\\x", "D:\\x", "\\rooted", "\\\\server\\share\\x"] {
            let plan = relative_nt_path_plan(&u(absolute), &u("C:\\Windows"), true).unwrap();
            assert_eq!(plan.relative_offset, None, "{absolute}");
        }
    }

    #[test]
    fn dos_devices() {
        assert!(is_dos_device_name(&u("CON")));
        assert!(is_dos_device_name(&u("nul.txt")));
        assert!(is_dos_device_name(&u("NUL. ")));
        assert!(is_dos_device_name(&u("C:\\path\\CON:")));
        assert!(is_dos_device_name(&u("C:\\path\\COM1")));
        assert!(is_dos_device_name(&u("LPT3")));
        assert!(is_dos_device_name(&u("\\\\.\\CON")));
        assert!(!is_dos_device_name(&u("COM0")));
        assert!(!is_dos_device_name(&u("README")));
        assert!(!is_dos_device_name(&u("CONSOLE")));
        assert!(!is_dos_device_name(&u("\\\\server\\share\\NUL")));
        assert!(!is_dos_device_name(&u("\\\\.\\NUL")));
        assert!(!is_dos_device_name(&u("//./CON")));
        assert!(!is_dos_device_name(&[0x014e, b'U' as u16, b'L' as u16]));
    }

    #[test]
    fn search_candidates_follow_path_and_extension_rules() {
        let candidates = dos_search_path_candidates(
            0,
            &u("C:\\one;D:\\two\\;;E:\\last"),
            &u("app"),
            Some(&u(".exe")),
        )
        .unwrap();
        assert_eq!(
            candidates.iter().map(|value| s(value)).collect::<Vec<_>>(),
            [
                "C:\\one\\app.exe",
                "D:\\two\\app.exe",
                "app.exe",
                "E:\\last\\app.exe",
            ]
        );
        assert_eq!(
            dos_search_path_candidates(0, &u("C:\\one"), &u("app.dll"), Some(&u(".exe"))).unwrap(),
            [u("C:\\one\\app.dll")]
        );
    }

    #[test]
    fn search_candidates_handle_full_paths_and_flags() {
        assert_eq!(
            dos_search_path_candidates(0, &u("ignored"), &u("C:\\bin\\app"), Some(&u(".exe")))
                .unwrap(),
            [u("C:\\bin\\app"), u("C:\\bin\\app.exe")]
        );
        assert_eq!(
            dos_search_path_candidates(0, &u("ignored"), &u("C:\\bin\\app.dll"), Some(&u(".exe")))
                .unwrap(),
            [u("C:\\bin\\app.dll")]
        );
        assert_eq!(
            dos_search_path_candidates(4, &u("ignored"), &u("C:\\bin\\app.dll"), Some(&u(".exe")))
                .unwrap(),
            [u("C:\\bin\\app.dll"), u("C:\\bin\\app.dll.exe")]
        );
        assert!(
            dos_search_path_candidates(2, &u("C:\\one"), &u("..\\app"), None)
                .unwrap()
                .is_empty()
        );
    }
}
