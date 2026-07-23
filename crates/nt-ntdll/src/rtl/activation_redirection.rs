//! Pure filename and output planning for `RtlDosApplyFileIsolationRedirection_Ustr`.

use alloc::vec::Vec;

use crate::NtStatus;

use super::{
    activation_section::{
        DllRedirectionData, DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME,
        DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT,
        DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL,
    },
    strings,
};

pub const RTL_DOS_APPLY_FILE_REDIRECTION_USTR_FLAG_RESPECT_DOT_LOCAL: u32 = 0x01;
pub const RTL_DOS_APPLY_FILE_REDIRECTION_USTR_OUTFLAG_DOT_LOCAL_REDIRECT: u32 = 0x01;
pub const RTL_DOS_APPLY_FILE_REDIRECTION_USTR_OUTFLAG_ACTCTX_REDIRECT: u32 = 0x02;

pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
pub const STATUS_NAME_TOO_LONG: NtStatus = 0xC000_0106;
pub const STATUS_SXS_KEY_NOT_FOUND: NtStatus = 0xC015_0008;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedIsolationName {
    pub lookup_name: Vec<u16>,
    pub path_is_relative: bool,
    pub actctx_lookup_allowed: bool,
}

pub fn prepare_isolation_name(
    flags: u32,
    original: &[u16],
    extension: Option<&[u16]>,
) -> Result<PreparedIsolationName, NtStatus> {
    if flags & !RTL_DOS_APPLY_FILE_REDIRECTION_USTR_FLAG_RESPECT_DOT_LOCAL != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if original.is_empty() {
        return Err(STATUS_SXS_KEY_NOT_FOUND);
    }
    let leaf_start = original
        .iter()
        .rposition(|unit| is_separator(*unit))
        .map_or(0, |position| position + 1);
    let leaf = &original[leaf_start..];
    let has_extension = leaf.iter().any(|unit| *unit == b'.' as u16);
    let extension = (!has_extension)
        .then_some(extension)
        .flatten()
        .filter(|extension| !extension.is_empty());
    if let Some(extension) = extension {
        let required_units = original
            .len()
            .checked_add(extension.len())
            .and_then(|length| length.checked_add(1))
            .ok_or(STATUS_NAME_TOO_LONG)?;
        if required_units > (u16::MAX as usize / 2) {
            return Err(STATUS_NAME_TOO_LONG);
        }
    }
    let capacity = leaf
        .len()
        .checked_add(extension.map_or(0, |extension| extension.len()))
        .ok_or(STATUS_NO_MEMORY)?;
    let mut lookup_name = Vec::new();
    lookup_name
        .try_reserve_exact(capacity)
        .map_err(|_| STATUS_NO_MEMORY)?;
    lookup_name.extend_from_slice(leaf);
    if let Some(extension) = extension {
        lookup_name.extend_from_slice(extension);
    }
    Ok(PreparedIsolationName {
        lookup_name,
        path_is_relative: is_relative_dos_path(original),
        actctx_lookup_allowed: has_extension || extension.is_some(),
    })
}

pub fn absolute_path_is_system32(original: &[u16], system_root: &[u16]) -> bool {
    let Some(separator) = original.iter().rposition(|unit| is_separator(*unit)) else {
        return false;
    };
    let parent = trim_trailing_separators(&original[..separator]);
    let mut expected = Vec::new();
    if expected
        .try_reserve_exact(system_root.len() + "\\System32".len())
        .is_err()
    {
        return false;
    }
    expected.extend_from_slice(trim_trailing_separators(system_root));
    expected.extend("\\System32".bytes().map(u16::from));
    unicode_eq_ci(parent, &expected)
}

pub fn redirection_applies_to_path(flags: u32, path_is_relative: bool) -> bool {
    path_is_relative || flags & DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL != 0
}

pub fn compose_redirected_path(
    redirection: &DllRedirectionData,
    source: &[u16],
    assembly_directory: &[u16],
    system_root: &[u16],
    lookup_name: &[u16],
) -> Result<Vec<u16>, NtStatus> {
    let mut output = if redirection.flags & DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT != 0 {
        redirection_root(source, assembly_directory, system_root)?
    } else {
        Vec::new()
    };
    for segment in &redirection.path_segments {
        append_exact(&mut output, segment)?;
    }
    if redirection.flags & DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME == 0 {
        append_exact(&mut output, lookup_name)?;
    }
    Ok(output)
}

fn redirection_root(
    source: &[u16],
    assembly_directory: &[u16],
    system_root: &[u16],
) -> Result<Vec<u16>, NtStatus> {
    let source_leaf = source
        .iter()
        .rposition(|unit| is_separator(*unit))
        .map_or(source, |position| &source[position + 1..]);
    let mut global_leaf = Vec::new();
    global_leaf
        .try_reserve_exact(assembly_directory.len() + ".manifest".len())
        .map_err(|_| STATUS_NO_MEMORY)?;
    global_leaf.extend_from_slice(assembly_directory);
    global_leaf.extend(".manifest".bytes().map(u16::from));
    if !assembly_directory.is_empty() && unicode_eq_ci(source_leaf, &global_leaf) {
        let mut root = Vec::new();
        root.try_reserve_exact(system_root.len() + "\\winsxs\\".len() + assembly_directory.len())
            .map_err(|_| STATUS_NO_MEMORY)?;
        root.extend_from_slice(trim_trailing_separators(system_root));
        root.extend("\\winsxs\\".bytes().map(u16::from));
        root.extend_from_slice(assembly_directory);
        root.push(b'\\' as u16);
        Ok(root)
    } else {
        let parent_end = source
            .iter()
            .rposition(|unit| is_separator(*unit))
            .map_or(0, |position| position + 1);
        let mut root = Vec::new();
        root.try_reserve_exact(parent_end)
            .map_err(|_| STATUS_NO_MEMORY)?;
        root.extend_from_slice(&source[..parent_end]);
        Ok(root)
    }
}

fn append_exact(output: &mut Vec<u16>, component: &[u16]) -> Result<(), NtStatus> {
    output
        .try_reserve(component.len())
        .map_err(|_| STATUS_NO_MEMORY)?;
    output.extend_from_slice(component);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputSelection {
    Static,
    Dynamic,
    ExistenceOnly,
}

pub fn select_output(
    path_units: usize,
    static_capacity_bytes: Option<usize>,
    dynamic_allowed: bool,
    file_part_requested: bool,
) -> Result<(OutputSelection, usize), NtStatus> {
    let required_bytes = path_units
        .checked_add(1)
        .and_then(|units| units.checked_mul(2))
        .ok_or(STATUS_NO_MEMORY)?;
    if static_capacity_bytes.is_some_and(|capacity| capacity >= required_bytes) {
        Ok((OutputSelection::Static, required_bytes))
    } else if dynamic_allowed {
        Ok((OutputSelection::Dynamic, required_bytes))
    } else if static_capacity_bytes.is_none() && !file_part_requested {
        Ok((OutputSelection::ExistenceOnly, required_bytes))
    } else {
        Err(STATUS_BUFFER_TOO_SMALL)
    }
}

pub fn file_part_prefix_cch(path: &[u16]) -> usize {
    path.iter()
        .rposition(|unit| is_separator(*unit))
        .map_or(0, |position| position + 1)
}

fn is_relative_dos_path(path: &[u16]) -> bool {
    !is_absolute_dos_path(path)
}

fn is_absolute_dos_path(path: &[u16]) -> bool {
    path.first().copied().is_some_and(is_separator) || (path.len() >= 2 && path[1] == b':' as u16)
}

fn trim_trailing_separators(mut value: &[u16]) -> &[u16] {
    while value.last().copied().is_some_and(is_separator) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_separator(unit: u16) -> bool {
    unit == b'\\' as u16 || unit == b'/' as u16
}

fn unicode_eq_ci(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| strings::upcase_char(*left) == strings::upcase_char(*right))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn prepares_counted_leaf_and_extension_without_parent_dot_confusion() {
        let prepared =
            prepare_isolation_name(0, &wide("dir.with.dot\\library"), Some(&wide(".dll"))).unwrap();
        assert_eq!(prepared.lookup_name, wide("library.dll"));
        assert!(prepared.path_is_relative);
        assert!(prepared.actctx_lookup_allowed);
        let prepared =
            prepare_isolation_name(0, &wide("C:\\dir\\library.ocx"), Some(&wide(".dll"))).unwrap();
        assert_eq!(prepared.lookup_name, wide("library.ocx"));
        assert!(!prepared.path_is_relative);
        assert!(prepared.actctx_lookup_allowed);
        let prepared = prepare_isolation_name(0, &wide("library"), None).unwrap();
        assert_eq!(prepared.lookup_name, wide("library"));
        assert!(!prepared.actctx_lookup_allowed);
        assert_eq!(
            prepare_isolation_name(0, &vec![b'x' as u16; 32_766], Some(&wide(".dll"))),
            Err(STATUS_NAME_TOO_LONG)
        );
        assert_eq!(
            prepare_isolation_name(2, &wide("x.dll"), None),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn recognizes_only_system32_absolute_inputs_for_actctx_lookup() {
        assert!(absolute_path_is_system32(
            &wide("C:\\ReactOS\\System32\\comctl32.dll"),
            &wide("c:\\reactos")
        ));
        assert!(!absolute_path_is_system32(
            &wide("C:\\comctl32.dll"),
            &wide("C:\\ReactOS")
        ));
        assert!(redirection_applies_to_path(0, true));
        assert!(!redirection_applies_to_path(0, false));
        assert!(redirection_applies_to_path(
            DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL,
            false
        ));
    }

    #[test]
    fn composes_local_global_and_load_from_paths() {
        let omitted = DllRedirectionData {
            flags: DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT,
            path_segments: Vec::new(),
        };
        assert_eq!(
            compose_redirected_path(
                &omitted,
                &wide("C:\\app\\sample.manifest"),
                &[],
                &wide("C:\\ReactOS"),
                &wide("test.dll"),
            )
            .unwrap(),
            wide("C:\\app\\test.dll")
        );
        assert_eq!(
            compose_redirected_path(
                &omitted,
                &wide("C:\\ReactOS\\WinSxS\\x86_test.manifest"),
                &wide("x86_test"),
                &wide("C:\\ReactOS"),
                &wide("test.dll"),
            )
            .unwrap(),
            wide("C:\\ReactOS\\winsxs\\x86_test\\test.dll")
        );

        let complete = DllRedirectionData {
            flags: DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME,
            path_segments: vec![wide("bin\\renamed.dll")],
        };
        assert_eq!(
            compose_redirected_path(
                &complete,
                &wide("C:\\app\\sample.manifest"),
                &[],
                &wide("C:\\ReactOS"),
                &wide("test.dll"),
            )
            .unwrap(),
            wide("bin\\renamed.dll")
        );
        let directory = DllRedirectionData {
            flags: 0,
            path_segments: vec![wide("bin\\")],
        };
        assert_eq!(
            compose_redirected_path(
                &directory,
                &wide("C:\\app\\sample.manifest"),
                &[],
                &wide("C:\\ReactOS"),
                &wide("test.dll"),
            )
            .unwrap(),
            wide("bin\\test.dll")
        );
        let segmented = DllRedirectionData {
            flags: DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME,
            path_segments: vec![wide("%ROOT%\\"), wide("renamed.dll")],
        };
        assert_eq!(
            compose_redirected_path(
                &segmented,
                &wide("C:\\app\\sample.manifest"),
                &[],
                &wide("C:\\ReactOS"),
                &wide("test.dll"),
            )
            .unwrap(),
            wide("%ROOT%\\renamed.dll")
        );
    }

    #[test]
    fn output_selection_accepts_exact_static_capacity() {
        assert_eq!(
            select_output(4, Some(10), false, false),
            Ok((OutputSelection::Static, 10))
        );
        assert_eq!(
            select_output(4, Some(8), true, false),
            Ok((OutputSelection::Dynamic, 10))
        );
        assert_eq!(
            select_output(4, None, false, false),
            Ok((OutputSelection::ExistenceOnly, 10))
        );
        assert_eq!(
            select_output(4, None, false, true),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(file_part_prefix_cch(&wide("C:\\app\\x.dll")), 7);
    }

    #[test]
    fn decodes_generated_redirection_data() {
        let redirects = vec![
            super::super::activation::DllRedirect {
                name: wide("plain.dll"),
                load_from: None,
            },
            super::super::activation::DllRedirect {
                name: wide("mapped.dll"),
                load_from: Some(wide("bin\\mapped.dll")),
            },
        ];
        let section =
            super::super::activation_section::build_dll_redirection_section(&redirects).unwrap();
        let plain =
            super::super::activation_section::find_dll_redirection(&section, &wide("plain.dll"))
                .unwrap()
                .unwrap();
        assert_eq!(
            super::super::activation_section::decode_dll_redirection(&section, plain).unwrap(),
            DllRedirectionData {
                flags: DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT,
                path_segments: Vec::new(),
            }
        );
        let mapped =
            super::super::activation_section::find_dll_redirection(&section, &wide("mapped.dll"))
                .unwrap()
                .unwrap();
        assert_eq!(
            super::super::activation_section::decode_dll_redirection(&section, mapped).unwrap(),
            DllRedirectionData {
                flags: DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME,
                path_segments: vec![wide("bin\\mapped.dll")],
            }
        );

        let empty_section = super::super::activation_section::build_dll_redirection_section(&[
            super::super::activation::DllRedirect {
                name: wide("empty.dll"),
                load_from: Some(Vec::new()),
            },
        ])
        .unwrap();
        let empty_match = super::super::activation_section::find_dll_redirection(
            &empty_section,
            &wide("empty.dll"),
        )
        .unwrap()
        .unwrap();
        let empty =
            super::super::activation_section::decode_dll_redirection(&empty_section, empty_match)
                .unwrap();
        assert_eq!(
            empty,
            DllRedirectionData {
                flags: 0,
                path_segments: vec![Vec::new()],
            }
        );
        assert_eq!(
            compose_redirected_path(
                &empty,
                &wide("C:\\app\\sample.manifest"),
                &[],
                &wide("C:\\ReactOS"),
                &wide("empty.dll"),
            )
            .unwrap(),
            wide("empty.dll")
        );
    }
}
