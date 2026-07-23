//! Environment / current-directory / process-parameters `Rtl*` stragglers (state-coupled).
//!
//! These operate on the process's `RTL_USER_PROCESS_PARAMETERS` + environment block (both live in
//! the PEB — `nt-ntdll-layout`). In the real process they read/write the live PEB; here the pure
//! LOGIC is host-tested over an in-Rust model of the environment block + the process params, with a
//! documented seam where the live PEB pointer is needed (that pointer arrives from the Step-3
//! loader). Covered: `RtlCreateEnvironment`, `RtlDestroyEnvironment`,
//! `RtlQueryEnvironmentVariable_U`, `RtlSetEnvironmentVariable`, `RtlExpandEnvironmentStrings_U`,
//! `RtlGetCurrentDirectory_U`, `RtlSetCurrentDirectory_U`, `RtlGetFullPathName_U`,
//! `RtlNormalizeProcessParams` / `RtlDeNormalizeProcessParams`, `RtlCreateProcessParameters`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

use nt_ntdll_layout::RTL_USER_PROC_PARAMS_NORMALIZED;

/// An environment block: an ordered set of `NAME=VALUE` entries (case-insensitive on the name), the
/// form the Windows environment double-NUL block encodes. Modelled as parsed pairs so the query /
/// set / expand LOGIC is host-testable; the flat double-NUL UTF-16 block is the wire form the loader
/// materializes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Environment {
    /// The `(name, value)` pairs, in insertion order. Names are stored as given but matched
    /// case-insensitively (Windows env-var semantics).
    pub vars: Vec<(String, String)>,
}

impl Environment {
    /// `RtlCreateEnvironment` — a fresh (empty, or cloned-from-parent) environment.
    pub fn new() -> Self {
        Environment { vars: Vec::new() }
    }

    /// Parse a Windows double-NUL-terminated UTF-16 environment block into pairs
    /// (`RtlCreateEnvironmentEx`'s consumer form).
    pub fn from_block(block: &[u16]) -> Self {
        let mut vars = Vec::new();
        let mut start = 0;
        let mut i = 0;
        while i < block.len() {
            if block[i] == 0 {
                if i == start {
                    break; // double NUL — end of block
                }
                let entry: String = char::decode_utf16(block[start..i].iter().copied())
                    .map(|r| r.unwrap_or('\u{FFFD}'))
                    .collect();
                if let Some(eq) = environment_entry_separator(&entry) {
                    vars.push((entry[..eq].into(), entry[eq + 1..].into()));
                }
                start = i + 1;
            }
            i += 1;
        }
        Environment { vars }
    }

    /// Serialize back to a double-NUL UTF-16 block (`NAME=VALUE\0...\0\0`).
    pub fn to_block(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for (k, v) in &self.vars {
            out.extend(k.encode_utf16());
            out.push(b'=' as u16);
            out.extend(v.encode_utf16());
            out.push(0);
        }
        if out.is_empty() {
            out.push(0);
        }
        out.push(0); // terminating double NUL
        out
    }

    /// The number of variables (diagnostic).
    pub fn vars_len(&self) -> usize {
        self.vars.len()
    }

    /// The first variable's name (diagnostic).
    pub fn first_name(&self) -> Option<&str> {
        self.vars.first().map(|(k, _)| k.as_str())
    }

    /// `RtlQueryEnvironmentVariable_U` — case-insensitive lookup.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `RtlSetEnvironmentVariable` — set (or, with `value == None`, delete) a variable
    /// (case-insensitive name match).
    pub fn set(&mut self, name: &str, value: Option<&str>) {
        let _ = self.set_checked(name, value);
    }

    /// Checked `RtlSetEnvironmentVariable` model. ReactOS rejects an empty name and rejects `=`
    /// anywhere except the first character (which is reserved for hidden drive-current-directory
    /// variables such as `=C:`).
    pub fn set_checked(
        &mut self,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), EnvironmentSetError> {
        validate_variable_name(name)?;
        let pos = self
            .vars
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case(name));
        match (pos, value) {
            (Some(i), Some(v)) => self.vars[i].1 = v.into(),
            (Some(i), None) => {
                self.vars.remove(i);
            }
            (None, Some(v)) => {
                let insert_at = self
                    .vars
                    .iter()
                    .position(|(k, _)| compare_variable_names(k, name) == Ordering::Greater)
                    .unwrap_or(self.vars.len());
                self.vars.insert(insert_at, (name.into(), v.into()));
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// `RtlExpandEnvironmentStrings_U` — replace each `%NAME%` with its value (unknown → left as-is,
    /// matching Windows). `%%` is not special in Windows env expansion — only `%NAME%` pairs.
    pub fn expand(&self, input: &str) -> String {
        let mut out = String::new();
        let bytes: Vec<char> = input.chars().collect();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == '%' {
                // Find the closing '%'.
                if let Some(rel) = bytes[i + 1..].iter().position(|&c| c == '%') {
                    let name: String = bytes[i + 1..i + 1 + rel].iter().collect();
                    if let Some(v) = self.query(&name) {
                        out.push_str(v);
                    } else {
                        // Unknown var: Windows leaves the %NAME% literal in place.
                        out.push('%');
                        out.push_str(&name);
                        out.push('%');
                    }
                    i = i + 1 + rel + 1;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        out
    }
}

/// Error returned by [`Environment::set_checked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentSetError {
    InvalidName,
}

/// ReactOS-compatible environment-variable name validation.
pub fn validate_variable_name(name: &str) -> Result<(), EnvironmentSetError> {
    if name.is_empty() || name.chars().skip(1).any(|c| c == '=') {
        return Err(EnvironmentSetError::InvalidName);
    }
    Ok(())
}

fn environment_entry_separator(entry: &str) -> Option<usize> {
    let start = if entry.starts_with('=') { 1 } else { 0 };
    entry[start..].find('=').map(|rel| start + rel)
}

fn compare_variable_names(left: &str, right: &str) -> Ordering {
    let mut l = left.chars().map(fold_env_char);
    let mut r = right.chars().map(fold_env_char);
    loop {
        match (l.next(), r.next()) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => return a.cmp(&b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn fold_env_char(c: char) -> char {
    if c.is_ascii() {
        c.to_ascii_uppercase()
    } else {
        c
    }
}

/// The process's current directory (`RtlGetCurrentDirectory_U` / `RtlSetCurrentDirectory_U`) — a
/// UTF-16 DOS path. Kept as a model; the live copy lives in
/// `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CurrentDirectory {
    /// The current directory as a DOS path (e.g. `C:\Windows\System32`).
    pub path: String,
}

impl CurrentDirectory {
    /// `RtlGetCurrentDirectory_U` — the current directory (always with a trailing backslash, as
    /// Windows returns it).
    pub fn get(&self) -> String {
        if self.path.ends_with('\\') {
            self.path.clone()
        } else {
            let mut p = self.path.clone();
            p.push('\\');
            p
        }
    }

    /// `RtlSetCurrentDirectory_U` — set the current directory (strips a trailing backslash for the
    /// stored canonical form; `get` re-adds it).
    pub fn set(&mut self, path: &str) {
        self.path = path.trim_end_matches('\\').into();
    }

    /// `RtlGetFullPathName_U` (the pure resolution core): resolve `name` against this current
    /// directory. Absolute paths (`X:\...` or `\\...`) pass through; a rooted-but-driveless path
    /// (`\foo`) takes the cwd's drive; a relative path is appended to the cwd. `.`/`..` components
    /// are collapsed.
    pub fn full_path(&self, name: &str) -> String {
        let combined = if is_absolute(name) {
            name.into()
        } else if name.starts_with('\\') {
            // Rooted, driveless: take the cwd drive prefix (e.g. "C:").
            let drive = self.path.get(..2).unwrap_or("C:");
            let mut s = String::from(drive);
            s.push_str(name);
            s
        } else {
            let mut base = self.path.trim_end_matches('\\').to_string();
            base.push('\\');
            base.push_str(name);
            base
        };
        canonicalize(&combined)
    }
}

/// `RtlGetFullPathName_U` over UTF-16 units (the on-target form): resolve `name` against `cwd`
/// (a fully-qualified DOS directory, e.g. `C:\Windows`). Absolute paths pass through; a rooted
/// driveless path (`\foo`) takes the cwd drive; a relative path is appended to the cwd; `.`/`..`
/// collapse. Forward slashes are normalised to backslashes. Returns the full DOS path (no trailing
/// NUL). This is what `RtlGetFullPathName_UstrEx` writes to its StaticString/DynamicString out-param.
pub fn full_path_units(name: &[u16], cwd: &[u16]) -> Vec<u16> {
    // Convert both to lossy Strings for the pure logic (paths are ASCII-ish DOS paths; any non-BMP is
    // preserved via char round-trip). Using String keeps ONE canonicalization implementation.
    let mut name_s = String::from_utf16_lossy(name);
    name_s = name_s.replace('/', "\\");
    let cwd_s = String::from_utf16_lossy(cwd);
    let mut cd = CurrentDirectory::default();
    if !cwd_s.is_empty() {
        cd.set(&cwd_s);
    }
    let name_bytes = name_s.as_bytes();
    let same_drive_relative = name_bytes.len() >= 2
        && name_bytes[1] == b':'
        && name_bytes.get(2) != Some(&b'\\')
        && cwd_s.as_bytes().get(1) == Some(&b':')
        && name_bytes[0].eq_ignore_ascii_case(&cwd_s.as_bytes()[0]);
    let full = if same_drive_relative {
        if name_bytes.len() == 2 {
            canonicalize(&cwd_s)
        } else {
            let mut combined = cwd_s.trim_end_matches('\\').to_string();
            combined.push('\\');
            combined.push_str(&name_s[2..]);
            canonicalize(&combined)
        }
    } else {
        cd.full_path(&name_s)
    };
    full.encode_utf16()
        .map(|c| if c == b'/' as u16 { b'\\' as u16 } else { c })
        .collect()
}

/// Whether a DOS path is absolute (`X:\...` drive-absolute or `\\...` UNC).
pub fn is_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) // X:\
        || p.starts_with("\\\\") // UNC
}

/// Collapse `.` and `..` components in a backslash path (the `RtlGetFullPathName_U` canonicalization).
pub fn canonicalize(path: &str) -> String {
    // Preserve a leading drive+root, local-device, or UNC prefix. Local-device paths need their
    // `\\.\` / `\\?\` discriminator intact: treating `\\.\pipe` as ordinary UNC collapses the
    // `.` component and changes the native path from `\??\pipe` to `\??\UNC\pipe`.
    let (prefix, rest) = if path.len() >= 3 && path.as_bytes()[1] == b':' {
        (&path[..3], &path[3..])
    } else if path.starts_with("\\\\.\\") || path.starts_with("\\\\?\\") {
        (&path[..4], &path[4..])
    } else if let Some(r) = path.strip_prefix("\\\\") {
        // UNC: keep the "\\" prefix.
        return {
            let mut out = String::from("\\\\");
            out.push_str(&collapse(r));
            out
        };
    } else {
        ("", path)
    };
    let mut out = String::from(prefix);
    out.push_str(&collapse(rest));
    out
}

fn collapse(rest: &str) -> String {
    let mut comps: Vec<&str> = Vec::new();
    for comp in rest.split('\\') {
        match comp {
            "" | "." => {}
            ".." => {
                comps.pop();
            }
            c => comps.push(c),
        }
    }
    comps.join("\\")
}

/// `RtlNormalizeProcessParams` — set the `NORMALIZED` flag (in the real call it also rebases the
/// embedded `UNICODE_STRING` buffers from offsets to absolute pointers). Returns the new `Flags`.
pub fn normalize_flags(flags: u32) -> u32 {
    flags | RTL_USER_PROC_PARAMS_NORMALIZED
}

/// `RtlDeNormalizeProcessParams` — clear the `NORMALIZED` flag (rebase pointers back to offsets).
pub fn denormalize_flags(flags: u32) -> u32 {
    flags & !RTL_USER_PROC_PARAMS_NORMALIZED
}

/// Whether process params are normalized.
pub fn is_normalized(flags: u32) -> bool {
    flags & RTL_USER_PROC_PARAMS_NORMALIZED != 0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    #[test]
    fn env_set_query_delete() {
        let mut e = Environment::new();
        e.set("SystemRoot", Some("C:\\Windows"));
        e.set("Path", Some("C:\\Windows\\System32"));
        assert_eq!(e.query("systemroot"), Some("C:\\Windows")); // case-insensitive
        e.set("Path", Some("C:\\Windows")); // overwrite
        assert_eq!(e.query("Path"), Some("C:\\Windows"));
        e.set("Path", None); // delete
        assert_eq!(e.query("Path"), None);
    }

    #[test]
    fn env_set_rejects_invalid_names_and_sorts_insertions() {
        let mut e = Environment::new();
        assert_eq!(
            e.set_checked("", Some("bad")),
            Err(EnvironmentSetError::InvalidName)
        );
        assert_eq!(
            e.set_checked("A=B", Some("bad")),
            Err(EnvironmentSetError::InvalidName)
        );
        e.set_checked("Path", Some("C:\\bin")).unwrap();
        e.set_checked("ComSpec", Some("cmd.exe")).unwrap();
        e.set_checked("windir", Some("C:\\Windows")).unwrap();
        assert_eq!(
            e.vars.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            vec!["ComSpec", "Path", "windir"]
        );
    }

    #[test]
    fn env_block_roundtrip() {
        let mut e = Environment::new();
        e.set("A", Some("1"));
        e.set("B", Some("22"));
        let block = e.to_block();
        // Terminating double-NUL present.
        assert_eq!(block.last(), Some(&0));
        let e2 = Environment::from_block(&block);
        assert_eq!(e2.query("A"), Some("1"));
        assert_eq!(e2.query("B"), Some("22"));
    }

    #[test]
    fn empty_env_block_is_probeable_double_nul() {
        let e = Environment::new();
        assert_eq!(e.to_block(), [0, 0]);
    }

    #[test]
    fn env_block_parses_hidden_drive_current_directory_entries() {
        let mut block: Vec<u16> = "=C:=C:\\Windows\0Path=C:\\bin\0\0".encode_utf16().collect();
        let e = Environment::from_block(&block);
        assert_eq!(e.query("=C:"), Some("C:\\Windows"));
        assert_eq!(e.query("Path"), Some("C:\\bin"));

        let mut out = Environment::new();
        out.set_checked("Path", Some("C:\\bin")).unwrap();
        out.set_checked("=C:", Some("C:\\Windows")).unwrap();
        block = out.to_block();
        let e2 = Environment::from_block(&block);
        assert_eq!(e2.query("=C:"), Some("C:\\Windows"));
    }

    #[test]
    fn from_block_keeps_last_var_when_slice_includes_terminating_nul() {
        // The on-target `read_env_block` measures to the double-NUL and must INCLUDE the first NUL of
        // the double-NUL so `from_block` emits the LAST variable (it only emits on a NUL). This test
        // pins that: a block `SystemRoot=C:\Windows\0Path=C:\WinSys\0\0` sliced to include the first
        // terminating NUL (index of the second-to-last unit) must yield BOTH vars.
        let mut e = Environment::new();
        e.set("SystemRoot", Some("C:\\Windows"));
        e.set("Path", Some("C:\\WinSys"));
        let block = e.to_block(); // ...Path=C:\WinSys\0\0
                                  // Emulate read_env_block's slice: up to AND INCLUDING the first NUL of the double-NUL
                                  // (block.len()-1 drops only the final lone NUL, keeping the last var's own NUL).
        let sliced = &block[..block.len() - 1];
        let e2 = Environment::from_block(sliced);
        assert_eq!(e2.vars_len(), 2, "last variable must not be dropped");
        assert_eq!(e2.query("SystemRoot"), Some("C:\\Windows"));
        assert_eq!(e2.query("Path"), Some("C:\\WinSys"));
        // And a buggy slice that drops the last var's NUL too drops Path.
        let over_trimmed: Vec<u16> = "SystemRoot=C:\\Windows\0Path=C:\\WinSys"
            .encode_utf16()
            .collect();
        let e3 = Environment::from_block(&over_trimmed);
        assert!(e3.query("Path").is_none());
    }

    #[test]
    fn expand_strings() {
        let mut e = Environment::new();
        e.set("SystemRoot", Some("C:\\Windows"));
        assert_eq!(e.expand("%SystemRoot%\\System32"), "C:\\Windows\\System32");
        // Unknown var left literal.
        assert_eq!(e.expand("%Nope%\\x"), "%Nope%\\x");
        assert_eq!(e.expand("no vars"), "no vars");
    }

    #[test]
    fn current_directory() {
        let mut cd = CurrentDirectory::default();
        cd.set("C:\\Windows\\System32");
        assert_eq!(cd.get(), "C:\\Windows\\System32\\");
    }

    #[test]
    fn full_path_resolution() {
        let mut cd = CurrentDirectory::default();
        cd.set("C:\\Windows\\System32");
        // Relative.
        assert_eq!(
            cd.full_path("ntdll.dll"),
            "C:\\Windows\\System32\\ntdll.dll"
        );
        // Absolute passes through (canonicalized).
        assert_eq!(cd.full_path("D:\\a\\b"), "D:\\a\\b");
        // Rooted driveless takes the cwd drive.
        assert_eq!(cd.full_path("\\temp\\x"), "C:\\temp\\x");
        // .. collapses.
        assert_eq!(cd.full_path("..\\drivers"), "C:\\Windows\\drivers");
    }

    #[test]
    fn full_path_units_resolution() {
        let u = |s: &str| -> Vec<u16> { s.encode_utf16().collect() };
        let s = |v: &[u16]| -> String { String::from_utf16(v).unwrap() };
        // winlogon → services.exe: relative name resolved against C:\Windows.
        assert_eq!(
            s(&full_path_units(&u("services.exe"), &u("C:\\Windows"))),
            "C:\\Windows\\services.exe"
        );
        // Absolute passes through.
        assert_eq!(
            s(&full_path_units(&u("D:\\x\\y.exe"), &u("C:\\Windows"))),
            "D:\\x\\y.exe"
        );
        // Rooted driveless takes the cwd drive.
        assert_eq!(
            s(&full_path_units(&u("\\dir\\f"), &u("C:\\Windows"))),
            "C:\\dir\\f"
        );
        // Forward slashes normalise to backslashes.
        assert_eq!(
            s(&full_path_units(&u("sub/f.exe"), &u("C:\\Windows"))),
            "C:\\Windows\\sub\\f.exe"
        );
        assert_eq!(
            s(&full_path_units(&u("sub/../dir"), &u("C:\\Windows"))),
            "C:\\Windows\\dir"
        );
        assert_eq!(
            s(&full_path_units(&u("C:"), &u("C:\\Windows"))),
            "C:\\Windows"
        );
        assert_eq!(
            s(&full_path_units(&u("c:system32"), &u("C:\\Windows"))),
            "C:\\Windows\\system32"
        );
        assert_eq!(s(&full_path_units(&u("C:\\x"), &u("C:\\Windows"))), "C:\\x");
        assert_eq!(s(&full_path_units(&u("C:\\"), &u("C:\\Windows"))), "C:\\");
        assert_eq!(
            s(&full_path_units(
                &u("\\\\.\\pipe\\lsarpc"),
                &u("C:\\Windows")
            )),
            "\\\\.\\pipe\\lsarpc"
        );
    }

    #[test]
    fn canonicalize_paths() {
        assert_eq!(canonicalize("C:\\a\\.\\b\\..\\c"), "C:\\a\\c");
        assert_eq!(canonicalize("C:\\a\\b\\..\\.."), "C:\\");
        assert_eq!(
            canonicalize("\\\\server\\share\\a\\..\\b"),
            "\\\\server\\share\\b"
        );
        assert_eq!(
            canonicalize("\\\\.\\pipe\\.\\rpc\\..\\lsarpc"),
            "\\\\.\\pipe\\lsarpc"
        );
        assert_eq!(canonicalize("\\\\?\\C:\\a\\..\\b"), "\\\\?\\C:\\b");
    }

    #[test]
    fn normalize_flags_roundtrip() {
        let f = normalize_flags(0);
        assert!(is_normalized(f));
        assert!(!is_normalized(denormalize_flags(f)));
    }
}
