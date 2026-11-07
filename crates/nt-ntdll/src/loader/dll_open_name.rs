//! Name candidates for a DLL file open. The first candidate always preserves the caller's name.

use super::file_map_failure::FileMapFailureStage;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;

fn leaf(name: &[u8]) -> &[u8] {
    let start = name
        .iter()
        .rposition(|byte| matches!(byte, b'\\' | b'/'))
        .map_or(0, |index| index + 1);
    &name[start..]
}

fn has_extension(name: &[u8]) -> bool {
    leaf(name).contains(&b'.')
}

fn explicit_image_extension(name: &[u8]) -> bool {
    let leaf = leaf(name);
    [b"dll".as_slice(), b"drv", b"ocx", b"exe", b"cpl", b"sys", b"scr", b"mui"]
        .iter()
        .any(|suffix| {
            leaf.len() > suffix.len()
                && leaf[leaf.len() - suffix.len() - 1] == b'.'
                && leaf[leaf.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        })
}

/// A dotted module stem can name a `.dll` file. Probe the exact name first and use the appended
/// form only after an open returned a definitive name miss. Explicit PE file extensions and paths
/// retain their requested spelling even when absent.
pub fn retry_with_dll_extension(name: &[u8], stage: FileMapFailureStage, status: u32) -> bool {
    matches!(stage, FileMapFailureStage::Open)
        && status == STATUS_OBJECT_NAME_NOT_FOUND
        && !name.is_empty()
        && !name.contains(&b'\\')
        && !name.contains(&b'/')
        && !name.contains(&b':')
        && has_extension(name)
        && !name.ends_with(b".")
        && !explicit_image_extension(name)
}

/// Build the exact NT path used by `NtOpenFile`. `dll_fallback` is valid only after
/// [`retry_with_dll_extension`] accepted the preceding failed open.
pub fn build_candidate(name: &[u8], dll_fallback: bool, output: &mut [u16]) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    let prefix: &[u8] = if name.first() == Some(&b'\\') {
        b""
    } else if name.get(1) == Some(&b':') {
        b"\\??\\"
    } else {
        b"\\SystemRoot\\System32\\"
    };
    let append_dll = dll_fallback || !has_extension(name);
    let required = prefix
        .len()
        .checked_add(name.len())?
        .checked_add(if append_dll { 4 } else { 0 })?;
    if required > output.len() {
        return None;
    }
    let mut written = 0;
    for &byte in prefix.iter().chain(name) {
        output[written] = byte as u16;
        written += 1;
    }
    if append_dll {
        for &byte in b".dll" {
            output[written] = byte as u16;
            written += 1;
        }
    }
    Some(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn decoded(candidate: &[u16]) -> String {
        String::from_utf16(candidate).unwrap()
    }

    #[test]
    fn dotted_module_stem_retries_with_dll_only_after_name_miss() {
        let mut path = [0u16; 180];
        let first = build_candidate(b"windows.storage", false, &mut path).unwrap();
        assert_eq!(decoded(&path[..first]), r"\SystemRoot\System32\windows.storage");
        assert!(retry_with_dll_extension(b"windows.storage", FileMapFailureStage::Open, 0xc000_0034));
        let second = build_candidate(b"windows.storage", true, &mut path).unwrap();
        assert_eq!(decoded(&path[..second]), r"\SystemRoot\System32\windows.storage.dll");
        for status in [0, 0xc000_003a, 0xc000_0022, 0xc000_007b] {
            assert!(!retry_with_dll_extension(b"windows.storage", FileMapFailureStage::Open, status));
        }
        for stage in [FileMapFailureStage::CreateSection, FileMapFailureStage::MapView] {
            assert!(!retry_with_dll_extension(b"windows.storage", stage, 0xc000_0034));
        }
    }

    #[test]
    fn explicit_extensions_and_paths_retain_exact_names() {
        let mut path = [0u16; 180];
        for (name, expected) in [
            (&b"syssetup.dll"[..], r"\SystemRoot\System32\syssetup.dll"),
            (&b"winspool.drv"[..], r"\SystemRoot\System32\winspool.drv"),
            (&b"control.ocx"[..], r"\SystemRoot\System32\control.ocx"),
            (&br"c:\windows\system32\custom.dll"[..], r"\??\c:\windows\system32\custom.dll"),
        ] {
            let len = build_candidate(name, false, &mut path).unwrap();
            assert_eq!(decoded(&path[..len]), expected);
            assert!(!retry_with_dll_extension(name, FileMapFailureStage::Open, 0xc000_0034));
        }
    }

    #[test]
    fn extensionless_name_gets_default_extension_on_first_open() {
        let mut path = [0u16; 180];
        let len = build_candidate(b"kernel32", false, &mut path).unwrap();
        assert_eq!(decoded(&path[..len]), r"\SystemRoot\System32\kernel32.dll");
        assert!(!retry_with_dll_extension(b"kernel32", FileMapFailureStage::Open, 0xc000_0034));
    }
}
