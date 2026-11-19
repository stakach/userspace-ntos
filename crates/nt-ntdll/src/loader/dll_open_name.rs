//! Name candidates for a DLL file open. The first candidate always preserves the caller's name.

use super::file_map_failure::FileMapFailureStage;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xc000_003a;

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

/// `name` is relative: neither an NT path nor a DOS drive path.
fn is_relative(name: &[u8]) -> bool {
    name.first() != Some(&b'\\') && name.get(1) != Some(&b':')
}

/// The default DLL search directories a relative name is tried in, in the standard order
/// (System32, the 16-bit System directory, then the Windows directory). The application
/// directory, current directory and PATH are not part of this loader's search.
const SEARCH_DIRECTORIES: [&[u8]; 3] =
    [b"\\SystemRoot\\System32\\", b"\\SystemRoot\\System\\", b"\\SystemRoot\\"];

/// One file name to try for a requested DLL name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Index into the search directories; ignored for an absolute name.
    directory: usize,
    /// Try the name with `.dll` appended.
    dll_fallback: bool,
}

/// Every candidate for `name`, in the order the loader tries them. The first preserves the
/// caller's spelling (with `.dll` added only when the leaf has no extension). A dotted module
/// stem is retried as `<stem>.dll` in the same directory, and a relative name moves to the next
/// search directory, each only after a definitive miss ([`is_definitive_miss`]).
pub fn candidates(name: &[u8]) -> impl Iterator<Item = Candidate> {
    let directories = if is_relative(name) { SEARCH_DIRECTORIES.len() } else { 1 };
    let dll_retry = !name.is_empty()
        && !name.contains(&b'\\')
        && !name.contains(&b'/')
        && !name.contains(&b':')
        && has_extension(name)
        && !name.ends_with(b".")
        && !explicit_image_extension(name);
    (0..directories).flat_map(move |directory| {
        [false, true]
            .into_iter()
            .filter(move |dll_fallback| !dll_fallback || dll_retry)
            .map(move |dll_fallback| Candidate { directory, dll_fallback })
    })
}

/// Only an open that proved the file or a directory on its path absent may move to the next
/// candidate; any other failure is the answer for this name.
pub fn is_definitive_miss(stage: FileMapFailureStage, status: u32) -> bool {
    matches!(stage, FileMapFailureStage::Open)
        && matches!(status, STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND)
}

/// Build the exact NT path used by `NtOpenFile` for one of [`candidates`]`(name)`.
pub fn build_candidate(name: &[u8], candidate: Candidate, output: &mut [u16]) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    let prefix: &[u8] = if name.first() == Some(&b'\\') {
        b""
    } else if name.get(1) == Some(&b':') {
        b"\\??\\"
    } else {
        SEARCH_DIRECTORIES.get(candidate.directory)?
    };
    let append_dll = candidate.dll_fallback || !has_extension(name);
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
    use alloc::vec::Vec;

    fn paths(name: &[u8]) -> Vec<String> {
        candidates(name)
            .map(|candidate| {
                let mut path = [0u16; 180];
                let len = build_candidate(name, candidate, &mut path).unwrap();
                String::from_utf16(&path[..len]).unwrap()
            })
            .collect()
    }

    #[test]
    fn dotted_module_stem_retries_with_dll_in_each_directory() {
        assert_eq!(paths(b"windows.storage"), [
            r"\SystemRoot\System32\windows.storage",
            r"\SystemRoot\System32\windows.storage.dll",
            r"\SystemRoot\System\windows.storage",
            r"\SystemRoot\System\windows.storage.dll",
            r"\SystemRoot\windows.storage",
            r"\SystemRoot\windows.storage.dll",
        ]);
    }

    #[test]
    fn a_relative_path_is_found_under_the_windows_directory() {
        // mpr loads a network provider by its registered ProviderPath, `System32\nfs41_np.dll`.
        let found = paths(br"system32\nfs41_np.dll");
        assert_eq!(found.last().map(String::as_str), Some(r"\SystemRoot\system32\nfs41_np.dll"));
        assert_eq!(found.len(), 3, "a path keeps its spelling: no .dll retry");
    }

    #[test]
    fn explicit_extensions_and_absolute_paths_retain_exact_names() {
        assert_eq!(paths(b"winspool.drv")[0], r"\SystemRoot\System32\winspool.drv");
        assert!(paths(b"winspool.drv").iter().all(|path| path.ends_with("winspool.drv")));
        assert_eq!(paths(br"c:\windows\system32\custom.dll"), [r"\??\c:\windows\system32\custom.dll"]);
        assert_eq!(paths(br"\SystemRoot\System32\x.dll"), [r"\SystemRoot\System32\x.dll"]);
    }

    #[test]
    fn extensionless_name_gets_default_extension_on_first_open() {
        assert_eq!(paths(b"kernel32")[0], r"\SystemRoot\System32\kernel32.dll");
        assert_eq!(paths(b"kernel32").len(), 3, "the default extension is not retried");
    }

    #[test]
    fn only_a_proven_absence_moves_on() {
        assert!(is_definitive_miss(FileMapFailureStage::Open, 0xc000_0034));
        assert!(is_definitive_miss(FileMapFailureStage::Open, 0xc000_003a));
        for status in [0, 0xc000_0022, 0xc000_007b, 0xc000_0043] {
            assert!(!is_definitive_miss(FileMapFailureStage::Open, status), "{status:#x}");
        }
        for stage in [FileMapFailureStage::CreateSection, FileMapFailureStage::MapView] {
            assert!(!is_definitive_miss(stage, 0xc000_0034));
        }
    }
}
