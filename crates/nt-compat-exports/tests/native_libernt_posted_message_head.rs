//! The hosted THREADINFO placeholder must seed the list head used by pinned LiberNT cleanup.

use std::fs;
use std::path::PathBuf;

const SOURCE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";
const POSTED_HEAD_OFFSET: u64 = 0x190;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("missing {name}"));
    let body = &source[start..];
    let open = body.find('{').unwrap();
    let mut depth = 0;
    for (index, ch) in body.char_indices().skip(open) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[..=index];
                }
            }
            _ => {}
        }
    }
    panic!("unclosed {name}")
}

fn raw_offset(bytes: &[u8], rva: u64) -> usize {
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&bytes[pe..pe + 4], b"PE\0\0");
    let count = u16::from_le_bytes(bytes[pe + 6..pe + 8].try_into().unwrap()) as usize;
    let optional = u16::from_le_bytes(bytes[pe + 20..pe + 22].try_into().unwrap()) as usize;
    for index in 0..count {
        let section = pe + 24 + optional + index * 40;
        let base = u32::from_le_bytes(bytes[section + 12..section + 16].try_into().unwrap()) as u64;
        let size = u32::from_le_bytes(bytes[section + 8..section + 12].try_into().unwrap()) as u64;
        if (base..base + size).contains(&rva) {
            return u32::from_le_bytes(bytes[section + 20..section + 24].try_into().unwrap())
                as usize
                + (rva - base) as usize;
        }
    }
    panic!("RVA 0x{rva:x} is outside pinned win32k.sys");
}

#[test]
fn native_posted_message_head_is_the_one_initialized_for_thread_cleanup() {
    let source = fs::read_to_string(root().join("components/ntos-executive/src/win32k_subsystem.rs"))
        .expect("win32k host source");
    assert!(
        source.contains("const THREADINFO_POSTED_MESSAGES_OFF: u64 = 0x190;"),
        "hosted THREADINFO must name pinned LiberNT's +0x190 posted-message head"
    );
    let initializer = function(&source, "init_threadinfo_placeholder");
    assert!(initializer.contains("THREADINFO_POSTED_MESSAGES_OFF"));
    assert!(initializer.contains("ensure_list_head_initialized(head)"));
    assert!(!initializer.contains("0x188, 0x2d8"));
    let list_initializer = function(&source, "initialize_list_head");
    assert!(list_initializer.contains("write_volatile(head as *mut u64, head)"));
    assert!(list_initializer.contains("write_volatile((head + 8) as *mut u64, head)"));

    // The pinned release image may be absent on CI. When cached locally, verify the native
    // cleanup's LEA instruction so the source offset cannot silently drift from the binary.
    if let Ok(manifest) = fs::read_to_string(root().join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.lines().any(|line| line == SOURCE_REVISION));
    }
    let image = root().join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if !image.exists() {
        return;
    }
    let bytes = fs::read(image).expect("cached pinned LiberNT win32k.sys");
    let instruction = raw_offset(&bytes, 0x886e2);
    assert_eq!(&bytes[instruction..instruction + 3], &[0x4c, 0x8d, 0xbe]);
    let displacement = i32::from_le_bytes(bytes[instruction + 3..instruction + 7].try_into().unwrap());
    assert_eq!(u64::try_from(displacement).unwrap(), POSTED_HEAD_OFFSET);
}
