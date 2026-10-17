use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const SOURCE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";
const TREE_SHA256: &str =
    "tree_sha256=c9aaa68134bf27138bb257819b4f58acb0b2b5dd1cf80515bae30683bf5d2df1";
const WIN32K_SHA256: &str = "cce42491d4093ba391c25ae2612bbd714ce28f95aa6a56a127e9f55736be187f";
const PDEV_ENTRY_RVA: u64 = 0x1b790;
const GPMDEV_RVA: u64 = 0x1b7168;
const HOST_GLOBALS: [(&str, u64); 5] = [
    ("G_ATOM_TABLE_RVA", 0x23c2a8),
    ("GPDESK_INPUT_DESKTOP_RVA", 0x23ae70),
    ("GSPKL_BASE_LAYOUT_RVA", 0x23b9f8),
    ("NR_GUI_APPS_RUNNING_RVA", 0x23b8a0),
    ("INPUT_WINDOW_STATION_RVA", 0x23cab8),
];

fn source_rva(source: &str, name: &str) -> u64 {
    let declaration = source
        .lines()
        .find(|line| line.contains(&format!("const {name}: u64 =")))
        .expect("win32k ABI declaration");
    let literal = declaration
        .split('=')
        .nth(1)
        .unwrap()
        .trim()
        .trim_end_matches(';');
    u64::from_str_radix(&literal.trim_start_matches("0x").replace('_', ""), 16)
        .expect("hexadecimal win32k RVA")
}

fn rip_target(bytes: &[u8], instruction_rva: u64, prefix: &[u8]) -> u64 {
    let instruction = raw_offset(bytes, instruction_rva);
    assert_eq!(&bytes[instruction..instruction + prefix.len()], prefix);
    let displacement = i32::from_le_bytes(
        bytes[instruction + prefix.len()..instruction + prefix.len() + 4]
            .try_into()
            .unwrap(),
    );
    ((instruction_rva + prefix.len() as u64 + 4) as i64 + displacement as i64) as u64
}

fn relocated_global(bytes: &[u8], slot_rva: u64) -> u64 {
    let slot = raw_offset(bytes, slot_rva);
    u64::from_le_bytes(bytes[slot..slot + 8].try_into().unwrap()) - 0x10000
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
    panic!("RVA 0x{rva:x} is not inside pinned win32k.sys");
}

#[test]
fn display_pdev_call_uses_the_pinned_libernt_entry_and_global() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Ok(manifest) = fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.lines().any(|line| line == SOURCE_REVISION));
        assert!(manifest.lines().any(|line| line == TREE_SHA256));
    }

    let source = fs::read_to_string(root.join("components/ntos-executive/src/win32k_subsystem.rs"))
        .expect("win32k host source");
    assert_eq!(
        source_rva(&source, "PDEVOBJ_L_CHANGE_DISPLAY_SETTINGS_RVA"),
        PDEV_ENTRY_RVA
    );
    assert_eq!(source_rva(&source, "GPMDEV_RVA"), GPMDEV_RVA);

    // The cached release image is optional in CI, but when present it proves both RVAs against
    // the native call from co_IntInitializeDesktopGraphics and its relocated gpmdev pointer.
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if !image.exists() {
        return;
    }
    let bytes = fs::read(image).expect("cached pinned win32k.sys");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), WIN32K_SHA256);

    let call_rva = 0xba8cb_u64;
    let call = raw_offset(&bytes, call_rva);
    assert_eq!(bytes[call], 0xe8);
    let displacement = i32::from_le_bytes(bytes[call + 1..call + 5].try_into().unwrap());
    assert_eq!(
        (call_rva + 5) as i64 + displacement as i64,
        PDEV_ENTRY_RVA as i64
    );

    assert_eq!(relocated_global(&bytes, 0x16ae58), GPMDEV_RVA);
}

#[test]
fn host_globals_match_the_pinned_libernt_win32k_image() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Ok(manifest) = fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.lines().any(|line| line == SOURCE_REVISION));
        assert!(manifest.lines().any(|line| line == TREE_SHA256));
    }

    let source = fs::read_to_string(root.join("components/ntos-executive/src/win32k_subsystem.rs"))
        .expect("win32k host source");
    for (name, expected) in HOST_GLOBALS {
        assert_eq!(
            source_rva(&source, name),
            expected,
            "{name} uses a stale ABI offset"
        );
    }

    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if !image.exists() {
        return;
    }
    let bytes = fs::read(image).expect("cached pinned win32k.sys");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), WIN32K_SHA256);

    // Native IntAddAtom passes the gAtomTable cell to RtlAddAtomToAtomTable.
    assert_eq!(rip_target(&bytes, 0xa55c5, &[0x48, 0x8b, 0x05]), 0x174390);
    assert_eq!(relocated_global(&bytes, 0x174390), HOST_GLOBALS[0].1);
    // NtUserSwitchDesktop compares and then stores gpdeskInputDesktop directly.
    assert_eq!(
        rip_target(&bytes, 0x53aef, &[0x48, 0x89, 0x05]),
        HOST_GLOBALS[1].1
    );
    // The IME layout traversal dereferences gspklBaseLayout before walking the KL list.
    assert_eq!(rip_target(&bytes, 0x6251d, &[0x48, 0x8b, 0x0d]), 0x17c010);
    assert_eq!(relocated_global(&bytes, 0x17c010), HOST_GLOBALS[2].1);
    // co_AddGuiApp increments the 0-to-1 graphics gate before initializing the display.
    assert_eq!(
        rip_target(&bytes, 0x5d289, &[0xf0, 0x0f, 0xc1, 0x15]),
        HOST_GLOBALS[3].1
    );
    // NtUserSwitchDesktop compares the target's parent to InputWindowStation.
    assert_eq!(rip_target(&bytes, 0x539f0, &[0x48, 0x8b, 0x1d]), 0x16f340);
    assert_eq!(relocated_global(&bytes, 0x16f340), HOST_GLOBALS[4].1);
}
