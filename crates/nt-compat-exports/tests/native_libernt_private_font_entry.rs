use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const EXPECTED_SOURCE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";
const EXPECTED_TREE_SHA256: &str =
    "tree_sha256=c9aaa68134bf27138bb257819b4f58acb0b2b5dd1cf80515bae30683bf5d2df1";
const FONT_ENTRY_RVA: u64 = 0x000e_bd10;
const FONT_SERVICE_RVA: u64 = 0x000e_6db0;
const WIN32K_SHA256: &str = "cce42491d4093ba391c25ae2612bbd714ce28f95aa6a56a127e9f55736be187f";

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn raw_offset(bytes: &[u8], rva: u64) -> usize {
    let pe = le_u32(bytes, 0x3c) as usize;
    assert_eq!(&bytes[pe..pe + 4], b"PE\0\0");
    let sections = le_u16(bytes, pe + 6) as usize;
    let optional_header = le_u16(bytes, pe + 20) as usize;
    for index in 0..sections {
        let section = pe + 24 + optional_header + index * 40;
        let virtual_size = le_u32(bytes, section + 8) as u64;
        let virtual_base = le_u32(bytes, section + 12) as u64;
        if (virtual_base..virtual_base + virtual_size).contains(&rva) {
            return le_u32(bytes, section + 20) as usize + (rva - virtual_base) as usize;
        }
    }
    panic!("RVA 0x{rva:x} is not inside the pinned PE");
}

#[test]
fn private_font_entry_matches_the_pinned_libernt_release_abi() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("LiberNT release manifest");
    assert!(manifest
        .lines()
        .any(|line| line == EXPECTED_SOURCE_REVISION));
    assert!(manifest.lines().any(|line| line == EXPECTED_TREE_SHA256));

    let host = fs::read_to_string(root.join("components/ntos-executive/src/win32k_subsystem.rs"))
        .expect("win32k host source");
    let declaration = host
        .lines()
        .find(|line| line.contains("pub const INT_GDI_ADD_FONT_MEM_RESOURCE_RVA: u64 ="))
        .expect("private font ABI declaration");
    let literal = declaration
        .split('=')
        .nth(1)
        .unwrap()
        .trim()
        .trim_end_matches(';');
    let actual = u64::from_str_radix(
        literal.trim_start_matches("0x").replace('_', "").as_str(),
        16,
    )
    .expect("hexadecimal private font RVA");
    assert_eq!(actual, FONT_ENTRY_RVA);

    // The release image is downloaded during native image generation. CI still checks the
    // source-revision and RVA contract when that local cache is absent.
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if !image.exists() {
        return;
    }
    let bytes = fs::read(image).expect("read cached pinned win32k.sys");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), WIN32K_SHA256);
    let entry = raw_offset(&bytes, FONT_ENTRY_RVA);
    assert_eq!(
        &bytes[entry..entry + 7],
        &[0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x53]
    );
    let service_call = raw_offset(&bytes, FONT_SERVICE_RVA + 0x85);
    assert_eq!(bytes[service_call], 0xe8);
    let displacement = i32::from_le_bytes(
        bytes[service_call + 1..service_call + 5]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        (FONT_SERVICE_RVA + 0x8a) as i64 + displacement as i64,
        FONT_ENTRY_RVA as i64
    );
}
