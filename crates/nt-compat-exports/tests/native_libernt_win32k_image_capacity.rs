//! Bound the native win32k frame run using the pinned LiberNT PE image, not its raw file length.

use std::path::Path;

const PINNED_LIBERNT_WIN32K_IMAGE_SIZE: u64 = 0x285000;
const PINNED_LIBERNT_WIN32K_FILE_SIZE: u64 = 2_088_960;

#[test]
fn native_win32k_code_run_covers_pinned_libernt_size_of_image() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("pinned LiberNT release manifest");
    assert!(
        manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"),
        "update pinned win32k geometry when the LiberNT release changes"
    );
    let cached_image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if cached_image.exists() {
        let bytes = std::fs::read(&cached_image).expect("pinned LiberNT win32k.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("valid pinned LiberNT win32k PE");
        assert_eq!(bytes.len() as u64, PINNED_LIBERNT_WIN32K_FILE_SIZE);
        assert_eq!(u64::from(pe.size_of_image()), PINNED_LIBERNT_WIN32K_IMAGE_SIZE);
    }

    let executive = include_str!("../../../components/ntos-executive/src/main.rs");
    let win32k = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let seh = include_str!("../../../components/ntos-executive/src/win32k_seh_image.rs");
    let raw_frames = literal_constant(executive, "WIN32KBUF_FRAMES");
    let mapped_frames = literal_constant(win32k, "WIN32K_IMAGE_FRAMES");
    let code_base = literal_constant(win32k, "WIN32K_CODE_VA");
    let aux_base = literal_constant(win32k, "WIN32K_AUX_PT_VADDR");
    let seh_frames = literal_constant(seh, "MAX_FRAMES");
    assert!(
        raw_frames * 0x1000 >= PINNED_LIBERNT_WIN32K_FILE_SIZE,
        "staging buffer must hold the complete raw win32k.sys file"
    );
    assert!(
        mapped_frames * 0x1000 >= PINNED_LIBERNT_WIN32K_IMAGE_SIZE,
        "win32k code-frame run must cover PE SizeOfImage, including virtual section tails"
    );
    let support_end = code_base + (mapped_frames + seh_frames) * 0x1000;
    assert!(
        support_end <= code_base + 2 * 0x20_0000,
        "win32k and SEH support must fit in the two mapped code page tables"
    );
    assert!(
        support_end <= aux_base,
        "win32k and SEH support must not overlap the executive's auxiliary data region"
    );
}

fn literal_constant(source: &str, name: &str) -> u64 {
    let declaration = source
        .lines()
        .find(|line| {
            line.starts_with(&format!("pub const {name}:"))
                || line.starts_with(&format!("pub(crate) const {name}:"))
        })
        .expect("native frame-count constant");
    let item = syn::parse_str::<syn::ItemConst>(declaration.split("//").next().unwrap())
        .expect("native frame-count constant syntax");
    let syn::Expr::Lit(value) = *item.expr else {
        panic!("{name} must have a literal frame count");
    };
    let syn::Lit::Int(value) = value.lit else {
        panic!("{name} must be an integer frame count");
    };
    let text = value.to_string().replace('_', "");
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).expect("hexadecimal frame count"),
        None => text.parse().expect("decimal frame count"),
    }
}
