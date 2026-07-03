//! # `nt-driver-test-fixtures` — synthetic PE image emitter
//!
//! Build valid PE32+/x86_64 `.sys`-like images by hand, so Driver Host crates +
//! tools can be tested without a Windows toolchain (there is no PE linker on the
//! build host). Emits headers, sections, an import table, and base relocations.

/// The default preferred load address for emitted images.
pub const DEFAULT_IMAGE_BASE: u64 = 0x1_4000_0000;

/// The real `SurtTest.sys` — a WDM driver built with the MSVC WDK by
/// <https://github.com/stakach/ntdriver> (x64 Release). Its preferred image base
/// is `0x140000000` and its entry (`DriverEntry`) is at RVA `0x5000`. Real x64
/// execution is only possible in QEMU (this build host is aarch64).
pub fn surttest_sys() -> &'static [u8] {
    include_bytes!("../fixtures/SurtTest.sys")
}

const NT_OFF: usize = 0x40;
const OPT_OFF: usize = 0x58; // NT_OFF + 4 (sig) + 20 (file header)
const SECTION_TABLE: usize = 0x148; // OPT_OFF + 240
const FILE_ALIGN: usize = 0x200;

/// A section to place in the image.
pub struct Section {
    pub name: [u8; 8],
    pub va: u32,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn align_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

/// A `.text` section (CODE | EXECUTE | READ) at `va`.
pub fn text_section(va: u32, data: Vec<u8>) -> Section {
    Section {
        name: *b".text\0\0\0",
        va,
        characteristics: 0x6000_0020,
        data,
    }
}

/// An `.rdata` section (INITIALIZED_DATA | READ) at `va`.
pub fn rdata_section(va: u32, data: Vec<u8>) -> Section {
    Section {
        name: *b".rdata\0\0",
        va,
        characteristics: 0x4000_0040,
        data,
    }
}

/// Build a PE32+/x86_64 image. `dirs` are `(data-directory index, rva, size)`
/// tuples (index 1 = import, 5 = base reloc).
pub fn build_pe(
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    sections: &[Section],
    dirs: &[(usize, u32, u32)],
) -> Vec<u8> {
    let n = sections.len();
    let size_of_headers = align_up(SECTION_TABLE + n * 40, FILE_ALIGN);

    let mut raw_off = size_of_headers;
    let mut raws = Vec::new();
    for s in sections {
        let sz = align_up(s.data.len().max(1), FILE_ALIGN);
        raws.push((raw_off, sz));
        raw_off += sz;
    }

    let mut b = vec![0u8; raw_off];
    put_u16(&mut b, 0, 0x5A4D); // MZ
    put_u32(&mut b, 0x3C, NT_OFF as u32);
    put_u32(&mut b, NT_OFF, 0x0000_4550); // PE\0\0
    put_u16(&mut b, NT_OFF + 4, 0x8664); // machine AMD64
    put_u16(&mut b, NT_OFF + 6, n as u16);
    put_u16(&mut b, NT_OFF + 4 + 16, 240); // SizeOfOptionalHeader
    put_u16(&mut b, NT_OFF + 4 + 18, 0x0002); // EXECUTABLE_IMAGE
    put_u16(&mut b, OPT_OFF, 0x020b); // PE32+
    put_u32(&mut b, OPT_OFF + 16, entry_rva);
    put_u64(&mut b, OPT_OFF + 24, image_base);
    put_u32(&mut b, OPT_OFF + 32, 0x1000); // SectionAlignment
    put_u32(&mut b, OPT_OFF + 36, FILE_ALIGN as u32);
    put_u32(&mut b, OPT_OFF + 56, size_of_image);
    put_u32(&mut b, OPT_OFF + 60, size_of_headers as u32);
    put_u16(&mut b, OPT_OFF + 68, 1); // Subsystem: NATIVE
    put_u32(&mut b, OPT_OFF + 108, 16); // NumberOfRvaAndSizes
    for &(idx, rva, size) in dirs {
        put_u32(&mut b, OPT_OFF + 112 + idx * 8, rva);
        put_u32(&mut b, OPT_OFF + 112 + idx * 8 + 4, size);
    }
    for (i, s) in sections.iter().enumerate() {
        let se = SECTION_TABLE + i * 40;
        b[se..se + 8].copy_from_slice(&s.name);
        put_u32(&mut b, se + 8, s.data.len() as u32);
        put_u32(&mut b, se + 12, s.va);
        put_u32(&mut b, se + 16, raws[i].1 as u32);
        put_u32(&mut b, se + 20, raws[i].0 as u32);
        put_u32(&mut b, se + 36, s.characteristics);
        b[raws[i].0..raws[i].0 + s.data.len()].copy_from_slice(&s.data);
    }
    b
}

/// A minimal valid image: one `.text` section (`nop; ret`) with `entry` at
/// `0x1000` and no imports.
pub fn minimal_pe() -> Vec<u8> {
    build_pe(
        DEFAULT_IMAGE_BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0x90, 0xC3])],
        &[],
    )
}

/// An image importing `funcs` (by name) from `dll`, plus a trivial `.text`.
pub fn pe_importing(dll: &str, funcs: &[&str]) -> Vec<u8> {
    let sec_va: u32 = 0x2000;
    let n = funcs.len();

    let desc_sz = 40usize; // one real descriptor + null terminator
    let ilt_off = desc_sz;
    let ilt_sz = (n + 1) * 8;
    let iat_off = ilt_off + ilt_sz;
    let iat_sz = (n + 1) * 8;
    let name_off = iat_off + iat_sz;
    let dll_bytes: Vec<u8> = dll.bytes().chain(core::iter::once(0)).collect();
    let byname_start = name_off + dll_bytes.len();

    let mut byname_offs = Vec::new();
    let mut cur = byname_start;
    for f in funcs {
        byname_offs.push(cur);
        cur += 2 + f.len() + 1; // hint + name + NUL
    }

    let mut d = vec![0u8; cur];
    let p32 = |d: &mut Vec<u8>, o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let p64 = |d: &mut Vec<u8>, o: usize, v: u64| d[o..o + 8].copy_from_slice(&v.to_le_bytes());

    p32(&mut d, 0x00, sec_va + ilt_off as u32); // OriginalFirstThunk
    p32(&mut d, 0x0c, sec_va + name_off as u32); // Name
    p32(&mut d, 0x10, sec_va + iat_off as u32); // FirstThunk
    for (i, &bo) in byname_offs.iter().enumerate() {
        p64(&mut d, ilt_off + i * 8, (sec_va + bo as u32) as u64);
        p64(&mut d, iat_off + i * 8, (sec_va + bo as u32) as u64);
    }
    d[name_off..name_off + dll_bytes.len()].copy_from_slice(&dll_bytes);
    for (i, f) in funcs.iter().enumerate() {
        let o = byname_offs[i];
        // hint = 0 (already), then name + NUL (already zeroed).
        d[o + 2..o + 2 + f.len()].copy_from_slice(f.as_bytes());
    }

    build_pe(
        DEFAULT_IMAGE_BASE,
        0x1000,
        0x4000,
        &[text_section(0x1000, vec![0xC3]), rdata_section(sec_va, d)],
        &[(1, sec_va, desc_sz as u32)],
    )
}
