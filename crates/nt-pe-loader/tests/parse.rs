//! PE-loader tests against hand-crafted PE32+ images: parse, map, relocate,
//! import listing, and malformed-image rejection (no panics).

use nt_pe_loader::{ImportRef, PeError, PeFile, Protection};

// --- a minimal PE32+ image builder -----------------------------------------

const NT_OFF: usize = 0x40;
const OPT_OFF: usize = 0x58; // NT_OFF + 4 (sig) + 20 (file header)
const SECTION_TABLE: usize = 0x148; // OPT_OFF + 240
const FILE_ALIGN: usize = 0x200;

struct Sec {
    name: [u8; 8],
    va: u32,
    chars: u32,
    data: Vec<u8>,
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

/// Build a PE32+/x86_64 image. `dirs[1]` = import dir, `dirs[5]` = base-reloc dir.
fn build_pe(
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    sections: &[Sec],
    dirs: &[(usize, u32, u32)], // (index, rva, size)
) -> Vec<u8> {
    let n = sections.len();
    let size_of_headers = align_up(SECTION_TABLE + n * 40, FILE_ALIGN);

    // Lay out section raw data after the headers.
    let mut raw_off = size_of_headers;
    let mut raws = Vec::new();
    for s in sections {
        let sz = align_up(s.data.len().max(1), FILE_ALIGN);
        raws.push((raw_off, sz));
        raw_off += sz;
    }
    let total = raw_off;

    let mut b = vec![0u8; total];
    // DOS header.
    put_u16(&mut b, 0, 0x5A4D); // MZ
    put_u32(&mut b, 0x3C, NT_OFF as u32);
    // NT signature.
    put_u32(&mut b, NT_OFF, 0x0000_4550); // PE\0\0
                                          // File header.
    put_u16(&mut b, NT_OFF + 4, 0x8664); // machine AMD64
    put_u16(&mut b, NT_OFF + 6, n as u16); // NumberOfSections
    put_u16(&mut b, NT_OFF + 4 + 16, 240); // SizeOfOptionalHeader
    put_u16(&mut b, NT_OFF + 4 + 18, 0x0002); // Characteristics: EXECUTABLE_IMAGE
                                              // Optional header (PE32+).
    put_u16(&mut b, OPT_OFF, 0x020b); // magic
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
    // Section table + raw data.
    for (i, s) in sections.iter().enumerate() {
        let se = SECTION_TABLE + i * 40;
        b[se..se + 8].copy_from_slice(&s.name);
        put_u32(&mut b, se + 8, s.data.len() as u32); // VirtualSize
        put_u32(&mut b, se + 12, s.va);
        put_u32(&mut b, se + 16, raws[i].1 as u32); // SizeOfRawData
        put_u32(&mut b, se + 20, raws[i].0 as u32); // PointerToRawData
        put_u32(&mut b, se + 36, s.chars);
        b[raws[i].0..raws[i].0 + s.data.len()].copy_from_slice(&s.data);
    }
    b
}

fn text_section(va: u32, data: Vec<u8>) -> Sec {
    Sec {
        name: *b".text\0\0\0",
        va,
        chars: 0x6000_0020, // CODE | EXECUTE | READ
        data,
    }
}

const BASE: u64 = 0x1_4000_0000;

#[test]
fn minimal_pe_parses_and_maps() {
    let pe_bytes = build_pe(
        BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0x90, 0xC3])], // nop; ret
        &[],
    );
    let pe = PeFile::parse(&pe_bytes).unwrap();
    assert_eq!(pe.image_base(), BASE);
    assert_eq!(pe.entry_point_rva(), 0x1000);
    assert_eq!(pe.sections().len(), 1);
    assert_eq!(pe.sections()[0].name_str(), ".text");
    assert!(pe.imports().unwrap().is_empty());

    let img = pe.map(BASE).unwrap();
    assert_eq!(img.entry_point(), BASE + 0x1000);
    assert_eq!(&img.bytes[0x1000..0x1002], &[0x90, 0xC3]);
}

#[test]
fn imports_are_listed() {
    // A .rdata section at VA 0x2000 holding an import table for
    // ntoskrnl.exe!IoCreateDevice.
    let sec_va: u32 = 0x2000;
    let mut d = vec![0u8; 0];
    // Layout inside the section (RVAs are sec_va + local offset):
    //   0x00 descriptors[2] (20 each)  -> 0x00..0x28
    //   0x28 ILT thunk (u64) + null    -> 0x28..0x38
    //   0x38 IAT thunk (u64) + null    -> 0x38..0x48
    //   0x48 dll name "ntoskrnl.exe\0" -> 0x48..0x55
    //   0x58 IMAGE_IMPORT_BY_NAME: hint(2) + "IoCreateDevice\0"
    let ilt = sec_va + 0x28;
    let iat = sec_va + 0x38;
    let name = sec_va + 0x48;
    let by_name = sec_va + 0x58;
    d.resize(0x80, 0);
    let put32 = |d: &mut Vec<u8>, o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |d: &mut Vec<u8>, o: usize, v: u64| d[o..o + 8].copy_from_slice(&v.to_le_bytes());
    // descriptor 0
    put32(&mut d, 0x00, ilt); // OriginalFirstThunk
    put32(&mut d, 0x0c, name); // Name
    put32(&mut d, 0x10, iat); // FirstThunk
                              // descriptor 1 = null terminator (already zero)
                              // ILT + IAT thunks -> by_name RVA (high bit clear)
    put64(&mut d, 0x28, by_name as u64);
    put64(&mut d, 0x38, by_name as u64);
    // dll name
    d[0x48..0x48 + 13].copy_from_slice(b"ntoskrnl.exe\0");
    // IMAGE_IMPORT_BY_NAME: hint=7, name
    d[0x58..0x5a].copy_from_slice(&7u16.to_le_bytes());
    d[0x5a..0x5a + 15].copy_from_slice(b"IoCreateDevice\0");

    let rdata = Sec {
        name: *b".rdata\0\0",
        va: sec_va,
        chars: 0x4000_0040, // INITIALIZED_DATA | READ
        data: d,
    };
    let pe_bytes = build_pe(
        BASE,
        0x1000,
        0x3000,
        &[text_section(0x1000, vec![0xC3]), rdata],
        &[(1, sec_va, 0x28)], // import dir
    );
    let pe = PeFile::parse(&pe_bytes).unwrap();
    let dlls = pe.imports().unwrap();
    assert_eq!(dlls.len(), 1);
    assert_eq!(dlls[0].name, "ntoskrnl.exe");
    assert_eq!(dlls[0].functions.len(), 1);
    match &dlls[0].functions[0] {
        ImportRef::ByName {
            name, iat_slot_rva, ..
        } => {
            assert_eq!(name, "IoCreateDevice");
            assert_eq!(*iat_slot_rva, iat); // where the resolved address goes
        }
        other => panic!("expected ByName, got {other:?}"),
    }
}

#[test]
fn relocations_are_applied_on_rebase() {
    // A .data section at VA 0x2000 whose first u64 is an absolute pointer
    // (== image_base), plus a base-reloc block fixing it up.
    let data_va: u32 = 0x2000;
    let reloc_va: u32 = 0x3000;
    let mut data = vec![0u8; 0x10];
    data[0..8].copy_from_slice(&BASE.to_le_bytes()); // pointer to be rebased

    // Base-reloc block for page 0x2000 with one DIR64 at offset 0.
    let mut reloc = vec![0u8; 0];
    reloc.extend_from_slice(&data_va.to_le_bytes()); // page RVA
    reloc.extend_from_slice(&12u32.to_le_bytes()); // block size = 8 + 2 entries*2
    reloc.extend_from_slice(&(10u16 << 12).to_le_bytes()); // DIR64 (type 10) @ offset 0
    reloc.extend_from_slice(&0u16.to_le_bytes()); // ABSOLUTE padding

    let sections = [
        text_section(0x1000, vec![0xC3]),
        Sec {
            name: *b".data\0\0\0",
            va: data_va,
            chars: 0xC000_0040,
            data,
        },
        Sec {
            name: *b".reloc\0\0",
            va: reloc_va,
            chars: 0x4200_0040,
            data: reloc,
        },
    ];
    let pe_bytes = build_pe(BASE, 0x1000, 0x4000, &sections, &[(5, reloc_va, 12)]);
    let pe = PeFile::parse(&pe_bytes).unwrap();
    assert_eq!(pe.relocations().unwrap().len(), 2); // DIR64 + ABSOLUTE

    let new_base = 0x2_0000_0000u64;
    let img = pe.map(new_base).unwrap();
    // The rebased pointer must have the delta applied.
    assert_eq!(img.u64_at_rva(data_va).unwrap(), new_base);
}

#[test]
fn security_cookie_from_load_config() {
    // A load-config directory at RVA 0x2000 whose SecurityCookie (offset 88) is
    // the VA of __security_cookie at RVA 0x3000.
    let lc_va: u32 = 0x2000;
    let mut lc = vec![0u8; 0x148];
    lc[88..96].copy_from_slice(&(BASE + 0x3000).to_le_bytes());
    let sec = Sec {
        name: *b".rdata\0\0",
        va: lc_va,
        chars: 0x4000_0040,
        data: lc,
    };
    let pe_bytes = build_pe(
        BASE,
        0x1000,
        0x4000,
        &[text_section(0x1000, vec![0xC3]), sec],
        &[(10, lc_va, 0x148)],
    );
    let pe = PeFile::parse(&pe_bytes).unwrap();
    assert_eq!(pe.security_cookie_rva(), Some(0x3000));

    // No load-config directory → None.
    let plain = build_pe(
        BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0xC3])],
        &[],
    );
    assert_eq!(PeFile::parse(&plain).unwrap().security_cookie_rva(), None);
}

#[test]
fn protection_from_section_characteristics() {
    let data = Sec {
        name: *b".data\0\0\0",
        va: 0x2000,
        chars: 0xC000_0040, // INITIALIZED_DATA | READ | WRITE
        data: vec![0u8; 8],
    };
    let pe_bytes = build_pe(
        BASE,
        0x1000,
        0x3000,
        &[text_section(0x1000, vec![0xC3]), data],
        &[],
    );
    let pe = PeFile::parse(&pe_bytes).unwrap();
    assert_eq!(pe.protection_at(0x1000), Protection::ReadExecute); // .text
    assert_eq!(pe.protection_at(0x2000), Protection::ReadWrite); // .data
    assert_eq!(pe.protection_at(0), Protection::ReadOnly); // headers
}

#[test]
fn malformed_images_are_rejected_without_panic() {
    assert_eq!(PeFile::parse(&[]).unwrap_err(), PeError::Truncated);
    assert_eq!(
        PeFile::parse(&[0, 0, 0, 0]).unwrap_err(),
        PeError::BadDosSignature
    );

    // Valid DOS, corrupt PE signature.
    let mut b = build_pe(
        BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0xC3])],
        &[],
    );
    b[NT_OFF] = 0;
    assert_eq!(PeFile::parse(&b).unwrap_err(), PeError::BadNtSignature);

    // Wrong machine (i386).
    let mut b = build_pe(
        BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0xC3])],
        &[],
    );
    put_u16(&mut b, NT_OFF + 4, 0x014c);
    assert_eq!(
        PeFile::parse(&b).unwrap_err(),
        PeError::UnsupportedMachine(0x014c)
    );

    // PE32 (not PE32+).
    let mut b = build_pe(
        BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0xC3])],
        &[],
    );
    put_u16(&mut b, OPT_OFF, 0x010b);
    assert_eq!(PeFile::parse(&b).unwrap_err(), PeError::NotPe32Plus(0x010b));

    // Truncated after the DOS header.
    let b = build_pe(
        BASE,
        0x1000,
        0x2000,
        &[text_section(0x1000, vec![0xC3])],
        &[],
    );
    assert!(PeFile::parse(&b[..0x50]).is_err());
}

// --- export-directory walk (the name -> AddressOfNameOrdinals -> AddressOfFunctions indirection) --
//
// Regression cover for the ntdll loader export-resolution walk (nt-ntdll-dll on_target.rs mirrors
// this exact indirection). The BATCH-18 boot bug was a per-VSpace demand-paging gap, not the math —
// but the walk math (a HIGH name index resolved via AoNO[i] -> AoF[ord], a FORWARDER export whose
// func RVA falls inside the export dir range, and the FIRST/LAST boundary names) is the load-bearing
// correctness this test pins so a future edit to the indirection (off-by-one, ordinal-base, name<->
// ordinal swap) is caught host-side. Modeled on the real kernel32 case that regressed:
// GetSystemTimeAsFileTime at a high name index resolving to a concrete .text RVA.
#[test]
fn export_directory_walk_resolves_high_index_forwarder_and_boundaries() {
    // Build a .edata section holding a synthetic IMAGE_EXPORT_DIRECTORY with N names. We deliberately
    // make the WANTED name a HIGH index (like kernel32's GetSystemTimeAsFileTime @ name-index 458) and
    // give AddressOfNameOrdinals a non-identity permutation so a name<->ordinal or ordinal-base bug
    // would mis-resolve. One export is a FORWARDER (its func RVA points INSIDE the export dir range).
    const EDATA_VA: u32 = 0x2000;
    const N: u32 = 300; // > 256 so a u8/u16 index bug surfaces; "high index" like the real case
    const HIGH: u32 = 199; // the name index we assert resolves correctly (deep in the table)

    // Section-local layout (all RVAs = EDATA_VA + local):
    //   0x00                 IMAGE_EXPORT_DIRECTORY (40 bytes)
    //   0x28                 AddressOfFunctions   [N] u32
    //   0x28 + N*4           AddressOfNames       [N] u32
    //   0x28 + N*8           AddressOfNameOrdinals[N] u16
    //   names_start          the NUL-terminated name strings
    //   fwd_str              a forwarder target string "OTHER.Func" (inside the dir range)
    let aof_local = 0x28u32;
    let aon_local = aof_local + N * 4;
    let aono_local = aon_local + N * 4;
    let names_local = aono_local + N * 2;

    let mut sec = vec![0u8; names_local as usize];

    // Emit the name strings; record each name's local offset. name[i] = "exp<i>", except:
    //   HIGH -> "GetSystemTimeAsFileTime" (the marquee high-index case)
    //   0    -> "AFirst" (first boundary)
    //   N-1  -> "ZLast"  (last boundary)
    //   1    -> "FwdExport" (a forwarder)
    let mut name_local = Vec::with_capacity(N as usize);
    let mut cur = names_local as usize;
    let push_name = |sec: &mut Vec<u8>, cur: &mut usize, s: &[u8]| -> u32 {
        let at = *cur as u32;
        sec.extend_from_slice(s);
        sec.push(0);
        *cur = sec.len();
        at
    };
    for i in 0..N {
        let s: Vec<u8> = match i {
            0 => b"AFirst".to_vec(),
            1 => b"FwdExport".to_vec(),
            HIGH => b"GetSystemTimeAsFileTime".to_vec(),
            x if x == N - 1 => b"ZLast".to_vec(),
            _ => {
                let mut v = b"exp".to_vec();
                v.extend_from_slice(i.to_string().as_bytes());
                v
            }
        };
        name_local.push(push_name(&mut sec, &mut cur, &s));
    }
    // The forwarder target string lives INSIDE the export dir range so it classifies as a forwarder.
    let fwd_str_local = {
        let at = sec.len() as u32;
        sec.extend_from_slice(b"OTHER.Func");
        sec.push(0);
        at
    };
    let edata_size = sec.len() as u32; // the export data-directory size (dir range = [VA, VA+size))

    // AddressOfFunctions: give each ordinal a distinct, checkable RVA in .text (0x1000-based), EXCEPT
    // the forwarder ordinal whose "RVA" points at fwd_str_local (inside the dir range).
    // AddressOfNameOrdinals: a NON-identity map (ordinal = N-1-i) so an identity assumption fails.
    let text_rva = |ord: u32| 0x1000 + ord * 0x10; // concrete export RVA for ordinal `ord`
    for i in 0..N {
        let ord = N - 1 - i; // non-identity permutation
        // AddressOfNames[i] = the name-string RVA.
        put_u32(&mut sec, (aon_local + i * 4) as usize, EDATA_VA + name_local[i as usize]);
        // AddressOfNameOrdinals[i] = ord (u16).
        put_u16(&mut sec, (aono_local + i * 2) as usize, ord as u16);
    }
    // AddressOfFunctions[ord] for every ordinal.
    for i in 0..N {
        let ord = N - 1 - i;
        let func_rva = if i == 1 {
            // the "FwdExport" name maps (via AoNO) to ordinal `ord`; make THAT ordinal a forwarder.
            EDATA_VA + fwd_str_local
        } else {
            text_rva(ord)
        };
        put_u32(&mut sec, (aof_local + ord * 4) as usize, func_rva);
    }

    // IMAGE_EXPORT_DIRECTORY header.
    put_u32(&mut sec, 16, 5); // Base (ordinal base) — deliberately != 0/1 to catch a base bug
    put_u32(&mut sec, 20, N); // NumberOfFunctions
    put_u32(&mut sec, 24, N); // NumberOfNames
    put_u32(&mut sec, 28, EDATA_VA + aof_local); // AddressOfFunctions
    put_u32(&mut sec, 32, EDATA_VA + aon_local); // AddressOfNames
    put_u32(&mut sec, 36, EDATA_VA + aono_local); // AddressOfNameOrdinals

    let edata = Sec {
        name: *b".edata\0\0",
        va: EDATA_VA,
        chars: 0x4000_0040, // INITIALIZED_DATA | READ
        data: sec,
    };
    let pe_bytes = build_pe(
        BASE,
        0x1000,
        0x4000,
        &[text_section(0x1000, vec![0x90, 0xC3]), edata],
        &[(0, EDATA_VA, edata_size)], // data dir 0 = export, size = the dir range
    );

    let pe = PeFile::parse(&pe_bytes).unwrap();
    let exports = pe.exports().unwrap();
    let find = |name: &str| exports.iter().find(|e| e.name == name).cloned();

    // High-index name resolves to the concrete RVA of ITS ordinal (via the non-identity AoNO map).
    let gst = find("GetSystemTimeAsFileTime").expect("high-index export must be found");
    let gst_ord = N - 1 - HIGH; // AoNO[HIGH]
    assert_eq!(gst.rva, 0x1000 + gst_ord * 0x10, "high-index func RVA via AoNO/AoF");
    assert_eq!(gst.ordinal, 5u16.wrapping_add(gst_ord as u16), "ordinal = base + AoNO index");

    // Boundary names (first + last in the name array) resolve correctly.
    let first = find("AFirst").expect("first export"); // name index 0 -> ordinal N-1
    assert_eq!(first.rva, 0x1000 + (N - 1) * 0x10);
    let last = find("ZLast").expect("last export"); // name index N-1 -> ordinal 0
    assert_eq!(last.rva, 0x1000);

    // The forwarder export is present; its RVA is inside the export-dir range (a forwarder string),
    // NOT a concrete .text RVA — the on-target resolver follows it, but the parser reports the RVA.
    let fwd = find("FwdExport").expect("forwarder export");
    assert!(
        fwd.rva >= EDATA_VA && fwd.rva < EDATA_VA + edata_size,
        "forwarder RVA {:#x} must fall inside the export dir range [{:#x},{:#x})",
        fwd.rva, EDATA_VA, EDATA_VA + edata_size
    );

    // Every one of the N names resolved (no silent drop at a high index / boundary).
    assert_eq!(exports.len(), N as usize, "all names resolved");
}

// --- fuzz-safety: parsing arbitrary / mutated bytes never panics (spec §7.2) --

use proptest::prelude::*;

proptest! {
    /// Arbitrary bytes must never panic the parser; every path returns a Result.
    #[test]
    fn parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(pe) = PeFile::parse(&bytes) {
            let _ = pe.imports();
            let _ = pe.relocations();
            let _ = pe.map(0x1_0000_0000);
        }
    }

    /// Single-byte corruptions of a valid image never panic.
    #[test]
    fn mutated_valid_pe_never_panics(at in 0usize..0x600, byte in any::<u8>()) {
        let mut b = build_pe(
            BASE, 0x1000, 0x4000,
            &[text_section(0x1000, vec![0x90, 0xC3])],
            &[],
        );
        if at < b.len() {
            b[at] = byte;
        }
        if let Ok(pe) = PeFile::parse(&b) {
            let _ = pe.imports();
            let _ = pe.relocations();
            let _ = pe.map(0x2_0000_0000);
        }
    }
}
