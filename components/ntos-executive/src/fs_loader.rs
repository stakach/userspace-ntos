//! `fs_loader` — the FAT32-by-path pool loader: mount, directory walk (8.3 + LFN),
//! file read, the demand-load pool, and load_dll_from_fs/hybrid. Extracted verbatim
//! from `main.rs` (pure reorg; no logic change). `struct Fat32` stays in `main.rs`
//! (this child module reaches its private fields).
#![allow(clippy::all)]
use crate::*;

/// Read `sector` off the disk (via AHCI) and return a pointer to its 512 bytes.
pub(crate) unsafe fn fat_read_sector(fs: &Fat32, sector: u32) -> *const u8 {
    ahci_read_sector(fs.ahci_vaddr, fs.dma_vaddr, fs.dma_paddr, sector as u64);
    (fs.dma_vaddr + 0x800) as *const u8
}

/// First disk sector of a cluster.
pub(crate) fn fat_cluster_sector(fs: &Fat32, cluster: u32) -> u32 {
    fs.data_start + (cluster - 2) * fs.spc
}

/// Follow the FAT: next cluster after `cluster` (>= 0x0FFF_FFF8 means end-of-chain).
pub(crate) unsafe fn fat_next(fs: &Fat32, cluster: u32) -> u32 {
    let byte = cluster * 4;
    let sec = fs.fat_start + byte / fs.bps;
    let off = (byte % fs.bps) as u64;
    let p = fat_read_sector(fs, sec);
    (core::ptr::read_unaligned(p.add(off as usize) as *const u32)) & 0x0FFF_FFFF
}

/// Scan directory `dir_cluster` (following its cluster chain) for the 8.3 name `name11`
/// (11 bytes, space-padded). Returns (first_cluster, size_bytes, attr). LFN / deleted /
/// volume-label / free entries are skipped. Extracts the entry before any further reads.
pub(crate) unsafe fn dir_find(fs: &Fat32, dir_cluster: u32, name11: &[u8; 11]) -> Option<(u32, u32, u8)> {
    let mut cl = dir_cluster;
    while cl >= 2 && cl < 0x0FFF_FFF8 {
        for s in 0..fs.spc {
            let p = fat_read_sector(fs, fat_cluster_sector(fs, cl) + s);
            for e in 0..(fs.bps as usize / 32) {
                let ent = p.add(e * 32);
                let first = *ent;
                if first == 0x00 {
                    return None; // end of directory
                }
                if first == 0xE5 {
                    continue; // deleted
                }
                let attr = *ent.add(0x0B);
                if attr == 0x0F || (attr & 0x08) != 0 {
                    continue; // LFN fragment or volume label
                }
                let mut matches = true;
                for i in 0..11 {
                    if *ent.add(i) != name11[i] {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    let hi = core::ptr::read_unaligned(ent.add(0x14) as *const u16) as u32;
                    let lo = core::ptr::read_unaligned(ent.add(0x1A) as *const u16) as u32;
                    let size = core::ptr::read_unaligned(ent.add(0x1C) as *const u32);
                    return Some(((hi << 16) | lo, size, attr));
                }
            }
        }
        cl = fat_next(fs, cl); // overwrites the buffer — fine, we're done with this cluster
    }
    None
}

/// Read a whole file (up to `size` bytes) from `first_cluster` into `dest_vaddr`, following
/// the FAT cluster chain. Each cluster is read via the AHCI into the shared data buffer, then
/// copied out to `dest_vaddr + offset` BEFORE the next read (which — incl. `fat_next` —
/// overwrites the buffer). Returns the number of bytes written.
pub(crate) unsafe fn fat_read_file(fs: &Fat32, first_cluster: u32, size: u32, dest_vaddr: u64) -> u32 {
    let mut cl = first_cluster;
    let mut written = 0u32;
    while cl >= 2 && cl < 0x0FFF_FFF8 && written < size {
        for s in 0..fs.spc {
            if written >= size {
                break;
            }
            let p = fat_read_sector(fs, fat_cluster_sector(fs, cl) + s);
            let n = core::cmp::min(fs.bps, size - written);
            for i in 0..n as u64 {
                core::ptr::write_volatile((dest_vaddr + written as u64 + i) as *mut u8, *p.add(i as usize));
            }
            written += n;
        }
        cl = fat_next(fs, cl);
    }
    written
}

/// Like `dir_find` but matches EITHER the 8.3 short entry OR the reassembled long (LFN) name of
/// `comp` — case-insensitive ASCII — so names WITHOUT a clean 8.3 alias (e.g. `advapi32_vista.dll`,
/// `windowscodecs.dll`) resolve by their real name. Returns `(first_cluster, size, attr)`. VFAT
/// stores 0-N LFN entries (attr 0x0F) physically BEFORE the 8.3 entry, each carrying 13 UTF-16
/// chars keyed by a 1-based sequence ordinal; this reassembles them (ASCII only — sufficient for
/// the ReactOS tree) and compares to `comp`. When an entry has an LFN, only the long name is
/// matched (the 8.3 is a mangled alias); otherwise the 8.3 short name is matched (old behavior).
pub(crate) unsafe fn dir_find_lfn(fs: &Fat32, dir_cluster: u32, comp: &[u8]) -> Option<(u32, u32, u8)> {
    let short = name_to_83(comp);
    // Lowercase the target (ASCII) once.
    let mut want = [0u8; 256];
    let want_len = if comp.len() < 256 { comp.len() } else { 256 };
    let mut i = 0;
    while i < want_len {
        let c = comp[i];
        want[i] = if c.is_ascii_uppercase() { c + 32 } else { c };
        i += 1;
    }
    // Does `comp` fit a clean 8.3 (base<=8, ext<=3, at most one dot)? If NOT, the 8.3 fallback
    // is UNSAFE: `name_to_83` truncates (e.g. "kernel32_vista.dll" -> "KERNEL32DLL") and would
    // COLLIDE with a different file's short entry ("kernel32.dll"). So the short-name match is
    // gated on `fits_83`; a long name matches ONLY via its reassembled LFN.
    let (mut base_len, mut ext_len, mut dots) = (0usize, 0usize, 0usize);
    for &c in comp {
        if c == b'.' {
            dots += 1;
        } else if dots >= 1 {
            ext_len += 1;
        } else {
            base_len += 1;
        }
    }
    let fits_83 = dots <= 1 && base_len >= 1 && base_len <= 8 && ext_len <= 3;
    let lfn_off: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut lfn = [0u8; 260]; // reassembled long name (lowercased ASCII)
    let mut term: Option<usize> = None; // index of the 0x0000 terminator, if seen
    let mut hi_ord = 0usize;
    let mut have_lfn = false;
    let mut cl = dir_cluster;
    while cl >= 2 && cl < 0x0FFF_FFF8 {
        for s in 0..fs.spc {
            let p = fat_read_sector(fs, fat_cluster_sector(fs, cl) + s);
            for e in 0..(fs.bps as usize / 32) {
                let ent = p.add(e * 32);
                let first = *ent;
                if first == 0x00 {
                    return None; // end of directory
                }
                if first == 0xE5 {
                    have_lfn = false; term = None; hi_ord = 0; // deleted — drop any pending LFN
                    continue;
                }
                let attr = *ent.add(0x0B);
                if attr == 0x0F {
                    // LFN fragment: place its 13 chars at [(ord-1)*13 ..].
                    let ord = (first & 0x1F) as usize;
                    if ord >= 1 && ord <= 20 {
                        have_lfn = true;
                        if ord > hi_ord { hi_ord = ord; }
                        let base = (ord - 1) * 13;
                        let mut k = 0;
                        while k < 13 {
                            let o = lfn_off[k];
                            let lo = *ent.add(o);
                            let hi = *ent.add(o + 1);
                            let idx = base + k;
                            if idx < 260 {
                                if lo == 0 && hi == 0 {
                                    if term.is_none() { term = Some(idx); }
                                } else if !(lo == 0xFF && hi == 0xFF) {
                                    lfn[idx] = if hi == 0 {
                                        if lo.is_ascii_uppercase() { lo + 32 } else { lo }
                                    } else {
                                        0xFF // non-ASCII — won't match an ASCII target
                                    };
                                }
                            }
                            k += 1;
                        }
                    }
                    continue;
                }
                if (attr & 0x08) != 0 {
                    have_lfn = false; term = None; hi_ord = 0; // volume label
                    continue;
                }
                // 8.3 entry: decide match against the long name (if any) or the short name.
                let matched = if have_lfn {
                    let len = term.unwrap_or(hi_ord * 13);
                    len == want_len && {
                        let mut m = true;
                        let mut j = 0;
                        while j < len {
                            if lfn[j] != want[j] { m = false; break; }
                            j += 1;
                        }
                        m
                    }
                } else {
                    fits_83 && {
                        let mut m = true;
                        let mut j = 0;
                        while j < 11 {
                            if *ent.add(j) != short[j] { m = false; break; }
                            j += 1;
                        }
                        m
                    }
                };
                if matched {
                    let hi = core::ptr::read_unaligned(ent.add(0x14) as *const u16) as u32;
                    let lo = core::ptr::read_unaligned(ent.add(0x1A) as *const u16) as u32;
                    let size = core::ptr::read_unaligned(ent.add(0x1C) as *const u32);
                    return Some(((hi << 16) | lo, size, attr));
                }
                have_lfn = false; term = None; hi_ord = 0;
            }
        }
        cl = fat_next(fs, cl);
    }
    None
}

/// Convert one path component (e.g. `b"ntdll.dll"`) to a space-padded 8.3 FAT short name.
/// ASCII-uppercases; splits on the LAST '.' (a leading dot is treated as part of the base);
/// truncates base to 8 and extension to 3. Good enough for the ReactOS install tree, whose
/// names (`reactos`, `system32`, `ntdll.dll`, …) all have clean 8.3 aliases — verified: mcopy
/// stores the uppercased 8.3 short entry (`REACTOS`, `SYSTEM32`, `NTDLL   DLL`) alongside an
/// LFN, and `dir_find` matches the short entry (skipping LFN fragments). No `~1` mangling.
pub(crate) fn name_to_83(comp: &[u8]) -> [u8; 11] {
    let mut out = [b' '; 11];
    let upper = |c: u8| if c.is_ascii_lowercase() { c - 32 } else { c };
    // Locate the extension separator = the last '.' that isn't the first char.
    let mut dot: Option<usize> = None;
    let mut i = 0usize;
    while i < comp.len() {
        if comp[i] == b'.' && i != 0 {
            dot = Some(i);
        }
        i += 1;
    }
    let (base_end, ext_start) = match dot {
        Some(d) => (d, d + 1),
        None => (comp.len(), comp.len()),
    };
    let mut j = 0usize;
    while j < 8 && j < base_end {
        out[j] = upper(comp[j]);
        j += 1;
    }
    let mut k = 0usize;
    while k < 3 && ext_start + k < comp.len() {
        out[8 + k] = upper(comp[ext_start + k]);
        k += 1;
    }
    out
}

/// Resolve a `\`- or `/`-separated PATH (e.g. `b"reactos\\system32\\ntdll.dll"`) from the
/// volume root, walking each component with `dir_find`. Returns `(first_cluster, size)` of the
/// final file, or `None` if any component is missing. 8.3 short names only (no LFN reassembly)
/// — sufficient for the real ReactOS tree, whose names carry clean 8.3 aliases. Each non-final
/// component must be a directory (FAT attr bit 0x10). This is the FS-backed-by-path primitive:
/// the seam a full `\SystemRoot\system32\X` loader generalizes (see P7).
pub(crate) unsafe fn fat_open_path(fs: &Fat32, path: &[u8]) -> Option<(u32, u32)> {
    let mut cur = fs.root_cl;
    let mut start = 0usize;
    let mut i = 0usize;
    let mut result: Option<(u32, u32)> = None;
    while i <= path.len() {
        let is_sep = i == path.len() || path[i] == b'\\' || path[i] == b'/';
        if is_sep {
            if i > start {
                let (cl, sz, attr) = dir_find_lfn(fs, cur, &path[start..i])?;
                if i == path.len() {
                    result = Some((cl, sz)); // final component = the file
                } else {
                    if (attr & 0x10) == 0 {
                        return None; // intermediate must be a directory
                    }
                    cur = cl;
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    result
}

/// Open `\reactos\system32\<leaf>` from the volume (the common ReactOS binary location) via the
/// LFN-aware path walk. Returns `(first_cluster, size)`. Builds the path in a stack buffer (the
/// storage host has no allocator). `leaf` may itself contain `\` for a sub-dir (e.g.
/// `b"drivers\\dxg.sys"`, `b"config\\system"`).
pub(crate) unsafe fn open_sys32(fs: &Fat32, leaf: &[u8]) -> Option<(u32, u32)> {
    let mut path = [0u8; 160];
    let mut n = 0usize;
    for &c in b"reactos\\system32\\" {
        path[n] = c;
        n += 1;
    }
    let mut i = 0;
    while i < leaf.len() && n < path.len() {
        path[n] = leaf[i];
        n += 1;
        i += 1;
    }
    fat_open_path(fs, &path[..n])
}

/// Does `\reactos\system32\<leaf>` exist on the executive's live FS? The REAL-FS existence
/// authority for NtQueryAttributesFile/NtOpenFile (replaces the hand-maintained SYSTEM32_FILES
/// seed): a System32 file exists iff it's present on the actual \reactos volume. `leaf` is a bare
/// leaf name (already lowercased/folded is fine — dir_find_lfn is ASCII case-insensitive). Returns
/// false if the FS isn't mounted yet (pre-boot) — the seed path never ran that early anyway.
pub(crate) unsafe fn sys32_exists(leaf: &[u8]) -> bool {
    if leaf.is_empty() {
        return false;
    }
    match exec_fs() {
        Some(fs) => open_sys32(&fs, leaf).is_some(),
        None => false,
    }
}

/// Does the `\reactos\system32` DIRECTORY exist on the executive's live FS (the KnownDLLs directory
/// open)? Walks to `system32` under `reactos` and confirms it's a directory. Returns false if the
/// FS isn't mounted yet. Real-FS authority for the System32 directory open in NtOpenFile.
pub(crate) unsafe fn sys32_dir_exists() -> bool {
    match exec_fs() {
        // dir_find_lfn returns (cluster, size, attr); attr bit 0x10 = directory. Walk root→reactos→system32.
        Some(fs) => {
            match dir_find_lfn(&fs, fs.root_cl, b"reactos") {
                Some((cl, _, attr)) if (attr & 0x10) != 0 => {
                    matches!(dir_find_lfn(&fs, cl, b"system32"), Some((_, _, a)) if (a & 0x10) != 0)
                }
                _ => false,
            }
        }
        None => false,
    }
}

// --- P7-A: EXECUTIVE-SIDE FS-BY-PATH LOADER (generic, zero-per-binary) ---------------------------
// After the isolated storage host reports and PARKS, the executive drives the SAME AHCI HBA itself
// (it owns the BAR cap at AHCI_VADDR + the DMA frame cap + the VT-d IO mapping at AHCI_IOVA) to
// resolve ANY \reactos path → bytes on demand. This is the mechanism that retires the fixed
// per-binary staging buffers: instead of the host batch-reading a hardcoded file list into ~15
// fixed dual-mapped buffers, the executive reads each binary BY PATH into a dynamically pooled
// buffer at load time. The demand-fault router + nt-dll-registry consume it UNCHANGED — they operate
// on PeFile byte-slices, which now point into the pool. Adding a P5 binary (services.exe/lsass/
// explorer) then needs NO new buffer/offset/fake: it just resolves from the FS.

/// The executive's own live FAT32 handle, mounted after the storage host parks (bound to the
/// executive's AHCI BAR + DMA-frame mappings). `None` until mounted. Read-only.
pub(crate) static mut EXEC_FS: Option<Fat32> = None;

/// Copy of the executive's mounted FAT32 handle (Fat32 is Copy), or None if not yet mounted.
/// Read via a raw pointer to avoid the static_mut_refs lint (single-threaded executive).
pub(crate) unsafe fn exec_fs() -> Option<Fat32> {
    core::ptr::read(core::ptr::addr_of!(EXEC_FS))
}

/// Load `path` (root-relative) from the executive's live FS into the pool and PE32+-parse it — the
/// generic replacement for a per-binary staging block. Returns `(Some(pe), pool_va)` on success (the
/// bytes stay resident in the pool for the demand-fault router), or `(None, 0)` so the caller can
/// fall back to a fixed staging buffer during the hybrid migration. `name` is for the boot log.
pub(crate) unsafe fn load_dll_from_fs(
    path: &[u8],
    name: &[u8],
) -> (Option<nt_pe_loader::PeFile<'static>>, u64) {
    if let Some(fs) = exec_fs() {
        if let Some((va, sz)) = load_file_to_pool(&fs, path) {
            let bytes: &'static [u8] = core::slice::from_raw_parts(va as *const u8, sz as usize);
            if let Ok(pe) = nt_pe_loader::PeFile::parse(bytes) {
                print_str(b"[ntos-exec] FS-by-path ");
                print_str(name);
                print_str(b": ");
                print_u64(sz as u64);
                print_str(b" bytes, PE32+ @pool=0x");
                print_hex((va >> 32) as u32);
                print_hex(va as u32);
                print_str(b"\n");
                return (Some(pe), va);
            }
            print_str(b"[ntos-exec] FS-by-path ");
            print_str(name);
            print_str(b": PARSE FAILED (fallback to staged buffer)\n");
        }
    }
    (None, 0)
}

/// Mount the FAT32 volume bound to the given AHCI/DMA mappings: read sector 0, parse the BPB.
/// Same BPB layout `storage_probe` parses; factored so both the host and the executive can mount.
pub(crate) unsafe fn fat32_mount(ahci_vaddr: u64, dma_vaddr: u64, dma_paddr: u64) -> Option<Fat32> {
    let _ = ahci_read_sector(ahci_vaddr, dma_vaddr, dma_paddr, 0);
    let bp = |o: u64| core::ptr::read_volatile((dma_vaddr + 0x800 + o) as *const u8);
    let bp16 = |o: u64| (bp(o) as u32) | ((bp(o + 1) as u32) << 8);
    let bp32 = |o: u64| bp16(o) | (bp16(o + 2) << 16);
    let bps = bp16(0x0B);
    let spc = bp(0x0D) as u32;
    let reserved = bp16(0x0E);
    let nfats = bp(0x10) as u32;
    let spf32 = bp32(0x24);
    let root_cl = bp32(0x2C);
    let is_fat32 = bp(0x52) == b'F' && bp(0x53) == b'A' && bp(0x54) == b'T';
    if bps == 512 && spc >= 1 && is_fat32 {
        Some(Fat32 {
            ahci_vaddr,
            dma_vaddr,
            dma_paddr,
            bps,
            spc,
            fat_start: reserved,
            data_start: reserved + nfats * spf32,
            root_cl,
        })
    } else {
        None
    }
}

/// The executive's on-demand file-buffer POOL: a fresh VA region whose frames are allocated + mapped
/// (into the executive's own VSpace) on demand, one file at a time. Replaces the ~15 fixed staging
/// buffers with a single bump-allocated arena. Each loaded PE's bytes persist here for the run so the
/// demand-fault router can fill hosted-process pages from them (same lifetime as the old buffers).
pub const POOL_VADDR: u64 = 0x0000_0100_1500_0000;
pub const POOL_PTS: u64 = 24; // 48 MiB (24 * 2 MiB) — headroom for the whole stack + P5 binaries
pub(crate) static POOL_NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) static POOL_INITED: AtomicU64 = AtomicU64::new(0);

/// Reserve the pool's page tables in the executive's VSpace (once). Idempotent.
pub(crate) unsafe fn pool_init() {
    if POOL_INITED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    for p in 0..POOL_PTS {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            POOL_VADDR + p * 0x20_0000,
            CAP_INIT_THREAD_VSPACE,
        );
    }
}

/// Allocate `nbytes` (page-rounded) of pool space, mapping fresh RW frames into the executive's
/// VSpace. Returns the base VA, or None if the pool is exhausted. Bump-only (no free) — pool buffers
/// live for the whole run, exactly like the fixed buffers they replace.
pub(crate) unsafe fn pool_alloc(nbytes: u32) -> Option<u64> {
    pool_init();
    let pages = ((nbytes as u64) + 0xFFF) / 0x1000;
    let off = POOL_NEXT.fetch_add(pages * 0x1000, Ordering::Relaxed);
    if off + pages * 0x1000 > POOL_PTS * 0x20_0000 {
        return None;
    }
    let base = POOL_VADDR + off;
    for i in 0..pages {
        let f = alloc_frame();
        let _ = page_map(f, base + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    Some(base)
}

/// Resolve `path` (root-relative, e.g. `b"reactos\\system32\\version.dll"`) on the executive's live
/// volume, read the WHOLE file into a fresh pool buffer, and return `(va, size)`. The bytes stay
/// resident for the run so a PeFile parsed over them + the demand-fault router keep working. This is
/// the single call the per-binary staging blocks collapse into: open path → bytes.
pub(crate) unsafe fn load_file_to_pool(fs: &Fat32, path: &[u8]) -> Option<(u64, u32)> {
    let (cluster, size) = fat_open_path(fs, path)?;
    if size == 0 {
        return None;
    }
    let va = pool_alloc(size)?;
    let read = fat_read_file(fs, cluster, size, va);
    if read < size {
        return None;
    }
    Some((va, size))
}
