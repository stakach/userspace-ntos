//! `fs_loader` — the FAT32-by-path pool loader: mount, directory walk (8.3 + LFN),
//! file read, the demand-load pool, and load_dll_from_fs/hybrid. Extracted verbatim
//! from `main.rs` (pure reorg; no logic change). `struct Fat32` stays in `main.rs`
//! (this child module reaches its private fields).
#![allow(clippy::all)]
use crate::*;

struct DirFindLfnScratch {
    short: [u8; 11],
    want: [u8; 256],
    lfn: [u8; 260],
}

#[repr(C)]
struct FatSectorCacheScratch {
    sector: u32,
    valid: u32,
    data: [u8; 512],
}

const LFN_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
pub(crate) const FAT32_SCRATCH_OFFSET: u64 = 0xA00;
const FAT32_FAT_CACHE_OFFSET: u64 =
    (FAT32_SCRATCH_OFFSET + core::mem::size_of::<DirFindLfnScratch>() as u64 + 7) & !7;
const _: () = assert!(
    FAT32_FAT_CACHE_OFFSET + core::mem::size_of::<FatSectorCacheScratch>() as u64 <= 0x1000
);

const SYSTEM32_CACHE_NAME_CAP: usize = 96;

#[derive(Clone, Copy)]
struct System32CacheEntry {
    name_len: u8,
    attr: u8,
    cluster: u32,
    size: u32,
    name: [u8; SYSTEM32_CACHE_NAME_CAP],
}

impl System32CacheEntry {
    const EMPTY: Self = Self {
        name_len: 0,
        attr: 0,
        cluster: 0,
        size: 0,
        name: [0; SYSTEM32_CACHE_NAME_CAP],
    };
}

const SYSTEM32_CACHE_STATE_BASE: usize = crate::allocator::COMPONENT_LOCAL_WORD_BASE;
const SYSTEM32_CACHE_STATE_PTR: usize = SYSTEM32_CACHE_STATE_BASE;
const SYSTEM32_CACHE_STATE_COUNT: usize = SYSTEM32_CACHE_STATE_BASE + 8;
const SYSTEM32_CACHE_STATE_READY: usize = SYSTEM32_CACHE_STATE_BASE + 16;
const SYSTEM32_CACHE_STATE_CAPACITY: usize = SYSTEM32_CACHE_STATE_BASE + 24;
const SYSTEM32_CACHE_STATE_OVERFLOW: usize = SYSTEM32_CACHE_STATE_BASE + 32;

const _: () = assert!(5 <= crate::allocator::COMPONENT_LOCAL_WORDS);

unsafe fn system32_cache_state_read(offset: usize) -> u64 {
    core::ptr::read_volatile(offset as *const u64)
}

unsafe fn system32_cache_state_write(offset: usize, value: u64) {
    core::ptr::write_volatile(offset as *mut u64, value);
}

unsafe fn system32_cache_entries_mut(capacity: usize) -> Option<&'static mut [System32CacheEntry]> {
    let capacity = capacity.max(1);
    let ptr = system32_cache_state_read(SYSTEM32_CACHE_STATE_PTR) as *mut System32CacheEntry;
    let current_capacity = system32_cache_state_read(SYSTEM32_CACHE_STATE_CAPACITY) as usize;
    if !ptr.is_null() && current_capacity >= capacity {
        return Some(core::slice::from_raw_parts_mut(ptr, current_capacity));
    }

    let bytes = core::mem::size_of::<System32CacheEntry>()
        .checked_mul(capacity)
        .and_then(|bytes| u32::try_from(bytes).ok())?;
    let allocated = pool_alloc(bytes)? as *mut System32CacheEntry;
    system32_cache_state_write(SYSTEM32_CACHE_STATE_PTR, allocated as u64);
    system32_cache_state_write(SYSTEM32_CACHE_STATE_CAPACITY, capacity as u64);
    Some(core::slice::from_raw_parts_mut(allocated, capacity))
}

unsafe fn system32_cache_entries() -> Option<&'static [System32CacheEntry]> {
    let ptr = system32_cache_state_read(SYSTEM32_CACHE_STATE_PTR) as *const System32CacheEntry;
    let capacity = system32_cache_state_read(SYSTEM32_CACHE_STATE_CAPACITY) as usize;
    if ptr.is_null() || capacity == 0 {
        None
    } else {
        Some(core::slice::from_raw_parts(ptr, capacity))
    }
}

/// Read `sector` off the disk (via AHCI) and return a pointer to its 512 bytes.
pub(crate) unsafe fn fat_read_sector(fs: &Fat32, sector: u32) -> *const u8 {
    fat_read_sector_checked(fs, sector)
        .unwrap_or((fs.dma_vaddr + AHCI_DMA_DATA_OFFSET) as *const u8)
}

unsafe fn fat_read_sector_checked(fs: &Fat32, sector: u32) -> Option<*const u8> {
    let census_started = fs.census.then(disk_census_ticks);
    let status = ahci_read_sector(fs.ahci_vaddr, fs.dma_vaddr, fs.dma_paddr, sector as u64);
    disk_census_record(census_started, 1);
    if status == 0xFF {
        print_str(b"[fat-sector] read timeout sector=");
        print_u64(sector as u64);
        print_str(b"\n");
        return None;
    }
    Some((fs.dma_vaddr + AHCI_DMA_DATA_OFFSET) as *const u8)
}

unsafe fn fat_read_sectors_checked(fs: &Fat32, sector: u32, count: u32) -> Option<*const u8> {
    let census_started = fs.census.then(disk_census_ticks);
    let status = ahci_read_sectors(
        fs.ahci_vaddr,
        fs.dma_vaddr,
        fs.dma_paddr,
        sector as u64,
        count,
    );
    disk_census_record(census_started, count as u64);
    if status == 0xFF {
        print_str(b"[fat-sector] read timeout sector=");
        print_u64(sector as u64);
        print_str(b" count=");
        print_u64(count as u64);
        print_str(b"\n");
        return None;
    }
    Some((fs.dma_vaddr + AHCI_DMA_DATA_OFFSET) as *const u8)
}

/// Fold one completed disk command into the census (no-op on the storage host's mount).
fn disk_census_record(started: Option<u64>, sectors: u64) {
    let Some(started) = started else { return };
    AHCI_CMDS.fetch_add(1, Ordering::Relaxed);
    AHCI_SECTORS.fetch_add(sectors, Ordering::Relaxed);
    AHCI_TICKS.fetch_add(disk_census_ticks().wrapping_sub(started), Ordering::Relaxed);
}

unsafe fn fat_cache_invalidate(fs: &Fat32) {
    let cache = &mut *((fs.dma_vaddr + FAT32_FAT_CACHE_OFFSET) as *mut FatSectorCacheScratch);
    cache.valid = 0;
}

/// Write one full FAT sector through the same AHCI DMA frame used by [`fat_read_sector`].
#[allow(dead_code)]
pub(crate) unsafe fn fat_write_sector(fs: &Fat32, sector: u32, data: &[u8]) -> u32 {
    if fs.bps != 512 || data.len() != fs.bps as usize {
        return 0xff;
    }
    core::ptr::copy_nonoverlapping(
        data.as_ptr(),
        (fs.dma_vaddr + AHCI_DMA_DATA_OFFSET) as *mut u8,
        data.len(),
    );
    ahci_write_sector(fs.ahci_vaddr, fs.dma_vaddr, fs.dma_paddr, sector as u64)
}

#[allow(dead_code)]
pub(crate) unsafe fn fat_write_sectors(fs: &Fat32, sector: u32, data: &[u8]) -> u32 {
    if fs.bps != 512 || data.is_empty() || data.len() % fs.bps as usize != 0 {
        return 0xff;
    }
    let sectors = (data.len() / fs.bps as usize) as u32;
    if sectors == 0 || sectors > AHCI_MAX_SECTORS_PER_WRITE {
        return 0xff;
    }
    core::ptr::copy_nonoverlapping(
        data.as_ptr(),
        (fs.dma_vaddr + AHCI_DMA_DATA_OFFSET) as *mut u8,
        data.len(),
    );
    ahci_write_sectors(
        fs.ahci_vaddr,
        fs.dma_vaddr,
        fs.dma_paddr,
        sector as u64,
        sectors,
    )
}

#[allow(dead_code)]
pub(crate) const WRITABLE_SNAPSHOT_RESERVE_BYTES: u32 = 16 * 1024 * 1024;
#[allow(dead_code)]
pub(crate) const WRITABLE_SNAPSHOT_RESERVE_SECTORS: u32 = WRITABLE_SNAPSHOT_RESERVE_BYTES / 512;

/// Return the raw disk region reserved immediately after the FAT-visible volume, if the BPB
/// exposes a finite volume size. The image builder appends this reserve outside FAT metadata.
#[allow(dead_code)]
pub(crate) fn writable_snapshot_reserve(fs: &Fat32) -> Option<(u32, u32)> {
    if fs.total_sectors == 0 {
        return None;
    }
    Some((fs.total_sectors, WRITABLE_SNAPSHOT_RESERVE_SECTORS))
}

/// First disk sector of a cluster.
pub(crate) fn fat_cluster_sector(fs: &Fat32, cluster: u32) -> u32 {
    fs.data_start + (cluster - 2) * fs.spc
}

const FAT_EOC_MIN: u32 = 0x0FFF_FFF8;

/// Follow the FAT: next cluster after `cluster` (>= 0x0FFF_FFF8 means end-of-chain).
pub(crate) unsafe fn fat_next(fs: &Fat32, cluster: u32) -> u32 {
    let byte = cluster * 4;
    let sec = fs.fat_start + byte / fs.bps;
    let off = (byte % fs.bps) as u64;
    let cache = &mut *((fs.dma_vaddr + FAT32_FAT_CACHE_OFFSET) as *mut FatSectorCacheScratch);
    if cache.valid != 1 || cache.sector != sec {
        let p = match fat_read_sector_checked(fs, sec) {
            Some(p) => p,
            None => return 0x0FFF_FFFF,
        };
        core::ptr::copy_nonoverlapping(p, cache.data.as_mut_ptr(), cache.data.len());
        cache.sector = sec;
        cache.valid = 1;
    }
    if off as usize + core::mem::size_of::<u32>() > cache.data.len() {
        return 0x0FFF_FFFF;
    }
    (core::ptr::read_unaligned(cache.data.as_ptr().add(off as usize) as *const u32)) & 0x0FFF_FFFF
}

/// Visit native directory entries in stable FAT stream order. LFN fragments are decoded by the
/// pure `nt-fs` parser after copying each DMA-backed slot to local storage.
pub(crate) unsafe fn fat_visit_directory(
    fs: &Fat32,
    dir_cluster: u32,
    mut visit: impl FnMut(nt_fs::DirectoryEntry, u32) -> bool,
) {
    let mut decoder = nt_fs::FatDirectoryDecoder::new();
    let cluster_bytes = fs.bps.saturating_mul(fs.spc);
    let mut file_index = 0u32;
    let mut cluster = dir_cluster;
    let max_clusters = if fs.spc == 0 {
        0
    } else {
        (fs.total_sectors / fs.spc).min(4096)
    };
    let mut clusters_seen = 0u32;
    while cluster >= 2 && cluster < 0x0fff_fff8 {
        if clusters_seen >= max_clusters {
            print_str(b"[fat-dir] visitor chain overrun cluster=");
            print_u64(dir_cluster as u64);
            print_str(b"\n");
            return;
        }
        clusters_seen += 1;
        for sector in 0..fs.spc {
            let data = match fat_read_sector_checked(fs, fat_cluster_sector(fs, cluster) + sector) {
                Some(data) => data,
                None => return,
            };
            for index in 0..(fs.bps as usize / 32) {
                let mut slot = [0u8; 32];
                core::ptr::copy_nonoverlapping(data.add(index * 32), slot.as_mut_ptr(), slot.len());
                match decoder.consume(&slot, file_index, cluster_bytes) {
                    nt_fs::FatDirectorySlot::End => return,
                    nt_fs::FatDirectorySlot::Skipped => {}
                    nt_fs::FatDirectorySlot::Entry(record) => {
                        if !visit(record.entry, record.first_cluster) {
                            return;
                        }
                    }
                }
                file_index = file_index.saturating_add(32);
            }
        }
        let next = fat_next(fs, cluster);
        if next == cluster {
            return;
        }
        cluster = next;
    }
}

fn component_has_separator(name: &[u8]) -> bool {
    name.iter().any(|byte| *byte == b'\\' || *byte == b'/')
}

fn ascii_units_to_lower(units: &[u16], out: &mut [u8; SYSTEM32_CACHE_NAME_CAP]) -> Option<usize> {
    if units.is_empty() || units.len() > out.len() {
        return None;
    }
    let mut i = 0usize;
    while i < units.len() {
        let unit = units[i];
        if unit > 0x7f || unit == b'\\' as u16 || unit == b'/' as u16 {
            return None;
        }
        out[i] = (unit as u8).to_ascii_lowercase();
        i += 1;
    }
    Some(units.len())
}

unsafe fn system32_cache_insert(
    cache: &mut [System32CacheEntry],
    name: &[u8],
    cluster: u32,
    size: u32,
    attr: u8,
    next: &mut usize,
) {
    if name.is_empty() || name.len() > SYSTEM32_CACHE_NAME_CAP {
        return;
    }
    let mut existing = 0usize;
    while existing < *next {
        let entry = &cache[existing];
        let len = entry.name_len as usize;
        if len == name.len() && entry.name[..len] == *name {
            return;
        }
        existing += 1;
    }
    if *next >= cache.len() {
        let overflow = system32_cache_state_read(SYSTEM32_CACHE_STATE_OVERFLOW);
        system32_cache_state_write(SYSTEM32_CACHE_STATE_OVERFLOW, overflow.saturating_add(1));
        return;
    }
    let entry = &mut cache[*next];
    *entry = System32CacheEntry::EMPTY;
    entry.name_len = name.len() as u8;
    entry.attr = attr;
    entry.cluster = cluster;
    entry.size = size;
    entry.name[..name.len()].copy_from_slice(name);
    *next += 1;
}

fn system32_cache_count_name(units: &[u16], scratch: &mut [u8; SYSTEM32_CACHE_NAME_CAP]) -> usize {
    if ascii_units_to_lower(units, scratch).is_some() {
        1
    } else {
        0
    }
}

unsafe fn system32_cache_candidate_count(fs: &Fat32, system32_cluster: u32) -> usize {
    let mut count = 0usize;
    fat_visit_directory(fs, system32_cluster, |record, _first_cluster| {
        let mut scratch = [0u8; SYSTEM32_CACHE_NAME_CAP];
        count = count.saturating_add(system32_cache_count_name(record.name(), &mut scratch));
        if !record.short_name().is_empty() {
            count =
                count.saturating_add(system32_cache_count_name(record.short_name(), &mut scratch));
        }
        true
    });
    count
}

unsafe fn system32_cache_build(fs: &Fat32) -> bool {
    let Some((reactos_cluster, _, reactos_attr)) = dir_find_lfn(fs, fs.root_cl, b"reactos") else {
        return false;
    };
    if reactos_attr & 0x10 == 0 {
        return false;
    }
    let Some((system32_cluster, _, system32_attr)) = dir_find_lfn(fs, reactos_cluster, b"system32")
    else {
        return false;
    };
    if system32_attr & 0x10 == 0 {
        return false;
    }

    let needed = system32_cache_candidate_count(fs, system32_cluster);
    let Some(cache) = system32_cache_entries_mut(needed) else {
        return false;
    };
    for entry in cache.iter_mut() {
        *entry = System32CacheEntry::EMPTY;
    }
    system32_cache_state_write(SYSTEM32_CACHE_STATE_OVERFLOW, 0);
    let mut next = 0usize;
    fat_visit_directory(fs, system32_cluster, |record, first_cluster| {
        let attr = record.attributes as u8;
        let size = record.end_of_file.min(u32::MAX as u64) as u32;
        let mut name = [0u8; SYSTEM32_CACHE_NAME_CAP];
        if let Some(len) = ascii_units_to_lower(record.name(), &mut name) {
            system32_cache_insert(cache, &name[..len], first_cluster, size, attr, &mut next);
        }
        if !record.short_name().is_empty() {
            let mut alias = [0u8; SYSTEM32_CACHE_NAME_CAP];
            if let Some(len) = ascii_units_to_lower(record.short_name(), &mut alias) {
                system32_cache_insert(cache, &alias[..len], first_cluster, size, attr, &mut next);
            }
        }
        true
    });
    system32_cache_state_write(SYSTEM32_CACHE_STATE_COUNT, next as u64);
    print_str(b"[fat-cache] system32 entries=");
    print_u64(next as u64);
    print_str(b" capacity=");
    print_u64(cache.len() as u64);
    print_str(b" overflow=");
    print_u64(system32_cache_state_read(SYSTEM32_CACHE_STATE_OVERFLOW));
    print_str(b"\n");
    true
}

unsafe fn system32_cache_lookup(fs: &Fat32, leaf: &[u8]) -> Option<(u32, u32, u8)> {
    if leaf.is_empty() || leaf.len() > SYSTEM32_CACHE_NAME_CAP || component_has_separator(leaf) {
        return None;
    }
    if system32_cache_state_read(SYSTEM32_CACHE_STATE_READY) == 0 {
        if !system32_cache_build(fs) {
            return None;
        }
        system32_cache_state_write(SYSTEM32_CACHE_STATE_READY, 1);
    }
    let cache = system32_cache_entries()?;
    let count = (system32_cache_state_read(SYSTEM32_CACHE_STATE_COUNT) as usize).min(cache.len());
    let mut wanted = [0u8; SYSTEM32_CACHE_NAME_CAP];
    let mut i = 0usize;
    while i < leaf.len() {
        wanted[i] = leaf[i].to_ascii_lowercase();
        i += 1;
    }
    let mut index = 0usize;
    while index < count {
        let entry = &cache[index];
        let len = entry.name_len as usize;
        if len == leaf.len() && entry.name[..len] == wanted[..leaf.len()] {
            return Some((entry.cluster, entry.size, entry.attr));
        }
        index += 1;
    }
    None
}

pub(crate) unsafe fn system32_cache_slot_reserve_hint(fs: &Fat32) -> Option<usize> {
    if system32_cache_state_read(SYSTEM32_CACHE_STATE_READY) == 0 {
        if !system32_cache_build(fs) {
            return None;
        }
        system32_cache_state_write(SYSTEM32_CACHE_STATE_READY, 1);
    }
    let count = system32_cache_state_read(SYSTEM32_CACHE_STATE_COUNT) as usize;
    let capacity = system32_cache_state_read(SYSTEM32_CACHE_STATE_CAPACITY) as usize;
    Some(count.min(capacity))
}

fn system32_leaf_from_volume_path(path: &[u8]) -> Option<&[u8]> {
    const PREFIX: &[u8] = b"reactos\\system32\\";
    const ALT_PREFIX: &[u8] = b"reactos/system32/";
    let leaf = if path.len() > PREFIX.len() && path[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        &path[PREFIX.len()..]
    } else if path.len() > ALT_PREFIX.len()
        && path[..ALT_PREFIX.len()].eq_ignore_ascii_case(ALT_PREFIX)
    {
        &path[ALT_PREFIX.len()..]
    } else {
        return None;
    };
    (!component_has_separator(leaf)).then_some(leaf)
}

/// Scan directory `dir_cluster` (following its cluster chain) for the 8.3 name `name11`
/// (11 bytes, space-padded). Returns (first_cluster, size_bytes, attr). LFN / deleted /
/// volume-label / free entries are skipped. Extracts the entry before any further reads.
pub(crate) unsafe fn dir_find(
    fs: &Fat32,
    dir_cluster: u32,
    name11: &[u8; 11],
) -> Option<(u32, u32, u8)> {
    let mut cl = dir_cluster;
    while cl >= 2 && cl < 0x0FFF_FFF8 {
        for s in 0..fs.spc {
            let p = fat_read_sector_checked(fs, fat_cluster_sector(fs, cl) + s)?;
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
pub(crate) unsafe fn fat_read_file(
    fs: &Fat32,
    first_cluster: u32,
    size: u32,
    dest_vaddr: u64,
) -> u32 {
    let mut cl = first_cluster;
    let mut written = 0u32;
    let cluster_bytes = fs.bps.saturating_mul(fs.spc);
    let max_clusters = if cluster_bytes == 0 {
        0
    } else {
        size.div_ceil(cluster_bytes).saturating_add(1)
    };
    let mut clusters_seen = 0u32;
    while cl >= 2 && cl < 0x0FFF_FFF8 && written < size {
        if clusters_seen >= max_clusters {
            print_str(b"[fat-read] cluster chain overrun first=");
            print_u64(first_cluster as u64);
            print_str(b" current=");
            print_u64(cl as u64);
            print_str(b" written=");
            print_u64(written as u64);
            print_str(b" size=");
            print_u64(size as u64);
            print_str(b"\n");
            break;
        }
        if fs.spc == 1 {
            let remaining_bytes = size - written;
            let cluster_limit = remaining_bytes
                .div_ceil(cluster_bytes)
                .min(AHCI_MAX_SECTORS_PER_READ)
                .max(1);
            let mut run_clusters = 1u32;
            let mut last_cluster = cl;
            let mut next_after_run = fat_next(fs, last_cluster);
            while run_clusters < cluster_limit
                && next_after_run == last_cluster.wrapping_add(1)
                && next_after_run < FAT_EOC_MIN
            {
                last_cluster = next_after_run;
                run_clusters += 1;
                next_after_run = fat_next(fs, last_cluster);
            }
            let Some(p) = fat_read_sectors_checked(fs, fat_cluster_sector(fs, cl), run_clusters)
            else {
                return written;
            };
            let bytes = (run_clusters * fs.bps).min(remaining_bytes);
            core::ptr::copy_nonoverlapping(
                p,
                (dest_vaddr + written as u64) as *mut u8,
                bytes as usize,
            );
            if run_clusters > 1 {
                fat_cache_invalidate(fs);
            }
            written += bytes;
            clusters_seen = clusters_seen.saturating_add(run_clusters);
            if next_after_run == last_cluster {
                print_str(b"[fat-read] self-referential cluster chain first=");
                print_u64(first_cluster as u64);
                print_str(b" cluster=");
                print_u64(last_cluster as u64);
                print_str(b"\n");
                break;
            }
            cl = next_after_run;
            continue;
        }

        clusters_seen += 1;
        let mut s = 0u32;
        while s < fs.spc && written < size {
            let remaining_bytes = size - written;
            let sectors = (fs.spc - s)
                .min(remaining_bytes.div_ceil(fs.bps))
                .min(AHCI_MAX_SECTORS_PER_READ)
                .max(1);
            let Some(p) = fat_read_sectors_checked(fs, fat_cluster_sector(fs, cl) + s, sectors)
            else {
                return written;
            };
            let bytes = (sectors * fs.bps).min(remaining_bytes);
            core::ptr::copy_nonoverlapping(
                p,
                (dest_vaddr + written as u64) as *mut u8,
                bytes as usize,
            );
            if sectors > 1 {
                fat_cache_invalidate(fs);
            }
            written += bytes;
            s += sectors;
        }
        let next = fat_next(fs, cl);
        if next == cl {
            print_str(b"[fat-read] self-referential cluster chain first=");
            print_u64(first_cluster as u64);
            print_str(b" cluster=");
            print_u64(cl as u64);
            print_str(b"\n");
            break;
        }
        cl = next;
    }
    written
}

/// Read one byte range from a FAT file into a caller-owned buffer.
pub(crate) unsafe fn fat_read_file_range(
    fs: &Fat32,
    first_cluster: u32,
    size: u32,
    offset: u32,
    output: &mut [u8],
) -> usize {
    if offset >= size || output.is_empty() {
        return 0;
    }
    let wanted = output.len().min((size - offset) as usize);
    let cluster_bytes = fs.spc.saturating_mul(fs.bps);
    if cluster_bytes == 0 {
        return 0;
    }
    let mut cluster = first_cluster;
    let mut skip_clusters = offset / cluster_bytes;
    while skip_clusters != 0 && cluster >= 2 && cluster < 0x0FFF_FFF8 {
        cluster = fat_next(fs, cluster);
        skip_clusters -= 1;
    }
    let mut within_cluster = offset % cluster_bytes;
    let mut written = 0usize;
    while cluster >= 2 && cluster < 0x0FFF_FFF8 && written < wanted {
        for sector in 0..fs.spc {
            let sector_start = sector * fs.bps;
            if within_cluster >= sector_start + fs.bps {
                continue;
            }
            let start = within_cluster.saturating_sub(sector_start) as usize;
            let Some(data) = fat_read_sector_checked(fs, fat_cluster_sector(fs, cluster) + sector)
            else {
                return written;
            };
            let count = (fs.bps as usize - start).min(wanted - written);
            core::ptr::copy_nonoverlapping(
                data.add(start),
                output.as_mut_ptr().add(written),
                count,
            );
            written += count;
            within_cluster = sector_start + fs.bps;
            if written == wanted {
                break;
            }
        }
        within_cluster = 0;
        if written < wanted {
            cluster = fat_next(fs, cluster);
        }
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
pub(crate) unsafe fn dir_find_lfn(
    fs: &Fat32,
    dir_cluster: u32,
    comp: &[u8],
) -> Option<(u32, u32, u8)> {
    let DirFindLfnScratch { short, want, lfn } = &mut *(fs.scratch_vaddr as *mut DirFindLfnScratch);
    name_to_83_into(comp, short);
    // Lowercase the target (ASCII) once.
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
    lfn.fill(0); // reassembled long name (lowercased ASCII)
    let mut term: Option<usize> = None; // index of the 0x0000 terminator, if seen
    let mut hi_ord = 0usize;
    let mut have_lfn = false;
    let mut cl = dir_cluster;
    let max_clusters = if fs.spc == 0 {
        0
    } else {
        (fs.total_sectors / fs.spc).min(4096)
    };
    let mut clusters_seen = 0u32;
    while cl >= 2 && cl < 0x0FFF_FFF8 {
        if clusters_seen >= max_clusters {
            print_str(b"[fat-dir] directory chain overrun cluster=");
            print_u64(dir_cluster as u64);
            print_str(b" component=");
            print_str(comp);
            print_str(b"\n");
            return None;
        }
        clusters_seen += 1;
        for s in 0..fs.spc {
            let p = fat_read_sector_checked(fs, fat_cluster_sector(fs, cl) + s)?;
            for e in 0..(fs.bps as usize / 32) {
                let ent = p.add(e * 32);
                let first = *ent;
                if first == 0x00 {
                    return None; // end of directory
                }
                if first == 0xE5 {
                    have_lfn = false;
                    term = None;
                    hi_ord = 0; // deleted — drop any pending LFN
                    continue;
                }
                let attr = *ent.add(0x0B);
                if attr == 0x0F {
                    // LFN fragment: place its 13 chars at [(ord-1)*13 ..].
                    let ord = (first & 0x1F) as usize;
                    if ord >= 1 && ord <= 20 {
                        have_lfn = true;
                        if ord > hi_ord {
                            hi_ord = ord;
                        }
                        let base = (ord - 1) * 13;
                        let mut k = 0;
                        while k < 13 {
                            let o = LFN_OFFSETS[k];
                            let lo = *ent.add(o);
                            let hi = *ent.add(o + 1);
                            let idx = base + k;
                            if idx < 260 {
                                if lo == 0 && hi == 0 {
                                    if term.is_none() {
                                        term = Some(idx);
                                    }
                                } else if !(lo == 0xFF && hi == 0xFF) {
                                    lfn[idx] = if hi == 0 {
                                        if lo.is_ascii_uppercase() {
                                            lo + 32
                                        } else {
                                            lo
                                        }
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
                    have_lfn = false;
                    term = None;
                    hi_ord = 0; // volume label
                    continue;
                }
                // 8.3 entry: decide match against the long name (if any) or the short name.
                let matched = if have_lfn {
                    let len = term.unwrap_or(hi_ord * 13);
                    len == want_len && {
                        let mut m = true;
                        let mut j = 0;
                        while j < len {
                            if lfn[j] != want[j] {
                                m = false;
                                break;
                            }
                            j += 1;
                        }
                        m
                    }
                } else {
                    fits_83 && {
                        let mut m = true;
                        let mut j = 0;
                        while j < 11 {
                            if *ent.add(j) != short[j] {
                                m = false;
                                break;
                            }
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
                have_lfn = false;
                term = None;
                hi_ord = 0;
            }
        }
        let next = fat_next(fs, cl);
        if next == cl {
            print_str(b"[fat-dir] self-referential directory chain cluster=");
            print_u64(dir_cluster as u64);
            print_str(b" component=");
            print_str(comp);
            print_str(b"\n");
            return None;
        }
        cl = next;
    }
    None
}

/// Convert one path component (e.g. `b"ntdll.dll"`) to a space-padded 8.3 FAT short name.
/// ASCII-uppercases; splits on the LAST '.' (a leading dot is treated as part of the base);
/// truncates base to 8 and extension to 3. Good enough for the ReactOS install tree, whose
/// names (`reactos`, `system32`, `ntdll.dll`, …) all have clean 8.3 aliases — verified: mcopy
/// stores the uppercased 8.3 short entry (`REACTOS`, `SYSTEM32`, `NTDLL   DLL`) alongside an
/// LFN, and `dir_find` matches the short entry (skipping LFN fragments). No `~1` mangling.
fn name_to_83_into(comp: &[u8], out: &mut [u8; 11]) {
    out.fill(b' ');
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
}

/// Resolve a `\`- or `/`-separated PATH (e.g. `b"reactos\\system32\\ntdll.dll"`) from the
/// volume root, walking each component with `dir_find`. Returns `(first_cluster, size)` of the
/// final file, or `None` if any component is missing. 8.3 short names only (no LFN reassembly)
/// — sufficient for the real ReactOS tree, whose names carry clean 8.3 aliases. Each non-final
/// component must be a directory (FAT attr bit 0x10). This is the FS-backed-by-path primitive:
/// the seam a full `\SystemRoot\system32\X` loader generalizes (see P7).
unsafe fn fat_open_path_entry_inner(
    fs: &Fat32,
    start_cluster: u32,
    path: &[u8],
    use_system32_cache: bool,
) -> Option<(u32, u32, u8)> {
    if use_system32_cache && start_cluster == fs.root_cl {
        if let Some(leaf) = system32_leaf_from_volume_path(path) {
            if let Some(entry) = system32_cache_lookup(fs, leaf) {
                return Some(entry);
            }
        }
    }
    let mut cur = start_cluster;
    let mut start = 0usize;
    let mut i = 0usize;
    let mut result: Option<(u32, u32, u8)> = None;
    while i <= path.len() {
        let is_sep = i == path.len() || path[i] == b'\\' || path[i] == b'/';
        if is_sep {
            if i > start {
                let (cl, sz, attr) = dir_find_lfn(fs, cur, &path[start..i])?;
                if i == path.len() {
                    result = Some((cl, sz, attr));
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

pub(crate) unsafe fn fat_open_path_entry(fs: &Fat32, path: &[u8]) -> Option<(u32, u32, u8)> {
    fat_open_path_entry_inner(fs, fs.root_cl, path, true)
}

pub(crate) unsafe fn fat_open_path_entry_uncached(
    fs: &Fat32,
    path: &[u8],
) -> Option<(u32, u32, u8)> {
    fat_open_path_entry_inner(fs, fs.root_cl, path, false)
}

/// Resolve a canonical relative path beneath an already-open FAT directory. Directory handles
/// carry the directory's first cluster, so this preserves identity across namespace traversal
/// without reconstructing an absolute path.
pub(crate) unsafe fn fat_open_path_entry_from(
    fs: &Fat32,
    start_cluster: u32,
    path: &[u8],
) -> Option<(u32, u32, u8)> {
    if path.is_empty() {
        Some((start_cluster, 0, 0x10))
    } else {
        fat_open_path_entry_inner(fs, start_cluster, path, false)
    }
}

pub(crate) unsafe fn fat_open_path_uncached(fs: &Fat32, path: &[u8]) -> Option<(u32, u32)> {
    let (cluster, size, attributes) = fat_open_path_entry_uncached(fs, path)?;
    (attributes & 0x10 == 0).then_some((cluster, size))
}

pub(crate) unsafe fn fat_open_path(fs: &Fat32, path: &[u8]) -> Option<(u32, u32)> {
    let (cluster, size, attributes) = fat_open_path_entry(fs, path)?;
    (attributes & 0x10 == 0).then_some((cluster, size))
}

unsafe fn open_sys32_path(fs: &Fat32, leaf: &[u8], use_system32_cache: bool) -> Option<(u32, u32)> {
    if use_system32_cache {
        if let Some(entry) = system32_cache_lookup(fs, leaf) {
            if entry.2 & 0x10 == 0 {
                return Some((entry.0, entry.1));
            }
            return None;
        }
    }
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
    if use_system32_cache {
        fat_open_path(fs, &path[..n])
    } else {
        fat_open_path_uncached(fs, &path[..n])
    }
}

/// Open `\reactos\system32\<leaf>` from the volume (the common ReactOS binary location) via the
/// LFN-aware path walk. Returns `(first_cluster, size)`. Builds the path in a stack buffer (the
/// storage host has no allocator). `leaf` may itself contain `\` for a sub-dir (e.g.
/// `b"drivers\\dxg.sys"`, `b"config\\system"`).
pub(crate) unsafe fn open_sys32(fs: &Fat32, leaf: &[u8]) -> Option<(u32, u32)> {
    open_sys32_path(fs, leaf, true)
}

/// Same path walk as [`open_sys32`], but without touching the executive's System32 cache.
///
/// The isolated storage host runs with the shared executive image mapped read-only and must never call
/// rootserver services such as cap allocation or the file pool. It can still do the real FAT walk and
/// copy bytes into its granted staging buffers.
pub(crate) unsafe fn open_sys32_uncached(fs: &Fat32, leaf: &[u8]) -> Option<(u32, u32)> {
    open_sys32_path(fs, leaf, false)
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

pub(crate) unsafe fn query_nt_path_attributes_into(
    name: &[u16],
    folded: &mut [u8],
    relative: &mut [u8],
) -> Option<u32> {
    let len = nt_fs::nt_path_to_volume_relative_into(name, b"reactos", folded, relative)?;
    if len == 0 {
        return Some(nt_fs::FILE_ATTRIBUTE_DIRECTORY);
    }
    let fs = exec_fs()?;
    let (_, _, fat_attributes) = fat_open_path_entry(&fs, &relative[..len])?;
    Some(nt_fs::file_attributes_from_fat(fat_attributes))
}

pub(crate) unsafe fn query_nt_path_standard_info_into(
    name: &[u16],
    folded: &mut [u8],
    relative: &mut [u8],
) -> Option<nt_fs::StandardInformation> {
    let len = nt_fs::nt_path_to_volume_relative_into(name, b"reactos", folded, relative)?;
    if len == 0 {
        return Some(nt_fs::StandardInformation {
            end_of_file: 0,
            is_directory: true,
            attributes: nt_fs::FILE_ATTRIBUTE_DIRECTORY,
        });
    }
    let fs = exec_fs()?;
    let (_, size, fat_attributes) = fat_open_path_entry(&fs, &relative[..len])?;
    let attributes = nt_fs::file_attributes_from_fat(fat_attributes);
    Some(nt_fs::StandardInformation {
        end_of_file: size as u64,
        is_directory: attributes & nt_fs::FILE_ATTRIBUTE_DIRECTORY != 0,
        attributes,
    })
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
/// bytes stay resident in the pool for the demand-fault router), or `(None, 0)` when the file is not
/// available as a valid PE. `name` is for the boot log.
pub(crate) unsafe fn load_dll_from_fs(
    path: &[u8],
    name: &[u8],
) -> (Option<nt_pe_loader::PeFile<'static>>, u64) {
    print_str(b"[ntos-exec] FS-by-path begin ");
    print_str(name);
    print_str(b" path=");
    print_str(path);
    print_str(b"\n");
    if let Some(fs) = exec_fs() {
        if let Some((va, sz)) = load_file_to_pool(&fs, path) {
            print_str(b"[ntos-exec] FS-by-path read ");
            print_str(name);
            print_str(b" bytes=");
            print_u64(sz as u64);
            print_str(b" @pool=0x");
            print_hex((va >> 32) as u32);
            print_hex(va as u32);
            print_str(b"\n");
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
            print_str(b": PARSE FAILED\n");
        } else {
            print_str(b"[ntos-exec] FS-by-path ");
            print_str(name);
            print_str(b": LOAD FAILED\n");
        }
    } else {
        print_str(b"[ntos-exec] FS-by-path ");
        print_str(name);
        print_str(b": NO FS\n");
    }
    (None, 0)
}

fn last_path_component_start(name: &[u8]) -> usize {
    // Find the last path separator; the leaf is everything after it.
    name.iter()
        .rposition(|&c| c == b'\\' || c == b'/')
        .map(|p| p + 1)
        .unwrap_or(0)
}

fn path_has_root_prefix(name: &[u8]) -> bool {
    name.first()
        .copied()
        .is_some_and(|c| c == b'\\' || c == b'/')
        || (name.len() >= 2 && name[1] == b':')
}

/// Convert a loader probe into the path that should be looked up below `\reactos\system32`.
/// Full DOS/NT paths keep the suffix after their `system32` component (for example
/// `c:\windows\system32\wbem\wmisvc.dll` -> `wbem\wmisvc.dll`), while already-relative loader paths
/// keep their subdirectories. Absolute paths outside System32 return an empty path here: callers
/// that support full paths must resolve them through the exact mounted-volume path, not through the
/// System32 search.
pub(crate) fn sys32_probe_relative_path(name: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= name.len() {
        let is_sep = i == name.len() || name[i] == b'\\' || name[i] == b'/';
        if is_sep {
            if i > start && name[start..i].eq_ignore_ascii_case(b"system32") {
                let mut rel = i + 1;
                while rel < name.len() && (name[rel] == b'\\' || name[rel] == b'/') {
                    rel += 1;
                }
                if rel < name.len() {
                    return &name[rel..];
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    if !path_has_root_prefix(name) && last_path_component_start(name) != 0 {
        name
    } else if !path_has_root_prefix(name) {
        &name[last_path_component_start(name)..]
    } else {
        b""
    }
}

/// Extract a default System32-relative image path and registry key from a folded requested object
/// name. `.dll` keeps the historical extensionless key; an explicit `.drv` keeps its full leaf
/// because registry normalization strips only the default DLL extension. Full paths still key by the
/// final component; `open_dll_read_result` decides whether to read an exact mounted-volume path or
/// use the returned System32-relative fallback.
fn split_dll_leaf(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let fallback = sys32_probe_relative_path(name);
    let leaf = &name[last_path_component_start(name)..];
    if leaf.len() < 5 {
        return None;
    }
    if leaf.ends_with(b".dll") {
        Some((fallback, &leaf[..leaf.len() - 4]))
    } else if leaf.ends_with(b".drv") {
        Some((fallback, leaf))
    } else {
        None
    }
}

/// Demand-load failure reason, kept compact so serial logs can identify the exact missing mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DemandLoadError {
    UnsupportedImageName,
    SxsProbe,
    DeniedDiverter,
    RegistrySlotAllocationFailed,
    StoreAllocationFailed { slot: usize },
    NoMountedFs,
    FileMissing,
    EmptyFile,
    PoolExhausted { size: u32 },
    ShortRead { expected: u32, actual: u32 },
    PeParseFailed,
    ArenaExhausted { image_size: u64 },
}

impl DemandLoadError {
    pub(crate) fn tag(self) -> &'static [u8] {
        match self {
            DemandLoadError::UnsupportedImageName => b"unsupported-name",
            DemandLoadError::SxsProbe => b"sxs-probe",
            DemandLoadError::DeniedDiverter => b"denied-diverter",
            DemandLoadError::RegistrySlotAllocationFailed => b"registry-slot-allocation-failed",
            DemandLoadError::StoreAllocationFailed { .. } => b"store-allocation-failed",
            DemandLoadError::NoMountedFs => b"no-mounted-fs",
            DemandLoadError::FileMissing => b"file-missing",
            DemandLoadError::EmptyFile => b"empty-file",
            DemandLoadError::PoolExhausted { .. } => b"pool-exhausted",
            DemandLoadError::ShortRead { .. } => b"short-read",
            DemandLoadError::PeParseFailed => b"pe-parse-failed",
            DemandLoadError::ArenaExhausted { .. } => b"arena-exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DemandLoadResult {
    pub slot: usize,
}

/// TRUE syscall-time demand-load: on a `resolve_name` MISS, resolve the requested DLL BY PATH from
/// the mounted ReactOS volume (or the default `\reactos\system32` search for bare dependency
/// names), load its bytes into the (reset-safe, cap-mapped) pool, claim a
/// registry/store slot, activate it (stem + geometry, assigning a compact collision-free base),
/// relocate the pool bytes to that base + patch its ImageBase, store the parsed `PeFile` into the
/// caller's `dll_pe_store`, and return the slot index. The demand-fault router + the
/// NtOpenFile→NtCreateSection→NtMapViewOfSection flow then treat it exactly like a boot-registered
/// DLL (no code-path difference — it operates on the PE store slice + the registry).
///
/// PERSISTENCE: the pool bytes live in the atomic-`POOL_NEXT` cap-mapped arena (NOT the bump heap →
/// survives the per-syscall reset). The service loop pre-reserves slots from the live System32 cache
/// before the heap mark, and a miss beyond that reserve grows the registry + PE store through checked
/// vector admission. The service loop pins the durable heap mark when that store reports growth.
/// Transient path, import, and relocation vectors from this syscall are reclaimed by the normal
/// per-syscall rewind.
///
/// # Safety
/// `store` and `reg` must be the live loop-owned DLL metadata stores. Single-threaded executive; no
/// aliasing.
pub(crate) unsafe fn demand_load_dll_result(
    reg: &mut nt_dll_registry::Registry,
    store: &mut DllPeStore,
    folded_name: &[u8],
) -> Result<DemandLoadResult, DemandLoadError> {
    let (leaf, stem) = split_dll_leaf(folded_name).ok_or(DemandLoadError::UnsupportedImageName)?;
    // Reject SxS/actctx probes (the registry's own rule) so we never demand-load a manifest as a DLL.
    if nt_dll_registry::Registry::is_sxs_probe(folded_name) {
        return Err(DemandLoadError::SxsProbe);
    }
    // BEHAVIORAL-PARITY DENYLIST (a tiny documented set, NOT a content list): a few System32 DLLs,
    // if satisfied, DIVERT a hosted process down an optional side-path the boot must NOT take at the
    // current frontier. The curated eager table historically EXCLUDED these (its open failed → the
    // loader gracefully degraded + proceeded), so demand-loading them is a REGRESSION, not progress:
    //   • apphelp — the Application-Compatibility shim engine CreateProcessW loads to check for shims.
    //     Loading it makes winlogon run the shim path (extra unserviceable NtCreateSection) and it
    //     never reaches NtCreateProcess(services.exe) → services/lsass never spawn. Real Windows has
    //     the app-compat database; we don't, so degrading (as the eager path did) is correct here.
    // This is the ONE place the "load anything by-path" policy is deliberately narrowed for boot
    // parity — a denylist of DIVERTERS, not an allowlist of content. Revisit when the diverted
    // side-path (app-compat DB) is actually implemented.
    if stem == b"apphelp" {
        return Err(DemandLoadError::DeniedDiverter);
    }
    let slot = if let Some(slot) = reg.first_free() {
        if store.ensure_slot(slot).is_err() {
            return Err(DemandLoadError::StoreAllocationFailed { slot });
        }
        slot
    } else {
        let slot = reg.len();
        if store.ensure_slot(slot).is_err() {
            return Err(DemandLoadError::StoreAllocationFailed { slot });
        }
        let reserved = reg
            .try_reserve_slot()
            .map_err(|_| DemandLoadError::RegistrySlotAllocationFailed)?;
        debug_assert_eq!(reserved, slot);
        reserved
    };
    let fs = exec_fs().ok_or(DemandLoadError::NoMountedFs)?;
    let (va, sz) = open_dll_read_result(&fs, folded_name, leaf)?;
    let bytes: &'static [u8] = core::slice::from_raw_parts(va as *const u8, sz as usize);
    let pe = nt_pe_loader::PeFile::parse(bytes).map_err(|_| DemandLoadError::PeParseFailed)?;
    let ext = image_extent(&pe);
    let entry = pe.entry_point_rva();
    // Claim the reserved slot and compact VA range. Arena exhaustion is a truthful load failure.
    if !reg.activate(slot, stem, ext, entry) {
        return Err(DemandLoadError::ArenaExhausted { image_size: ext });
    }
    let base = reg.base(slot);
    // Relocate to the compact arena base + patch OptionalHeader.ImageBase.
    apply_relocations_to_buf(&pe, va, base);
    let e_lfanew = core::ptr::read_volatile((va + 0x3c) as *const u32) as u64;
    core::ptr::write_volatile((va + e_lfanew + 0x30) as *mut u64, base);
    store
        .set(slot, Some(pe))
        .map_err(|_| DemandLoadError::StoreAllocationFailed { slot })?;
    crate::bump_progress(); // (B) a NEW DLL loaded = unambiguous forward progress (resets stall)
                            // samsrv.dll — lsass' SAM server. lsasrv/lsass resolve it at runtime; nothing in the executive
                            // names it, so a genuine by-path demand-load is the ONLY way it can appear. Recorded for the
                            // `exec_samsrv_hosted` gate spec (with its real on-disk byte size).
    if stem == b"samsrv" {
        crate::SAMSRV_LOADED_SIZE.store(sz as u64, core::sync::atomic::Ordering::Relaxed);
    }
    print_str(b"[ntos-exec] DEMAND-LOAD ");
    print_str(stem);
    print_str(b" (");
    print_u64(sz as u64);
    print_str(b" B) -> slot ");
    print_u64(slot as u64);
    print_str(b" base 0x");
    print_hex(base as u32);
    print_str(b"\n");
    Ok(DemandLoadResult { slot })
}

fn is_rooted_or_device_path(name: &[u8]) -> bool {
    name.starts_with(b"\\")
        || name.starts_with(b"/")
        || name.get(1).is_some_and(|byte| *byte == b':')
}

fn push_path_byte(out: &mut [u8], n: &mut usize, byte: u8) -> Option<()> {
    if *n >= out.len() {
        return None;
    }
    out[*n] = if byte == b'/' { b'\\' } else { byte };
    *n += 1;
    Some(())
}

fn push_path_component(out: &mut [u8], n: &mut usize, component: &[u8]) -> Option<()> {
    if component.is_empty() || component == b"." {
        return Some(());
    }
    if component == b".." || component.contains(&b':') {
        return None;
    }
    if *n != 0 {
        push_path_byte(out, n, b'\\')?;
    }
    for &byte in component {
        push_path_byte(out, n, byte.to_ascii_lowercase())?;
    }
    Some(())
}

fn push_path_suffix(out: &mut [u8], n: &mut usize, suffix: &[u8]) -> Option<()> {
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= suffix.len() {
        let is_sep = i == suffix.len() || suffix[i] == b'\\' || suffix[i] == b'/';
        if is_sep {
            push_path_component(out, n, &suffix[start..i])?;
            start = i + 1;
        }
        i += 1;
    }
    Some(())
}

fn drive_path_to_volume_relative_into(path_after_drive: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut n = 0usize;
    let mut relative = path_after_drive;
    while relative.starts_with(b"\\") || relative.starts_with(b"/") {
        relative = &relative[1..];
    }
    if relative == b"windows"
        || relative.starts_with(b"windows\\")
        || relative.starts_with(b"windows/")
    {
        push_path_component(out, &mut n, b"reactos")?;
        push_path_suffix(out, &mut n, &relative[b"windows".len()..])?;
    } else {
        push_path_suffix(out, &mut n, relative)?;
    }
    Some(n)
}

fn folded_dll_path_to_volume_relative_into(path: &[u8], out: &mut [u8]) -> Option<usize> {
    let system_prefix = b"\\systemroot";
    if path.starts_with(system_prefix)
        && path
            .get(system_prefix.len())
            .is_none_or(|byte| *byte == b'\\' || *byte == b'/')
    {
        let mut n = 0usize;
        push_path_component(out, &mut n, b"reactos")?;
        push_path_suffix(out, &mut n, &path[system_prefix.len()..])?;
        return Some(n);
    }

    let mut p = path;
    if let Some(rest) = p.strip_prefix(b"\\??\\") {
        p = rest;
    } else if let Some(rest) = p.strip_prefix(b"\\dosdevices\\") {
        p = rest;
    }
    if p.len() >= 3 && p[0] == b'c' && p[1] == b':' && (p[2] == b'\\' || p[2] == b'/') {
        return drive_path_to_volume_relative_into(&p[2..], out);
    }
    None
}

unsafe fn open_volume_relative_read_result(
    fs: &Fat32,
    path: &[u8],
) -> Result<(u64, u32), DemandLoadError> {
    let (cluster, size) = fat_open_path(fs, path).ok_or(DemandLoadError::FileMissing)?;
    open_cluster_read_result(fs, cluster, size)
}

unsafe fn open_cluster_read_result(
    fs: &Fat32,
    cluster: u32,
    size: u32,
) -> Result<(u64, u32), DemandLoadError> {
    if size == 0 {
        return Err(DemandLoadError::EmptyFile);
    }
    let va = pool_alloc(size).ok_or(DemandLoadError::PoolExhausted { size })?;
    let read = fat_read_file(fs, cluster, size, va);
    if read < size {
        return Err(DemandLoadError::ShortRead {
            expected: size,
            actual: read,
        });
    }
    Ok((va, size))
}

unsafe fn open_dll_read_result(
    fs: &Fat32,
    folded_name: &[u8],
    sys32_relative: &[u8],
) -> Result<(u64, u32), DemandLoadError> {
    let mut relative = [0u8; 192];
    if let Some(relative_len) = folded_dll_path_to_volume_relative_into(folded_name, &mut relative)
    {
        return open_volume_relative_read_result(fs, &relative[..relative_len]);
    }
    if is_rooted_or_device_path(folded_name) {
        return Err(DemandLoadError::FileMissing);
    }
    let fallback = if !sys32_relative.is_empty() {
        sys32_relative
    } else {
        &folded_name[last_path_component_start(folded_name)..]
    };
    open_sys32_read_result(fs, fallback)
}

/// Read `\reactos\system32\<leaf>` into a fresh pool buffer, returning `(va, size)`. Like
/// `load_file_to_pool` but with the System32 prefix built in.
unsafe fn open_sys32_read_result(fs: &Fat32, leaf: &[u8]) -> Result<(u64, u32), DemandLoadError> {
    print_str(b"[diag-fat-load] open-sys32 ");
    print_str(leaf);
    print_str(b"\n");
    let (cluster, size) = open_sys32(fs, leaf).ok_or(DemandLoadError::FileMissing)?;
    print_str(b"[diag-fat-load] read cluster=");
    print_u64(cluster as u64);
    print_str(b" size=");
    print_u64(size as u64);
    print_str(b"\n");
    open_cluster_read_result(fs, cluster, size)
}

/// Mount the FAT32 volume bound to the given AHCI/DMA mappings: read sector 0, parse the BPB.
/// Same BPB layout `storage_probe` parses; factored so both the host and the executive can mount.
pub(crate) unsafe fn fat32_mount(ahci_vaddr: u64, dma_vaddr: u64, dma_paddr: u64) -> Option<Fat32> {
    if ahci_read_sector(ahci_vaddr, dma_vaddr, dma_paddr, 0) == 0xFF {
        print_str(b"[fat-sector] read timeout sector=0\n");
        return None;
    }
    let bp = |o: u64| core::ptr::read_volatile((dma_vaddr + 0x800 + o) as *const u8);
    let bp16 = |o: u64| (bp(o) as u32) | ((bp(o + 1) as u32) << 8);
    let bp32 = |o: u64| bp16(o) | (bp16(o + 2) << 16);
    let bps = bp16(0x0B);
    let spc = bp(0x0D) as u32;
    let reserved = bp16(0x0E);
    let nfats = bp(0x10) as u32;
    let total16 = bp16(0x13);
    let total32 = bp32(0x20);
    let total_sectors = if total16 != 0 { total16 } else { total32 };
    let spf32 = bp32(0x24);
    let root_cl = bp32(0x2C);
    let is_fat32 = bp(0x52) == b'F' && bp(0x53) == b'A' && bp(0x54) == b'T';
    if bps == 512 && spc >= 1 && is_fat32 {
        Some(Fat32 {
            census: true,
            ahci_vaddr,
            dma_vaddr,
            dma_paddr,
            scratch_vaddr: dma_vaddr + FAT32_SCRATCH_OFFSET,
            bps,
            spc,
            total_sectors,
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
pub(crate) unsafe fn pool_init() -> bool {
    if POOL_INITED.load(Ordering::Relaxed) != 0 {
        return true;
    }
    for p in 0..POOL_PTS {
        let pt = alloc_slot();
        let retype_error =
            untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        if retype_error != 0 {
            print_str(b"[file-pool] page-table retype failed slot=0x");
            print_hex((pt >> 32) as u32);
            print_hex(pt as u32);
            print_str(b" error=");
            print_u64(retype_error);
            print_str(b"\n");
            return false;
        }
        let va = POOL_VADDR + p * 0x20_0000;
        let map_error = paging_struct_map_r(pt, LBL_X86_PAGE_TABLE_MAP, va, CAP_INIT_THREAD_VSPACE);
        if map_error != 0 {
            print_str(b"[file-pool] page-table map failed slot=0x");
            print_hex((pt >> 32) as u32);
            print_hex(pt as u32);
            print_str(b" va=0x");
            print_hex((va >> 32) as u32);
            print_hex(va as u32);
            print_str(b" error=");
            print_u64(map_error);
            print_str(b"\n");
            let _ = cnode_delete_recycle_r(pt);
            return false;
        }
    }
    POOL_INITED.store(1, Ordering::Relaxed);
    true
}

/// Allocate `nbytes` (page-rounded) of pool space, mapping fresh RW frames into the executive's
/// VSpace. Returns the base VA, or None if the pool is exhausted. Bump-only (no free) — pool buffers
/// live for the whole run, exactly like the fixed buffers they replace.
pub(crate) unsafe fn pool_alloc(nbytes: u32) -> Option<u64> {
    if !pool_init() {
        return None;
    }
    let pages = ((nbytes as u64) + 0xFFF) / 0x1000;
    let off = POOL_NEXT.fetch_add(pages * 0x1000, Ordering::Relaxed);
    if off + pages * 0x1000 > POOL_PTS * 0x20_0000 {
        print_str(b"[file-pool] exhausted request=");
        print_u64(nbytes as u64);
        print_str(b" used=");
        print_u64(off);
        print_str(b" cap=");
        print_u64(POOL_PTS * 0x20_0000);
        print_str(b"\n");
        return None;
    }
    let base = POOL_VADDR + off;
    for i in 0..pages {
        let (f, frame_error) = alloc_frame_r();
        if frame_error != 0 || f == 0 {
            print_str(b"[file-pool] frame retype failed va=0x");
            let va = base + i * 0x1000;
            print_hex((va >> 32) as u32);
            print_hex(va as u32);
            print_str(b" error=");
            print_u64(frame_error);
            print_str(b"\n");
            return None;
        }
        let va = base + i * 0x1000;
        let map_error = page_map_r(f, va, RW_NX, CAP_INIT_THREAD_VSPACE);
        if map_error != 0 {
            print_str(b"[file-pool] frame map failed frame=0x");
            print_hex((f >> 32) as u32);
            print_hex(f as u32);
            print_str(b" va=0x");
            print_hex((va >> 32) as u32);
            print_hex(va as u32);
            print_str(b" error=");
            print_u64(map_error);
            print_str(b"\n");
            let _ = cnode_delete_recycle_r(f);
            return None;
        }
    }
    Some(base)
}

/// Resolve `path` (root-relative, e.g. `b"reactos\\system32\\version.dll"`) on the executive's live
/// volume, read the WHOLE file into a fresh pool buffer, and return `(va, size)`. The bytes stay
/// resident for the run so a PeFile parsed over them + the demand-fault router keep working. This is
/// the single call the per-binary staging blocks collapse into: open path → bytes.
pub(crate) unsafe fn load_file_to_pool(fs: &Fat32, path: &[u8]) -> Option<(u64, u32)> {
    print_str(b"[fat-load] open begin path=");
    print_str(path);
    print_str(b"\n");
    let (cluster, size) = fat_open_path(fs, path)?;
    print_str(b"[fat-load] open end cluster=");
    print_u64(cluster as u64);
    print_str(b" size=");
    print_u64(size as u64);
    print_str(b"\n");
    if size == 0 {
        return None;
    }
    let va = pool_alloc(size)?;
    print_str(b"[fat-load] read begin size=");
    print_u64(size as u64);
    print_str(b" va=0x");
    print_hex((va >> 32) as u32);
    print_hex(va as u32);
    print_str(b"\n");
    let read = fat_read_file(fs, cluster, size, va);
    print_str(b"[fat-load] read end actual=");
    print_u64(read as u64);
    print_str(b" expected=");
    print_u64(size as u64);
    print_str(b"\n");
    if read < size {
        return None;
    }
    Some((va, size))
}
