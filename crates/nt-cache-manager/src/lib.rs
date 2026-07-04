//! # `nt-cache-manager` — NT Cache Manager (section-backed file cache)
//!
//! The NT Cache Manager (spec: NT Cache Manager + Section-Backed File Cache): a per-stream
//! [`SharedCacheMap`] of 4 KiB [`CachePage`]s over a filesystem-neutral [`CachedStreamBacking`],
//! exposing the `Cc*` file-cache exports a WDM/FS driver calls:
//!
//! - [`SharedCacheMap::cc_copy_read`] / [`SharedCacheMap::cc_copy_write`] — cached I/O (a read
//!   miss faults a page in from the backing store; a write dirties the page + extends EOF).
//! - [`SharedCacheMap::cc_flush_cache`] — write dirty pages back to the backing store.
//! - [`SharedCacheMap::cc_set_file_sizes`] — truncate/extend (dropping cached pages past EOF).
//! - pin/unpin ([`Bcb`]), a [`SharedCacheMap::lazy_write_pass`], and LRU [`SharedCacheMap::evict`].
//!
//! Cached I/O goes through pages; noncached I/O bypasses the cache (spec §6.4). `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const PAGE_SIZE: usize = 4096;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;

/// The three NT stream sizes (spec §15, `CC_FILE_SIZES`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileSizes {
    pub allocation_size: u64,
    pub file_size: u64,
    pub valid_data_length: u64,
}

/// The filesystem-neutral backing a cache map reads/writes through (spec §10.2). For MemFs this
/// is the file's byte store; for a real FS it would dispatch paging I/O.
pub trait CachedStreamBacking {
    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, u32>;
    fn write_at(&mut self, offset: u64, src: &[u8]) -> Result<usize, u32>;
    fn flush(&mut self) -> Result<(), u32>;
    fn set_file_size(&mut self, file_size: u64) -> Result<(), u32>;
}

/// An in-memory backing store — the unit-test + fixture backing (models MemFs file bytes).
#[derive(Default)]
pub struct MemoryBacking {
    pub bytes: Vec<u8>,
    pub flushes: u32,
}

impl MemoryBacking {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes, flushes: 0 }
    }
}

impl CachedStreamBacking for MemoryBacking {
    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, u32> {
        let start = (offset as usize).min(self.bytes.len());
        let n = dst.len().min(self.bytes.len() - start);
        dst[..n].copy_from_slice(&self.bytes[start..start + n]);
        Ok(n)
    }
    fn write_at(&mut self, offset: u64, src: &[u8]) -> Result<usize, u32> {
        let start = offset as usize;
        if start + src.len() > self.bytes.len() {
            self.bytes.resize(start + src.len(), 0);
        }
        self.bytes[start..start + src.len()].copy_from_slice(src);
        Ok(src.len())
    }
    fn flush(&mut self) -> Result<(), u32> {
        self.flushes += 1;
        Ok(())
    }
    fn set_file_size(&mut self, file_size: u64) -> Result<(), u32> {
        self.bytes.resize(file_size as usize, 0);
        Ok(())
    }
}

/// A cached 4 KiB page of a stream (spec §9.1).
struct CachePage {
    data: Box<[u8; PAGE_SIZE]>,
    valid_len: u16,
    dirty: bool,
    pinned: u32,
    last_access_tick: u64,
}

impl CachePage {
    fn empty() -> Self {
        CachePage {
            data: Box::new([0u8; PAGE_SIZE]),
            valid_len: 0,
            dirty: false,
            pinned: 0,
            last_access_tick: 0,
        }
    }
}

/// A pin handle over a range of cache pages (spec §16.1, `PUBLIC_BCB`).
pub struct Bcb {
    pages: Vec<u64>,
}

impl Bcb {
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

/// The per-stream cached state (spec §8.1): 4 KiB pages over a [`CachedStreamBacking`].
pub struct SharedCacheMap<B: CachedStreamBacking> {
    backing: B,
    file_size: u64,
    valid_data_length: u64,
    allocation_size: u64,
    pin_access: bool,
    pages: BTreeMap<u64, CachePage>,
    tick: u64,
}

impl<B: CachedStreamBacking> SharedCacheMap<B> {
    /// `CcInitializeCacheMap` (spec §11): create the cache map for a stream over `backing`.
    pub fn cc_initialize_cache_map(backing: B, sizes: FileSizes, pin_access: bool) -> Self {
        SharedCacheMap {
            backing,
            file_size: sizes.file_size,
            valid_data_length: sizes.valid_data_length,
            allocation_size: sizes.allocation_size.max(sizes.file_size),
            pin_access,
            pages: BTreeMap::new(),
            tick: 0,
        }
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }
    pub fn valid_data_length(&self) -> u64 {
        self.valid_data_length
    }
    pub fn pin_access(&self) -> bool {
        self.pin_access
    }
    /// `CcIsThereDirtyData` (spec §7.1).
    pub fn cc_is_there_dirty_data(&self) -> bool {
        self.pages.values().any(|p| p.dirty)
    }
    pub fn cached_page_count(&self) -> usize {
        self.pages.len()
    }
    /// Consume the cache map, returning the backing store (e.g. after a final flush).
    pub fn into_backing(self) -> B {
        self.backing
    }
    pub fn backing(&self) -> &B {
        &self.backing
    }

    fn now(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Fault a page in from the backing store if not already cached; `valid_len` is clipped to
    /// the stream's file size.
    fn ensure_page(&mut self, page_idx: u64) -> Result<(), u32> {
        if self.pages.contains_key(&page_idx) {
            return Ok(());
        }
        let page_off = page_idx * PAGE_SIZE as u64;
        let valid = (self.file_size.saturating_sub(page_off)).min(PAGE_SIZE as u64) as usize;
        let mut page = CachePage::empty();
        if valid > 0 {
            self.backing.read_at(page_off, &mut page.data[..valid])?;
        }
        page.valid_len = valid as u16;
        let tick = self.now();
        page.last_access_tick = tick;
        self.pages.insert(page_idx, page);
        Ok(())
    }

    /// `CcCopyRead` (spec §12): copy `len` bytes from `offset` into `dst`, faulting pages in from
    /// the backing store. Returns `(status, bytes_copied)`, clipped to EOF (spec §12.3, §9.4).
    pub fn cc_copy_read(&mut self, offset: u64, len: usize, dst: &mut [u8]) -> (u32, usize) {
        if offset >= self.file_size {
            return (STATUS_END_OF_FILE, 0); // at/beyond EOF → zero bytes (spec §9.4)
        }
        let end = (offset + len as u64).min(self.file_size);
        let mut copied = 0usize;
        let mut pos = offset;
        while pos < end && copied < dst.len() {
            let page_idx = pos / PAGE_SIZE as u64;
            let page_off = (pos % PAGE_SIZE as u64) as usize;
            if self.ensure_page(page_idx).is_err() {
                break;
            }
            let tick = self.now();
            let page = self.pages.get_mut(&page_idx).unwrap();
            page.last_access_tick = tick;
            let avail = (page.valid_len as usize).saturating_sub(page_off);
            let n = avail.min((end - pos) as usize).min(dst.len() - copied);
            if n == 0 {
                break;
            }
            dst[copied..copied + n].copy_from_slice(&page.data[page_off..page_off + n]);
            copied += n;
            pos += n as u64;
        }
        // A short read at EOF is still success — Information reports the bytes copied (spec §12.3).
        (STATUS_SUCCESS, copied)
    }

    /// `CcCopyWrite` (spec §13): copy `src` into cache pages at `offset`, marking them dirty and
    /// extending EOF as needed. `write_through` flushes the affected range before returning.
    pub fn cc_copy_write(&mut self, offset: u64, src: &[u8], write_through: bool) -> u32 {
        let end = offset + src.len() as u64;
        if end > self.file_size {
            self.file_size = end;
            self.valid_data_length = end;
            self.allocation_size = self.allocation_size.max(end);
        }
        let mut written = 0usize;
        let mut pos = offset;
        while written < src.len() {
            let page_idx = pos / PAGE_SIZE as u64;
            let page_off = (pos % PAGE_SIZE as u64) as usize;
            // Fault in a partially-written existing page so we don't lose neighbouring bytes.
            let page_off_bytes = page_idx * PAGE_SIZE as u64;
            if !self.pages.contains_key(&page_idx) && page_off_bytes < self.file_size {
                let _ = self.ensure_page(page_idx);
            }
            let tick = self.now();
            let page = self.pages.entry(page_idx).or_insert_with(CachePage::empty);
            let n = (PAGE_SIZE - page_off).min(src.len() - written);
            page.data[page_off..page_off + n].copy_from_slice(&src[written..written + n]);
            page.valid_len = page.valid_len.max((page_off + n) as u16);
            page.dirty = true;
            page.last_access_tick = tick;
            written += n;
            pos += n as u64;
        }
        if write_through {
            return self.cc_flush_cache(Some(offset), Some(src.len() as u64));
        }
        STATUS_SUCCESS
    }

    /// `CcFlushCache` (spec §14): write dirty pages in the range (whole map if `offset` is `None`)
    /// back to the backing store + flush it. A dirty page stays dirty if its write fails.
    pub fn cc_flush_cache(&mut self, offset: Option<u64>, length: Option<u64>) -> u32 {
        let (lo, hi) = match offset {
            None => (0, u64::MAX),
            Some(o) => (
                o / PAGE_SIZE as u64,
                (o + length.unwrap_or(0)).div_ceil(PAGE_SIZE as u64),
            ),
        };
        let mut status = STATUS_SUCCESS;
        let indices: Vec<u64> = self
            .pages
            .iter()
            .filter(|(idx, p)| p.dirty && **idx >= lo && **idx < hi)
            .map(|(idx, _)| *idx)
            .collect();
        for idx in indices {
            let page_off = idx * PAGE_SIZE as u64;
            let bytes: Vec<u8> = {
                let p = self.pages.get(&idx).unwrap();
                p.data[..p.valid_len as usize].to_vec()
            };
            match self.backing.write_at(page_off, &bytes) {
                Ok(_) => self.pages.get_mut(&idx).unwrap().dirty = false,
                Err(e) => status = e, // leave the page dirty
            }
        }
        if self.backing.flush().is_err() && status == STATUS_SUCCESS {
            status = STATUS_END_OF_FILE; // surface a backing flush error
        }
        status
    }

    /// `CcSetFileSizes` (spec §15.1): update sizes; on truncate drop cached pages past EOF.
    pub fn cc_set_file_sizes(&mut self, sizes: FileSizes) {
        if sizes.file_size < self.file_size {
            let last_page = sizes.file_size / PAGE_SIZE as u64;
            self.pages.retain(|idx, _| *idx <= last_page);
            // Clip the final partial page's valid bytes.
            if let Some(p) = self.pages.get_mut(&last_page) {
                let keep = (sizes.file_size % PAGE_SIZE as u64) as usize;
                if (p.valid_len as usize) > keep {
                    p.data[keep..].iter_mut().for_each(|b| *b = 0);
                    p.valid_len = keep as u16;
                }
            }
        }
        self.file_size = sizes.file_size;
        self.valid_data_length = sizes.valid_data_length.min(sizes.file_size);
        self.allocation_size = sizes.allocation_size.max(sizes.file_size);
        let _ = self.backing.set_file_size(sizes.file_size);
    }

    /// `CcGetFileSizePointer` (spec §15.2) — the current cached file size.
    pub fn cc_get_file_size(&self) -> u64 {
        self.file_size
    }

    /// `CcPurgeCacheSection` (spec §20): drop *clean* pages in the range (dirty/pinned kept).
    /// Returns `true` if the whole requested range was purged.
    pub fn cc_purge_cache_section(&mut self, offset: u64, length: u64) -> bool {
        let lo = offset / PAGE_SIZE as u64;
        let hi = (offset + length).div_ceil(PAGE_SIZE as u64);
        let mut fully = true;
        self.pages.retain(|idx, p| {
            if *idx >= lo && *idx < hi {
                if p.dirty || p.pinned > 0 {
                    fully = false;
                    true
                } else {
                    false
                }
            } else {
                true
            }
        });
        fully
    }

    // --- pin/unpin (spec §16) ------------------------------------------------

    /// `CcPinRead` (spec §16.2): fault + pin the pages spanning the range, returning a BCB.
    pub fn cc_pin_read(&mut self, offset: u64, length: u64) -> Bcb {
        let lo = offset / PAGE_SIZE as u64;
        let hi = (offset + length).div_ceil(PAGE_SIZE as u64).max(lo + 1);
        let mut pages = Vec::new();
        for idx in lo..hi {
            let _ = self.ensure_page(idx);
            if let Some(p) = self.pages.get_mut(&idx) {
                p.pinned += 1;
                pages.push(idx);
            }
        }
        Bcb { pages }
    }

    /// `CcPreparePinWrite` (spec §16.3): pin a range for modification.
    pub fn cc_prepare_pin_write(&mut self, offset: u64, length: u64) -> Bcb {
        let end = offset + length;
        if end > self.file_size {
            self.file_size = end;
            self.valid_data_length = end;
        }
        self.cc_pin_read(offset, length)
    }

    /// `CcSetDirtyPinnedData` (spec §16.4): mark a BCB's pages dirty.
    pub fn cc_set_dirty_pinned_data(&mut self, bcb: &Bcb) {
        for idx in &bcb.pages {
            let vl = self.pinned_valid(*idx);
            if let Some(p) = self.pages.get_mut(idx) {
                p.dirty = true;
                p.valid_len = p.valid_len.max(vl);
            }
        }
    }

    fn pinned_valid(&self, idx: u64) -> u16 {
        let page_off = idx * PAGE_SIZE as u64;
        (self.file_size.saturating_sub(page_off)).min(PAGE_SIZE as u64) as u16
    }

    /// `CcUnpinData` (spec §16.5): release a BCB's pins.
    pub fn cc_unpin_data(&mut self, bcb: Bcb) {
        for idx in bcb.pages {
            if let Some(p) = self.pages.get_mut(&idx) {
                p.pinned = p.pinned.saturating_sub(1);
            }
        }
    }

    // --- lazy writer + eviction (spec §17, §19) ------------------------------

    /// A lazy-writer pass (spec §17.2): flush all dirty pages to the backing store.
    pub fn lazy_write_pass(&mut self) -> u32 {
        self.cc_flush_cache(None, None)
    }

    /// Evict the least-recently-used *clean, unpinned* page (spec §19.1). Returns whether one was
    /// dropped. A dirty page must be flushed first (not evicted here).
    pub fn evict(&mut self) -> bool {
        let victim = self
            .pages
            .iter()
            .filter(|(_, p)| !p.dirty && p.pinned == 0)
            .min_by_key(|(_, p)| p.last_access_tick)
            .map(|(idx, _)| *idx);
        match victim {
            Some(idx) => {
                self.pages.remove(&idx);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
