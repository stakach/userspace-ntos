//! # `nt-address-space` — Memory Manager address space + fault handling
//!
//! The demand-paging layer beneath the section objects (spec: NT Memory Manager Address Space +
//! Fault Handling): an [`AddressSpace`] with a VAD tree (64 KiB allocation granularity, 4 KiB
//! pages, first-fit VA allocation + overlap detection, commit accounting), demand-mode section /
//! anonymous view reservation, a page-**fault resolver** ([`AddressSpace::fault`]) that
//! materialises section-backed pages from the Cache Manager and zero-fills anonymous pages
//! (with protection + access-violation checks), dirty writeback on unmap, and
//! `MmProbeAndLockPages` MDL locking.
//!
//! Unlike the eager M24 view, a reserved view's pages start `CommittedNotResident` and only
//! become `Resident` on first touch (a fault) — real demand paging. The resolved page's bytes are
//! a host-side buffer; the Driver Host projects it into a real VA. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use nt_cache_manager::{CachedStreamBacking, SharedCacheMap};

pub const PAGE_SIZE: u64 = 4096;
pub const ALLOCATION_GRANULARITY: u64 = 64 * 1024;

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_003E;
pub const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

// Page protection
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;

fn writable(p: u32) -> bool {
    p == PAGE_READWRITE
}
fn valid_prot(p: u32) -> bool {
    matches!(p, PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE)
}

/// The kind of access that raised a fault (spec §12.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FaultAccess {
    Read,
    Write,
    Execute,
    Lock,
}

/// Which access rights an MDL lock requires (spec §15.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LockAccess {
    Read,
    Write,
}

/// What a VAD maps (spec §7.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ViewType {
    PrivateAnonymous,
    MappedDataSection,
    SystemMappedSection,
}

/// A page's residency state (spec §7.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageState {
    CommittedNotResident,
    Resident,
}

pub type VadId = u32;
pub type SectionId = u32;

struct VadRegion {
    base: u64,
    size: u64,
    protection: u32,
    view_type: ViewType,
    section: Option<SectionId>,
    section_offset: u64,
}

impl VadRegion {
    fn end(&self) -> u64 {
        self.base + self.size
    }
    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

struct VirtualPage {
    state: PageState,
    data: Vec<u8>, // PAGE_SIZE bytes once resident
    dirty: bool,
    locked_count: u32,
}

/// A locked page list returned by `MmProbeAndLockPages` (spec §15).
pub struct Mdl {
    base: u64,
    length: u64,
    locked: bool,
}

impl Mdl {
    pub fn is_locked(&self) -> bool {
        self.locked
    }
    pub fn page_count(&self) -> u64 {
        self.length.div_ceil(PAGE_SIZE)
    }
}

/// A process/system/driver-host virtual address space (spec §7.1).
pub struct AddressSpace {
    lower_bound: u64,
    upper_bound: u64,
    vads: Vec<Option<VadRegion>>,
    pages: BTreeMap<u64, VirtualPage>, // keyed by virtual page number
    commit_charge: u64,
    commit_limit: u64,
}

impl AddressSpace {
    /// A synthetic test/driver-host address space spanning `[lower, upper)` with a commit limit.
    pub fn new(lower_bound: u64, upper_bound: u64, commit_limit: u64) -> Self {
        AddressSpace {
            lower_bound,
            upper_bound,
            vads: Vec::new(),
            pages: BTreeMap::new(),
            commit_charge: 0,
            commit_limit,
        }
    }

    pub fn commit_charge(&self) -> u64 {
        self.commit_charge
    }
    pub fn resident_page_count(&self) -> usize {
        self.pages
            .values()
            .filter(|p| p.state == PageState::Resident)
            .count()
    }
    pub fn vad_count(&self) -> usize {
        self.vads.iter().filter(|v| v.is_some()).count()
    }
    /// The section a VAD maps (spec §7.2), or `None` for a private-anonymous VAD.
    pub fn vad_section(&self, vad: VadId) -> Option<SectionId> {
        self.vads.get(vad as usize)?.as_ref()?.section
    }

    fn vad_at(&self, addr: u64) -> Option<&VadRegion> {
        self.vads
            .iter()
            .filter_map(|v| v.as_ref())
            .find(|v| v.contains(addr))
    }
    fn overlaps(&self, base: u64, size: u64) -> bool {
        self.vads
            .iter()
            .filter_map(|v| v.as_ref())
            .any(|v| base < v.end() && v.base < base + size)
    }

    /// First-fit free-region search (spec §9.3), aligned to the allocation granularity.
    fn find_free(&self, size: u64) -> Option<u64> {
        let aligned = size.div_ceil(ALLOCATION_GRANULARITY) * ALLOCATION_GRANULARITY;
        let mut base = self.lower_bound.div_ceil(ALLOCATION_GRANULARITY) * ALLOCATION_GRANULARITY;
        while base + aligned <= self.upper_bound {
            if !self.overlaps(base, aligned) {
                return Some(base);
            }
            base += ALLOCATION_GRANULARITY;
        }
        None
    }

    fn push_vad(&mut self, v: VadRegion) -> VadId {
        let id = self.vads.len() as VadId;
        self.vads.push(Some(v));
        id
    }

    /// Reserve a VA region + create a VAD for a mapped view (spec §9.2, §10.2). Demand mode:
    /// pages start `CommittedNotResident`. `base = None` finds a free region. Charges commit.
    pub fn reserve_view(
        &mut self,
        base: Option<u64>,
        size: u64,
        protection: u32,
        view_type: ViewType,
        section: Option<SectionId>,
        section_offset: u64,
    ) -> Result<(VadId, u64), u32> {
        if !valid_prot(protection) || size == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let base = match base {
            Some(b) => {
                let aligned = b / ALLOCATION_GRANULARITY * ALLOCATION_GRANULARITY;
                if aligned != b {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if b < self.lower_bound || b + size > self.upper_bound || self.overlaps(b, size) {
                    return Err(STATUS_CONFLICTING_ADDRESSES);
                }
                b
            }
            None => self.find_free(size).ok_or(STATUS_NO_MEMORY)?,
        };
        // Commit accounting (spec §17): charge the whole reserved view.
        if self.commit_charge + size > self.commit_limit {
            return Err(STATUS_COMMITMENT_LIMIT);
        }
        self.commit_charge += size;
        let id = self.push_vad(VadRegion {
            base,
            size,
            protection,
            view_type,
            section,
            section_offset,
        });
        Ok((id, base))
    }

    fn page_valid_len(vad: &VadRegion, page_base: u64) -> usize {
        let off_in_vad = page_base - vad.base;
        (vad.size - off_in_vad).min(PAGE_SIZE) as usize
    }

    /// The page-fault resolver for a **section-backed** page (spec §12.2-§12.3): find the VAD,
    /// check protection, and materialise the page from the Cache Manager if not resident. Marks
    /// the page dirty on a write fault (spec §12.4).
    pub fn fault<B: CachedStreamBacking>(
        &mut self,
        addr: u64,
        access: FaultAccess,
        cache: &mut SharedCacheMap<B>,
    ) -> u32 {
        let page_base = addr / PAGE_SIZE * PAGE_SIZE;
        let (prot, vt, sec_off, valid) = match self.vad_at(addr) {
            None => return STATUS_ACCESS_VIOLATION, // no VAD (spec §12.2)
            Some(v) => (
                v.protection,
                v.view_type,
                v.section_offset + (page_base - v.base),
                Self::page_valid_len(v, page_base),
            ),
        };
        if prot == PAGE_NOACCESS {
            return STATUS_ACCESS_VIOLATION;
        }
        if access == FaultAccess::Write && !writable(prot) {
            return STATUS_ACCESS_VIOLATION; // write to read-only (spec §12.4)
        }
        let vpn = page_base / PAGE_SIZE;
        let resident = self
            .pages
            .get(&vpn)
            .map(|p| p.state == PageState::Resident)
            .unwrap_or(false);
        if !resident {
            let mut data = vec![0u8; PAGE_SIZE as usize];
            if vt != ViewType::PrivateAnonymous {
                cache.cc_copy_read(sec_off, valid, &mut data); // materialise from cache
            }
            self.pages.insert(
                vpn,
                VirtualPage {
                    state: PageState::Resident,
                    data,
                    dirty: false,
                    locked_count: self.pages.get(&vpn).map(|p| p.locked_count).unwrap_or(0),
                },
            );
        }
        if access == FaultAccess::Write {
            self.pages.get_mut(&vpn).unwrap().dirty = true;
        }
        STATUS_SUCCESS
    }

    /// The fault resolver for an **anonymous** page (spec §12.2): zero-fill on first touch.
    pub fn fault_anonymous(&mut self, addr: u64, access: FaultAccess) -> u32 {
        let page_base = addr / PAGE_SIZE * PAGE_SIZE;
        let prot = match self.vad_at(addr) {
            None => return STATUS_ACCESS_VIOLATION,
            Some(v) => v.protection,
        };
        if prot == PAGE_NOACCESS || (access == FaultAccess::Write && !writable(prot)) {
            return STATUS_ACCESS_VIOLATION;
        }
        let vpn = page_base / PAGE_SIZE;
        self.pages.entry(vpn).or_insert_with(|| VirtualPage {
            state: PageState::Resident,
            data: vec![0u8; PAGE_SIZE as usize],
            dirty: false,
            locked_count: 0,
        });
        if access == FaultAccess::Write {
            self.pages.get_mut(&vpn).unwrap().dirty = true;
        }
        STATUS_SUCCESS
    }

    /// Demand read `len` bytes at `addr`, faulting section pages in as needed (spec §12).
    pub fn read<B: CachedStreamBacking>(
        &mut self,
        addr: u64,
        len: usize,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(len);
        let mut pos = addr;
        while out.len() < len {
            let st = self.fault(pos, FaultAccess::Read, cache);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            let vpn = pos / PAGE_SIZE;
            let off = (pos % PAGE_SIZE) as usize;
            let page = self.pages.get(&vpn).unwrap();
            let n = (PAGE_SIZE as usize - off).min(len - out.len());
            out.extend_from_slice(&page.data[off..off + n]);
            pos += n as u64;
        }
        Ok(out)
    }

    /// Demand write `bytes` at `addr`, faulting pages in for write + marking them dirty (spec §12.4).
    pub fn write<B: CachedStreamBacking>(
        &mut self,
        addr: u64,
        bytes: &[u8],
        cache: &mut SharedCacheMap<B>,
    ) -> Result<(), u32> {
        let mut written = 0;
        let mut pos = addr;
        while written < bytes.len() {
            let st = self.fault(pos, FaultAccess::Write, cache);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            let vpn = pos / PAGE_SIZE;
            let off = (pos % PAGE_SIZE) as usize;
            let page = self.pages.get_mut(&vpn).unwrap();
            let n = (PAGE_SIZE as usize - off).min(bytes.len() - written);
            page.data[off..off + n].copy_from_slice(&bytes[written..written + n]);
            page.dirty = true;
            written += n;
            pos += n as u64;
        }
        Ok(())
    }

    /// `ZwUnmapViewOfSection` for a file-backed VAD (spec §11.1-§11.2): write dirty resident pages
    /// back through the cache (`CcCopyWrite`), release the pages, and free the VAD (releasing
    /// commit). A `CcFlushCache` after this reaches the file.
    pub fn unmap_view<B: CachedStreamBacking>(
        &mut self,
        vad: VadId,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<(), u32> {
        let region = self
            .vads
            .get_mut(vad as usize)
            .and_then(|v| v.take())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let first = region.base / PAGE_SIZE;
        let last = (region.end() - 1) / PAGE_SIZE;
        for vpn in first..=last {
            if let Some(page) = self.pages.remove(&vpn) {
                if page.dirty && writable(region.protection) {
                    let page_base = vpn * PAGE_SIZE;
                    let valid = Self::page_valid_len(&region, page_base);
                    let sec_off = region.section_offset + (page_base - region.base);
                    cache.cc_copy_write(sec_off, &page.data[..valid], false);
                }
            }
        }
        self.commit_charge = self.commit_charge.saturating_sub(region.size);
        Ok(())
    }

    /// Free an anonymous VAD (no writeback; releases commit).
    pub fn unmap_anonymous(&mut self, vad: VadId) -> Result<(), u32> {
        let region = self
            .vads
            .get_mut(vad as usize)
            .and_then(|v| v.take())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let first = region.base / PAGE_SIZE;
        let last = (region.end() - 1) / PAGE_SIZE;
        for vpn in first..=last {
            self.pages.remove(&vpn);
        }
        self.commit_charge = self.commit_charge.saturating_sub(region.size);
        Ok(())
    }

    /// `MmProbeAndLockPages` (spec §15.2): fault in + lock the pages spanning `[base, base+len)`,
    /// verifying the access right. Returns a locked [`Mdl`].
    pub fn mm_probe_and_lock_pages<B: CachedStreamBacking>(
        &mut self,
        base: u64,
        length: u64,
        access: LockAccess,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<Mdl, u32> {
        let fa = match access {
            LockAccess::Read => FaultAccess::Read,
            LockAccess::Write => FaultAccess::Write,
        };
        let mut pos = base / PAGE_SIZE * PAGE_SIZE;
        let end = base + length;
        while pos < end {
            let st = self.fault(pos, fa, cache);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            self.pages.get_mut(&(pos / PAGE_SIZE)).unwrap().locked_count += 1;
            pos += PAGE_SIZE;
        }
        Ok(Mdl {
            base,
            length,
            locked: true,
        })
    }

    /// `MmUnlockPages` (spec §15.3): decrement the lock count on the MDL's pages.
    pub fn mm_unlock_pages(&mut self, mdl: &mut Mdl) {
        let mut pos = mdl.base / PAGE_SIZE * PAGE_SIZE;
        let end = mdl.base + mdl.length;
        while pos < end {
            if let Some(p) = self.pages.get_mut(&(pos / PAGE_SIZE)) {
                p.locked_count = p.locked_count.saturating_sub(1);
            }
            pos += PAGE_SIZE;
        }
        mdl.locked = false;
    }

    /// The lock count of the page containing `addr` (for MDL tests).
    pub fn page_locked_count(&self, addr: u64) -> u32 {
        self.pages
            .get(&(addr / PAGE_SIZE))
            .map(|p| p.locked_count)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests;
