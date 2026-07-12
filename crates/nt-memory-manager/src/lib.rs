//! # `nt-memory-manager` — section objects + mapped views
//!
//! The NT Memory Manager section layer (spec: NT Memory Manager Section Objects + Mapped Views):
//! `ZwCreateSection` (file-backed via the Cache Manager, or pagefile/anonymous), `ZwMapViewOfSection`
//! / `ZwUnmapViewOfSection`, `MmMapViewInSystemSpace`, a page-protection model with access checks,
//! and Cache Manager coherency.
//!
//! v0.1 uses **Approach B** (spec §12.1): a file-backed view *materialises* its bytes by reading
//! through a [`SharedCacheMap`] (`CcCopyRead`), writable views mark dirty, and unmap/flush writes
//! dirty pages back through the cache (`CcCopyWrite` + `CcFlushCache`). The mapped "pointer" is a
//! view-local byte buffer (`view_read`/`view_write`); the Driver Host projects it into a real VA.
//! `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use nt_cache_manager::{CachedStreamBacking, SharedCacheMap};

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_003E;
pub const STATUS_SECTION_TOO_BIG: u32 = 0xC000_0040;
pub const STATUS_INVALID_VIEW_SIZE: u32 = 0xC000_001F;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

// Page protection (spec §17.1)
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;

// Allocation attributes (spec §8.3)
pub const SEC_COMMIT: u32 = 0x0800_0000;
pub const SEC_RESERVE: u32 = 0x0400_0000;
pub const SEC_IMAGE: u32 = 0x0100_0000;
pub const SEC_NOCACHE: u32 = 0x1000_0000;

fn prot_is_writable(p: u32) -> bool {
    p == PAGE_READWRITE || p == PAGE_WRITECOPY
}
fn prot_is_valid(p: u32) -> bool {
    matches!(
        p,
        PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
    )
}

/// Which address space a view lives in (spec §10.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressSpace {
    /// The current process / Driver Host projection (`ZwMapViewOfSection`).
    Process,
    /// System space (`MmMapViewInSystemSpace`).
    System,
}

/// How a section is backed (spec §8.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Backing {
    /// Backed by a file stream, kept coherent through the Cache Manager.
    File,
    /// Anonymous committed memory ("pagefile" section, spec §9.3).
    Pagefile,
}

/// An opaque section handle.
pub type SectionId = u32;
/// An opaque mapped-view handle.
pub type ViewId = u32;

struct SectionObject {
    backing: Backing,
    maximum_size: u64,
    page_protection: u32,
    /// Anonymous sections own their bytes here; file sections stay in the cache.
    anon: Option<Vec<u8>>,
    view_count: u32,
    deleting: bool,
}

struct MappedView {
    section: SectionId,
    section_offset: u64,
    protection: u32,
    address_space: AddressSpace,
    /// The materialised bytes (Approach B) — the "mapped pointer" in the host model.
    buffer: Vec<u8>,
    dirty: bool,
}

/// The Memory Manager: section objects + their mapped views (spec §8, §10).
#[derive(Default)]
pub struct MemoryManager {
    sections: Vec<Option<SectionObject>>,
    views: Vec<Option<MappedView>>,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn section(&self, id: SectionId) -> Option<&SectionObject> {
        self.sections
            .get(id as usize)?
            .as_ref()
            .filter(|s| !s.deleting)
    }
    fn section_mut(&mut self, id: SectionId) -> Option<&mut SectionObject> {
        self.sections
            .get_mut(id as usize)?
            .as_mut()
            .filter(|s| !s.deleting)
    }

    fn push_section(&mut self, s: SectionObject) -> SectionId {
        let id = self.sections.len() as SectionId;
        self.sections.push(Some(s));
        id
    }

    /// `ZwCreateSection` over a **file** stream (spec §13): the section shares the file's data
    /// through the Cache Manager. Validates protection + `SEC_IMAGE` rejection.
    pub fn zw_create_section_file(
        &mut self,
        maximum_size: u64,
        page_protection: u32,
        allocation_attributes: u32,
    ) -> Result<SectionId, u32> {
        if !prot_is_valid(page_protection) {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        if allocation_attributes & SEC_IMAGE != 0 {
            return Err(STATUS_NOT_SUPPORTED); // SEC_IMAGE unsupported (spec §8.3)
        }
        Ok(self.push_section(SectionObject {
            backing: Backing::File,
            maximum_size,
            page_protection,
            anon: None,
            view_count: 0,
            deleting: false,
        }))
    }

    /// `ZwCreateSection` for a **pagefile/anonymous** section (spec §9.3): committed zeroed memory
    /// of `size` bytes (`SEC_RESERVE` is accepted but committed here — commit-on-first-touch is
    /// modelled as up-front zeroing).
    pub fn zw_create_section_pagefile(
        &mut self,
        size: u64,
        page_protection: u32,
        allocation_attributes: u32,
    ) -> Result<SectionId, u32> {
        if !prot_is_valid(page_protection) {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        if allocation_attributes & SEC_IMAGE != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        Ok(self.push_section(SectionObject {
            backing: Backing::Pagefile,
            maximum_size: size,
            page_protection,
            anon: Some(vec![0u8; size as usize]),
            view_count: 0,
            deleting: false,
        }))
    }

    pub fn section_backing(&self, id: SectionId) -> Option<Backing> {
        self.section(id).map(|s| s.backing)
    }

    fn clamp_view(
        &self,
        section: &SectionObject,
        offset: u64,
        size: u64,
    ) -> Result<(u64, u64), u32> {
        if offset > section.maximum_size {
            return Err(STATUS_INVALID_VIEW_SIZE);
        }
        let avail = section.maximum_size - offset;
        let sz = if size == 0 { avail } else { size.min(avail) };
        if sz > section.maximum_size {
            return Err(STATUS_SECTION_TOO_BIG);
        }
        Ok((offset, sz))
    }

    /// `ZwMapViewOfSection` for a **file-backed** section (spec §14), materialising the view from
    /// the stream's cache (`CcCopyRead`, Approach B). `view_size == 0` maps to the section end.
    pub fn zw_map_view_of_section_file<B: CachedStreamBacking>(
        &mut self,
        section: SectionId,
        cache: &mut SharedCacheMap<B>,
        offset: u64,
        view_size: u64,
        protection: u32,
        address_space: AddressSpace,
    ) -> Result<ViewId, u32> {
        if !prot_is_valid(protection) {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        let sec = self.section(section).ok_or(STATUS_INVALID_HANDLE)?;
        if sec.backing != Backing::File {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let (off, sz) = self.clamp_view(sec, offset, view_size)?;
        let mut buffer = vec![0u8; sz as usize];
        let (_, n) = cache.cc_copy_read(off, sz as usize, &mut buffer);
        buffer.truncate(n); // materialise the valid file bytes
        Ok(self.push_view(MappedView {
            section,
            section_offset: off,
            protection,
            address_space,
            buffer,
            dirty: false,
        }))
    }

    /// `ZwMapViewOfSection` for an **anonymous** section (spec §11.2): a zeroed committed view.
    pub fn zw_map_view_of_section_anon(
        &mut self,
        section: SectionId,
        offset: u64,
        view_size: u64,
        protection: u32,
        address_space: AddressSpace,
    ) -> Result<ViewId, u32> {
        if !prot_is_valid(protection) {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        let sec = self.section(section).ok_or(STATUS_INVALID_HANDLE)?;
        if sec.backing != Backing::Pagefile {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let (off, sz) = self.clamp_view(sec, offset, view_size)?;
        let anon = sec.anon.as_ref().unwrap();
        let start = off as usize;
        let end = (start + sz as usize).min(anon.len());
        let buffer = anon[start..end].to_vec();
        Ok(self.push_view(MappedView {
            section,
            section_offset: off,
            protection,
            address_space,
            buffer,
            dirty: false,
        }))
    }

    /// `MmMapViewInSystemSpace` (spec §16) — map a file-backed section into system space.
    pub fn mm_map_view_in_system_space<B: CachedStreamBacking>(
        &mut self,
        section: SectionId,
        cache: &mut SharedCacheMap<B>,
        view_size: u64,
    ) -> Result<ViewId, u32> {
        let prot = self
            .section(section)
            .map(|s| s.page_protection)
            .unwrap_or(PAGE_READWRITE);
        self.zw_map_view_of_section_file(section, cache, 0, view_size, prot, AddressSpace::System)
    }

    fn push_view(&mut self, mut v: MappedView) -> ViewId {
        if let Some(s) = self.section_mut(v.section) {
            s.view_count += 1;
        }
        // Find a free slot (unmapped views leave None holes).
        let id = self.views.iter().position(|x| x.is_none());
        v.dirty = false;
        match id {
            Some(i) => {
                self.views[i] = Some(v);
                i as ViewId
            }
            None => {
                self.views.push(Some(v));
                (self.views.len() - 1) as ViewId
            }
        }
    }

    fn view(&self, id: ViewId) -> Option<&MappedView> {
        self.views.get(id as usize)?.as_ref()
    }
    fn view_mut(&mut self, id: ViewId) -> Option<&mut MappedView> {
        self.views.get_mut(id as usize)?.as_mut()
    }

    /// Read from a mapped view (spec §17.2 — a `PAGE_NOACCESS` view can't be read).
    pub fn view_read(&self, id: ViewId, offset: u64, len: usize) -> Result<Vec<u8>, u32> {
        let v = self.view(id).ok_or(STATUS_INVALID_HANDLE)?;
        if v.protection == PAGE_NOACCESS {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let start = (offset as usize).min(v.buffer.len());
        let end = (start + len).min(v.buffer.len());
        Ok(v.buffer[start..end].to_vec())
    }

    /// Write into a mapped view (spec §11.3, §17.2). Requires a writable protection; marks the
    /// view dirty so unmap/flush propagates the change to the backing.
    pub fn view_write(&mut self, id: ViewId, offset: u64, bytes: &[u8]) -> Result<(), u32> {
        let v = self.view_mut(id).ok_or(STATUS_INVALID_HANDLE)?;
        if !prot_is_writable(v.protection) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let start = offset as usize;
        if start + bytes.len() > v.buffer.len() {
            return Err(STATUS_INVALID_VIEW_SIZE);
        }
        v.buffer[start..start + bytes.len()].copy_from_slice(bytes);
        v.dirty = true;
        Ok(())
    }

    /// `ZwUnmapViewOfSection` for a **file-backed** view (spec §15): if the view is writable +
    /// dirty, write it back through the cache (`CcCopyWrite`, Approach B). The whole writable view
    /// is treated as dirty (conservative v0.1 policy, spec §11.3).
    pub fn zw_unmap_view_of_section_file<B: CachedStreamBacking>(
        &mut self,
        id: ViewId,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<(), u32> {
        let v = self
            .views
            .get_mut(id as usize)
            .and_then(|x| x.take())
            .ok_or(STATUS_INVALID_HANDLE)?;
        if prot_is_writable(v.protection) && v.dirty {
            cache.cc_copy_write(v.section_offset, &v.buffer, false);
        }
        if let Some(s) = self.section_mut(v.section) {
            s.view_count = s.view_count.saturating_sub(1);
        }
        Ok(())
    }

    /// `ZwUnmapViewOfSection` for an **anonymous** view: write dirty bytes back to the section's
    /// committed memory (so another view of the same section sees them).
    pub fn zw_unmap_view_of_section_anon(&mut self, id: ViewId) -> Result<(), u32> {
        let v = self
            .views
            .get_mut(id as usize)
            .and_then(|x| x.take())
            .ok_or(STATUS_INVALID_HANDLE)?;
        if prot_is_writable(v.protection) && v.dirty {
            let off = v.section_offset as usize;
            if let Some(s) = self.section_mut(v.section) {
                if let Some(anon) = s.anon.as_mut() {
                    let end = (off + v.buffer.len()).min(anon.len());
                    anon[off..end].copy_from_slice(&v.buffer[..end - off]);
                }
            }
        }
        if let Some(s) = self.section_mut(v.section) {
            s.view_count = s.view_count.saturating_sub(1);
        }
        Ok(())
    }

    /// The address space a view was mapped into (spec §10.2).
    pub fn view_address_space(&self, id: ViewId) -> Option<AddressSpace> {
        self.view(id).map(|v| v.address_space)
    }
    pub fn view_count(&self, section: SectionId) -> u32 {
        self.section(section).map(|s| s.view_count).unwrap_or(0)
    }
    pub fn active_view_count(&self) -> usize {
        self.views.iter().filter(|v| v.is_some()).count()
    }

    /// `ZwClose` on the last section handle (spec §8): mark the section deleting once no views
    /// remain. Returns whether it was deleted.
    pub fn close_section(&mut self, id: SectionId) -> bool {
        match self.section_mut(id) {
            Some(s) if s.view_count == 0 => {
                s.deleting = true;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
