use alloc::vec::Vec;

use crate::PAGE_NOACCESS;

pub const GENERIC_SECTION_BACKING_NONE: u8 = 0;
pub const GENERIC_SECTION_BACKING_ANON: u8 = 1;
pub const GENERIC_SECTION_BACKING_DISK: u8 = 2;
pub const GENERIC_SECTION_BACKING_OVERLAY: u8 = 3;
pub const SECTION_ATTR_SEC_BASED: u32 = 0x0020_0000;
pub const SECTION_ATTR_SEC_FILE: u32 = 0x0080_0000;
pub const SECTION_ATTR_SEC_IMAGE: u32 = 0x0100_0000;
pub const SECTION_ATTR_SEC_RESERVE: u32 = 0x0400_0000;
pub const SECTION_ATTR_SEC_COMMIT: u32 = 0x0800_0000;

const SECTION_INITIAL_RESERVE: usize = 16;
const VIEW_INITIAL_RESERVE: usize = 32;
const PAGE_INITIAL_RESERVE: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericSectionBacking {
    pub kind: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    pub overlay_file_id: u64,
}

impl GenericSectionBacking {
    pub const fn none() -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_NONE,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: 0,
        }
    }

    pub const fn anonymous() -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_ANON,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: 0,
        }
    }

    pub const fn disk(first_cluster: u32, file_size: u32) -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_DISK,
            first_cluster,
            file_size,
            overlay_file_id: 0,
        }
    }

    pub const fn overlay(file_id: u64) -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_OVERLAY,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: file_id,
        }
    }

    pub const fn is_live(self) -> bool {
        self.kind != GENERIC_SECTION_BACKING_NONE
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericSection {
    pub live: bool,
    pub owner_pi: usize,
    pub handle: u64,
    pub size: u64,
    pub protection: u32,
    pub allocation_attributes: u32,
    pub backing: GenericSectionBacking,
}

impl GenericSection {
    const fn empty() -> Self {
        Self {
            live: false,
            owner_pi: 0,
            handle: 0,
            size: 0,
            protection: PAGE_NOACCESS,
            allocation_attributes: 0,
            backing: GenericSectionBacking::none(),
        }
    }

    pub fn basic_attributes(self) -> u32 {
        let mut attributes = self.allocation_attributes
            & (SECTION_ATTR_SEC_BASED
                | SECTION_ATTR_SEC_IMAGE
                | SECTION_ATTR_SEC_RESERVE
                | SECTION_ATTR_SEC_COMMIT);
        match self.backing.kind {
            GENERIC_SECTION_BACKING_DISK | GENERIC_SECTION_BACKING_OVERLAY => {
                attributes |= SECTION_ATTR_SEC_FILE;
            }
            GENERIC_SECTION_BACKING_ANON => {
                if attributes & (SECTION_ATTR_SEC_COMMIT | SECTION_ATTR_SEC_RESERVE) == 0 {
                    attributes |= SECTION_ATTR_SEC_COMMIT;
                }
            }
            _ => {}
        }
        attributes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericSectionView {
    pub live: bool,
    pub pi: usize,
    pub section_index: usize,
    pub base: u64,
    pub size: u64,
    pub section_offset: u64,
}

impl GenericSectionView {
    const fn empty() -> Self {
        Self {
            live: false,
            pi: 0,
            section_index: usize::MAX,
            base: 0,
            size: 0,
            section_offset: 0,
        }
    }

    fn contains(self, pi: usize, page: u64) -> bool {
        self.live
            && self.pi == pi
            && page >= self.base
            && page < self.base.saturating_add(self.size)
    }
}

#[derive(Clone, Copy)]
struct GenericSectionPage {
    live: bool,
    section_index: usize,
    page_index: u64,
    frame: u64,
    dirty: bool,
}

impl GenericSectionPage {
    const fn empty() -> Self {
        Self {
            live: false,
            section_index: usize::MAX,
            page_index: 0,
            frame: 0,
            dirty: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenericSectionTableStats {
    pub live_sections: usize,
    pub section_records: usize,
    pub section_capacity: usize,
    pub section_growths: u64,
    pub section_allocation_failures: u64,
    pub live_views: usize,
    pub view_records: usize,
    pub view_capacity: usize,
    pub view_growths: u64,
    pub view_allocation_failures: u64,
    pub live_pages: usize,
    pub page_records: usize,
    pub page_capacity: usize,
    pub page_growths: u64,
    pub page_allocation_failures: u64,
}

pub struct GenericSectionTable {
    sections: Vec<GenericSection>,
    views: Vec<GenericSectionView>,
    pages: Vec<GenericSectionPage>,
    dirty: bool,
    section_growths: u64,
    section_allocation_failures: u64,
    view_growths: u64,
    view_allocation_failures: u64,
    page_growths: u64,
    page_allocation_failures: u64,
}

impl GenericSectionTable {
    pub const fn new() -> Self {
        Self {
            sections: Vec::new(),
            views: Vec::new(),
            pages: Vec::new(),
            dirty: false,
            section_growths: 0,
            section_allocation_failures: 0,
            view_growths: 0,
            view_allocation_failures: 0,
            page_growths: 0,
            page_allocation_failures: 0,
        }
    }

    pub fn reset(&mut self) -> bool {
        self.reset_with_reserve(
            SECTION_INITIAL_RESERVE,
            VIEW_INITIAL_RESERVE,
            PAGE_INITIAL_RESERVE,
        )
    }

    pub fn reset_with_reserve(
        &mut self,
        section_reserve: usize,
        view_reserve: usize,
        page_reserve: usize,
    ) -> bool {
        self.sections.clear();
        self.views.clear();
        self.pages.clear();
        self.dirty = false;
        self.section_growths = 0;
        self.section_allocation_failures = 0;
        self.view_growths = 0;
        self.view_allocation_failures = 0;
        self.page_growths = 0;
        self.page_allocation_failures = 0;
        if self.sections.try_reserve(section_reserve).is_err() {
            self.section_allocation_failures = 1;
            return false;
        }
        if self.views.try_reserve(view_reserve).is_err() {
            self.view_allocation_failures = 1;
            return false;
        }
        if self.pages.try_reserve(page_reserve).is_err() {
            self.page_allocation_failures = 1;
            return false;
        }
        true
    }

    fn append_section(&mut self, section: GenericSection) -> Option<usize> {
        let old_capacity = self.sections.capacity();
        if self.sections.try_reserve(1).is_err() {
            self.section_allocation_failures = self.section_allocation_failures.saturating_add(1);
            return None;
        }
        if self.sections.capacity() != old_capacity {
            self.section_growths = self.section_growths.saturating_add(1);
            self.dirty = true;
        }
        self.sections.push(section);
        Some(self.sections.len() - 1)
    }

    fn append_view(&mut self, view: GenericSectionView) -> bool {
        let old_capacity = self.views.capacity();
        if self.views.try_reserve(1).is_err() {
            self.view_allocation_failures = self.view_allocation_failures.saturating_add(1);
            return false;
        }
        if self.views.capacity() != old_capacity {
            self.view_growths = self.view_growths.saturating_add(1);
            self.dirty = true;
        }
        self.views.push(view);
        true
    }

    fn append_page(&mut self, page: GenericSectionPage) -> bool {
        let old_capacity = self.pages.capacity();
        if self.pages.try_reserve(1).is_err() {
            self.page_allocation_failures = self.page_allocation_failures.saturating_add(1);
            return false;
        }
        if self.pages.capacity() != old_capacity {
            self.page_growths = self.page_growths.saturating_add(1);
            self.dirty = true;
        }
        self.pages.push(page);
        true
    }

    pub fn create(
        &mut self,
        owner_pi: usize,
        handle: u64,
        size: u64,
        protection: u32,
        allocation_attributes: u32,
        backing: GenericSectionBacking,
    ) -> Option<usize> {
        if size == 0 || !backing.is_live() {
            return None;
        }
        if handle != 0 {
            if let Some(index) = self.index_for_handle(owner_pi, handle) {
                self.sections[index].size = size;
                self.sections[index].protection = protection;
                self.sections[index].allocation_attributes = allocation_attributes;
                self.sections[index].backing = backing;
                return Some(index);
            }
        }
        let section = GenericSection {
            live: true,
            owner_pi,
            handle,
            size,
            protection,
            allocation_attributes,
            backing,
        };
        if let Some(index) = self.sections.iter().position(|entry| !entry.live) {
            self.sections[index] = section;
            Some(index)
        } else {
            self.append_section(section)
        }
    }

    pub fn bind_handle(&mut self, index: usize, handle: u64) -> bool {
        if handle == 0 {
            return false;
        }
        let Some(section) = self.sections.get_mut(index) else {
            return false;
        };
        if !section.live {
            return false;
        }
        section.handle = handle;
        true
    }

    pub fn clear_section(&mut self, index: usize) {
        if let Some(section) = self.sections.get_mut(index) {
            *section = GenericSection::empty();
        }
        for view in &mut self.views {
            if view.live && view.section_index == index {
                *view = GenericSectionView::empty();
            }
        }
        for page in &mut self.pages {
            if page.live && page.section_index == index {
                *page = GenericSectionPage::empty();
            }
        }
    }

    fn section_has_views(&self, index: usize) -> bool {
        self.views
            .iter()
            .any(|view| view.live && view.section_index == index)
    }

    fn clear_section_if_unreferenced(&mut self, index: usize) {
        if self
            .sections
            .get(index)
            .is_some_and(|section| section.live && section.handle == 0)
            && !self.section_has_views(index)
        {
            self.clear_section(index);
        }
    }

    pub fn release_handle(&mut self, index: usize) -> bool {
        let Some(section) = self.sections.get_mut(index) else {
            return false;
        };
        if !section.live {
            return false;
        }
        section.handle = 0;
        self.clear_section_if_unreferenced(index);
        true
    }

    pub fn index_for_handle(&self, owner_pi: usize, handle: u64) -> Option<usize> {
        self.sections.iter().position(|section| {
            section.live && section.owner_pi == owner_pi && section.handle == handle
        })
    }

    pub fn section(&self, index: usize) -> Option<GenericSection> {
        self.sections
            .get(index)
            .copied()
            .filter(|section| section.live)
    }

    pub fn map_view(
        &mut self,
        pi: usize,
        section_index: usize,
        base: u64,
        size: u64,
        section_offset: u64,
    ) -> bool {
        if self.section(section_index).is_none() || base == 0 || size == 0 {
            return false;
        }
        let view = GenericSectionView {
            live: true,
            pi,
            section_index,
            base,
            size,
            section_offset,
        };
        if let Some(index) = self.views.iter().position(|entry| !entry.live) {
            self.views[index] = view;
            true
        } else {
            self.append_view(view)
        }
    }

    pub fn unmap_view(&mut self, pi: usize, base: u64) -> Option<GenericSectionView> {
        for view in &mut self.views {
            if view.live && view.pi == pi && view.base == base {
                let removed = *view;
                *view = GenericSectionView::empty();
                self.clear_section_if_unreferenced(removed.section_index);
                return Some(removed);
            }
        }
        None
    }

    pub fn first_view_for_process(&self, pi: usize) -> Option<GenericSectionView> {
        self.views
            .iter()
            .copied()
            .find(|view| view.live && view.pi == pi)
    }

    pub fn view_for_page(&self, pi: usize, page: u64) -> Option<(usize, GenericSectionView)> {
        self.views
            .iter()
            .find(|view| view.contains(pi, page))
            .map(|view| (view.section_index, *view))
    }

    pub fn page_frame(&self, section_index: usize, page_index: u64) -> Option<u64> {
        self.pages
            .iter()
            .find(|page| {
                page.live && page.section_index == section_index && page.page_index == page_index
            })
            .map(|page| page.frame)
            .filter(|frame| *frame != 0)
    }

    pub fn set_page_frame(&mut self, section_index: usize, page_index: u64, frame: u64) -> bool {
        if frame == 0 {
            return false;
        }
        if let Some(page) = self.pages.iter_mut().find(|page| {
            page.live && page.section_index == section_index && page.page_index == page_index
        }) {
            page.frame = frame;
            return true;
        }
        let page = GenericSectionPage {
            live: true,
            section_index,
            page_index,
            frame,
            dirty: false,
        };
        if let Some(index) = self.pages.iter().position(|entry| !entry.live) {
            self.pages[index] = page;
            true
        } else {
            self.append_page(page)
        }
    }

    pub fn mark_page_dirty(&mut self, section_index: usize, page_index: u64) -> bool {
        if let Some(page) = self.pages.iter_mut().find(|page| {
            page.live && page.section_index == section_index && page.page_index == page_index
        }) {
            page.dirty = true;
            true
        } else {
            false
        }
    }

    pub fn clear_page_dirty(&mut self, section_index: usize, page_index: u64) -> bool {
        if let Some(page) = self.pages.iter_mut().find(|page| {
            page.live && page.section_index == section_index && page.page_index == page_index
        }) {
            page.dirty = false;
            true
        } else {
            false
        }
    }

    pub fn next_dirty_page_for_view(
        &self,
        view: GenericSectionView,
        section: GenericSection,
    ) -> Option<(u64, u64, u64, usize)> {
        let view_start = view.section_offset;
        let view_end = view.section_offset.saturating_add(view.size);
        for page in &self.pages {
            if !page.live || !page.dirty || page.section_index != view.section_index {
                continue;
            }
            let page_offset = page.page_index.saturating_mul(0x1000);
            if page_offset < view_start || page_offset >= view_end {
                continue;
            }
            let len = section.size.saturating_sub(page_offset).min(0x1000) as usize;
            if len != 0 {
                return Some((page.page_index, page.frame, page_offset, len));
            }
        }
        None
    }

    pub fn take_dirty(&mut self) -> bool {
        let dirty = self.dirty;
        self.dirty = false;
        dirty
    }

    pub fn stats(&self) -> GenericSectionTableStats {
        GenericSectionTableStats {
            live_sections: self.sections.iter().filter(|section| section.live).count(),
            section_records: self.sections.len(),
            section_capacity: self.sections.capacity(),
            section_growths: self.section_growths,
            section_allocation_failures: self.section_allocation_failures,
            live_views: self.views.iter().filter(|view| view.live).count(),
            view_records: self.views.len(),
            view_capacity: self.views.capacity(),
            view_growths: self.view_growths,
            view_allocation_failures: self.view_allocation_failures,
            live_pages: self.pages.iter().filter(|page| page.live).count(),
            page_records: self.pages.len(),
            page_capacity: self.pages.capacity(),
            page_growths: self.page_growths,
            page_allocation_failures: self.page_allocation_failures,
        }
    }
}

impl Default for GenericSectionTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_section(table: &mut GenericSectionTable, owner_pi: usize, handle: u64) -> usize {
        table
            .create(
                owner_pi,
                handle,
                0x4000,
                crate::PAGE_READWRITE,
                SECTION_ATTR_SEC_COMMIT,
                GenericSectionBacking::anonymous(),
            )
            .unwrap()
    }

    #[test]
    fn records_grow_past_bootstrap_reservations() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 1));
        let initial = table.stats();
        for index in 0..=initial.section_capacity {
            create_section(&mut table, 2, 0x40 + index as u64 * 4);
        }
        for index in 0..=initial.view_capacity {
            assert!(table.map_view(2, 0, 0x1000 + index as u64 * 0x2000, 0x1000, 0,));
        }
        for index in 0..=initial.page_capacity {
            assert!(table.set_page_frame(0, index as u64, 0x100 + index as u64));
        }
        let stats = table.stats();
        assert_eq!(stats.live_sections, initial.section_capacity + 1);
        assert_eq!(stats.live_views, initial.view_capacity + 1);
        assert_eq!(stats.live_pages, initial.page_capacity + 1);
        assert!(stats.section_capacity > initial.section_capacity);
        assert!(stats.view_capacity > initial.view_capacity);
        assert!(stats.page_capacity > initial.page_capacity);
        assert_eq!(stats.section_growths, 1);
        assert_eq!(stats.view_growths, 1);
        assert_eq!(stats.page_growths, 1);
        assert!(table.take_dirty());
        assert!(!table.take_dirty());
    }

    #[test]
    fn cleared_records_are_reused_without_growth() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 1));
        let section = create_section(&mut table, 3, 0x40);
        assert!(table.map_view(3, section, 0x1000, 0x1000, 0));
        assert!(table.set_page_frame(section, 0, 0x100));
        table.clear_section(section);
        let replacement = create_section(&mut table, 3, 0x44);
        assert_eq!(replacement, section);
        assert!(table.map_view(3, replacement, 0x2000, 0x1000, 0));
        assert!(table.set_page_frame(replacement, 1, 0x200));
        let stats = table.stats();
        assert_eq!(stats.section_records, 1);
        assert_eq!(stats.view_records, 1);
        assert_eq!(stats.page_records, 1);
        assert_eq!(stats.section_growths, 0);
        assert_eq!(stats.view_growths, 0);
        assert_eq!(stats.page_growths, 0);
        assert!(!table.take_dirty());
    }

    #[test]
    fn releasing_last_handle_waits_for_views() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 1));
        let section = create_section(&mut table, 4, 0x40);
        assert!(table.map_view(5, section, 0x1000, 0x2000, 0));
        assert!(table.release_handle(section));
        assert!(table.section(section).is_some());
        assert!(table.unmap_view(5, 0x1000).is_some());
        assert!(table.section(section).is_none());
    }

    #[test]
    fn dirty_page_lookup_respects_view_offset() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 4));
        let section_index = create_section(&mut table, 2, 0x40);
        assert!(table.map_view(2, section_index, 0x4000, 0x1000, 0x1000));
        assert!(table.set_page_frame(section_index, 0, 0x100));
        assert!(table.set_page_frame(section_index, 1, 0x200));
        assert!(table.mark_page_dirty(section_index, 0));
        assert!(table.mark_page_dirty(section_index, 1));
        let (_, view) = table.view_for_page(2, 0x4000).unwrap();
        let section = table.section(section_index).unwrap();
        assert_eq!(
            table.next_dirty_page_for_view(view, section),
            Some((1, 0x200, 0x1000, 0x1000))
        );
    }
}
