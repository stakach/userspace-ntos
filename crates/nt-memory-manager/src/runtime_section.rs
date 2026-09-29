use alloc::vec::Vec;

#[path = "section_control_area.rs"]
mod control_area;
use control_area::ControlArea;
pub use control_area::{SectionFileIdentity, SectionMountId, SectionMountIds};

#[path = "section_mount_binding.rs"]
mod mount_binding;
pub use mount_binding::{SectionMountBindingError, SectionMountBindings};

#[path = "section_pages.rs"]
mod pages;
pub use pages::{SectionPagePublication, SectionPagePublicationError};

#[path = "section_file_io.rs"]
mod file_io;
pub use file_io::{SectionFilePage, SectionFileReadIo, SectionFileResizeIo, SectionFileWriteIo};

#[path = "section_retirement.rs"]
mod retirement;
pub use retirement::{
    PendingSectionFrames, SectionIdentity, SectionRetirement, SectionRetirementIo,
    SectionRetirementResource,
};

use crate::{MemoryLifetime, PAGE_NOACCESS, STATUS_INVALID_PARAMETER_2, STATUS_NOT_MAPPED_VIEW};

pub const GENERIC_SECTION_BACKING_NONE: u8 = 0;
pub const GENERIC_SECTION_BACKING_ANON: u8 = 1;
pub const GENERIC_SECTION_BACKING_DISK: u8 = 2;
pub const GENERIC_SECTION_BACKING_OVERLAY: u8 = 3;
pub const GENERIC_SECTION_BACKING_ROUTED: u8 = 4;
pub const SECTION_ATTR_SEC_BASED: u32 = 0x0020_0000;
pub const SECTION_ATTR_SEC_FILE: u32 = 0x0080_0000;
pub const SECTION_ATTR_SEC_IMAGE: u32 = 0x0100_0000;
pub const SECTION_ATTR_SEC_RESERVE: u32 = 0x0400_0000;
pub const SECTION_ATTR_SEC_COMMIT: u32 = 0x0800_0000;

const SECTION_INITIAL_RESERVE: usize = 16;
const VIEW_INITIAL_RESERVE: usize = 32;
const PAGE_INITIAL_RESERVE: usize = 128;

/// Opaque ownership key for one routed FILE_OBJECT reference, not a file identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutedSectionLease(u64);

impl RoutedSectionLease {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericSectionBacking {
    pub kind: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    pub overlay_file_id: u64,
    pub routed_lease: Option<RoutedSectionLease>,
    pub file: Option<SectionFileIdentity>,
    pub file_extent: u64,
}

impl GenericSectionBacking {
    pub const fn none() -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_NONE,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: 0,
            routed_lease: None,
            file: None,
            file_extent: 0,
        }
    }

    pub const fn anonymous() -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_ANON,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: 0,
            routed_lease: None,
            file: None,
            file_extent: 0,
        }
    }

    pub const fn disk(first_cluster: u32, file_size: u32, file: SectionFileIdentity) -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_DISK,
            first_cluster,
            file_size,
            overlay_file_id: 0,
            routed_lease: None,
            file: Some(file),
            file_extent: file_size as u64,
        }
    }

    pub const fn overlay(file_id: u64, file: SectionFileIdentity, file_extent: u64) -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_OVERLAY,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: file_id,
            routed_lease: None,
            file: Some(file),
            file_extent,
        }
    }

    pub const fn routed(
        lease: RoutedSectionLease,
        file: SectionFileIdentity,
        file_extent: u64,
    ) -> Self {
        Self {
            kind: GENERIC_SECTION_BACKING_ROUTED,
            first_cluster: 0,
            file_size: 0,
            overlay_file_id: 0,
            routed_lease: Some(lease),
            file: Some(file),
            file_extent,
        }
    }

    pub const fn is_live(self) -> bool {
        self.kind != GENERIC_SECTION_BACKING_NONE
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericSection {
    pub live: bool,
    pub generation: u64,
    control_area: u64,
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
            generation: 0,
            control_area: 0,
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
            GENERIC_SECTION_BACKING_DISK
            | GENERIC_SECTION_BACKING_OVERLAY
            | GENERIC_SECTION_BACKING_ROUTED => {
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
    pub generation: u64,
    pub pi: usize,
    pub lifetime: MemoryLifetime,
    pub section_index: usize,
    pub base: u64,
    pub size: u64,
    pub section_offset: u64,
}

/// Exact identity of an isolated provider address space. The caller must obtain and validate
/// these values from its provider catalog, not from an IPC badge or a bare VSpace capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderVspaceIdentity {
    pub domain: u64,
    pub generation: u64,
}

impl ProviderVspaceIdentity {
    pub const fn is_valid(self) -> bool {
        self.domain != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSectionView {
    pub generation: u64,
    pub owner: ProviderVspaceIdentity,
    pub section: SectionIdentity,
    pub base: u64,
    pub size: u64,
    pub section_offset: u64,
}

impl ProviderSectionView {
    fn contains(self, page: u64) -> bool {
        page >= self.base && self.base.checked_add(self.size).is_some_and(|end| page < end)
    }
}

/// A page-aligned range within one data-file view, ready for backing-store writeback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericSectionFlushPlan {
    pub view: GenericSectionView,
    pub section: GenericSection,
    pub base: u64,
    pub size: u64,
    pub section_offset: u64,
}

impl GenericSectionView {
    const fn empty() -> Self {
        Self {
            live: false,
            generation: 0,
            pi: 0,
            lifetime: MemoryLifetime::UnpublishedImage(0),
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

    pub fn permits_retirement_page(
        self,
        process: crate::ProcessIdentity,
        page: u64,
        frame_lifetime: Option<MemoryLifetime>,
        pagefile_lifetime: Option<MemoryLifetime>,
    ) -> bool {
        let expected = MemoryLifetime::Process(process);
        self.live
            && process.is_valid()
            && self.lifetime == expected
            && page >= self.base
            && self.base.checked_add(self.size).is_some_and(|end| page < end)
            && frame_lifetime.is_none_or(|lifetime| lifetime == expected)
            && pagefile_lifetime.is_none_or(|lifetime| lifetime == expected)
    }
}

#[derive(Clone, Copy)]
struct GenericSectionPage {
    live: bool,
    control_area: u64,
    page_index: u64,
    frame: u64,
    dirty: bool,
    dirty_epoch: u64,
}

impl GenericSectionPage {
    const fn empty() -> Self {
        Self {
            live: false,
            control_area: 0,
            page_index: 0,
            frame: 0,
            dirty: false,
            dirty_epoch: 0,
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
    pub live_provider_views: usize,
    pub provider_view_capacity: usize,
    pub provider_view_growths: u64,
    pub provider_view_allocation_failures: u64,
    pub live_pages: usize,
    pub page_records: usize,
    pub page_capacity: usize,
    pub page_growths: u64,
    pub page_allocation_failures: u64,
}

pub struct GenericSectionTable {
    sections: Vec<GenericSection>,
    control_areas: Vec<ControlArea>,
    views: Vec<GenericSectionView>,
    provider_views: Vec<ProviderSectionView>,
    pages: Vec<GenericSectionPage>,
    dirty_epoch: u64,
    section_generation: u64,
    view_generation: u64,
    provider_view_generation: u64,
    section_growths: u64,
    section_allocation_failures: u64,
    view_growths: u64,
    view_allocation_failures: u64,
    provider_view_growths: u64,
    provider_view_allocation_failures: u64,
    page_growths: u64,
    page_allocation_failures: u64,
}

impl GenericSectionTable {
    pub const fn new() -> Self {
        Self {
            sections: Vec::new(),
            control_areas: Vec::new(),
            views: Vec::new(),
            provider_views: Vec::new(),
            pages: Vec::new(),
            dirty_epoch: 0,
            section_generation: 0,
            view_generation: 0,
            provider_view_generation: 0,
            section_growths: 0,
            section_allocation_failures: 0,
            view_growths: 0,
            view_allocation_failures: 0,
            provider_view_growths: 0,
            provider_view_allocation_failures: 0,
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
        if self
            .sections
            .iter()
            .any(|section| section.backing.is_live())
            || !self.provider_views.is_empty()
            || self.pages.iter().any(|page| page.live)
        {
            return false;
        }
        self.sections.clear();
        self.control_areas.clear();
        self.views.clear();
        self.provider_views.clear();
        self.pages.clear();
        self.section_growths = 0;
        self.section_allocation_failures = 0;
        self.view_growths = 0;
        self.view_allocation_failures = 0;
        self.provider_view_growths = 0;
        self.provider_view_allocation_failures = 0;
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
        if self.provider_views.try_reserve(view_reserve).is_err() {
            self.provider_view_allocation_failures = 1;
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
        match backing.kind {
            GENERIC_SECTION_BACKING_ANON
                if backing.file.is_none() && backing.routed_lease.is_none() => {}
            GENERIC_SECTION_BACKING_DISK | GENERIC_SECTION_BACKING_OVERLAY
                if backing.file.is_some()
                    && backing.routed_lease.is_none()
                    && size <= backing.file_extent
                    && backing.file_extent <= crate::data_section::MAX_DATA_SECTION_SIZE => {}
            GENERIC_SECTION_BACKING_ROUTED
                if backing.file.is_some()
                    && backing.routed_lease.is_some()
                    && backing.overlay_file_id == 0
                    && backing.first_cluster == 0
                    && backing.file_size == 0
                    && size <= backing.file_extent
                    && backing.file_extent <= crate::data_section::MAX_DATA_SECTION_SIZE
                    && !self.sections.iter().any(|section| {
                        section.backing.kind == GENERIC_SECTION_BACKING_ROUTED
                            && section.backing.routed_lease == backing.routed_lease
                    }) => {}
            _ => return None,
        }
        if handle != 0 {
            if self.index_for_handle(owner_pi, handle).is_some() {
                return None;
            }
        }
        let generation = self.section_generation.checked_add(1)?;
        self.section_generation = generation;
        self.validate_backing_extent(backing).ok()?;
        let existing = self.matching_control_area(backing);
        if existing.is_none() {
            self.control_areas.try_reserve(1).ok()?;
        }
        let area_id = existing.map_or(generation, |index| self.control_areas[index].id);
        let section = GenericSection {
            live: true,
            generation,
            control_area: area_id,
            owner_pi,
            handle,
            size,
            protection,
            allocation_attributes,
            backing,
        };
        let index = if let Some(index) = self
            .sections
            .iter()
            .position(|entry| !entry.backing.is_live())
        {
            self.sections[index] = section;
            index
        } else {
            self.append_section(section)?
        };
        if let Some(area) = existing {
            self.control_areas[area].extent = backing.file_extent;
            self.control_areas[area].segment_extent =
                self.control_areas[area].segment_extent.max(size);
        } else {
            let area = ControlArea {
                id: area_id,
                file: backing.file,
                kind: backing.kind,
                segment_extent: if backing.file.is_some() {
                    backing.file_extent
                } else {
                    size
                },
                extent: if backing.file.is_some() {
                    backing.file_extent
                } else {
                    size
                },
            };
            if let Some(slot) = self.control_areas.iter_mut().find(|area| area.id == 0) {
                *slot = area;
            } else {
                self.control_areas.push(area);
            }
        }
        Some(index)
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
            section.live = false;
            section.handle = 0;
        }
        for view in &mut self.views {
            if view.live && view.section_index == index {
                *view = GenericSectionView::empty();
            }
        }
        self.provider_views.retain(|view| view.section.index != index);
        // Keep source frames and backing until the mechanism acknowledges their release.
    }

    fn section_has_views(&self, index: usize) -> bool {
        self.views
            .iter()
            .any(|view| view.live && view.section_index == index)
            || self.provider_views.iter().any(|view| view.section.index == index)
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

    pub fn section_identity(&self, index: usize) -> Option<SectionIdentity> {
        self.section(index).map(|section| SectionIdentity {
            index,
            generation: section.generation,
        })
    }

    /// Publish a provider-owned view only after its VSpace reservation has succeeded. Views in
    /// different provider address spaces may use the same VA; ranges in one space may not overlap.
    pub fn map_provider_view(
        &mut self,
        owner: ProviderVspaceIdentity,
        section: SectionIdentity,
        base: u64,
        size: u64,
        section_offset: u64,
    ) -> Option<ProviderSectionView> {
        if !owner.is_valid() || base == 0 || size == 0 || (base | size | section_offset) & 0xfff != 0 {
            return None;
        }
        let Some(end) = base.checked_add(size) else { return None };
        let Some(section_end) = section_offset.checked_add(size) else { return None };
        if self.section_identity(section.index) != Some(section)
            || self.sections[section.index]
                .size
                .checked_add(0xfff)
                .map(|size| size & !0xfff)
                .is_none_or(|extent| extent < section_end)
            || self.provider_views.iter().any(|view| {
                view.owner.domain == owner.domain
                    && (view.owner.generation != owner.generation
                        || (base < view.base + view.size && view.base < end))
            })
        {
            return None;
        }
        let generation = self.provider_view_generation.checked_add(1)?;
        let old_capacity = self.provider_views.capacity();
        if self.provider_views.try_reserve(1).is_err() {
            self.provider_view_allocation_failures = self.provider_view_allocation_failures.saturating_add(1);
            return None;
        }
        if self.provider_views.capacity() != old_capacity {
            self.provider_view_growths = self.provider_view_growths.saturating_add(1);
        }
        let view = ProviderSectionView { generation, owner, section, base, size, section_offset };
        self.provider_views.push(view);
        self.provider_view_generation = generation;
        Some(view)
    }

    pub fn provider_view_for_page(
        &self,
        owner: ProviderVspaceIdentity,
        page: u64,
    ) -> Option<ProviderSectionView> {
        if !owner.is_valid() { return None; }
        self.provider_views.iter().copied().find(|view| {
            view.owner == owner
                && view.contains(page)
                && self.section_identity(view.section.index) == Some(view.section)
        })
    }

    /// Enumerate exact views while retiring one provider address-space generation.
    pub fn first_provider_view(
        &self,
        owner: ProviderVspaceIdentity,
    ) -> Option<ProviderSectionView> {
        if !owner.is_valid() {
            return None;
        }
        self.provider_views.iter().copied().find(|view| view.owner == owner)
    }

    /// An unmap must name the exact view incarnation, not just a reusable address.
    pub fn unmap_provider_view_exact(&mut self, view: ProviderSectionView) -> Option<ProviderSectionView> {
        if !view.owner.is_valid() || view.generation == 0 { return None; }
        let index = self.provider_views.iter().position(|candidate| {
            *candidate == view
                && self.section_identity(candidate.section.index) == Some(candidate.section)
        })?;
        let view = self.provider_views.remove(index);
        self.clear_section_if_unreferenced(view.section.index);
        Some(view)
    }

    pub fn map_view_with_lifetime(
        &mut self,
        pi: usize,
        lifetime: MemoryLifetime,
        section_index: usize,
        base: u64,
        size: u64,
        section_offset: u64,
    ) -> bool {
        if !lifetime.is_valid() || self.section(section_index).is_none() || base == 0 || size == 0 {
            return false;
        }
        let Some(generation) = self.view_generation.checked_add(1) else {
            return false;
        };
        let view = GenericSectionView {
            live: true,
            generation,
            pi,
            lifetime,
            section_index,
            base,
            size,
            section_offset,
        };
        let published = if let Some(index) = self.views.iter().position(|entry| !entry.live) {
            self.views[index] = view;
            true
        } else {
            self.append_view(view)
        };
        if published {
            self.view_generation = generation;
        }
        published
    }

    #[cfg(test)]
    pub fn map_view(
        &mut self,
        pi: usize,
        section_index: usize,
        base: u64,
        size: u64,
        section_offset: u64,
    ) -> bool {
        self.map_view_with_lifetime(
            pi,
            MemoryLifetime::Process(crate::ProcessIdentity {
                pid: pi as u32 + 1,
                generation: crate::ProcessGeneration::Hosted(1),
            }),
            section_index,
            base,
            size,
            section_offset,
        )
    }

    pub fn unmap_view_exact(
        &mut self,
        pi: usize,
        lifetime: MemoryLifetime,
        base: u64,
    ) -> Option<GenericSectionView> {
        for view in &mut self.views {
            if view.live && view.pi == pi && view.lifetime == lifetime && view.base == base {
                let removed = *view;
                *view = GenericSectionView::empty();
                self.clear_section_if_unreferenced(removed.section_index);
                return Some(removed);
            }
        }
        None
    }

    #[cfg(test)]
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

    pub fn first_view_for_process_exact(
        &self,
        pi: usize,
        lifetime: MemoryLifetime,
    ) -> Option<GenericSectionView> {
        self.views
            .iter()
            .copied()
            .find(|view| view.live && view.pi == pi && view.lifetime == lifetime)
    }

    pub fn view_for_page(&self, pi: usize, page: u64) -> Option<(usize, GenericSectionView)> {
        self.views
            .iter()
            .find(|view| view.contains(pi, page))
            .map(|view| (view.section_index, *view))
    }

    /// Resolve and page-align an `NtFlushVirtualMemory` range. A flush is confined to one
    /// data-file view; a zero input size means from `base` to that view's end.
    pub fn plan_flush(
        &self,
        pi: usize,
        base: u64,
        size: u64,
    ) -> Result<GenericSectionFlushPlan, u32> {
        const PAGE_MASK: u64 = 0xfff;

        let (section_index, view) = self.view_for_page(pi, base).ok_or(STATUS_NOT_MAPPED_VIEW)?;
        let section = self.section(section_index).ok_or(STATUS_NOT_MAPPED_VIEW)?;
        if !matches!(
            section.backing.kind,
            GENERIC_SECTION_BACKING_DISK | GENERIC_SECTION_BACKING_OVERLAY
        ) {
            return Err(STATUS_NOT_MAPPED_VIEW);
        }

        let view_end = view
            .base
            .checked_add(view.size)
            .ok_or(STATUS_INVALID_PARAMETER_2)?;
        let flush_base = base & !PAGE_MASK;
        if flush_base < view.base {
            return Err(STATUS_NOT_MAPPED_VIEW);
        }
        let flush_end = if size == 0 {
            view_end
        } else {
            let requested_end = base.checked_add(size).ok_or(STATUS_INVALID_PARAMETER_2)?;
            if requested_end > view_end {
                return Err(STATUS_NOT_MAPPED_VIEW);
            }
            requested_end
                .checked_add(PAGE_MASK)
                .ok_or(STATUS_INVALID_PARAMETER_2)?
                & !PAGE_MASK
        };
        let flush_end = flush_end.min(view_end);
        let flush_size = flush_end
            .checked_sub(flush_base)
            .filter(|size| *size != 0)
            .ok_or(STATUS_INVALID_PARAMETER_2)?;
        let section_offset = view
            .section_offset
            .checked_add(flush_base - view.base)
            .ok_or(STATUS_INVALID_PARAMETER_2)?;
        Ok(GenericSectionFlushPlan {
            view,
            section,
            base: flush_base,
            size: flush_size,
            section_offset,
        })
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
            live_provider_views: self.provider_views.len(),
            provider_view_capacity: self.provider_views.capacity(),
            provider_view_growths: self.provider_view_growths,
            provider_view_allocation_failures: self.provider_view_allocation_failures,
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

    fn file_identity(file_id: u64) -> SectionFileIdentity {
        SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id,
        }
    }

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

    fn provider(domain: u64, generation: u64) -> ProviderVspaceIdentity {
        ProviderVspaceIdentity { domain, generation }
    }

    #[test]
    fn process_view_generation_changes_on_exact_unmap_and_slot_reuse() {
        let mut table = GenericSectionTable::new();
        let section = create_section(&mut table, 2, 0x40);
        let lifetime = MemoryLifetime::Process(crate::ProcessIdentity {
            pid: 17,
            generation: crate::ProcessGeneration::Hosted(3),
        });
        assert!(table.map_view_with_lifetime(2, lifetime, section, 0x10000, 0x2000, 0));
        let first = table.first_view_for_process_exact(2, lifetime).unwrap();
        assert_ne!(first.generation, 0);
        assert_eq!(table.view_for_page(2, 0x11000).unwrap().1.generation, first.generation);
        assert_eq!(table.unmap_view_exact(2, lifetime, 0x10000), Some(first));
        assert!(table.map_view_with_lifetime(2, lifetime, section, 0x10000, 0x2000, 0));
        let second = table.first_view_for_process_exact(2, lifetime).unwrap();
        assert_eq!(table.stats().view_records, 1);
        assert_eq!(second.generation, first.generation + 1);
        assert_eq!(table.view_for_page(2, 0x11000).unwrap().1, second);
    }

    #[test]
    fn process_view_generation_survives_table_reset_and_fails_closed_at_wrap() {
        let mut table = GenericSectionTable::new();
        let section = create_section(&mut table, 2, 0x40);
        assert!(table.map_view(2, section, 0x10000, 0x1000, 0));
        let first = table.first_view_for_process(2).unwrap();
        assert!(table.unmap_view(2, 0x10000).is_some());
        assert!(table.release_handle(section));
        let retirement = table.next_retirement().unwrap();
        assert!(table.complete_retirement(retirement));
        assert!(table.reset());
        let replacement = create_section(&mut table, 2, 0x40);
        assert!(table.map_view(2, replacement, 0x10000, 0x1000, 0));
        assert_eq!(table.first_view_for_process(2).unwrap().generation, first.generation + 1);

        assert!(table.unmap_view(2, 0x10000).is_some());
        table.view_generation = u64::MAX;
        assert!(!table.map_view(2, replacement, 0x10000, 0x1000, 0));
        assert_eq!(table.stats().live_views, 0);
        assert_eq!(table.view_generation, u64::MAX);
    }

    #[test]
    fn provider_view_retains_section_backing_after_handle_close() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let section = table.section_identity(index).unwrap();
        let owner = provider(7, 11);
        let view = table.map_provider_view(owner, section, 0x10000, 0x2000, 0).unwrap();
        assert!(table.release_handle(index));
        assert_eq!(table.provider_view_for_page(owner, 0x11000).unwrap().section, section);
        assert!(table.section(index).is_some());
        assert!(table.next_retirement().is_none());
        assert_eq!(table.stats().live_provider_views, 1);

        assert_eq!(table.unmap_provider_view_exact(view).unwrap().section, section);
        assert!(table.section(index).is_none());
        assert_eq!(table.next_retirement().unwrap().identity(), section);
        assert_eq!(table.stats().live_provider_views, 0);
    }

    #[test]
    fn stale_provider_view_cannot_unmap_same_base_replacement() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let section = table.section_identity(index).unwrap();
        let owner = provider(7, 11);
        let first = table.map_provider_view(owner, section, 0x10000, 0x1000, 0).unwrap();
        assert_eq!(table.unmap_provider_view_exact(first), Some(first));
        let replacement = table.map_provider_view(owner, section, 0x10000, 0x1000, 0).unwrap();
        assert_ne!(first.generation, replacement.generation);
        assert_eq!(table.unmap_provider_view_exact(first), None);
        assert_eq!(table.provider_view_for_page(owner, 0x10000), Some(replacement));
    }

    #[test]
    fn provider_view_generation_exhaustion_refuses_map() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let section = table.section_identity(index).unwrap();
        table.provider_view_generation = u64::MAX;

        assert!(table.map_provider_view(provider(7, 11), section, 0x10000, 0x1000, 0).is_none());
        assert_eq!(table.stats().live_provider_views, 0);
        assert_eq!(table.provider_view_generation, u64::MAX);
    }

    #[test]
    fn provider_view_rejects_overlap_and_stale_generation() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let section = table.section_identity(index).unwrap();
        let first = provider(7, 11);
        let next = provider(7, 12);
        let other = provider(8, 1);
        let first_view = table.map_provider_view(first, section, 0x10000, 0x2000, 0).unwrap();
        assert!(table.map_provider_view(first, section, 0x11000, 0x1000, 0).is_none());
        let second_view = table.map_provider_view(first, section, 0x12000, 0x1000, 0x2000).unwrap();
        assert!(table.map_provider_view(other, section, 0x10000, 0x1000, 0).is_some());
        assert_eq!(table.first_provider_view(first).unwrap().base, 0x10000);
        assert!(table.first_provider_view(next).is_none());
        assert!(table.provider_view_for_page(next, 0x10000).is_none());
        assert!(table.unmap_provider_view_exact(ProviderSectionView { owner: next, ..first_view }).is_none());
        assert!(table.map_provider_view(next, section, 0x20000, 0x1000, 0).is_none());
        assert!(table.unmap_provider_view_exact(first_view).is_some());
        assert!(table.unmap_provider_view_exact(second_view).is_some());
        assert!(table.first_provider_view(first).is_none());
        assert!(table.map_provider_view(next, section, 0x10000, 0x1000, 0).is_some());
        assert!(table.provider_view_for_page(first, 0x10000).is_none());
        assert!(table.unmap_provider_view_exact(first_view).is_none());
    }

    #[test]
    fn provider_view_validates_section_generation_and_range() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let section = table.section_identity(index).unwrap();
        let stale = SectionIdentity { index, generation: section.generation + 1 };
        let owner = provider(7, 11);
        assert!(table.map_provider_view(owner, stale, 0x10000, 0x1000, 0).is_none());
        assert!(table.map_provider_view(provider(0, 11), section, 0x10000, 0x1000, 0).is_none());
        assert!(table.map_provider_view(owner, section, 0x10001, 0x1000, 0).is_none());
        assert!(table.map_provider_view(owner, section, 0x10000, 0x1000, 1).is_none());
        assert!(table.map_provider_view(owner, section, 0x10000, 0x2000, 0x3000).is_none());
        assert!(table.map_provider_view(owner, section, u64::MAX & !0xfff, 0x2000, 0).is_none());
        assert!(table.map_provider_view(owner, section, 0x10000, 0x1000, 0x3000).is_some());
    }

    #[test]
    fn provider_view_covers_last_partial_file_page() {
        let mut table = GenericSectionTable::new();
        let index = table.create(
            2,
            0x40,
            0x1001,
            crate::PAGE_READONLY,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::disk(1, 0x1001, file_identity(7)),
        ).unwrap();
        let section = table.section_identity(index).unwrap();
        let owner = provider(7, 11);
        assert!(table.map_provider_view(owner, section, 0x10000, 0x2000, 0).is_some());
        assert_eq!(table.provider_view_for_page(owner, 0x11000).unwrap().section_offset, 0);
        assert!(table.map_provider_view(owner, section, 0x20000, 0x1000, 0x2000).is_none());
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
    }

    #[test]
    fn cleared_records_are_reused_without_growth() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 1));
        let section = create_section(&mut table, 3, 0x40);
        assert!(table.map_view(3, section, 0x1000, 0x1000, 0));
        assert!(table.set_page_frame(section, 0, 0x100));
        table.clear_section(section);
        while let Some(ticket) = table.next_retirement() {
            assert!(table.complete_retirement(ticket));
        }
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

    #[test]
    fn flush_plan_rounds_one_data_view_range_to_pages() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 1));
        let section = table
            .create(
                2,
                0x40,
                0x8000,
                crate::PAGE_READWRITE,
                SECTION_ATTR_SEC_COMMIT,
                GenericSectionBacking::overlay(7, file_identity(7), 0x8000),
            )
            .unwrap();
        assert!(table.map_view(3, section, 0x1_0000, 0x4000, 0x2000));

        let plan = table.plan_flush(3, 0x1_1080, 0x1010).unwrap();
        assert_eq!(plan.base, 0x1_1000);
        assert_eq!(plan.size, 0x2000);
        assert_eq!(plan.section_offset, 0x3000);
        assert_eq!(plan.view.section_index, section);
    }

    #[test]
    fn zero_length_flush_extends_to_view_end() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 1));
        let section = table
            .create(
                2,
                0x40,
                0x8000,
                crate::PAGE_READWRITE,
                SECTION_ATTR_SEC_COMMIT,
                GenericSectionBacking::disk(4, 0x8000, file_identity(4)),
            )
            .unwrap();
        assert!(table.map_view(4, section, 0x2_0000, 0x5000, 0x1000));

        let plan = table.plan_flush(4, 0x2_2345, 0).unwrap();
        assert_eq!(plan.base, 0x2_2000);
        assert_eq!(plan.size, 0x3000);
        assert_eq!(plan.section_offset, 0x3000);
    }

    #[test]
    fn flush_rejects_unmapped_anonymous_and_cross_view_ranges() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(2, 2, 1));
        let data = table
            .create(
                2,
                0x40,
                0x4000,
                crate::PAGE_READWRITE,
                SECTION_ATTR_SEC_COMMIT,
                GenericSectionBacking::overlay(7, file_identity(7), 0x8000),
            )
            .unwrap();
        let anonymous = create_section(&mut table, 2, 0x44);
        assert!(table.map_view(5, data, 0x3_0000, 0x2000, 0));
        assert!(table.map_view(5, anonymous, 0x4_0000, 0x2000, 0));

        assert_eq!(
            table.plan_flush(5, 0x2_f000, 0x1000),
            Err(STATUS_NOT_MAPPED_VIEW)
        );
        assert_eq!(
            table.plan_flush(5, 0x4_0000, 0x1000),
            Err(STATUS_NOT_MAPPED_VIEW)
        );
        assert_eq!(
            table.plan_flush(5, 0x3_1000, 0x2000),
            Err(STATUS_NOT_MAPPED_VIEW)
        );
    }

    #[test]
    fn flush_dirty_lookup_is_confined_to_the_planned_pages() {
        let mut table = GenericSectionTable::new();
        assert!(table.reset_with_reserve(1, 1, 4));
        let section = table
            .create(
                2,
                0x40,
                0x4000,
                crate::PAGE_READWRITE,
                SECTION_ATTR_SEC_COMMIT,
                GenericSectionBacking::overlay(7, file_identity(7), 0x8000),
            )
            .unwrap();
        assert!(table.map_view(6, section, 0x5_0000, 0x4000, 0));
        for page in 0..4 {
            assert!(table.set_page_frame(section, page, 0x100 + page));
            assert!(table.mark_page_dirty(section, page));
        }

        let plan = table.plan_flush(6, 0x5_1001, 1).unwrap();
        assert_eq!(
            table.next_dirty_page_for_flush(plan),
            Some((1, 0x101, 0x1000, 0x1000))
        );
        let tickets = table.prepare_writeback(plan).unwrap();
        assert_eq!(tickets.len(), 1);
        assert!(table.complete_writeback_page(tickets[0]));
        assert_eq!(table.next_dirty_page_for_flush(plan), None);
        assert_eq!(
            table.next_dirty_page_for_view(plan.view, plan.section),
            Some((0, 0x100, 0, 0x1000))
        );
    }

    #[test]
    fn dirty_epoch_exhaustion_cannot_reuse_a_completion_identity() {
        let mut table = GenericSectionTable::new();
        let section = create_section(&mut table, 2, 0x40);
        assert!(table.set_page_frame(section, 0, 100));
        table.dirty_epoch = u64::MAX;
        assert!(!table.mark_page_dirty(section, 0));
        assert!(!table.set_page_frame(section, 0, 101));
        assert_eq!(table.page_frame(section, 0), Some(100));
    }

    #[test]
    fn page_publication_reuses_an_existing_frame_without_adopting_candidate() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let identity = table.section_identity(index).unwrap();
        assert_eq!(
            table.publish_page_frame_exact(identity, 0, 100),
            Ok(SectionPagePublication::Inserted)
        );
        assert_eq!(
            table.publish_page_frame_exact(identity, 0, 101),
            Ok(SectionPagePublication::Existing(100))
        );
        assert_eq!(table.page_frame(index, 0), Some(100));
        assert_eq!(table.stats().live_pages, 1);
    }

    #[test]
    fn page_publication_rejects_a_reused_section_slot() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let stale = table.section_identity(index).unwrap();
        assert!(table.release_handle(index));
        let retirement = table.next_retirement().unwrap();
        assert_eq!(retirement.identity(), stale);
        assert!(table.complete_retirement(retirement));
        let replacement = create_section(&mut table, 2, 0x41);
        assert_eq!(replacement, index);
        let fresh = table.section_identity(replacement).unwrap();
        assert_ne!(fresh, stale);
        assert_eq!(
            table.publish_page_frame_exact(stale, 0, 100),
            Err(SectionPagePublicationError::StaleSection)
        );
        assert_eq!(table.page_frame(replacement, 0), None);
        assert_eq!(
            table.publish_page_frame_exact(fresh, 0, 101),
            Ok(SectionPagePublication::Inserted)
        );
    }

    #[test]
    fn page_publication_follows_view_lifetime_after_handle_close() {
        let mut table = GenericSectionTable::new();
        let index = create_section(&mut table, 2, 0x40);
        let identity = table.section_identity(index).unwrap();
        let owner = provider(7, 11);
        let view = table.map_provider_view(owner, identity, 0x10000, 0x1000, 0).unwrap();
        assert!(table.release_handle(index));
        assert_eq!(
            table.publish_page_frame_exact(identity, 0, 100),
            Ok(SectionPagePublication::Inserted)
        );
        assert!(table.unmap_provider_view_exact(view).is_some());
        assert_eq!(
            table.publish_page_frame_exact(identity, 1, 101),
            Err(SectionPagePublicationError::StaleSection)
        );
        assert_eq!(table.page_frame(index, 1), None);
    }
}
