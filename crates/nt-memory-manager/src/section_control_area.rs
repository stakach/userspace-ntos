//! Mounted-file identity and shared data-section ownership, independent of open handles.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionMountId(u64);

pub struct SectionMountIds {
    next: u64,
}
impl SectionMountIds {
    pub const fn new() -> Self {
        Self { next: 0 }
    }
    pub fn allocate(&mut self) -> Option<SectionMountId> {
        self.next = self.next.checked_add(1)?;
        Some(SectionMountId(self.next))
    }
}
impl Default for SectionMountIds {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionFileIdentity {
    pub mount: SectionMountId,
    pub file_id: u64,
}

#[derive(Clone, Copy)]
pub(super) struct ControlArea {
    pub id: u64,
    pub file: Option<SectionFileIdentity>,
    pub kind: u8,
    pub extent: u64,
}

impl ControlArea {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            file: None,
            kind: GENERIC_SECTION_BACKING_NONE,
            extent: 0,
        }
    }
}

impl GenericSectionTable {
    pub(super) fn control_area_live(&self, id: u64) -> bool {
        id != 0
            && self
                .sections
                .iter()
                .any(|section| section.live && section.control_area == id)
    }

    pub(super) fn matching_control_area(&self, backing: GenericSectionBacking) -> Option<usize> {
        let file = backing.file?;
        self.control_areas.iter().position(|area| {
            area.file == Some(file) && area.kind == backing.kind && self.control_area_live(area.id)
        })
    }

    pub(super) fn control_area(&self, section_index: usize) -> Option<ControlArea> {
        let section = self.section(section_index)?;
        self.control_areas
            .iter()
            .copied()
            .find(|area| area.id == section.control_area)
    }

    fn validate_area_extent(&self, area: ControlArea, extent: u64) -> Result<(), u32> {
        if extent < area.extent {
            return Err(0xc000_0011);
        } // STATUS_END_OF_FILE
        if extent > crate::data_section::MAX_DATA_SECTION_SIZE {
            return Err(crate::STATUS_SECTION_TOO_BIG);
        }
        // The old EOF tail is cached zero padding, not newly appended file data. Do not widen
        // writeback over it until file-I/O and resident-page coherence can update that tail.
        if extent > area.extent
            && area.extent & 0xfff != 0
            && self.pages.iter().any(|page| {
                page.live && page.control_area == area.id && page.page_index == area.extent / 0x1000
            })
        {
            return Err(0xc000_0243); // STATUS_USER_MAPPED_FILE
        }
        Ok(())
    }

    /// Refresh only extents that cannot invalidate resident data. Shrink and cached partial-page
    /// growth remain refused until mapped-file I/O coherence handles those transitions.
    pub fn refresh_file_extent(&mut self, section_index: usize, extent: u64) -> Result<(), u32> {
        let section = self.section(section_index).ok_or(STATUS_NOT_MAPPED_VIEW)?;
        if section.backing.file.is_none() {
            return Err(STATUS_NOT_MAPPED_VIEW);
        }
        let index = self
            .control_areas
            .iter()
            .position(|area| area.id == section.control_area)
            .ok_or(STATUS_NOT_MAPPED_VIEW)?;
        self.validate_area_extent(self.control_areas[index], extent)?;
        self.control_areas[index].extent = extent;
        Ok(())
    }

    pub fn validate_backing_extent(&self, backing: GenericSectionBacking) -> Result<(), u32> {
        if let Some(index) = self.matching_control_area(backing) {
            self.validate_area_extent(self.control_areas[index], backing.file_extent)?;
        }
        Ok(())
    }

    /// Run before real EOF extension, so an extension cannot hide earlier external truncation or
    /// mutate a file whose cached partial-page tail cannot yet be made coherent.
    pub fn validate_file_creation(
        &self,
        backing: GenericSectionBacking,
        requested_size: u64,
    ) -> Result<(), u32> {
        self.validate_backing_extent(backing)?;
        if requested_size > backing.file_extent
            && requested_size <= crate::data_section::MAX_DATA_SECTION_SIZE
        {
            self.validate_backing_extent(GenericSectionBacking {
                file_extent: requested_size,
                ..backing
            })?;
        }
        Ok(())
    }

    pub(super) fn retire_control_area_if_unreferenced(&mut self, id: u64) {
        if self
            .sections
            .iter()
            .any(|section| section.backing.is_live() && section.control_area == id)
        {
            return;
        }
        assert!(!self
            .pages
            .iter()
            .any(|page| page.live && page.control_area == id));
        if let Some(area) = self.control_areas.iter_mut().find(|area| area.id == id) {
            *area = ControlArea::empty();
        }
    }
}

#[cfg(test)]
#[path = "section_control_area_tests.rs"]
mod tests;
