//! Managed image views retain the existing image authority through mapping and cleanup effects.

use super::*;
use crate::ProcessIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageMappedViewPhase {
    Prepared,
    Mapping,
    Mapped,
    Retiring,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageMappedView {
    pub process: ProcessIdentity,
    pub base: u64,
    pub size: u64,
    pub phase: ImageMappedViewPhase,
}

/// This receipt does not perform cleanup. A backend may acknowledge it only after exact mapped
/// frames and aliases have retired; uncertain effects must quarantine the view instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "retain the receipt until every view resource has acknowledged cleanup"]
pub struct ImageMappedViewRetirement {
    view: ImageViewRef,
    generation: u64,
}

impl ImageMappedViewRetirement {
    pub fn view(self) -> ImageViewRef { self.view }
}

pub(super) struct ManagedView {
    view: ImageViewRef,
    mapping: ImageMappedView,
    retirement: Option<ImageMappedViewRetirement>,
}

impl ImageSectionTable {
    fn managed_index(&self, view: ImageViewRef) -> Result<usize, ImageSectionError> {
        self.reference_index(view.area, view.generation, ReferenceKind::View)?;
        self.mapped_views.iter().position(|row| row.view == view)
            .ok_or(ImageSectionError::InvalidReference)
    }

    /// Reserve metadata and a genuine image view reference before any mapping effect. Names,
    /// numeric handles and target VSpace capabilities are authenticated by the executive caller.
    pub fn reserve_mapped_view(
        &mut self,
        section: ImageSectionRef,
        process: ProcessIdentity,
        base: u64,
        size: u64,
    ) -> Result<ImageViewRef, ImageSectionError> {
        self.reference_index(section.area, section.generation, ReferenceKind::Section)?;
        let end = base.checked_add(size).ok_or(ImageSectionError::InvalidReference)?;
        if !process.is_valid() || base == 0 || base & 0xfff != 0
            || size == 0 || size & 0xfff != 0
            || self.mapped_views.iter().any(|row| row.mapping.process == process
                && base < row.mapping.base + row.mapping.size && row.mapping.base < end)
        {
            return Err(ImageSectionError::InvalidReference);
        }
        self.mapped_views.try_reserve(1).map_err(|_| ImageSectionError::InsufficientResources)?;
        let view = self.reference_view(section)?;
        self.mapped_views.push(ManagedView {
            view,
            mapping: ImageMappedView { process, base, size, phase: ImageMappedViewPhase::Prepared },
            retirement: None,
        });
        Ok(view)
    }

    pub fn mapped_view(&self, view: ImageViewRef) -> Option<ImageMappedView> {
        self.managed_index(view).ok().map(|index| self.mapped_views[index].mapping)
    }

    /// Mark entry before native map/metadata effects. An entered mapping cannot use the pure
    /// Prepared abort path even when final publication has not yet acknowledged.
    pub fn begin_mapped_view_mapping(
        &mut self, view: ImageViewRef, process: ProcessIdentity,
    ) -> Result<(), ImageSectionError> {
        let index = self.managed_index(view)?;
        let row = &mut self.mapped_views[index];
        if row.mapping.process != process || row.mapping.phase != ImageMappedViewPhase::Prepared {
            return Err(ImageSectionError::InvalidReference);
        }
        row.mapping.phase = ImageMappedViewPhase::Mapping;
        Ok(())
    }

    pub fn publish_mapped_view(&mut self, view: ImageViewRef) -> Result<(), ImageSectionError> {
        let index = self.managed_index(view)?;
        let row = &mut self.mapped_views[index];
        if row.mapping.phase != ImageMappedViewPhase::Mapping {
            return Err(ImageSectionError::InvalidReference);
        }
        row.mapping.phase = ImageMappedViewPhase::Mapped;
        Ok(())
    }

    /// Only a known unentered reservation may release without a native cleanup receipt.
    pub fn abort_prepared_mapped_view(
        &mut self, view: ImageViewRef, process: ProcessIdentity,
    ) -> Result<(), ImageSectionError> {
        let index = self.managed_index(view)?;
        let row = &self.mapped_views[index];
        if row.mapping.process != process || row.mapping.phase != ImageMappedViewPhase::Prepared {
            return Err(ImageSectionError::InvalidReference);
        }
        let reference = self.reference_index(view.area, view.generation, ReferenceKind::View)?;
        self.mapped_views.swap_remove(index);
        self.references[reference] = None;
        Ok(())
    }

    /// Entered but refused mapping may retire its accepted prefix through the same checked path
    /// as a published view. The native owner, not this value policy, proves each cleanup ACK.
    pub fn begin_mapped_view_retirement(
        &mut self, view: ImageViewRef, process: ProcessIdentity,
    ) -> Result<ImageMappedViewRetirement, ImageSectionError> {
        let index = self.managed_index(view)?;
        let row = &self.mapped_views[index];
        if row.mapping.process != process {
            return Err(ImageSectionError::InvalidReference);
        }
        if row.mapping.phase == ImageMappedViewPhase::Retiring {
            return row.retirement.ok_or(ImageSectionError::InvalidReference);
        }
        if !matches!(row.mapping.phase, ImageMappedViewPhase::Mapping | ImageMappedViewPhase::Mapped) {
            return Err(ImageSectionError::InvalidReference);
        }
        let receipt = ImageMappedViewRetirement { view, generation: self.next_generation()? };
        let row = &mut self.mapped_views[index];
        row.mapping.phase = ImageMappedViewPhase::Retiring;
        row.retirement = Some(receipt);
        Ok(receipt)
    }

    pub fn acknowledge_mapped_view_retirement(
        &mut self, receipt: ImageMappedViewRetirement,
    ) -> Result<(), ImageSectionError> {
        let index = self.managed_index(receipt.view)?;
        let row = &self.mapped_views[index];
        if row.mapping.phase != ImageMappedViewPhase::Retiring || row.retirement != Some(receipt) {
            return Err(ImageSectionError::InvalidReference);
        }
        let reference = self.reference_index(receipt.view.area, receipt.view.generation, ReferenceKind::View)?;
        self.mapped_views.swap_remove(index);
        self.references[reference] = None;
        Ok(())
    }

    pub fn quarantine_mapped_view(&mut self, view: ImageViewRef) -> Result<(), ImageSectionError> {
        let index = self.managed_index(view)?;
        let row = &mut self.mapped_views[index];
        if !matches!(row.mapping.phase, ImageMappedViewPhase::Mapping | ImageMappedViewPhase::Retiring) {
            return Err(ImageSectionError::InvalidReference);
        }
        row.mapping.phase = ImageMappedViewPhase::Quarantined;
        Ok(())
    }
}
