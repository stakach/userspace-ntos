//! Stable-file image ownership and checked cache purge, independent of loader names and handles.
//!
//! This is the image half of NT's MmFlushImageSection boundary. Delete admission must additionally
//! check data-section user references/creation; file systems choose the operation-specific status.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::SectionFileIdentity;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageAreaId {
    owner: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "creation must be published or aborted; dropping the token retains ownership"]
pub struct ImageCreation(ImageAreaId);

impl ImageCreation {
    pub fn area(self) -> ImageAreaId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "release the reference only after its external owner is gone"]
pub struct ImageSectionRef {
    area: ImageAreaId,
    generation: u64,
}

impl ImageSectionRef {
    pub fn area(self) -> ImageAreaId {
        self.area
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "retain the reference until checked view teardown completes"]
pub struct ImageViewRef {
    area: ImageAreaId,
    generation: u64,
}

impl ImageViewRef {
    pub fn area(self) -> ImageAreaId {
        self.area
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "retain the acquired creation or section reference"]
pub enum ImageAcquire {
    /// Establish backing ownership and parse/publish the image before completing this creation.
    Create(ImageCreation),
    /// Reuse the existing identity-bound cache, retaining a distinct section reference.
    Section(ImageSectionRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageSectionError {
    InsufficientResources,
    InvalidReference,
    CreationInProgress,
    CleanupPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFlushError {
    InUse,
    PurgeFailed(u32),
}

pub trait ImageSectionPurge {
    /// Invalidate all parsed-image/cache entries and retire image frames, aliases and backing
    /// references belonging to this area. Do not write modified image pages back to the file.
    /// Success means no stale image bytes/resources survive. Failure may make partial progress,
    /// but must retain exact remaining resources for retry with the same area ID. An aborted
    /// creation also comes here, even when it acquired no resources.
    fn purge_image(&mut self, area: ImageAreaId, file: SectionFileIdentity) -> Result<(), u32>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AreaState {
    Creating,
    Ready,
    PurgeRequired,
}

struct Area {
    id: ImageAreaId,
    file: SectionFileIdentity,
    state: AreaState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceKind {
    Section,
    View,
}

struct Reference {
    area: ImageAreaId,
    generation: u64,
    kind: ReferenceKind,
}

/// Durable image lifetime authority. The caller serializes this table with image cache effects
/// and file mutation/copy-up, and retains each backing FILE_OBJECT independently of user handles.
/// Register ownership before parsing or mapping; release views only after checked teardown. The
/// purge callback must not reenter this table. A successful flush is admission only while that
/// same serialization is held through the file mutation.
///
/// Slots are reusable but IDs never are. Copying a token does not acquire another reference;
/// duplicate handles need `duplicate_section`. Dropping tokens or the table cannot free backend
/// resources, so the table must outlive all creations, references and pending purge work.
pub struct ImageSectionTable {
    owner: u64,
    generation: u64,
    areas: Vec<Option<Area>>,
    references: Vec<Option<Reference>>,
}

impl Default for ImageSectionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageSectionTable {
    pub const fn new() -> Self {
        Self {
            owner: 0,
            generation: 0,
            areas: Vec::new(),
            references: Vec::new(),
        }
    }

    fn next_generation(&mut self) -> Result<u64, ImageSectionError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ImageSectionError::InsufficientResources)?;
        if self.owner == 0 {
            self.owner = NEXT_OWNER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| ImageSectionError::InsufficientResources)?;
        }
        self.generation = generation;
        Ok(generation)
    }

    fn area_index(&self, id: ImageAreaId) -> Result<usize, ImageSectionError> {
        self.areas
            .iter()
            .position(|area| area.as_ref().is_some_and(|area| area.id == id))
            .ok_or(ImageSectionError::InvalidReference)
    }

    pub fn file_identity(&self, id: ImageAreaId) -> Option<SectionFileIdentity> {
        self.areas
            .get(self.area_index(id).ok()?)?
            .as_ref()
            .map(|area| area.file)
    }

    /// Existing live and idle caches share the same stable-file area. A pending creation cannot
    /// be reused, nor can a cache that may have been partially destroyed by a failed purge.
    pub fn acquire(
        &mut self,
        file: SectionFileIdentity,
    ) -> Result<ImageAcquire, ImageSectionError> {
        if let Some(area) = self.areas.iter().flatten().find(|area| area.file == file) {
            return match area.state {
                AreaState::Creating => Err(ImageSectionError::CreationInProgress),
                AreaState::PurgeRequired => Err(ImageSectionError::CleanupPending),
                AreaState::Ready => {
                    let area = area.id;
                    let generation = self.add_reference(area, ReferenceKind::Section)?;
                    Ok(ImageAcquire::Section(ImageSectionRef { area, generation }))
                }
            };
        }
        let slot = reserve_slot(&mut self.areas)?;
        let generation = self.next_generation()?;
        let id = ImageAreaId {
            owner: self.owner,
            generation,
        };
        put_slot(
            &mut self.areas,
            slot,
            Area {
                id,
                file,
                state: AreaState::Creating,
            },
        );
        Ok(ImageAcquire::Create(ImageCreation(id)))
    }

    /// Call only after the identity-bound image cache is usable. Allocation failure leaves the
    /// creation token live; the caller can retry publication or abort into checked purge.
    pub fn publish(
        &mut self,
        creation: ImageCreation,
    ) -> Result<ImageSectionRef, ImageSectionError> {
        let index = self.creating_index(creation)?;
        let generation = self.add_reference(creation.0, ReferenceKind::Section)?;
        self.areas[index].as_mut().unwrap().state = AreaState::Ready;
        Ok(ImageSectionRef {
            area: creation.0,
            generation,
        })
    }

    pub fn abort(&mut self, creation: ImageCreation) -> Result<(), ImageSectionError> {
        let index = self.creating_index(creation)?;
        self.areas[index].as_mut().unwrap().state = AreaState::PurgeRequired;
        Ok(())
    }

    fn creating_index(&self, creation: ImageCreation) -> Result<usize, ImageSectionError> {
        let index = self.area_index(creation.0)?;
        if self.areas[index].as_ref().unwrap().state != AreaState::Creating {
            return Err(ImageSectionError::InvalidReference);
        }
        Ok(index)
    }

    fn add_reference(
        &mut self,
        area: ImageAreaId,
        kind: ReferenceKind,
    ) -> Result<u64, ImageSectionError> {
        let slot = reserve_slot(&mut self.references)?;
        let generation = self.next_generation()?;
        put_slot(
            &mut self.references,
            slot,
            Reference {
                area,
                generation,
                kind,
            },
        );
        Ok(generation)
    }

    fn reference_index(
        &self,
        area: ImageAreaId,
        generation: u64,
        kind: ReferenceKind,
    ) -> Result<usize, ImageSectionError> {
        self.references
            .iter()
            .position(|entry| {
                entry.as_ref().is_some_and(|entry| {
                    entry.area == area && entry.generation == generation && entry.kind == kind
                })
            })
            .ok_or(ImageSectionError::InvalidReference)
    }

    pub fn duplicate_section(
        &mut self,
        section: ImageSectionRef,
    ) -> Result<ImageSectionRef, ImageSectionError> {
        self.reference_index(section.area, section.generation, ReferenceKind::Section)?;
        let generation = self.add_reference(section.area, ReferenceKind::Section)?;
        Ok(ImageSectionRef {
            area: section.area,
            generation,
        })
    }

    /// Acquire before effectful mapping, keeping this reference through mapping failure until
    /// rollback has released all resources. The view survives closing every section handle.
    pub fn reference_view(
        &mut self,
        section: ImageSectionRef,
    ) -> Result<ImageViewRef, ImageSectionError> {
        self.reference_index(section.area, section.generation, ReferenceKind::Section)?;
        let generation = self.add_reference(section.area, ReferenceKind::View)?;
        Ok(ImageViewRef {
            area: section.area,
            generation,
        })
    }

    pub fn close_section(&mut self, section: ImageSectionRef) -> Result<(), ImageSectionError> {
        let index =
            self.reference_index(section.area, section.generation, ReferenceKind::Section)?;
        self.references[index] = None;
        Ok(())
    }

    /// The backend must already have acknowledged complete view teardown, including private COW
    /// frames and shared aliases. A failed/partial unmap must keep this reference alive.
    pub fn release_view(&mut self, view: ImageViewRef) -> Result<(), ImageSectionError> {
        let index = self.reference_index(view.area, view.generation, ReferenceKind::View)?;
        self.references[index] = None;
        Ok(())
    }

    /// Refuse live image references, then purge all cached image state before admitting mutation.
    /// This is not data-section truncation or delete admission, and does not choose an FSD status.
    pub fn flush_for_write(
        &mut self,
        file: SectionFileIdentity,
        io: &mut impl ImageSectionPurge,
    ) -> Result<(), ImageFlushError> {
        let Some(index) = self
            .areas
            .iter()
            .position(|area| area.as_ref().is_some_and(|area| area.file == file))
        else {
            return Ok(());
        };
        let area = self.areas[index].as_mut().unwrap();
        if area.state == AreaState::Creating
            || self
                .references
                .iter()
                .flatten()
                .any(|entry| entry.area == area.id)
        {
            return Err(ImageFlushError::InUse);
        }
        area.state = AreaState::PurgeRequired;
        io.purge_image(area.id, file)
            .map_err(ImageFlushError::PurgeFailed)?;
        self.areas[index] = None;
        Ok(())
    }
}

fn reserve_slot<T>(slots: &mut Vec<Option<T>>) -> Result<usize, ImageSectionError> {
    if let Some(index) = slots.iter().position(Option::is_none) {
        return Ok(index);
    }
    slots
        .try_reserve(1)
        .map_err(|_| ImageSectionError::InsufficientResources)?;
    Ok(slots.len())
}

fn put_slot<T>(slots: &mut Vec<Option<T>>, index: usize, value: T) {
    if index == slots.len() {
        slots.push(Some(value));
    } else {
        slots[index] = Some(value);
    }
}

#[cfg(test)]
#[path = "image_section_tests.rs"]
mod tests;
