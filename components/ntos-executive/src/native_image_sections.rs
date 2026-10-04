//! Native SEC_IMAGE Section objects backed by the memory manager's image authority.
//!
//! The object namespace owns names. This store owns only Section object identities,
//! captured image source metadata, and the references that keep that source alive.

use alloc::vec::Vec;
use nt_memory_manager::image_section::{
    ImageAcquire, ImageAreaId, ImagePermanentRef, ImageSectionError, ImageSectionPurge,
    ImageSectionRef, ImageSectionTable, ImageViewRef,
};
use nt_memory_manager::{GenericSectionBacking, SectionFileIdentity};
use nt_process::SectionId;

const IMAGE_SECTION_ID_TAG: u32 = 0x8000_0000;
const IMAGE_SECTION_ID_MAX: u32 = 0x7fff_ffff;

/// An image Section ID cannot alias a generic data Section index. IDs never wrap or reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeImageSectionId(SectionId);

impl NativeImageSectionId {
    pub(crate) const fn section_id(self) -> SectionId {
        self.0
    }

    pub(crate) const fn from_section_id(id: SectionId) -> Option<Self> {
        if id & IMAGE_SECTION_ID_TAG != 0 {
            Some(Self(id))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImageError {
    Authority(ImageSectionError),
    InvalidSection,
    InvalidSource,
    InsufficientResources,
}

impl From<ImageSectionError> for NativeImageError {
    fn from(value: ImageSectionError) -> Self {
        Self::Authority(value)
    }
}

/// The source is captured before publication and held until checked image purge.
/// For a routed source, `backing.routed_lease` names an independently retained
/// FILE_OBJECT capture; dropping this value alone does not release that capture.
/// `local_file` similarly owns a local File IO reference, independent of handles.
#[must_use = "retire captured backing ownership after checked image purge"]
pub(crate) struct NativeImageSource {
    pub(crate) backing: GenericSectionBacking,
    pub(crate) pe_header: Vec<u8>,
    pub(crate) local_file: Option<crate::file_image_section::LocalImageFile>,
    /// Captured opened pathname for process metadata, never source selection.
    pub(crate) image_path: Option<Vec<u8>>,
    pub(crate) observation_target: Option<nt_exe_image::CapturedImageObservation>,
}

impl NativeImageSource {
    pub(crate) fn has_complete_image(&self) -> bool {
        self.backing.is_live()
            && self.backing.file_extent != 0
            && u64::try_from(self.pe_header.len()).ok() == Some(self.backing.file_extent)
    }

    fn valid_for(&self, file: SectionFileIdentity) -> bool {
        self.backing.is_live() && self.backing.file == Some(file) && !self.pe_header.is_empty()
    }
}

/// A reserve token is retained through asynchronous header read. On failure,
/// call `abort`; an existing-area reservation instead owns a regular section ref.
#[must_use = "publish or abort the image reservation"]
pub(crate) struct NativeImageReservation {
    file: SectionFileIdentity,
    acquisition: Option<ImageAcquire>,
}

impl NativeImageReservation {
    pub(crate) const fn needs_source(&self) -> bool {
        matches!(self.acquisition, Some(ImageAcquire::Create(_)))
    }

    pub(crate) const fn file(&self) -> SectionFileIdentity {
        self.file
    }
}

struct StoredSource {
    area: ImageAreaId,
    file: SectionFileIdentity,
    source: NativeImageSource,
}

struct SectionObject {
    id: NativeImageSectionId,
    area: ImageAreaId,
    /// One authority Section reference for the entire handle group, regardless
    /// of how many duplicated handles refer to this Section object.
    group: Option<ImageSectionRef>,
    permanent: Option<ImagePermanentRef>,
}

/// Serialization with file mutation, image page fill, and view teardown belongs
/// to the executive caller. The table remains live while any source is cached.
pub(crate) struct NativeImageStore {
    authority: ImageSectionTable,
    next_id: u32,
    sources: Vec<StoredSource>,
    objects: Vec<SectionObject>,
    views: Vec<ImageViewRef>,
}

impl NativeImageStore {
    pub(crate) fn reserve_mapped_view(
        &mut self, id: NativeImageSectionId, process: nt_memory_manager::ProcessIdentity,
        base: u64, size: u64,
    ) -> Result<ImageViewRef, NativeImageError> {
        let group = self.objects[self.object_index(id)?].group.ok_or(NativeImageError::InvalidSection)?;
        self.views.try_reserve(1).map_err(|_| NativeImageError::InsufficientResources)?;
        let view = self.authority.reserve_mapped_view(group, process, base, size)?;
        self.views.push(view);
        Ok(view)
    }

    pub(crate) fn mapped_view(&self, view: ImageViewRef) -> Option<nt_memory_manager::image_section::ImageMappedView> {
        self.authority.mapped_view(view)
    }

    pub(crate) fn begin_mapped_view_mapping(&mut self, view: ImageViewRef, process: nt_memory_manager::ProcessIdentity) -> Result<(), NativeImageError> {
        self.authority.begin_mapped_view_mapping(view, process).map_err(Into::into)
    }

    pub(crate) fn publish_mapped_view(&mut self, view: ImageViewRef) -> Result<(), NativeImageError> {
        self.authority.publish_mapped_view(view).map_err(Into::into)
    }

    pub(crate) fn abort_prepared_mapped_view(&mut self, view: ImageViewRef, process: nt_memory_manager::ProcessIdentity) -> Result<(), NativeImageError> {
        let index = self.views.iter().position(|candidate| *candidate == view).ok_or(NativeImageError::InvalidSection)?;
        self.authority.abort_prepared_mapped_view(view, process)?;
        self.views.swap_remove(index);
        Ok(())
    }

    pub(crate) fn begin_mapped_view_retirement(&mut self, view: ImageViewRef, process: nt_memory_manager::ProcessIdentity) -> Result<nt_memory_manager::image_section::ImageMappedViewRetirement, NativeImageError> {
        self.authority.begin_mapped_view_retirement(view, process).map_err(Into::into)
    }

    pub(crate) fn acknowledge_mapped_view_retirement(&mut self, receipt: nt_memory_manager::image_section::ImageMappedViewRetirement) -> Result<(), NativeImageError> {
        let view = receipt.view();
        let index = self.views.iter().position(|candidate| *candidate == view).ok_or(NativeImageError::InvalidSection)?;
        self.authority.acknowledge_mapped_view_retirement(receipt)?;
        self.views.swap_remove(index);
        Ok(())
    }

    pub(crate) const fn new() -> Self {
        Self {
            authority: ImageSectionTable::new(),
            next_id: 1,
            sources: Vec::new(),
            objects: Vec::new(),
            views: Vec::new(),
        }
    }

    pub(crate) fn reserve(
        &mut self,
        file: SectionFileIdentity,
    ) -> Result<NativeImageReservation, NativeImageError> {
        let acquisition = self.authority.acquire(file)?;
        Ok(NativeImageReservation {
            file,
            acquisition: Some(acquisition),
        })
    }

    /// `source` must be Some for first publication, None for an existing area.
    /// It is taken only after all fallible admission checks and authority
    /// publication succeed. On error, the reservation and source remain owned
    /// by the caller for explicit rollback.
    pub(crate) fn publish(
        &mut self,
        reservation: &mut NativeImageReservation,
        source: &mut Option<NativeImageSource>,
    ) -> Result<NativeImageSectionId, NativeImageError> {
        let acquisition = reservation
            .acquisition
            .ok_or(NativeImageError::InvalidSection)?;
        let area = match acquisition {
            ImageAcquire::Create(creation) => {
                if !source
                    .as_ref()
                    .is_some_and(|source| source.valid_for(reservation.file))
                {
                    return Err(NativeImageError::InvalidSource);
                }
                if self
                    .sources
                    .iter()
                    .any(|entry| entry.area == creation.area())
                {
                    return Err(NativeImageError::InvalidSource);
                }
                creation.area()
            }
            ImageAcquire::Section(section) => {
                if source.is_some() {
                    return Err(NativeImageError::InvalidSource);
                }
                if !self
                    .sources
                    .iter()
                    .any(|entry| entry.area == section.area())
                {
                    return Err(NativeImageError::InvalidSource);
                }
                section.area()
            }
        };
        if self.next_id == 0 || self.next_id > IMAGE_SECTION_ID_MAX {
            return Err(NativeImageError::InsufficientResources);
        }
        self.objects
            .try_reserve(1)
            .map_err(|_| NativeImageError::InsufficientResources)?;
        if matches!(acquisition, ImageAcquire::Create(_)) {
            self.sources
                .try_reserve(1)
                .map_err(|_| NativeImageError::InsufficientResources)?;
        }
        let group = match acquisition {
            ImageAcquire::Create(creation) => self.authority.publish(creation)?,
            ImageAcquire::Section(section) => section,
        };
        if matches!(acquisition, ImageAcquire::Create(_)) {
            self.sources.push(StoredSource {
                area,
                file: reservation.file,
                source: source.take().expect("validated new image source"),
            });
        }
        let id = NativeImageSectionId(IMAGE_SECTION_ID_TAG | self.next_id);
        self.next_id += 1;
        self.objects.push(SectionObject {
            id,
            area,
            group: Some(group),
            permanent: None,
        });
        reservation.acquisition = None;
        Ok(id)
    }

    pub(crate) fn abort(
        &mut self,
        reservation: &mut NativeImageReservation,
    ) -> Result<(), NativeImageError> {
        let acquisition = reservation
            .acquisition
            .ok_or(NativeImageError::InvalidSection)?;
        match acquisition {
            ImageAcquire::Create(creation) => {
                self.authority.abort(creation)?;
                struct EmptyCreation;
                impl ImageSectionPurge for EmptyCreation {
                    fn purge_image(
                        &mut self,
                        _area: ImageAreaId,
                        _file: SectionFileIdentity,
                    ) -> Result<(), u32> {
                        Ok(())
                    }
                }
                self.authority
                    .flush_for_write(reservation.file, &mut EmptyCreation)
                    .expect("unpublished image creation owns no cache or references");
            }
            ImageAcquire::Section(section) => self.authority.close_section(section)?,
        }
        reservation.acquisition = None;
        Ok(())
    }

    fn object_index(&self, id: NativeImageSectionId) -> Result<usize, NativeImageError> {
        self.objects
            .iter()
            .position(|object| object.id == id)
            .ok_or(NativeImageError::InvalidSection)
    }

    pub(crate) fn source(&self, id: NativeImageSectionId) -> Option<&NativeImageSource> {
        let object = self.objects.get(self.object_index(id).ok()?)?;
        self.sources
            .iter()
            .find(|source| source.area == object.area)
            .map(|source| &source.source)
    }

    pub(crate) fn source_for_view(&self, view: ImageViewRef) -> Option<&NativeImageSource> {
        if !self.views.contains(&view) {
            return None;
        }
        self.sources
            .iter()
            .find(|source| source.area == view.area())
            .map(|source| &source.source)
    }

    /// Reestablish the one Section reference for a named object whose previous
    /// handle group closed. The ProcessManager owns all handle counts, including
    /// duplication and inheritance; call this only before publishing a handle
    /// when its current count for this object is zero.
    pub(crate) fn ensure_handle_group(
        &mut self,
        id: NativeImageSectionId,
    ) -> Result<(), NativeImageError> {
        let index = self.object_index(id)?;
        let object = &mut self.objects[index];
        if object.group.is_none() {
            let permanent = object.permanent.ok_or(NativeImageError::InvalidSection)?;
            let group = self.authority.open_permanent(permanent)?;
            object.group = Some(group);
        }
        Ok(())
    }

    /// Call only after ProcessManager has removed the final handle to this
    /// Section object. A view or permanent name retains its own reference.
    pub(crate) fn close_handle_group(
        &mut self,
        id: NativeImageSectionId,
    ) -> Result<(), NativeImageError> {
        let index = self.object_index(id)?;
        let object = &mut self.objects[index];
        let group = object.group.ok_or(NativeImageError::InvalidSection)?;
        self.authority.close_section(group)?;
        object.group = None;
        if object.permanent.is_none() {
            self.objects.remove(index);
        }
        Ok(())
    }

    /// The namespace retains its own reference before publishing the name.
    pub(crate) fn make_permanent(
        &mut self,
        id: NativeImageSectionId,
    ) -> Result<(), NativeImageError> {
        let index = self.object_index(id)?;
        let object = &self.objects[index];
        if object.permanent.is_some() {
            return Err(NativeImageError::InvalidSection);
        }
        let group = object.group.ok_or(NativeImageError::InvalidSection)?;
        let permanent = self.authority.reference_permanent(group)?;
        self.objects[index].permanent = Some(permanent);
        Ok(())
    }

    /// Release only after ObjEntry has withdrawn the namespace object.
    pub(crate) fn withdraw_permanent(
        &mut self,
        id: NativeImageSectionId,
    ) -> Result<(), NativeImageError> {
        let index = self.object_index(id)?;
        let permanent = self.objects[index]
            .permanent
            .ok_or(NativeImageError::InvalidSection)?;
        self.authority.release_permanent(permanent)?;
        self.objects[index].permanent = None;
        if self.objects[index].group.is_none() {
            self.objects.remove(index);
        }
        Ok(())
    }

    pub(crate) fn reference_view(
        &mut self,
        id: NativeImageSectionId,
    ) -> Result<ImageViewRef, NativeImageError> {
        let group = self.objects[self.object_index(id)?]
            .group
            .ok_or(NativeImageError::InvalidSection)?;
        self.views
            .try_reserve(1)
            .map_err(|_| NativeImageError::InsufficientResources)?;
        let view = self.authority.reference_view(group)?;
        self.views.push(view);
        Ok(view)
    }

    /// The caller must finish frame and alias teardown before this release.
    pub(crate) fn release_view(&mut self, view: ImageViewRef) -> Result<(), NativeImageError> {
        let index = self
            .views
            .iter()
            .position(|candidate| *candidate == view)
            .ok_or(NativeImageError::InvalidSection)?;
        self.authority.release_view(view)?;
        let removed = self.views.remove(index);
        debug_assert_eq!(removed, view);
        Ok(())
    }

    /// Transfer captured source ownership only after acknowledged authority purge.
    /// The caller must explicitly retire or transfer its backing owner; failure
    /// leaves the source in this store, including every retained local File ref.
    #[must_use = "retire or transfer the purged image source backing"]
    pub(crate) fn flush_for_write(
        &mut self,
        file: SectionFileIdentity,
        io: &mut impl ImageSectionPurge,
    ) -> Result<Option<NativeImageSource>, nt_memory_manager::image_section::ImageFlushError> {
        struct Purge<'a, T>(&'a mut T);
        impl<T: ImageSectionPurge> ImageSectionPurge for Purge<'_, T> {
            fn purge_image(&mut self, area: ImageAreaId, file: SectionFileIdentity) -> Result<(), u32> {
                // The authority has excluded every live view/handle before this callback.
                unsafe { crate::native_image_residency::purge_area(area)?; }
                self.0.purge_image(area, file)
            }
        }
        self.authority.flush_for_write(file, &mut Purge(io))?;
        Ok(self.sources.iter().position(|source| source.file == file)
            .map(|index| self.sources.remove(index).source))
    }

    pub(crate) fn file_identity(&self, id: NativeImageSectionId) -> Option<SectionFileIdentity> {
        let object = self.objects.get(self.object_index(id).ok()?)?;
        self.authority.file_identity(object.area)
    }

    pub(crate) fn area(&self, id: NativeImageSectionId) -> Option<ImageAreaId> {
        Some(self.objects.get(self.object_index(id).ok()?)?.area)
    }
}
