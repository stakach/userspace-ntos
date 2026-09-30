//! Native image Section admission from an exact, retained routed FILE_OBJECT.

use super::*;
use crate::native_image_sections::{NativeImageError, NativeImageSectionId, NativeImageSource};

const SEC_IMAGE: u32 = 0x0100_0000;
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xc000_007b;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xc000_0035;

pub(crate) struct RoutedImageAdmission {
    pub(crate) capture: crate::driver_launch::hosted_file_capture::Capture,
    pub(crate) metadata: nt_memory_manager::RoutedSectionMetadata,
    pub(crate) header: Vec<u8>,
    pub(crate) name: Option<crate::section_metadata_work::ImageObjectName>,
}

#[must_use = "publish or abort the native image Section handle"]
pub(crate) struct ReservedNativeImageSection {
    publication: nt_process::NativeSectionHandlePublication,
    id: NativeImageSectionId,
    named: Option<(usize, u64)>,
}

impl ReservedNativeImageSection {
    pub(crate) fn value(&self) -> u64 {
        self.publication.value()
    }

    pub(crate) fn publish(&mut self, handler: &mut ExecNtHandler) -> Result<u64, u32> {
        self.publication.publish(&mut handler.pm)
    }

    pub(crate) fn abort(&mut self, handler: &mut ExecNtHandler) {
        if let Some((index, identity)) = self.named {
            let entry = &mut handler.obj_ns[index];
            assert_eq!(entry.identity, identity);
            assert_eq!(entry.payload, u64::from(self.id.section_id()));
            entry.unlink();
            handler.image_sections.withdraw_permanent(self.id).expect("unpublished image name pin");
        }
        assert_eq!(
            self.publication.abort(&mut handler.pm),
            Ok(Some(self.id.section_id())),
        );
        handler.image_sections.close_handle_group(self.id).expect("unpublished image handle group");
    }
}

pub(crate) fn map_image_error(error: NativeImageError) -> u32 {
    match error {
        NativeImageError::InsufficientResources
        | NativeImageError::Authority(nt_memory_manager::image_section::ImageSectionError::InsufficientResources) =>
            STATUS_INSUFFICIENT_RESOURCES,
        _ => STATUS_INVALID_IMAGE_FORMAT,
    }
}

fn validate_pe_header(header: &[u8], file_size: u64) -> Result<(), u32> {
    let pe = nt_pe_loader::PeFile::parse(header).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    if !pe.headers().is_executable()
        || pe.size_of_image() == 0
        || u64::from(pe.headers().size_of_headers) > file_size
    {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    pe.image_page_fill_plan(0, file_size)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    for section in pe.sections() {
        if section.size_of_raw_data != 0 {
            let raw_end = u64::from(section.pointer_to_raw_data)
                .checked_add(u64::from(section.size_of_raw_data))
                .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            if raw_end > file_size {
                return Err(STATUS_INVALID_IMAGE_FORMAT);
            }
        }
        if section.virtual_size != 0 || section.size_of_raw_data != 0 {
            pe.image_page_fill_plan(section.virtual_address, file_size)
                .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        }
    }
    Ok(())
}

impl ExecNtHandler {
    pub(crate) unsafe fn reserve_native_image_section(
        &mut self,
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        attributes: u32,
        maximum_size: u64,
        page_protection: u32,
        allocation_attrs: u32,
        admission: RoutedImageAdmission,
    ) -> Result<ReservedNativeImageSection, u32> {
        if maximum_size != 0
            || !matches!(page_protection, 0x02 | 0x10 | 0x20)
            || allocation_attrs != SEC_IMAGE
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if admission.metadata.is_directory || admission.metadata.end_of_file == 0 {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        validate_pe_header(&admission.header, admission.metadata.end_of_file)?;
        if let Some(ref name) = admission.name {
            let Some(root) = self.obj_ns.get(name.root_index) else {
                return Err(STATUS_INVALID_HANDLE);
            };
            if root.identity != name.root_identity || root.kind != OBJ_KIND_DIRECTORY {
                return Err(STATUS_INVALID_HANDLE);
            }
            if self.obj_resolve(&name.path, name.root_index).is_some() {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
        }
        let mut publication = self.pm.reserve_native_section_handle(
            caller,
            attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2),
        )?;
        let mut image = match self.image_sections.reserve(admission.metadata.file) {
            Ok(image) => image,
            Err(error) => {
                publication.abort(&mut self.pm).expect("unbound image handle reservation");
                return Err(map_image_error(error));
            }
        };
        let mut source = None;
        let mut routed_lease = None;
        if image.needs_source() {
            let lease = match crate::hosted_routed_image_capture::reserve(admission.capture) {
                Ok(lease) => lease,
                Err(_capture) => {
                    self.image_sections.abort(&mut image).expect("unpublished image reservation");
                    publication.abort(&mut self.pm).expect("unbound image handle reservation");
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
            };
            routed_lease = Some(lease);
            source = Some(NativeImageSource {
                backing: nt_memory_manager::GenericSectionBacking::routed(
                    lease,
                    admission.metadata.file,
                    admission.metadata.end_of_file,
                ),
                pe_header: admission.header,
            });
        }
        let id = match self.image_sections.publish(&mut image, &mut source) {
            Ok(id) => id,
            Err(error) => {
                self.image_sections.abort(&mut image).expect("unpublished image reservation");
                if let Some(lease) = routed_lease {
                    crate::hosted_routed_image_capture::cancel_unbound(lease).expect("unbound image File capture");
                }
                publication.abort(&mut self.pm).expect("unbound image handle reservation");
                return Err(map_image_error(error));
            }
        };
        if let Some(lease) = routed_lease {
            let area = self.image_sections.area(id).expect("published image area");
            assert!(crate::hosted_routed_image_capture::bind(lease, area));
        }
        let mut named = None;
        if let Some(name) = admission.name {
            let permanent = attributes & OBJ_PERMANENT != 0;
            if let Err(error) = self.image_sections.make_permanent(id) {
                self.image_sections.close_handle_group(id).expect("failed image name pin");
                publication.abort(&mut self.pm).expect("unbound image handle reservation");
                return Err(map_image_error(error));
            }
            let Some(index) = self.obj_create(&name.path, name.root_index, OBJ_KIND_SECTION, &[], permanent) else {
                self.image_sections.withdraw_permanent(id).expect("failed image name publication");
                self.image_sections.close_handle_group(id).expect("failed image name publication");
                publication.abort(&mut self.pm).expect("unbound image handle reservation");
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            };
            self.obj_ns[index].payload = u64::from(id.section_id());
            named = Some((index, self.obj_ns[index].identity));
        }
        if let Err(status) = publication.bind(&mut self.pm, id.section_id(), desired_access) {
            if let Some((index, _)) = named {
                self.obj_ns[index].unlink();
                self.image_sections.withdraw_permanent(id).expect("failed image handle binding");
            }
            self.image_sections.close_handle_group(id).expect("failed image handle binding");
            publication.abort(&mut self.pm).expect("failed image handle binding reservation");
            return Err(status);
        }
        Ok(ReservedNativeImageSection { publication, id, named })
    }
}
