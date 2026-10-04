//! Backing and handle ownership for native generic data-section creation.

use super::*;
use crate::local_section_file;
use nt_process::native_handle::NativeHandleCaller;

pub(crate) struct RoutedSectionAdmission {
    pub(crate) capture: crate::driver_launch::hosted_file_capture::Capture,
    pub(crate) metadata: nt_memory_manager::RoutedSectionMetadata,
}

#[must_use = "reserved Section must be published or aborted"]
pub(crate) struct ReservedGenericDataSection {
    publication: nt_process::NativeSectionHandlePublication,
    index: usize,
    identity: nt_memory_manager::SectionIdentity,
    pub(crate) size: u64,
}

impl ReservedGenericDataSection {
    pub(crate) fn value(&self) -> u64 {
        self.publication.value()
    }

    pub(crate) fn publish(&mut self, handler: &mut ExecNtHandler) -> Result<u64, u32> {
        let sections = unsafe {
            &*handler
                .loop_ctx
                .expect("Section publication context")
                .generic_sections
        };
        assert_eq!(sections.section_identity(self.index), Some(self.identity));
        self.publication.publish(&mut handler.pm)
    }

    pub(crate) fn abort(&mut self, handler: &mut ExecNtHandler) {
        let sections = unsafe {
            &mut *handler
                .loop_ctx
                .expect("Section rollback context")
                .generic_sections
        };
        assert_eq!(sections.section_identity(self.index), Some(self.identity));
        assert_eq!(
            self.publication.abort(&mut handler.pm),
            Ok(Some(self.index as nt_process::SectionId)),
        );
        sections.clear_section(self.index);
    }

    pub(crate) fn into_object_reference(
        mut self,
        handler: &mut ExecNtHandler,
    ) -> Result<(nt_memory_manager::SectionReference, u64, u32), u32> {
        let sections = unsafe {
            &mut *handler.loop_ctx.expect("reserved Section context").generic_sections
        };
        assert_eq!(sections.section_identity(self.index), Some(self.identity));
        let protection = sections.section(self.index).expect("reserved Section").protection;
        let Some(reference) = sections.retain_section(self.identity) else {
            self.abort(handler);
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        };
        // The object reference must fence backing lifetime before canceling its invisible handle.
        if self.publication.abort(&mut handler.pm) != Ok(Some(self.index as nt_process::SectionId)) {
            unsafe { crate::provider_bugcheck::report(0xc4, [self.index as u64, self.size, 0, 91]); }
        }
        let sections = unsafe { &mut *handler.loop_ctx.expect("Section context").generic_sections };
        assert_eq!(sections.section_identity(self.index), Some(self.identity));
        assert!(sections.release_handle(self.index));
        Ok((reference, self.size, protection))
    }
}

impl ExecNtHandler {
    pub(crate) fn native_section_owner_pi(
        &self,
        caller: NativeHandleCaller,
    ) -> Result<usize, u32> {
        (0..MAX_PI)
            .find(|&pi| self.pm_pid_for_pi(pi) == Some(caller.effective_process()))
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)
    }

    /// Reserve a real section and an invisible native handle. The caller must publish only after
    /// output delivery, or abort to retire the section and its retained backing reference.
    pub(crate) unsafe fn reserve_generic_data_section(
        &mut self,
        caller: NativeHandleCaller,
        owner_pi: usize,
        desired_access: u32,
        attributes: u32,
        maxsize: u64,
        page_protection: u32,
        allocation_attrs: u32,
        sec_file: u64,
        mut routed_admission: Option<RoutedSectionAdmission>,
    ) -> Result<ReservedGenericDataSection, u32> {
        let _durable = allocator::enter_durable();
        const STATUS_INVALID_FILE_FOR_SECTION: u32 = 0xC000_0020;
        nt_memory_manager::data_section::data_section_file_access(page_protection)?;
        if self.pm_pid_for_pi(owner_pi) != Some(caller.effective_process()) {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        let generic_sections = self.loop_ctx.ok_or(0xC000_00A3u32)?.generic_sections;
        let mut routed_lease = None;
        let mut local_lease = None;
        let (backing, backing_size) = if sec_file == 0 && routed_admission.is_none() {
            if maxsize == 0 {
                return Err(0xC000_00F2); // STATUS_INVALID_PARAMETER_4
            }
            if maxsize > i64::MAX as u64 {
                return Err(nt_memory_manager::STATUS_SECTION_TOO_BIG);
            }
            (GenericSectionBacking::anonymous(), maxsize)
        } else {
            let (object, access) = if let Some(admission) = routed_admission.as_ref() {
                (
                    nt_process::HandleObject::RoutedFile {
                        file_id: admission.capture.file_id(),
                        device_id: admission.capture.device_id(),
                    },
                    admission.capture.granted_access(),
                )
            } else {
                let source = self.pm.lookup_native_section_file_source(caller, sec_file)?;
                (source.object(), source.granted_access())
            };
            nt_memory_manager::data_section::check_data_section_file_access(
                page_protection,
                access,
            )?;
            let (backing, routed_size) = match object {
                nt_process::HandleObject::DiskFile {
                    first_cluster,
                    size,
                    object_id,
                } => {
                    let (backing, lease) = local_section_file::reserve_disk_source(
                        self, object_id, first_cluster, size,
                    )?;
                    local_lease = Some(lease);
                    (backing, None)
                }
                nt_process::HandleObject::OverlayFile(file_id) => {
                    (crate::writable_fs::section_backing(file_id)?, None)
                }
                nt_process::HandleObject::RoutedFile { file_id, device_id } => {
                    let mount = crate::mounted_volume::mount_id_for_live_device(device_id)
                        .ok_or(STATUS_INVALID_FILE_FOR_SECTION)?;
                    let (capture, metadata) = if let Some(admission) = routed_admission.take() {
                        if admission.metadata.file.mount != mount {
                            return Err(STATUS_INVALID_FILE_FOR_SECTION);
                        }
                        (admission.capture, admission.metadata)
                    } else {
                        let capture = crate::driver_launch::hosted_file_capture::capture(
                            file_id, device_id, access,
                        )?;
                        let metadata =
                            crate::routed_section_io::query_metadata(file_id, device_id, mount)?;
                        (capture, metadata)
                    };
                    let extent = metadata.prepare_readonly(maxsize, page_protection, access)?;
                    let lease = crate::hosted_routed_section_capture::reserve(capture)
                        .map_err(|_capture| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
                    routed_lease = Some(lease);
                    (
                        GenericSectionBacking::routed(lease, metadata.file, extent.file_size),
                        Some(extent.section_size),
                    )
                }
                _ => return Err(STATUS_INVALID_FILE_FOR_SECTION),
            };
            if let Err(status) = (&*generic_sections).validate_file_creation(backing, maxsize) {
                if let Some(lease) = local_lease {
                    local_section_file::cancel_unbound(self, lease)?;
                }
                if let Some(lease) = routed_lease {
                    crate::hosted_routed_section_capture::cancel_unbound(lease)
                        .expect("failed routed Section admission retains its File reference");
                }
                return Err(status);
            }
            match routed_size {
                Some(size) => (backing, size),
                None => {
                    match service_prepare_data_section_file(backing, maxsize, page_protection, access) {
                        Ok(prepared) => prepared,
                        Err(status) => {
                            if let Some(lease) = local_lease {
                                local_section_file::cancel_unbound(self, lease)?;
                            }
                            return Err(status);
                        }
                    }
                }
            }
        };
        if let Err(status) = (&*generic_sections).validate_backing_extent(backing) {
            if let Some(lease) = local_lease {
                local_section_file::cancel_unbound(self, lease)?;
            }
            if let Some(lease) = routed_lease {
                crate::hosted_routed_section_capture::cancel_unbound(lease)
                    .expect("failed routed Section extent retains its File reference");
            }
            return Err(status);
        }
        let mut publication = match self.pm.reserve_native_section_handle(caller, attributes) {
            Ok(publication) => publication,
            Err(status) => {
                if let Some(lease) = local_lease {
                    local_section_file::cancel_unbound(self, lease)?;
                }
                if let Some(lease) = routed_lease {
                    crate::hosted_routed_section_capture::cancel_unbound(lease)
                        .expect("failed Section handle reservation retains its File reference");
                }
                return Err(status);
            }
        };
        if backing.kind == GENERIC_SECTION_BACKING_OVERLAY {
            if let Err(status) = crate::writable_fs::retain_io_reference(backing.overlay_file_id) {
                publication
                    .abort(&mut self.pm)
                    .expect("empty Section reservation aborts");
                return Err(status);
            }
        }
        let generic_sections = &mut *generic_sections;
        let Some(index) = generic_sections.create(
            owner_pi,
            0,
            backing_size,
            page_protection,
            allocation_attrs,
            backing,
        ) else {
            if backing.kind == GENERIC_SECTION_BACKING_OVERLAY {
                crate::writable_fs::release_io_reference(backing.overlay_file_id)
                    .expect("failed Section creation retains its overlay File reference");
            }
            if let Some(lease) = routed_lease {
                crate::hosted_routed_section_capture::cancel_unbound(lease)
                    .expect("failed routed Section creation retains its File reference");
            }
            publication
                .abort(&mut self.pm)
                .expect("empty Section reservation aborts");
            if let Some(lease) = local_lease {
                local_section_file::cancel_unbound(self, lease)?;
            }
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        };
        let identity = generic_sections
            .section_identity(index)
            .expect("new Section has an exact identity");
        if let Some(lease) = local_lease {
            assert!(local_section_file::bind(lease, identity));
        }
        if let Some(lease) = routed_lease {
            assert!(crate::hosted_routed_section_capture::bind(lease, identity));
        }
        let handle = publication.value();
        if let Err(status) =
            publication.bind(&mut self.pm, index as nt_process::SectionId, desired_access)
        {
            generic_sections.clear_section(index);
            publication
                .abort(&mut self.pm)
                .expect("failed Section binding leaves an empty reservation");
            return Err(status);
        }
        if !generic_sections.bind_handle(index, handle) {
            generic_sections.clear_section(index);
            publication
                .abort(&mut self.pm)
                .expect("bound Section reservation aborts");
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(ReservedGenericDataSection {
            publication,
            index,
            identity,
            size: backing_size,
        })
    }
}
