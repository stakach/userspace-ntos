//! File sizing and page-in through the mounted backing owner, before section/frame publication.

use super::section_retirement::{release_unpublished_section_frame, reserve_pagein_cleanup};
use super::*;
use crate::local_section_file;
use nt_memory_manager::data_section::{
    prepare_data_section_file, read_data_section_page, DataSectionFileInfo, DataSectionFileIo,
    DataSectionReadIo, DATA_PAGE_SIZE, STATUS_IO_DEVICE_ERROR,
};

struct BackingIo {
    backing: GenericSectionBacking,
    route: Option<crate::hosted_routed_section_capture::Route>,
}

fn pagein_failure(stage: &[u8], identity: nt_memory_manager::SectionIdentity, status: u32) -> u32 {
    print_str(b"[section-pagein-failed] stage="); print_str(stage);
    print_str(b" section="); print_u64(identity.index() as u64);
    print_str(b" status="); print_hex(status); print_str(b"\n");
    status
}

impl DataSectionFileIo for BackingIo {
    fn query_file(&mut self) -> Result<DataSectionFileInfo, u32> {
        match self.backing.kind {
            GENERIC_SECTION_BACKING_DISK => Ok(DataSectionFileInfo {
                end_of_file: self.backing.file_size as u64,
                is_directory: false,
                read_only_volume: true,
            }),
            GENERIC_SECTION_BACKING_OVERLAY => {
                let info =
                    unsafe { crate::writable_fs::file_object_information(self.backing.overlay_file_id) }?
                        .metadata;
                Ok(DataSectionFileInfo {
                    end_of_file: info.end_of_file,
                    is_directory: info.is_directory,
                    read_only_volume: false,
                })
            }
            nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED => {
                self.route.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                Ok(DataSectionFileInfo {
                    end_of_file: self.backing.file_extent,
                    is_directory: false,
                    read_only_volume: true,
                })
            }
            _ => Err(0xc000_0024), // STATUS_OBJECT_TYPE_MISMATCH
        }
    }

    fn extend_file(&mut self, size: u64) -> Result<(), u32> {
        if self.backing.kind != GENERIC_SECTION_BACKING_OVERLAY {
            return Err(0xc000_00a2); // The boot FAT mount is read-only.
        }
        let status = unsafe {
            crate::writable_fs::set_information(
                self.backing.overlay_file_id,
                nt_fs::FILE_END_OF_FILE_INFORMATION,
                &size.to_le_bytes(),
            )
        };
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }
}

impl DataSectionReadIo for BackingIo {
    fn read(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize) {
        unsafe {
            match self.backing.kind {
                GENERIC_SECTION_BACKING_DISK => {
                    let Some(fs) = exec_fs() else {
                        return (0xc000_00a3, 0);
                    };
                    let Ok(offset) = u32::try_from(offset) else {
                        return (STATUS_IO_DEVICE_ERROR, 0);
                    };
                    (
                        0,
                        fat_read_file_range(
                            &fs,
                            self.backing.first_cluster,
                            self.backing.file_size,
                            offset,
                            output,
                        ),
                    )
                }
                GENERIC_SECTION_BACKING_OVERLAY => {
                    crate::writable_fs::read_into(self.backing.overlay_file_id, Some(offset), output)
                }
                nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED => {
                    let Some(route) = self.route else {
                        return (nt_fs::STATUS_INVALID_HANDLE, 0);
                    };
                    crate::routed_section_io::read(route.file_id, route.device_id, offset, output)
                }
                _ => (0xc000_0024, 0),
            }
        }
    }
}

pub(crate) unsafe fn service_prepare_data_section_file(
    backing: GenericSectionBacking,
    maximum_size: u64,
    protection: u32,
    granted_access: u32,
) -> Result<(GenericSectionBacking, u64), u32> {
    prepare_data_section_file(
        maximum_size,
        protection,
        granted_access,
        &mut BackingIo { backing, route: None },
    )
    .map(|extent| {
        (
            GenericSectionBacking {
                file_extent: extent.file_size,
                ..backing
            },
            extent.section_size,
        )
    })
}

pub(crate) unsafe fn service_generic_section_frame(
    generic_sections: *mut GenericSectionTable,
    section_index: usize,
    identity: nt_memory_manager::SectionIdentity,
    section: GenericSection,
    page_index: u64,
    scratch_base: u64,
    routed_metadata_validated: bool,
) -> Result<u64, u32> {
    page_index
        .checked_mul(DATA_PAGE_SIZE as u64)
        .filter(|offset| *offset < section.size)
        .ok_or(nt_memory_manager::STATUS_INVALID_VIEW_SIZE)?;
    if (&*generic_sections).section_identity(section_index) != Some(identity) {
        return Err(pagein_failure(b"section-identity", identity, nt_fs::STATUS_INVALID_HANDLE));
    }
    if section.backing.kind == GENERIC_SECTION_BACKING_DISK {
        let lease = section.backing.local_lease.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        local_section_file::validate_bound(lease, identity, section.backing)?;
    }
    let route = if let Some(lease) = section.backing.routed_lease {
        Some(
            crate::hosted_routed_section_capture::route(lease, identity)
                .ok_or_else(|| pagein_failure(b"backing-owner", identity, nt_fs::STATUS_INVALID_HANDLE))?,
        )
    } else {
        None
    };
    if let Some(frame) = (&*generic_sections).page_frame(section_index, page_index) {
        return Ok(frame);
    }
    let mut io = BackingIo { backing: section.backing, route };
    if routed_metadata_validated {
        if section.backing.kind != nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        return (&*generic_sections).page_frame(section_index, page_index)
            .ok_or(nt_address_space::STATUS_NOT_COMMITTED);
    }
    let file_size = if section.backing.kind != GENERIC_SECTION_BACKING_ANON {
        let info = io.query_file().map_err(|status| pagein_failure(b"backing-metadata", identity, status))?;
        Some(info.end_of_file)
    } else {
        None
    };
    {
        let table = &mut *generic_sections;
        if let Some(lease) = section.backing.local_lease {
            local_section_file::validate_bound(lease, identity, section.backing)?;
        }
        if table.section_identity(section_index) != Some(identity)
            || section.backing.routed_lease.is_some_and(|lease| {
                crate::hosted_routed_section_capture::route(lease, identity) != route
            })
        {
            return Err(pagein_failure(b"metadata-identity", identity, nt_fs::STATUS_INVALID_HANDLE));
        }
        if let Some(file_size) = file_size {
            table.refresh_file_extent(section_index, file_size)
                .map_err(|status| pagein_failure(b"extent", identity, status))?;
        }
        if let Some(frame) = table.page_frame(section_index, page_index) {
            return Ok(frame);
        }
    }
    // Provider I/O runs without a live Section-table borrow. Its result is only a candidate until
    // the exact Section incarnation and routed lease have been revalidated.
    let mut bytes = [0u8; DATA_PAGE_SIZE];
    if let Some(file_size) = file_size {
        read_data_section_page(page_index, section.size, file_size, &mut bytes, &mut io)
            .map_err(|status| pagein_failure(b"backing-read", identity, status))?;
    }
    if let Some(lease) = section.backing.local_lease {
        local_section_file::validate_bound(lease, identity, section.backing)?;
    }
    if (&*generic_sections).section_identity(section_index) != Some(identity)
        || section.backing.routed_lease.is_some_and(|lease| {
            crate::hosted_routed_section_capture::route(lease, identity) != route
        })
    {
        return Err(pagein_failure(b"read-identity", identity, nt_fs::STATUS_INVALID_HANDLE));
    }
    if let Some(frame) = (&*generic_sections).page_frame(section_index, page_index) {
        return Ok(frame);
    }
    service_publish_section_frame_from_bytes(generic_sections, identity, page_index, &bytes, scratch_base)
        .map_err(|status| pagein_failure(b"frame-publication", identity, status))
}

pub(crate) unsafe fn service_publish_section_frame_from_bytes(
    generic_sections: *mut GenericSectionTable,
    identity: nt_memory_manager::SectionIdentity,
    page_index: u64,
    bytes: &[u8],
    scratch_base: u64,
) -> Result<u64, u32> {
    if bytes.len() != DATA_PAGE_SIZE {
        return Err(STATUS_IO_DEVICE_ERROR);
    }
    reserve_pagein_cleanup()?;
    let scratch = scratch_base.checked_add(DEMAND_SCRATCH_WINDOW - 0x3000)
        .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    let zero_scratch = scratch_base.checked_add(DEMAND_SCRATCH_WINDOW - 0x1000)
        .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    // Acquiring a cached frame already maps its zeroing alias into this root-owned window.
    if !ensure_executive_paging(scratch) || !ensure_executive_paging(zero_scratch) {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let frame = vm_frame_acquire(scratch_base)?;
    if page_map_r(frame, scratch, RW_NX, CAP_INIT_THREAD_VSPACE) != 0 {
        release_unpublished_section_frame(frame);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), scratch as *mut u8, DATA_PAGE_SIZE);
    let unmap_status = page_unmap_r(frame);
    if unmap_status != 0 {
        release_unpublished_section_frame(frame);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    match (&mut *generic_sections).publish_page_frame_exact(identity, page_index, frame) {
        Ok(nt_memory_manager::SectionPagePublication::Inserted) => Ok(frame),
        Ok(nt_memory_manager::SectionPagePublication::Existing(existing)) => {
            release_unpublished_section_frame(frame);
            Ok(existing)
        }
        Err(nt_memory_manager::SectionPagePublicationError::StaleSection) => {
            release_unpublished_section_frame(frame);
            Err(nt_fs::STATUS_INVALID_HANDLE)
        }
        Err(_) => {
            release_unpublished_section_frame(frame);
            Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}
