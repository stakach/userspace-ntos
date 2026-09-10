//! File sizing and page-in through the mounted backing owner, before section/frame publication.

use super::section_retirement::{release_unpublished_section_frame, reserve_pagein_cleanup};
use super::*;
use nt_memory_manager::data_section::{
    prepare_data_section_file, read_data_section_page, DataSectionFileInfo, DataSectionFileIo,
    DataSectionReadIo, DATA_PAGE_SIZE, STATUS_IO_DEVICE_ERROR,
};

struct BackingIo(GenericSectionBacking);

impl DataSectionFileIo for BackingIo {
    fn query_file(&mut self) -> Result<DataSectionFileInfo, u32> {
        match self.0.kind {
            GENERIC_SECTION_BACKING_DISK => Ok(DataSectionFileInfo {
                end_of_file: self.0.file_size as u64,
                is_directory: false,
                read_only_volume: true,
            }),
            GENERIC_SECTION_BACKING_OVERLAY => {
                let info =
                    unsafe { crate::writable_fs::file_object_information(self.0.overlay_file_id) }?
                        .metadata;
                Ok(DataSectionFileInfo {
                    end_of_file: info.end_of_file,
                    is_directory: info.is_directory,
                    read_only_volume: false,
                })
            }
            _ => Err(0xc000_0024), // STATUS_OBJECT_TYPE_MISMATCH
        }
    }

    fn extend_file(&mut self, size: u64) -> Result<(), u32> {
        if self.0.kind != GENERIC_SECTION_BACKING_OVERLAY {
            return Err(0xc000_00a2); // The boot FAT mount is read-only.
        }
        let status = unsafe {
            crate::writable_fs::set_information(
                self.0.overlay_file_id,
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
            match self.0.kind {
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
                            self.0.first_cluster,
                            self.0.file_size,
                            offset,
                            output,
                        ),
                    )
                }
                GENERIC_SECTION_BACKING_OVERLAY => {
                    crate::writable_fs::read_into(self.0.overlay_file_id, Some(offset), output)
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
        &mut BackingIo(backing),
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

pub(super) unsafe fn service_generic_section_frame(
    generic_sections: &mut GenericSectionTable,
    section_index: usize,
    section: GenericSection,
    page_index: u64,
    scratch_base: u64,
) -> Result<u64, u32> {
    page_index
        .checked_mul(DATA_PAGE_SIZE as u64)
        .filter(|offset| *offset < section.size)
        .ok_or(nt_memory_manager::STATUS_INVALID_VIEW_SIZE)?;
    let mut io = BackingIo(section.backing);
    let file_size = if section.backing.kind != GENERIC_SECTION_BACKING_ANON {
        let info = io.query_file()?;
        generic_sections.refresh_file_extent(section_index, info.end_of_file)?;
        Some(info.end_of_file)
    } else {
        None
    };
    if let Some(frame) = generic_sections.page_frame(section_index, page_index) {
        return Ok(frame);
    }
    // Finish backing I/O before acquiring a physical frame. Failed reads never enter the cache.
    let mut bytes = [0u8; DATA_PAGE_SIZE];
    if let Some(file_size) = file_size {
        read_data_section_page(page_index, section.size, file_size, &mut bytes, &mut io)?;
    }
    reserve_pagein_cleanup()?;
    let frame = vm_frame_acquire(scratch_base)?;
    let scratch = scratch_base + DEMAND_SCRATCH_WINDOW - 0x3000;
    if page_map_r(frame, scratch, RW_NX, CAP_INIT_THREAD_VSPACE) != 0 {
        release_unpublished_section_frame(frame);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), scratch as *mut u8, DATA_PAGE_SIZE);
    let unmap_status = page_unmap_r(frame);
    if unmap_status != 0 || !generic_sections.set_page_frame(section_index, page_index, frame) {
        release_unpublished_section_frame(frame);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    Ok(frame)
}
