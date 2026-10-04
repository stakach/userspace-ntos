//! Local image capture uses the opened File body, never reopens a guessed image path.

use crate::*;
use alloc::vec::Vec;
use nt_memory_manager::GenericSectionBacking;

pub(crate) use crate::local_section_file::LocalSectionFile as LocalImageFile;

pub(crate) unsafe fn submit_local_image_section(
    handler: &mut ExecNtHandler,
    caller: nt_process::native_handle::NativeHandleCaller,
    source: nt_process::NativeSectionFileSource,
    output: u64,
    desired_access: u32,
    attributes: u32,
    maximum_size: u64,
    page_protection: u32,
    allocation_attrs: u32,
    file_handle: u64,
    name: Option<crate::section_metadata_work::ImageObjectName>,
) -> u32 {
    let _durable = allocator::enter_durable();
    let result = (|| {
        if maximum_size != 0 || allocation_attrs != 0x0100_0000 {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        nt_memory_manager::data_section::data_section_file_access(page_protection)?;
        if !matches!(page_protection, 0x02 | 0x10 | 0x20) {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        handler.probe_copy_scalar::<8>(output)?;
        nt_memory_manager::data_section::check_data_section_file_access(
            page_protection,
            source.granted_access(),
        )?;
        let observation_target = handler.capture_native_image_observation(file_handle);
        let (file, backing) = match source.object() {
            nt_process::HandleObject::DiskFile {
                object_id,
                first_cluster,
                size,
            } => {
                let open = handler.readonly_file_opens.get(object_id)?;
                if open.first_cluster != first_cluster
                    || open.size != size
                    || open.metadata.is_directory
                {
                    return Err(nt_fs::STATUS_INVALID_HANDLE);
                }
                let identity = exec_fs_file_identity(open.metadata.file_id)
                    .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                (
                    LocalImageFile::Disk {
                        object_id,
                        first_cluster,
                        size,
                    },
                    GenericSectionBacking::disk(first_cluster, size, identity),
                )
            }
            nt_process::HandleObject::OverlayFile(object_id) => (
                LocalImageFile::Overlay { object_id },
                crate::writable_fs::section_backing(object_id)?,
            ),
            _ => return Err(nt_fs::STATUS_INVALID_HANDLE),
        };
        let identity = backing.file.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        let mut image = handler
            .image_sections
            .reserve(identity)
            .map_err(crate::exec_handler::image_section_create::map_image_error)?;
        let mut retained = None;
        let captured = (|| {
            let mut header = Vec::new();
            let mut image_path = Vec::new();
            if image.needs_source() {
                match &file {
                    LocalImageFile::Disk { object_id, .. } => {
                        let open = handler.readonly_file_opens.get(*object_id)?;
                        image_path
                            .try_reserve_exact(open.volume_relative_path().len())
                            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
                        image_path.extend_from_slice(open.volume_relative_path());
                        handler.readonly_file_opens.retain_io(*object_id)?;
                    }
                    LocalImageFile::Overlay { object_id } => {
                        image_path = crate::writable_fs::opened_name(*object_id)?.into_bytes();
                        crate::writable_fs::retain_io_reference(*object_id)?;
                    }
                }
                retained = Some(file);
                let length = usize::try_from(backing.file_extent)
                    .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
                if length == 0 {
                    return Err(0xc000_007bu32);
                }
                header
                    .try_reserve_exact(length)
                    .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
                header.resize(length, 0);
                let copied = match retained.as_ref().expect("retained local image File") {
                    LocalImageFile::Disk {
                        first_cluster,
                        size,
                        ..
                    } => {
                        let fs = exec_fs().ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                        crate::fs_loader::fat_read_file_range(
                            &fs,
                            *first_cluster,
                            *size,
                            0,
                            &mut header,
                        )
                    }
                    LocalImageFile::Overlay { object_id } => {
                        let (status, copied) =
                            crate::writable_fs::read_backing_into(*object_id, 0, &mut header);
                        if status != 0 {
                            return Err(status);
                        }
                        copied
                    }
                };
                if copied != length {
                    return Err(0xc000_0185u32);
                }
            }
            handler.reserve_local_native_image_section(
                caller,
                desired_access,
                attributes,
                maximum_size,
                page_protection,
                allocation_attrs,
                backing,
                header,
                image_path,
                name,
                observation_target,
                &mut retained,
                &mut image,
            )
        })();
        if captured.is_err() && image.is_pending() {
            handler
                .image_sections
                .abort(&mut image)
                .expect("unpublished local image reservation");
        }
        if let Some(file) = retained {
            file.release(handler);
        }
        let mut section = captured?;
        if let Err(status) =
            handler.process_memory_write_status(handler.pi, output, &section.value().to_le_bytes())
        {
            section.abort(handler);
            return Err(status);
        }
        match section.publish(handler) {
            Ok(_) => Ok(()),
            Err(status) => {
                section.abort(handler);
                Err(status)
            }
        }
    })();
    result.map_or_else(|status| status, |()| 0)
}
