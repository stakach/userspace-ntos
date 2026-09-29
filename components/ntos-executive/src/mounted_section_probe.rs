//! Native mounted-file Section proof, run after the executive scratch VSpace is mapped.

use core::ptr::addr_of_mut;

use nt_io_manager::{
    CreateOptions, CreateParameters, DeviceId, ExternalDispatchResult, FileState, IoParameters,
    ShareAccess,
};
use nt_memory_manager::{GenericSectionBacking, GenericSectionTable};
use nt_types::{AccessMask, ClientId, UnicodeString};

use crate::{
    driver_launch::{self, hosted_file_capture, IO_MANAGER_COMPONENT_ID},
    hosted_routed_section_capture, mounted_volume, service_sec_image, temporary_frame_alias,
};

static mut PROBE_SECTIONS: GenericSectionTable = GenericSectionTable::new();
const FONT: &str = "reactos\\Fonts\\arial.ttf";
const PAGE_SIZE: usize = 4096;

pub(crate) unsafe fn probe_font_section_after_file_close(device_id: u64, scratch_base: u64) -> bool {
    let mut status = 0u32;
    let mut checksum = 0u64;
    let mut content_ok = false;
    let mut after_close = false;
    let mut retired = false;
    let client = ClientId(IO_MANAGER_COMPONENT_ID);
    let device = DeviceId(device_id);
    let table = &mut *addr_of_mut!(PROBE_SECTIONS);
    if service_sec_image::service_drain_section_retirement(table).is_err() || !table.reset() {
        status = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;
    } else {
        let name = UnicodeString::from_str(FONT);
        match driver_launch::io_manager_mut().allocate_external_file(
            client,
            device,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            name,
        ) {
            Err(error) => status = error.raw() as u32,
            Ok(file) => {
                let mut release_queued = false;
                let mut section_index = None;
                let mut section_owner = None;
                let result = (|| -> Result<(), u32> {
                    let created = driver_launch::io_manager_mut()
                        .build_and_dispatch_external_to_device(
                            client,
                            device,
                            Some(file),
                            0,
                            0,
                            nt_io_abi::major::IRP_MJ_CREATE,
                            IoParameters::Create(CreateParameters {
                                desired_access: AccessMask::GENERIC_READ,
                                share_access: ShareAccess::READ,
                                create_disposition: nt_fs::FILE_OPEN,
                                ..CreateParameters::default()
                            }),
                            0,
                            0,
                            &mut [],
                        )
                        .map_err(|error| error.raw() as u32)?;
                    if !matches!(created, ExternalDispatchResult::Completed {
                        status: nt_status::NtStatus::SUCCESS,
                        file_context: Some(_),
                        ..
                    }) {
                        return Err(nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR);
                    }
                    let mount = mounted_volume::mount_id_for_live_device(device_id)
                        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                    let capture = hosted_file_capture::capture(
                        file.raw(), device_id, AccessMask::GENERIC_READ.bits(),
                    )?;
                    let metadata = crate::routed_section_io::query_metadata(
                        file.raw(), device_id, mount,
                    )?;
                    let extent = metadata.prepare_readonly(
                        0, nt_address_space::PAGE_READONLY, AccessMask::GENERIC_READ.bits(),
                    )?;
                    if extent.section_size < PAGE_SIZE as u64 || extent.file_size < PAGE_SIZE as u64 {
                        return Err(nt_memory_manager::STATUS_INVALID_VIEW_SIZE);
                    }
                    let lease = hosted_routed_section_capture::reserve(capture)
                        .map_err(|_capture| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
                    let backing = GenericSectionBacking::routed(
                        lease, metadata.file, extent.file_size,
                    );
                    let Some(index) = table.create(
                        0, 0, extent.section_size, nt_address_space::PAGE_READONLY, 0, backing,
                    ) else {
                        hosted_routed_section_capture::cancel_unbound(lease)
                            .expect("unpublished probe Section owns its File capture");
                        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
                    };
                    section_index = Some(index);
                    let identity = table.section_identity(index).expect("new probe Section");
                    assert!(hosted_routed_section_capture::bind(lease, identity));
                    section_owner = Some((lease, identity));
                    driver_launch::io_manager_mut()
                        .queue_external_file_release(client, file)
                        .map_err(|error| error.raw() as u32)?;
                    release_queued = true;
                    if driver_launch::io_manager_mut().file(file).map(|file| file.state)
                        != Some(FileState::CleanupPending)
                    {
                        return Err(nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR);
                    }

                    let section = table.section(index).expect("live probe Section");
                    let frame = service_sec_image::service_generic_section_frame(
                        table, index, identity, section, 0, scratch_base, false,
                    )?;
                    let (valid, hash) = temporary_frame_alias::with_scratch_range(
                        frame, scratch_base, 0..PAGE_SIZE, false, |alias| {
                            let bytes = core::slice::from_raw_parts(alias as *const u8, PAGE_SIZE);
                            let table_count = u16::from_be_bytes([bytes[4], bytes[5]]);
                            let valid = bytes[0..4] == [0, 1, 0, 0]
                                && table_count != 0
                                && bytes[24..].iter().any(|byte| *byte != 0);
                            let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
                                (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
                            });
                            (valid, hash)
                        },
                    )?;
                    content_ok = valid && table.page_frame(index, 0) == Some(frame);
                    checksum = hash;
                    if !content_ok {
                        return Err(nt_fs::STATUS_DATA_ERROR);
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    status = error;
                }
                if let Some(index) = section_index {
                    table.clear_section(index);
                    retired = service_sec_image::service_drain_section_retirement(table).is_ok()
                        && section_owner.is_some_and(|(lease, identity)| {
                            hosted_routed_section_capture::route(lease, identity).is_none()
                        })
                        && table.reset();
                    if !retired && status == 0 {
                        status = nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR;
                    }
                }
                if !release_queued {
                    if let Err(error) = driver_launch::io_manager_mut().release_external_file(client, file) {
                        status = error.raw() as u32;
                    }
                }
                for _ in 0..3 {
                    if driver_launch::io_manager_mut().file(file).is_none() {
                        break;
                    }
                    driver_launch::io_manager_mut().pump();
                }
                after_close = release_queued && driver_launch::io_manager_mut().file(file).is_none();
                if !after_close && status == 0 {
                    status = nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR;
                }
            }
        }
    }
    crate::print_str(b"[mounted-section] page-after-file-close content=");
    crate::print_u64(content_ok as u64);
    crate::print_str(b" retired=");
    crate::print_u64(retired as u64);
    crate::print_str(b" file-gone=");
    crate::print_u64(after_close as u64);
    crate::print_str(b" hash=0x");
    crate::print_hex((checksum >> 32) as u32);
    crate::print_hex(checksum as u32);
    crate::print_str(b" status=0x");
    crate::print_hex(status);
    crate::print_str(b"\n");
    status == 0 && content_ok && retired && after_close
}
