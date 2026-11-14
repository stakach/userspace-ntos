//! The File `NtSaveKey` writes its hive image to.
//!
//! The Configuration Manager writes through the File the caller opened (`CmpFileWrite` is
//! `ZwWriteFile` on that handle), then flushes it. A local overlay File is written in place; a
//! File on the mounted volume takes the same sequence as canonical IRPs.

use super::*;

/// The caller's destination, resolved once with write access proven on its handle.
#[derive(Clone, Copy)]
pub(super) enum SaveKeyFile {
    Overlay(u64),
    /// A canonical File on the mounted volume device.
    MountedVolume(u64),
}

static SAVE_KEY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

impl ExecNtHandler {
    pub(super) fn save_key_file_for(&self, handle: u64) -> Result<SaveKeyFile, u32> {
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;

        let process_handle =
            nt_process::Handle::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let object = self
            .pm
            .lookup_handle(pid, process_handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let access = self
            .pm
            .handle_access(pid, process_handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if access & (FILE_WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        match object {
            nt_process::HandleObject::OverlayFile(file_id) => Ok(SaveKeyFile::Overlay(file_id)),
            nt_process::HandleObject::RoutedFile { file_id, device_id } => {
                let (live_device_id, _) =
                    driver_launch::hosted_file_route(file_id).ok_or(STATUS_INVALID_HANDLE)?;
                if live_device_id != device_id {
                    return Err(STATUS_INVALID_HANDLE);
                }
                // The mounted volume completes WRITE, SET_INFORMATION and FLUSH inline. A File
                // on any other device may pend, and a save has no owner to retain that IRP.
                if crate::mounted_volume::exec_volume_device() != Some(device_id) {
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
                Ok(SaveKeyFile::MountedVolume(file_id))
            }
            nt_process::HandleObject::File(_)
            | nt_process::HandleObject::DiskFile { .. }
            | nt_process::HandleObject::Directory { .. } => {
                Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST)
            }
            _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
    }

    /// Replace the File's contents with `image` and flush it: truncate, write the whole image at
    /// offset zero, then flush. The first failing step's status is the save's status.
    pub(super) unsafe fn write_save_key_image(file: SaveKeyFile, image: &[u8]) -> u32 {
        let status = match file {
            SaveKeyFile::Overlay(file_id) => Self::write_overlay_save_key_image(file_id, image),
            SaveKeyFile::MountedVolume(file_id) => {
                Self::write_mounted_save_key_image(file_id, image)
            }
        };
        Self::trace_save_key(file, image.len(), status);
        status
    }

    unsafe fn write_overlay_save_key_image(file_id: u64, image: &[u8]) -> u32 {
        let truncate = 0u64.to_le_bytes();
        let status = crate::writable_fs::set_information(
            file_id,
            nt_fs::FILE_END_OF_FILE_INFORMATION,
            &truncate,
        );
        if status != nt_fs::STATUS_SUCCESS {
            return status;
        }
        let (status, written) = crate::writable_fs::write(file_id, Some(0), image);
        if status != nt_fs::STATUS_SUCCESS {
            return status;
        }
        if written != image.len() {
            return nt_fs::STATUS_INSUFFICIENT_RESOURCES;
        }
        crate::writable_fs::flush(file_id)
    }

    unsafe fn write_mounted_save_key_image(file_id: u64, image: &[u8]) -> u32 {
        // Each WRITE is copied into a system buffer; bound that copy rather than doubling the
        // whole image in the executive heap.
        const WRITE_CHUNK: usize = 64 * 1024;
        // The Configuration Manager's own writes run as the System thread, as `Zw` calls do.
        let caller = crate::initial_system_driver_caller();
        let terminal = |result: Result<(i32, u64, Option<nt_io_manager::IrpId>, Option<u64>), u32>| {
            match result {
                // No owner can retain a pending save IRP; the mounted volume never returns one.
                Ok((_, _, Some(_), _)) => Err(STATUS_UNSUCCESSFUL),
                Ok((0, information, None, _)) => Ok(information),
                Ok((status, _, None, _)) => Err(status as u32),
                Err(status) => Err(status),
            }
        };
        let truncate = 0u64.to_le_bytes();
        if let Err(status) = terminal(driver_launch::dispatch_hosted_file_set_information_irp_result_exact(
            file_id,
            caller,
            nt_io_manager::SetInformationParameters {
                info_class: nt_fs::FILE_END_OF_FILE_INFORMATION,
                length: truncate.len() as u32,
                target_file: None,
                control: nt_io_manager::SetInformationControl::None,
            },
            &truncate,
        )) {
            return status;
        }
        let mut offset = 0usize;
        for chunk in image.chunks(WRITE_CHUNK) {
            match terminal(driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file_id,
                major::IRP_MJ_WRITE,
                caller,
                nt_io_manager::ReadWriteParameters {
                    length: chunk.len() as u32,
                    key: 0,
                    offset: offset as u64,
                },
                chunk,
                &mut [],
            )) {
                Ok(written) if written == chunk.len() as u64 => offset += chunk.len(),
                Ok(_) => return nt_fs::STATUS_INSUFFICIENT_RESOURCES,
                Err(status) => return status,
            }
        }
        match terminal(driver_launch::dispatch_hosted_file_irp_result_exact(
            file_id,
            major::IRP_MJ_FLUSH_BUFFERS as u64,
            0,
            caller,
            &[],
            &mut [],
            0,
        )) {
            Ok(_) => nt_fs::STATUS_SUCCESS,
            Err(status) => status,
        }
    }

    /// One bounded line per save: which File, how many bytes, and the status setup will see.
    fn trace_save_key(file: SaveKeyFile, bytes: usize, status: u32) {
        if SAVE_KEY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 16 {
            return;
        }
        print_str(b"[profile-hive] save-key path=\"");
        match file {
            SaveKeyFile::Overlay(file_id) => {
                match unsafe { crate::writable_fs::opened_name(file_id) } {
                    Ok(name) => print_ascii_str(&name),
                    Err(_) => print_str(b"?"),
                }
                print_str(b"\" file=overlay");
            }
            SaveKeyFile::MountedVolume(file_id) => {
                driver_launch::print_hosted_file_name(file_id);
                print_str(b"\" file=mounted-volume");
            }
        }
        print_str(b" bytes=");
        print_u64(bytes as u64);
        print_str(b" status=");
        print_hex(status);
        print_str(b"\n");
    }
}
