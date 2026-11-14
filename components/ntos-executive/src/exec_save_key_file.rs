//! The File `NtSaveKey` writes its hive image to.
//!
//! The Configuration Manager writes through the File the caller opened (`CmpFileWrite` is
//! `ZwWriteFile` on that handle), then flushes it.

use super::*;

/// The caller's destination, resolved once with write access proven on its handle.
#[derive(Clone, Copy)]
pub(super) enum SaveKeyFile {
    Overlay(u64),
}

impl ExecNtHandler {
    /// Other file backends fail visibly until they take the same write sequence.
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
            nt_process::HandleObject::File(_)
            | nt_process::HandleObject::RoutedFile { .. }
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
        let SaveKeyFile::Overlay(file_id) = file;
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
}
