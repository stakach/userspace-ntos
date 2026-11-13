//! Exact source reads, separate from the portable image-area and reservation authority.

use crate::native_image_sections::{NativeImageContents, NativeImageSource};
use crate::ExecNtHandler;
use alloc::vec::Vec;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

impl NativeImageSource {
    pub(crate) fn read_exact(
        &self,
        handler: &ExecNtHandler,
        area: nt_memory_manager::image_section::ImageAreaId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), u32> {
        if !self.has_readable_image()
            || offset
                .checked_add(output.len() as u64)
                .is_none_or(|end| end > self.backing.file_extent)
        {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        match &self.contents {
            NativeImageContents::RetainedDisk => self
                .local_file
                .as_ref()
                .ok_or(nt_fs::STATUS_INVALID_HANDLE)?
                .read_exact(handler, self.backing, offset, output),
            NativeImageContents::RetainedRouted => {
                let lease = self.backing.routed_lease.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                let (file_id, device_id, file_context, _) = unsafe {
                    crate::hosted_routed_image_capture::route(lease, area)
                }
                .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                let (status, read) = crate::routed_section_io::read_retained(
                    file_id, device_id, file_context, offset, output,
                );
                if status != 0 {
                    return Err(status);
                }
                if read != output.len() {
                    return Err(0xc000_0185);
                }
                Ok(())
            }
            NativeImageContents::Snapshot(bytes) => {
                let start = usize::try_from(offset).map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
                let end = start
                    .checked_add(output.len())
                    .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
                output.copy_from_slice(bytes.get(start..end).ok_or(nt_fs::STATUS_INVALID_HANDLE)?);
                Ok(())
            }
        }
    }

    /// Only an actual process constructor needs a contiguous raw PE for the existing loader.
    /// The returned bytes belong to its private parsed-image owner, not this shared source.
    pub(crate) fn materialize_process_snapshot(
        &self,
        handler: &ExecNtHandler,
        area: nt_memory_manager::image_section::ImageAreaId,
    ) -> Result<Vec<u8>, u32> {
        if !self.has_readable_image() {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        let length = usize::try_from(self.backing.file_extent)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        bytes.resize(length, 0);
        self.read_exact(handler, area, 0, &mut bytes)?;
        Ok(bytes)
    }
}
