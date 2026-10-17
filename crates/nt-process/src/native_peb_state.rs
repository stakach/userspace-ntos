//! Exact process PEB projections for kernel Ps imports.

use crate::{ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_IMAGE_FORMAT};

impl ProcessManager {
    /// Return the PEB recorded for this published EPROCESS, including the genuine null PEB of
    /// the initial System process. An unrelated or retired body has no authority.
    pub fn peb_for_kernel_process_object(&self, eprocess: u64) -> Result<u64, u32> {
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(process.peb_base_address)
    }

    /// A native AMD64 process has no 32-bit PEB. The current image loader admits AMD64 images
    /// only, and the designated initial System process is native kernel code. Other processes
    /// lack architecture proof and cannot inherit a fabricated null PEB32.
    pub fn peb32_for_kernel_process_object(&self, eprocess: u64) -> Result<u64, u32> {
        match self.wow64_pointer_for_kernel_process_object(eprocess)? {
            0 => Ok(0),
            _ => Err(STATUS_INVALID_IMAGE_FORMAT),
        }
    }
}
