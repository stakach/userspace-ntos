//! Process image architecture authority for Ps WOW64 projections.

use crate::{ProcessId, ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_IMAGE_FORMAT};
use nt_pe_loader::PeFile;

/// `PeFile` currently validates PE32+/AMD64 only. Keep that fact attached to the exact process
/// identity rather than returning a global null WOW64 pointer for every process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessArchitectureProof {
    /// The exact designated initial System process is the kernel's own native process.
    NativeKernel,
    Amd64Image,
}

impl ProcessManager {
    /// Admit architecture only after the caller has parsed the process's own image with
    /// `nt-pe-loader`; its `PeFile` cannot represent an unsupported machine.
    pub fn admit_validated_process_image(
        &mut self,
        pid: ProcessId,
        _validated_image: &PeFile<'_>,
    ) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.architecture_proof = Some(ProcessArchitectureProof::Amd64Image);
        Ok(())
    }

    /// The kernel's `WOW64_PROCESS*` for one exact process. Zero is proved by AMD64 image
    /// admission; an image-less process has no architecture evidence and is refused.
    pub fn process_wow64_pointer(&self, pid: ProcessId) -> Result<u64, u32> {
        let process = self.processes.get(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        match process.architecture_proof {
            Some(ProcessArchitectureProof::NativeKernel | ProcessArchitectureProof::Amd64Image) => Ok(0),
            None => Err(STATUS_INVALID_IMAGE_FORMAT),
        }
    }

    /// Resolve the published EPROCESS first so a stale or foreign pointer cannot inherit the
    /// current process's native-image proof.
    pub fn wow64_pointer_for_kernel_process_object(&self, eprocess: u64) -> Result<u64, u32> {
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.process_wow64_pointer(pid)
    }
}
