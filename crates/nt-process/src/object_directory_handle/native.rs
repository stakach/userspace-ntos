//! Native scope for typed executive directory references.

use super::*;
use crate::native_handle::{
    NativeHandleCaller, NativeHandleScope, NativePsCloseError, KERNEL_HANDLE_TAG,
    OBJ_KERNEL_HANDLE, STATUS_OBJECT_TYPE_MISMATCH,
};
use nt_types::AccessMode;

#[cfg(test)]
use crate::native_handle::INVALID_KERNEL_HANDLE_BUGCHECK;

const OBJ_INHERIT: u32 = 2;

impl ProcessManager {
    /// Reserve in the system table for a kernel handle, otherwise in the effective caller table.
    /// Namespace/security attributes are validated by the executive before it supplies a target.
    pub fn reserve_native_object_directory_handle(
        &mut self,
        caller: NativeHandleCaller,
        attributes: u32,
    ) -> Result<ObjectDirectoryHandlePublication, u32> {
        self.validate_native_handle_caller(caller)?;
        let kernel = attributes & OBJ_KERNEL_HANDLE != 0;
        if attributes & !(OBJ_KERNEL_HANDLE | OBJ_INHERIT) != 0
            || (kernel && caller.mode() != AccessMode::KernelMode)
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        let owner = if kernel {
            self.initial_system_identity()
                .ok_or(STATUS_INVALID_HANDLE)?
                .process_id()
        } else {
            caller.effective_process()
        };
        let mut publication = self.reserve_object_directory_handle(owner)?;
        if publication.value > 0x7fff_fffc {
            publication.abort(self)?;
            return Err(crate::STATUS_INSUFFICIENT_RESOURCES);
        }
        publication.value |= if kernel { KERNEL_HANDLE_TAG } else { 0 };
        publication.flags.inherit = attributes & OBJ_INHERIT != 0;
        Ok(publication)
    }

    /// Resolve a visible typed directory handle; the executive owns namespace lifetime.
    pub fn lookup_native_object_directory_handle(
        &self,
        caller: NativeHandleCaller,
        value: u64,
        desired_access: u32,
    ) -> Result<u64, u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let object = self
            .lookup_handle(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let HandleObject::ObjectDirectory(directory) = object else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let granted = self
            .handle_access(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if caller.mode() == AccessMode::UserMode && desired_access & !granted != 0 {
            return Err(crate::STATUS_ACCESS_DENIED);
        }
        Ok(directory)
    }

    /// Remove the exact table reference and return its executive-owned identity for cleanup.
    pub fn close_native_object_directory_handle(
        &mut self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<u64, NativePsCloseError> {
        let target = self
            .inspect_native_close_target(caller, value)
            .map_err(NativePsCloseError::Status)?;
        let HandleObject::ObjectDirectory(directory) = target.object() else {
            return Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH));
        };
        let removed = self.close_native_handle(caller, value)?;
        debug_assert_eq!(removed.into_object(), HandleObject::ObjectDirectory(directory));
        Ok(directory)
    }
}

#[cfg(test)]
mod tests;
