//! Native Key namespace selection shares the canonical Ps handle decoder, not Ps bodies.

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
    /// Reserve the canonical table before CM work. The adapter authenticates the caller and
    /// strips non-handle OBJECT_ATTRIBUTES after applying their namespace/security semantics.
    pub fn reserve_native_registry_key_handle(
        &mut self,
        caller: NativeHandleCaller,
        attributes: u32,
    ) -> Result<RegistryKeyHandlePublication, u32> {
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
        let mut publication = self.reserve_registry_key_handle(owner)?;
        if publication.value > 0x7fff_fffc {
            publication.abort(self)?;
            return Err(crate::STATUS_INSUFFICIENT_RESOURCES);
        }
        publication.value |= if kernel { KERNEL_HANDLE_TAG } else { 0 };
        publication.flags.inherit = attributes & OBJ_INHERIT != 0;
        Ok(publication)
    }

    /// Resolve a visible Key lease. This is a synchronous borrow, not a retained CM reference;
    /// callers crossing IPC must separately retain the CM target before releasing ownership.
    pub fn lookup_native_registry_key_handle(
        &self,
        caller: NativeHandleCaller,
        value: u64,
        desired_access: u32,
    ) -> Result<u32, u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let object = self
            .lookup_handle(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let HandleObject::RegistryKey(key) = object else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let granted = self
            .handle_access(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if caller.mode() == AccessMode::UserMode && desired_access & !granted != 0 {
            return Err(crate::STATUS_ACCESS_DENIED);
        }
        Ok(key)
    }

    /// Remove one visible table reference and return its CM lease for canonical close cleanup.
    /// Bound publication slots are invisible, and protect-close is never silently overridden.
    pub fn close_native_registry_key_handle(
        &mut self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<u32, NativePsCloseError> {
        let target = self
            .inspect_native_close_target(caller, value)
            .map_err(NativePsCloseError::Status)?;
        let HandleObject::RegistryKey(key) = target.object() else {
            return Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH));
        };
        let removed = self.close_native_handle(caller, value)?;
        debug_assert_eq!(removed.into_object(), HandleObject::RegistryKey(key));
        Ok(key)
    }
}

#[cfg(test)]
mod tests;
