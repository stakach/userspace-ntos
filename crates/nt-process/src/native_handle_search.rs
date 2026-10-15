//! Kernel ObFind-style inspection of an existing target process handle table.
//! This observes published entries only; it never opens a handle or acquires a reference.

use crate::native_handle::{NativeHandleCaller, NativeHandleInformation};
use crate::{Handle, HandleObject, ProcessId, ProcessManager, ProcessState};
use nt_types::AccessMode;

impl ProcessManager {
    /// Find the first published target-table entry matching the supplied pure object/type
    /// predicate and optional exact handle information. The adapter authenticates its kernel
    /// lane before capturing `caller`; `target` is a canonical, non-reused ProcessId, not a PI.
    /// Returned values belong to the target table and are never implicitly kernel-tagged.
    pub fn find_native_handle(
        &self,
        caller: NativeHandleCaller,
        target: ProcessId,
        information: Option<NativeHandleInformation>,
        mut matches: impl FnMut(HandleObject) -> bool,
    ) -> Result<Option<Handle>, u32> {
        self.validate_native_handle_caller(caller)?;
        if caller.mode() != AccessMode::KernelMode {
            return Err(crate::STATUS_ACCESS_DENIED);
        }
        let process = self.process(target).ok_or(crate::STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) || process.exit_status.is_some()
        {
            return Err(crate::STATUS_INVALID_HANDLE);
        }
        for (slot, entry) in process.handles.iter().enumerate() {
            let Some(entry) = entry.entry() else { continue };
            let actual = NativeHandleInformation {
                attributes: u32::from(entry.flags.inherit) * 2
                    | u32::from(entry.flags.protect_from_close),
                granted_access: Some(entry.granted_access),
            };
            if information.is_some_and(|filter| filter != actual) || !matches(entry.object) {
                continue;
            }
            return Ok(Some(crate::slot_to_handle(slot)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
