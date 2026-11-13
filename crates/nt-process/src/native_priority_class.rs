//! Exact EPROCESS priority-class access for Ps kernel exports.

use crate::{ProcessManager, STATUS_INVALID_HANDLE};

impl ProcessManager {
    /// Return only the stored EPROCESS priority class. Scheduler base priority and quantum are
    /// separate state, so this getter does not derive one from the other.
    pub fn priority_class_for_kernel_process_object(&self, eprocess: u64) -> Result<u8, u32> {
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(process.priority_class())
    }

    /// `PsSetProcessPriorityClass` changes the EPROCESS class byte without applying the
    /// `PsSetProcessPriorityByClass` scheduler transition.
    pub fn set_priority_class_for_kernel_process_object(
        &mut self,
        eprocess: u64,
        priority_class: u8,
    ) -> Result<(), u32> {
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.set_process_priority_class(pid, priority_class)
    }
}
