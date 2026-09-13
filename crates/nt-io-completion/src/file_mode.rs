//! Memory-only synchronization of canonical File mode with its completion policy.

use crate::{FileCompletionTable, FileIoMode, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

impl<const FILES: usize> FileCompletionTable<FILES> {
    /// Preflight policy ownership before updating the canonical File body. The closure must be
    /// memory-only, must validate before mutation, and must not reenter this policy table.
    /// Derive `next_mode` and the canonical change from the same validated transition; the closure
    /// must commit that exact mode, not independently select another canonical policy.
    /// A failure changes neither policy nor ownership. Success changes only the live mode;
    /// existing acquired/queued operations retain their captured alertability.
    pub fn update_io_mode_with(
        &mut self,
        file_id: u64,
        expected_device: u64,
        tid: u64,
        expected_live_mode: FileIoMode,
        next_mode: FileIoMode,
        commit_body: impl FnOnce() -> Result<(), u32>,
    ) -> Result<(), u32> {
        if tid == 0 || tid == u64::MAX {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if expected_device == 0 || entry.device_id != expected_device {
            return Err(STATUS_INVALID_HANDLE);
        }
        if entry.handle_publication_reserved
            || entry.io_mode != expected_live_mode
            || entry.io_mode.is_synchronous() != next_mode.is_synchronous()
            || (entry.io_mode.is_synchronous()
                && (entry.serialization.io_lock_owner() != Some(tid)
                    || entry.serialization.io_grant_owner().is_some()))
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        commit_body()?;
        entry.io_mode = next_mode;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
