//! Atomic admission of an I/O reference and its FILE_OBJECT signal state.

use super::*;

impl FileSystem {
    /// Retain one I/O reference and clear the file signal without a fallible rollback boundary.
    /// Cleanup may retain existing I/O, but a new operation requires a live handle reference.
    pub fn zw_begin_file_io(&mut self, handle: u64) -> Result<(), u32> {
        let index = usize::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let object = self
            .handles
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if object.references < object.handle_references {
            return Err(STATUS_DATA_ERROR);
        }
        if object.handle_references == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.volume.node(object.node_id).ok_or(STATUS_DATA_ERROR)?;
        let references = object
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        object.references = references;
        object.signaled = false;
        Ok(())
    }
}

#[cfg(test)]
#[path = "file_io_lifetime/tests.rs"]
mod tests;
