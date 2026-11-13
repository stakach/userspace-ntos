//! Apply committed file-delta WAL records to an unpublished, restored volume.

use super::*;
use crate::file_delta_wal_payload::{
    FileDeltaReplayCursor, FileDeltaWalPayload, FileDeltaWalReplayError,
};

impl FileSystem {
    /// Apply one committed file delta. The physical WAL already proves durability and frame
    /// order; this checks the delta chain and the exact persisted file before any change.
    ///
    /// Every refusal except `OutOfMemory` leaves the volume and cursor untouched.
    pub fn replay_file_delta_wal_payload(
        &mut self,
        cursor: &mut FileDeltaReplayCursor,
        payload: FileDeltaWalPayload<'_>,
    ) -> Result<(), FileDeltaWalReplayError> {
        use FileDeltaWalReplayError::*;
        if !cursor.admits(payload.sequence()) {
            return Err(OutOfOrder);
        }
        let rel = self.to_relative(&normalize_separators(payload.path())).ok_or(MissingFile)?;
        let node_id = self.volume.lookup(&rel).ok_or(MissingFile)?;
        let node = self.volume.node(node_id).ok_or(MissingFile)?;
        if node.is_dir {
            return Err(MissingFile);
        }
        if node.file_id != payload.file_id() {
            return Err(ForeignIdentity);
        }
        if self.wal_protected_node(node_id) {
            return Err(ProtectedTarget);
        }
        // The exact length comes first: it drops bytes a later record regrows as zeroes, and
        // every extent then lies inside the file. Only allocation can fail from here on.
        if self.volume.set_end_of_file(node_id, payload.end_of_file()) != STATUS_SUCCESS {
            return Err(OutOfMemory);
        }
        for extent in payload.extents() {
            if self.volume.write_at(node_id, extent.offset, extent.bytes, None) != extent.bytes.len() {
                return Err(OutOfMemory);
            }
            self.volume
                .mark_data_initialized_through(node_id, extent.offset + extent.bytes.len() as u64);
        }
        self.volume.ensure_allocation_covers_eof(node_id);
        self.volume.touch_write(node_id);
        cursor.advance(payload.sequence());
        Ok(())
    }
}

#[cfg(test)]
#[path = "file_delta_replay_tests.rs"]
mod tests;
