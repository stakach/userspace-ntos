//! Restore resolved basic-information state into an unpublished volume.

use super::*;
use crate::file_basic_wal_payload::{validate, FileBasicWalPayload};
use crate::file_delta_wal_payload::FileDeltaWalReplayError;
use crate::volume_wal_sequence::VolumeWalReplayCursor;

impl FileSystem {
    /// Apply only records beyond the selected snapshot's authenticated WAL base. An older
    /// metadata state must never overwrite newer metadata in a later selected snapshot.
    /// Every refusal leaves the restored volume and typed-file cursor unchanged.
    pub fn replay_file_basic_wal_payload(
        &mut self,
        cursor: &mut VolumeWalReplayCursor,
        payload: FileBasicWalPayload<'_>,
    ) -> Result<(), FileDeltaWalReplayError> {
        use FileDeltaWalReplayError::*;
        if !cursor.admits(payload.sequence) {
            return Err(OutOfOrder);
        }
        validate(payload).map_err(|_| ForeignIdentity)?;
        let rel = self.to_relative(&normalize_separators(payload.path)).ok_or(MissingFile)?;
        let node_id = self.volume.lookup(&rel).ok_or(MissingFile)?;
        let node = self.volume.node(node_id).ok_or(MissingFile)?;
        if node.file_id != payload.file_id
            || node.is_dir != (payload.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
        {
            return Err(ForeignIdentity);
        }
        if self.wal_protected_subtree(node_id) {
            return Err(ProtectedTarget);
        }
        let node = self.volume.node_mut(node_id).ok_or(MissingFile)?;
        node.attributes = payload.attributes;
        node.creation_time = payload.times[0];
        node.last_access_time = payload.times[1];
        node.last_write_time = payload.times[2];
        node.change_time = payload.times[3];
        cursor.advance(payload.sequence);
        Ok(())
    }
}

#[cfg(test)]
#[path = "file_basic_replay_tests.rs"]
mod tests;
