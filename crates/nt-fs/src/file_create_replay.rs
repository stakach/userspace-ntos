//! Restore a committed namespace entry into an unpublished volume before its content deltas.

use super::*;
use crate::file_create_wal_payload::{validate, FileCreateWalPayload};
use crate::file_delta_wal_payload::{FileDeltaReplayCursor, FileDeltaWalReplayError};

impl FileSystem {
    /// A matching entry in a later snapshot is already present; a missing entry is created with
    /// its recorded identity and metadata. The caller discards this volume after `OutOfMemory`.
    pub fn replay_file_create_wal_payload(
        &mut self,
        cursor: &mut FileDeltaReplayCursor,
        payload: FileCreateWalPayload<'_>,
    ) -> Result<(), FileDeltaWalReplayError> {
        use FileDeltaWalReplayError::*;
        if !cursor.admits(payload.sequence) {
            return Err(OutOfOrder);
        }
        validate(payload).map_err(|_| ForeignIdentity)?;
        let rel = self.to_relative(&normalize_separators(payload.path)).ok_or(MissingFile)?;
        // MountManager returns a leading separator; snapshot paths and child preparation use
        // paths relative to the MemFs root.
        let rel = rel.trim_start_matches('\\');
        if !MemFs::valid_snapshot_path(&rel) {
            return Err(MissingFile);
        }
        let (parent_path, leaf) = MemFs::parent_and_leaf_relative(&rel).ok_or(MissingFile)?;
        let parent = self.volume.lookup(parent_path).ok_or(MissingFile)?;
        if !self.volume.node(parent).is_some_and(|node| {
            node.is_dir && node.file_id == payload.parent_file_id
        }) {
            return Err(ForeignIdentity);
        }
        if let Some(existing) = self.volume.lookup(&rel) {
            if self.wal_protected_subtree(existing) {
                return Err(ProtectedTarget);
            }
            let node = self.volume.node(existing).ok_or(MissingFile)?;
            if node.file_id != payload.file_id || node.is_dir != payload.is_directory {
                return Err(ForeignIdentity);
            }
            cursor.advance(payload.sequence);
            return Ok(());
        }
        if self.volume.nodes.iter().flatten().any(|node| node.file_id == payload.file_id) {
            return Err(ForeignIdentity);
        }
        // MemFs allocates file IDs in sequence. A lower ID was already consumed by a later
        // snapshot; a higher ID would skip an unlogged namespace creation.
        if payload.file_id != self.volume.next_file_id {
            return Err(ForeignIdentity);
        }
        let options = if payload.is_directory { FILE_DIRECTORY_FILE } else { FILE_NON_DIRECTORY_FILE };
        let mut allocator = file_create::CreateAllocator::default();
        let mut plan = self.volume.prepare_create_child(
            parent, leaf, options, payload.attributes, &mut allocator,
        ).map_err(|status| match status {
            STATUS_INSUFFICIENT_RESOURCES => OutOfMemory,
            STATUS_OBJECT_PATH_NOT_FOUND => MissingFile,
            _ => ForeignIdentity,
        })?;
        let file_create::PreparedCreate::New { node, .. } = &mut plan else {
            return Err(ForeignIdentity);
        };
        node.file_id = payload.file_id;
        node.attributes = payload.attributes;
        node.creation_time = payload.times[0];
        node.last_access_time = payload.times[1];
        node.last_write_time = payload.times[2];
        node.change_time = payload.times[3];
        self.volume.apply_create(plan);
        self.volume.next_file_id = self.volume.next_file_id.max(payload.file_id + 1);
        cursor.advance(payload.sequence);
        Ok(())
    }
}
