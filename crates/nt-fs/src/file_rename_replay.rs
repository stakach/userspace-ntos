//! Restore a committed rename into an unpublished volume before later creates and byte deltas.

use super::*;
use crate::file_delta_wal_payload::FileDeltaWalReplayError;
use crate::file_rename_wal_payload::{validate, FileRenameWalPayload};
use crate::volume_wal_sequence::VolumeWalReplayCursor;

impl FileSystem {
    pub fn replay_file_rename_wal_payload(
        &mut self,
        cursor: &mut VolumeWalReplayCursor,
        payload: FileRenameWalPayload<'_>,
    ) -> Result<(), FileDeltaWalReplayError> {
        use FileDeltaWalReplayError::*;
        if !cursor.admits(payload.sequence) {
            return Err(OutOfOrder);
        }
        validate(payload).map_err(|_| ForeignIdentity)?;
        let source_rel = self.to_relative(&normalize_separators(payload.source_path))
            .ok_or(MissingFile)?;
        let target_rel = self.to_relative(&normalize_separators(payload.target_path))
            .ok_or(MissingFile)?;
        let source_rel = source_rel.trim_start_matches('\\');
        let target_rel = target_rel.trim_start_matches('\\');
        if !MemFs::valid_snapshot_path(source_rel) || !MemFs::valid_snapshot_path(target_rel) {
            return Err(MissingFile);
        }
        let (source_parent_path, source_leaf) =
            MemFs::parent_and_leaf_relative(source_rel).ok_or(MissingFile)?;
        let (target_parent_path, target_leaf) =
            MemFs::parent_and_leaf_relative(target_rel).ok_or(MissingFile)?;
        let source_parent = self.volume.lookup(source_parent_path).ok_or(MissingFile)?;
        let target_parent = self.volume.lookup(target_parent_path).ok_or(MissingFile)?;
        if !self.volume.node(source_parent).is_some_and(|node| {
            node.is_dir && node.file_id == payload.source_parent_file_id
        }) || !self.volume.node(target_parent).is_some_and(|node| {
            node.is_dir && node.file_id == payload.target_parent_file_id
        }) {
            return Err(ForeignIdentity);
        }
        let source = self.volume.child_long_entry(source_parent, source_leaf)
            .map(|entry| (entry.id, entry.node_id));
        let target = self.volume.child_long_entry(target_parent, target_leaf)
            .map(|entry| (entry.id, entry.node_id));
        // A later snapshot may contain both the moved file and a new file at its old name.
        // The moved identity at its exact long name proves this operation is already represented;
        // leave later snapshot metadata intact, including timestamps a later basic-info update
        // may have set backwards.
        if source.is_none_or(|(_, node)| self.volume.node(node)
            .is_none_or(|node| node.file_id != payload.source_file_id))
            && target.is_some_and(|(_, node)| {
                self.volume.node(node).is_some_and(|node| node.file_id == payload.source_file_id)
            })
        {
            let target_node = target.ok_or(MissingFile)?.1;
            if self.wal_protected_subtree(target_node) {
                return Err(ProtectedTarget);
            }
            cursor.advance(payload.sequence);
            return Ok(());
        }
        let (source_entry, source_node) = source.ok_or(MissingFile)?;
        let source_node_body = self.volume.node(source_node).ok_or(MissingFile)?;
        if source_node_body.file_id != payload.source_file_id {
            return Err(ForeignIdentity);
        }
        if self.wal_protected_subtree(source_node) {
            return Err(ProtectedTarget);
        }
        let replaced_node = match target {
            Some((_, node)) => {
                let body = self.volume.node(node).ok_or(MissingFile)?;
                if body.file_id != payload.replaced_file_id {
                    return Err(ForeignIdentity);
                }
                if self.wal_protected_subtree(node) {
                    return Err(ProtectedTarget);
                }
                Some(node)
            }
            None if payload.replaced_file_id == 0 => {
                if self.volume.child_entry(target_parent, target_leaf).is_some() {
                    return Err(ForeignIdentity);
                }
                None
            }
            None => return Err(ForeignIdentity),
        };
        let plan = self.volume.prepare_rename_into_parent_with_short_name(
            source_node, source_entry, target_parent, target_leaf, true,
            Some(payload.moved_short_name),
        ).map_err(|status| match status {
            STATUS_INSUFFICIENT_RESOURCES => OutOfMemory,
            STATUS_OBJECT_PATH_NOT_FOUND | STATUS_OBJECT_NAME_NOT_FOUND => MissingFile,
            _ => ForeignIdentity,
        })?;
        // Preparation validated every identity and reserved every allocation. Any unexpected
        // apply refusal means the unpublished volume cannot be published.
        if self.volume.apply_rename_into_parent(plan) != STATUS_SUCCESS {
            return Err(OutOfMemory);
        }
        if let Some(node) = replaced_node {
            self.volume.reap_unlinked(node);
        }
        let moved = self.volume.node_mut(source_node).ok_or(OutOfMemory)?;
        moved.change_time = payload.change_time;
        self.volume.current_time_100ns =
            self.volume.current_time_100ns.max(payload.change_time);
        cursor.advance(payload.sequence);
        Ok(())
    }
}
