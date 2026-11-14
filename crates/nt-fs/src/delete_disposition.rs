//! Delete disposition of an open file: `FileDispositionInformation` and `FILE_DELETE_ON_CLOSE`.
//!
//! DeletePending is a property of the opened directory entry, shared by every File open on it
//! (FASTFAT's `FCB_STATE_DELETE_ON_CLOSE`). `FILE_DELETE_ON_CLOSE` belongs to one File and
//! becomes that shared state when the File's last handle closes. The entry leaves the namespace
//! when the last File open on it is cleaned up; until then it cannot be opened again.

use super::file_create::PreparedCreate;
use super::*;

impl FileObject {
    /// Still holds, or has yet to release, its share of the opened entry.
    fn holds_entry_open(&self) -> bool {
        self.handle_references != 0 || self.cleanup_reference_held
    }

    /// This File will ask for its entry's deletion, now or when its handle closes.
    pub(super) fn requests_delete(&self) -> bool {
        self.delete_pending || self.delete_on_close
    }
}

impl FileSystem {
    fn entry_delete_pending(&self, entry_id: u64, node_id: u64) -> bool {
        self.handles.iter().flatten().any(|object| {
            object.entry_id == entry_id
                && object.node_id == node_id
                && object.delete_pending
                && object.holds_entry_open()
        })
    }

    /// A directory has exactly one entry, so its node identifies it.
    fn directory_delete_pending(&self, node_id: u64) -> bool {
        self.handles.iter().flatten().any(|object| {
            object.node_id == node_id && object.delete_pending && object.holds_entry_open()
        })
    }

    /// CREATE admission against delete state. A delete-pending entry admits no new open and a
    /// delete-pending directory no new entry; a read-only file cannot be asked to delete itself.
    /// `FILE_CREATE` of an existing name has already collided before this is asked.
    pub(super) fn check_create_delete_state(
        &self,
        plan: &PreparedCreate,
        options: u32,
    ) -> Result<(), u32> {
        let delete_on_close = options & FILE_DELETE_ON_CLOSE != 0;
        match plan {
            PreparedCreate::Existing { node, entry, .. } => {
                if self.entry_delete_pending(*entry, *node) {
                    return Err(STATUS_DELETE_PENDING);
                }
                if delete_on_close {
                    let status = self.volume.can_mark_delete_pending(*node, false);
                    // Emptiness is decided when the directory's handle closes.
                    if status != STATUS_SUCCESS && status != STATUS_DIRECTORY_NOT_EMPTY {
                        return Err(status);
                    }
                }
            }
            PreparedCreate::New { parent, node, .. } => {
                if self.directory_delete_pending(*parent) {
                    return Err(STATUS_DELETE_PENDING);
                }
                if delete_on_close && node.attributes & FILE_ATTRIBUTE_READONLY != 0 {
                    return Err(STATUS_CANNOT_DELETE);
                }
            }
        }
        Ok(())
    }

    /// `FileDispositionInformation`: set or clear DeletePending on the entry `handle` opened,
    /// as seen through every File open on it.
    pub(super) fn set_delete_disposition(
        &mut self,
        handle: u64,
        delete: bool,
        ignore_readonly: bool,
    ) -> u32 {
        let Some(object) = self.obj(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let (entry_id, node_id) = (object.entry_id, object.node_id);
        if delete {
            let status = self.volume.can_mark_delete_pending(node_id, ignore_readonly);
            if status != STATUS_SUCCESS {
                return status;
            }
        }
        self.mark_entry_delete_pending(entry_id, node_id, delete);
        STATUS_SUCCESS
    }

    fn mark_entry_delete_pending(&mut self, entry_id: u64, node_id: u64, pending: bool) {
        for object in self.handles.iter_mut().flatten() {
            if object.entry_id == entry_id && object.node_id == node_id {
                object.delete_pending = pending;
            }
        }
    }

    /// Final-handle cleanup of the File at `index`: whether its entry must now leave the
    /// namespace. A File opened delete-on-close first publishes that as the entry's DeletePending,
    /// so the Files still open on the entry carry the delete to their own cleanup. A directory
    /// that holds entries when its last handle closes is kept and stops being delete-pending.
    pub(super) fn delete_due_at_cleanup(&mut self, index: usize) -> bool {
        let object = self.handles[index].as_ref().expect("cleanup owner");
        if !object.requests_delete() {
            return false;
        }
        let (entry_id, node_id) = (object.entry_id, object.node_id);
        self.mark_entry_delete_pending(entry_id, node_id, true);
        let still_open = self.handles.iter().enumerate().any(|(other, object)| {
            other != index
                && object.as_ref().is_some_and(|object| {
                    object.entry_id == entry_id
                        && object.node_id == node_id
                        && object.holds_entry_open()
                })
        });
        if still_open {
            return false;
        }
        if self.volume.node(node_id).is_some_and(|node| node.is_dir && !node.children.is_empty()) {
            self.mark_entry_delete_pending(entry_id, node_id, false);
            return false;
        }
        true
    }
}

#[cfg(test)]
#[path = "delete_disposition/tests.rs"]
mod tests;
