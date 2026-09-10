//! Canonical FILE_OBJECT serialization and deferred final-handle cleanup.

use super::*;
use nt_io_completion::{FileIoAcquireResult, FileIoMode, FileIoRelease};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCleanupEffects {
    pub namespace_changed: bool,
    pub notifications_completed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIoState {
    pub owner_tid: Option<u64>,
    pub waiters: u32,
    pub references: u32,
    pub handle_references: u32,
    pub cleanup_pending: bool,
    pub cleanup_error: Option<u32>,
    pub signaled: bool,
}

impl FileObject {
    fn io_mode(&self) -> FileIoMode {
        if self.create_options & FILE_SYNCHRONOUS_IO_ALERT != 0 {
            FileIoMode::SynchronousAlertable
        } else if self.create_options & FILE_SYNCHRONOUS_IO_NONALERT != 0 {
            FileIoMode::SynchronousNonAlertable
        } else {
            FileIoMode::Asynchronous
        }
    }

    fn minimum_references(&self) -> Result<u32, u32> {
        if (self.cleanup_reference_held && self.handle_references != 0)
            || (!self.cleanup_reference_held
                && (self.serialization.cleanup_waiting() || self.serialization.is_cleanup_owner()))
        {
            return Err(STATUS_DATA_ERROR);
        }
        let minimum = u64::from(self.handle_references)
            + u64::from(self.cleanup_reference_held)
            + self.serialization.ordinary_io_references();
        u32::try_from(minimum).map_err(|_| STATUS_DATA_ERROR)
    }
}

impl FileSystem {
    /// Enumerate retained cleanup owners without allocating. The usual empty path is constant time.
    pub fn pending_file_cleanup_from(&self, start: usize) -> Option<(usize, u64)> {
        if self.pending_file_cleanup_count == 0 {
            return None;
        }
        self.handles
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(index, object)| {
                object
                    .as_ref()
                    .filter(|object| object.cleanup_reference_held)
                    .map(|_| (index, index as u64))
            })
    }

    /// Effects remain sticky across automatic and explicit cleanup until the executive consumes them.
    pub fn take_file_cleanup_effects(&mut self) -> FileCleanupEffects {
        core::mem::take(&mut self.file_cleanup_effects)
    }

    pub(super) fn checked_file_io_index(&self, handle: u64) -> Result<usize, u32> {
        let index = usize::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let object = self
            .handles
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if object.references < object.minimum_references()? {
            return Err(STATUS_DATA_ERROR);
        }
        if object.references == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.volume.node(object.node_id).ok_or(STATUS_DATA_ERROR)?;
        Ok(index)
    }

    /// This observation remains available when cleanup preparation failed on backing corruption.
    pub fn zw_file_io_state(&self, handle: u64) -> Result<FileIoState, u32> {
        let index = usize::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let object = self
            .handles
            .get(index)
            .and_then(Option::as_ref)
            .filter(|object| object.references != 0)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(FileIoState {
            owner_tid: object.serialization.io_lock_owner(),
            waiters: object.serialization.io_waiter_count(),
            references: object.references,
            handle_references: object.handle_references,
            cleanup_pending: object.cleanup_reference_held,
            cleanup_error: object.cleanup_error,
            signaled: object.signaled,
        })
    }

    /// Atomically retain and admit a new operation. Contention retains its reference for the
    /// executive's waiter; neither acquisition nor waiting changes the File event.
    pub fn zw_acquire_file_io(
        &mut self,
        handle: u64,
        tid: u64,
    ) -> Result<FileIoAcquireResult, u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        if object.handle_references == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        if object.serialization.io_grant_owner() == Some(tid) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut serialization = object.serialization;
        let acquired =
            serialization.begin_io(object.io_mode(), tid, object.cleanup_reference_held)?;
        let references = object
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        object.references = references;
        object.serialization = serialization;
        Ok(acquired)
    }

    /// Consume an exact promoted grant, including after final-handle close, without retaining twice.
    pub fn zw_adopt_file_io(&mut self, handle: u64, tid: u64) -> Result<(), u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        let mode = object.io_mode();
        object.serialization.adopt_io_grant(mode, tid)
    }

    pub fn zw_promote_file_io_waiter(&mut self, handle: u64, tid: u64) -> Result<u32, u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        let mode = object.io_mode();
        object.serialization.promote_io_waiter(mode, tid)
    }

    /// Cancel one externally owned FIFO waiter and release that waiter's retained reference.
    pub fn zw_cancel_file_io_waiter(&mut self, handle: u64) -> Result<u32, u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        let waiters = object.serialization.cancel_io_waiter()?;
        object.references -= 1;
        self.finish_local_io_transition(handle, index);
        Ok(waiters)
    }

    /// Cancel an unconsumed promoted grant and its retained reference exactly once.
    pub fn zw_cancel_promoted_file_io(
        &mut self,
        handle: u64,
        tid: u64,
    ) -> Result<FileIoRelease, u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        let release = object.serialization.cancel_promoted_io(tid)?;
        object.references -= 1;
        self.finish_local_io_transition(handle, index);
        Ok(release)
    }

    /// Release Busy only. The terminal delivery owner keeps its separate I/O reference until ACK.
    pub fn zw_release_file_io(&mut self, handle: u64, tid: u64) -> Result<FileIoRelease, u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        let mode = object.io_mode();
        let release = object.serialization.release_io(mode, tid)?;
        self.finish_local_io_transition(handle, index);
        Ok(release)
    }

    pub fn zw_retain_io_reference(&mut self, handle: u64) -> Result<(), u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        if object.handle_references == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        object.references = object
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        Ok(())
    }

    /// Never consume a handle, cleanup, acquired-operation, or counted-waiter reference.
    pub fn zw_release_io_reference(&mut self, handle: u64) -> Result<(), u32> {
        let index = self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        if object.references == object.minimum_references()? {
            return Err(STATUS_INVALID_HANDLE);
        }
        object.references -= 1;
        self.finish_local_io_transition(handle, index);
        Ok(())
    }

    fn finish_local_io_transition(&mut self, handle: u64, index: usize) {
        if self.handles[index]
            .as_ref()
            .is_some_and(|object| object.cleanup_reference_held)
        {
            // The operation/reference transition already committed. A cleanup preparation error
            // belongs to its retained cleanup owner, never to a retry of that completed transition.
            let _ = self.zw_redrive_file_cleanup(handle);
        }
        if self.handles[index]
            .as_ref()
            .is_some_and(|object| object.references == 0)
        {
            self.handles[index] = None;
            self.reap_unlinked_nodes();
        }
    }

    /// Consume one handle. Once consumed, return SUCCESS even if cleanup preparation fails:
    /// its transferred reference and error remain observable through `zw_file_io_state` and
    /// retryable through `zw_redrive_file_cleanup`, not by closing the same handle again.
    pub fn zw_close(&mut self, handle: u64) -> u32 {
        let index = match self.checked_file_io_index(handle) {
            Ok(index) => index,
            Err(status) => return status,
        };
        let object = self.handles[index].as_mut().unwrap();
        if object.handle_references == 0 {
            return STATUS_INVALID_HANDLE;
        }
        if object.handle_references != 1 {
            object.handle_references -= 1;
            object.references -= 1;
            return STATUS_SUCCESS;
        }
        let mut serialization = object.serialization;
        if let Err(status) = serialization.begin_cleanup(object.io_mode()) {
            return status;
        }
        let Some(pending_count) = self.pending_file_cleanup_count.checked_add(1) else {
            return STATUS_QUOTA_EXCEEDED;
        };
        object.handle_references = 0;
        object.cleanup_reference_held = true;
        object.serialization = serialization;
        self.pending_file_cleanup_count = pending_count;
        self.finish_local_io_transition(handle, index);
        STATUS_SUCCESS
    }

    /// Advance only this object's retained cleanup. False means absent cleanup or remaining Busy
    /// ownership; an error retains the cleanup reference/share claim for a later exact redrive.
    pub fn zw_redrive_file_cleanup(&mut self, handle: u64) -> Result<bool, u32> {
        let index = usize::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let object = self
            .handles
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !object.cleanup_reference_held {
            return Ok(false);
        }
        let result = self.advance_file_cleanup(handle, index);
        if let Err(status) = result {
            self.handles[index].as_mut().unwrap().cleanup_error = Some(status);
        }
        result
    }

    fn advance_file_cleanup(&mut self, handle: u64, index: usize) -> Result<bool, u32> {
        self.checked_file_io_index(handle)?;
        let object = self.handles[index].as_mut().unwrap();
        let mode = object.io_mode();
        if object.serialization.cleanup_waiting()
            && !object.serialization.promote_cleanup_if_ready(mode, true)?
        {
            return Ok(false);
        }
        if object.io_mode().is_synchronous() && !object.serialization.is_cleanup_owner() {
            return Ok(false);
        }
        let object = self.handles[index].as_ref().unwrap();
        let entry_id = object.entry_id;
        let node = self.volume.node(object.node_id).ok_or(STATUS_DATA_ERROR)?;
        let filter = if node.is_dir {
            crate::FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            crate::FILE_NOTIFY_CHANGE_FILE_NAME
        };
        let deleted_name = if object.delete_pending
            && entry_id != 0
            && self.checked_object_entry(object)?.is_some()
        {
            if node.link_count == 0 {
                return Err(STATUS_DATA_ERROR);
            }
            if node.is_dir && !node.children.is_empty() {
                return Err(STATUS_DIRECTORY_NOT_EMPTY);
            }
            Some(self.volume.try_opened_name(entry_id)?)
        } else {
            None
        };
        // Fallible namespace preparation precedes cleanup effects. An absent exact entry
        // is already unlinked, not permission to delete a replacement with the same spelling.
        if deleted_name.is_some() {
            self.volume.unlink_entry(entry_id)?;
            self.file_cleanup_effects.namespace_changed = true;
        }
        self.file_cleanup_effects.notifications_completed |=
            self.notifications.cleanup_file_object(handle) != 0;
        if let Some(deleted_name) = deleted_name {
            self.file_cleanup_effects.notifications_completed |=
                self.notifications.report_change(crate::DirectoryChange {
                    full_path: &deleted_name,
                    filter,
                    action: crate::FILE_ACTION_REMOVED,
                }) != 0;
        }
        let object = self.handles[index].as_mut().unwrap();
        if object.io_mode().is_synchronous() {
            object
                .serialization
                .release_cleanup_io()
                .expect("validated cleanup lost Busy");
        }
        object.cleanup_reference_held = false;
        object.cleanup_error = None;
        object.references -= 1;
        self.pending_file_cleanup_count = self
            .pending_file_cleanup_count
            .checked_sub(1)
            .expect("retained cleanup missing from pending count");
        if object.references == 0 {
            self.handles[index] = None;
        }
        self.reap_unlinked_nodes();
        Ok(true)
    }
}

#[cfg(test)]
#[path = "file_io_serialization/tests.rs"]
mod tests;
