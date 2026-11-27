//! `FileBasicInformation` on an open writable-volume File: timestamps and attributes.

use super::*;

/// A single validated basic-information update with its resolved clock value.
/// The FileSystem remains unchanged until this move-only value is applied.
pub struct PreparedBasicInformation {
    handle: u64,
    node_id: u64,
    entry_id: u64,
    before: FileMetadata,
    after: FileMetadata,
    opened_path: Option<String>,
    notify: bool,
}

impl PreparedBasicInformation {
    pub fn resolved_metadata(&self) -> FileMetadata { self.after }

    pub fn changes_volume(&self) -> bool { self.before != self.after }

    /// Snapshot-only Basic work may wait behind an unrelated SET or rename. Recompute from the
    /// captured input at the last in-memory entry point, but only for the same live File node.
    /// A future WAL publisher must use its separately validated physical identity instead.
    pub fn rebase_snapshot(&self, fs: &FileSystem, input: &[u8])
        -> Result<PreparedBasicInformation, u32> {
        let object = fs.obj(self.handle).ok_or(STATUS_DATA_ERROR)?;
        if object.node_id != self.node_id { return Err(STATUS_DATA_ERROR); }
        fs.prepare_basic_information(self.handle, input)
    }

    /// The exact live entry name captured for a future durable producer. The synchronous Zw
    /// surface uses the same prepared state without allocating or retaining a path.
    pub fn opened_path(&self) -> Option<&str> { self.opened_path.as_deref() }
}

/// A validated `FILE_BASIC_INFORMATION` request. `None` leaves the stored value unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BasicInformationChange {
    creation_time: Option<u64>,
    last_access_time: Option<u64>,
    last_write_time: Option<u64>,
    change_time: Option<u64>,
    /// The complete stored attribute set, without `FILE_ATTRIBUTE_NORMAL`.
    attributes: Option<u32>,
}

impl BasicInformationChange {
    /// Zero keeps a time; so does -1, which FASTFAT reads as "and stop updating it implicitly".
    /// Zero attributes keep the stored set; `FILE_ATTRIBUTE_NORMAL` alone clears it.
    pub(crate) fn parse(data: &[u8], is_directory: bool) -> Result<Self, u32> {
        if data.len() < 40 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let time = |offset: usize| {
            let value = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            (value != 0 && value != u64::MAX).then_some(value)
        };
        let requested = u32::from_le_bytes(data[32..36].try_into().unwrap());
        // A file is never a directory and a directory is never temporary (vfatfs finfo.c).
        let contradicts_kind = if is_directory {
            FILE_ATTRIBUTE_TEMPORARY
        } else {
            FILE_ATTRIBUTE_DIRECTORY
        };
        if requested & contradicts_kind != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let attributes = (requested != 0).then(|| {
            let stored = requested & FILE_ATTRIBUTE_SETTABLE & !FILE_ATTRIBUTE_NORMAL;
            if is_directory {
                stored | FILE_ATTRIBUTE_DIRECTORY
            } else {
                stored
            }
        });
        Ok(Self {
            creation_time: time(0),
            last_access_time: time(8),
            last_write_time: time(16),
            change_time: time(24),
            attributes,
        })
    }

    pub(crate) fn is_empty(self) -> bool {
        self == Self {
            creation_time: None,
            last_access_time: None,
            last_write_time: None,
            change_time: None,
            attributes: None,
        }
    }
}

impl FileSystem {
    /// Validate a live named File and freeze the resolved metadata without mutating it. The
    /// captured entry name allows a later publisher to refuse a rename or replacement while its
    /// physical work is outstanding. Unlinked Files retain ordinary synchronous Zw semantics.
    pub fn prepare_basic_information(
        &self, handle: u64, data: &[u8],
    ) -> Result<PreparedBasicInformation, u32> {
        self.prepare_basic_information_inner(handle, data, true)
    }

    fn prepare_basic_information_inner(
        &self, handle: u64, data: &[u8], capture_path: bool,
    ) -> Result<PreparedBasicInformation, u32> {
        let object = self.obj(handle).ok_or(STATUS_INVALID_HANDLE)?;
        let node = self.volume.node(object.node_id).ok_or(STATUS_INVALID_HANDLE)?;
        let change = BasicInformationChange::parse(data, node.is_dir)?;
        let before = self.volume.metadata(object.node_id, object.delete_pending)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let opened_path = if capture_path {
            if object.entry_id != 0 && self.checked_object_entry(object)?.is_none() {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            }
            Some(self.query_opened_name(handle)?)
        } else {
            None
        };
        let mut after = before;
        if !change.is_empty() {
            after.creation_time = change.creation_time.unwrap_or(before.creation_time);
            after.last_access_time = change.last_access_time.unwrap_or(before.last_access_time);
            after.last_write_time = change.last_write_time.unwrap_or(before.last_write_time);
            after.attributes = change.attributes.unwrap_or(before.attributes);
            after.change_time = change.change_time.unwrap_or(self.volume.current_time_100ns);
        }
        Ok(PreparedBasicInformation {
            handle, node_id: object.node_id, entry_id: object.entry_id,
            before, after, opened_path, notify: !change.is_empty(),
        })
    }

    /// Apply only to the same live File and namespace entry that preparation observed. A stale
    /// plan has no effect; the caller holding a durable record must retain that uncertainty.
    pub fn apply_prepared_basic_information(
        &mut self, prepared: PreparedBasicInformation,
    ) -> Result<FileMetadata, u32> {
        let object = self.obj(prepared.handle).ok_or(STATUS_DATA_ERROR)?;
        if object.node_id != prepared.node_id || object.entry_id != prepared.entry_id
            || self.volume.metadata(object.node_id, object.delete_pending) != Some(prepared.before)
        {
            return Err(STATUS_DATA_ERROR);
        }
        if let Some(path) = prepared.opened_path.as_deref() {
            if (object.entry_id != 0 && self.checked_object_entry(object)?.is_none())
                || self.query_opened_name(prepared.handle).as_deref() != Ok(path)
            {
                return Err(STATUS_DATA_ERROR);
            }
        }
        let node = self.volume.node_mut(prepared.node_id).ok_or(STATUS_DATA_ERROR)?;
        node.creation_time = prepared.after.creation_time;
        node.last_access_time = prepared.after.last_access_time;
        node.last_write_time = prepared.after.last_write_time;
        node.attributes = prepared.after.attributes;
        node.change_time = prepared.after.change_time;
        if prepared.notify {
            self.report_handle_change(
                prepared.handle,
                crate::FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | crate::FILE_NOTIFY_CHANGE_CREATION
                    | crate::FILE_NOTIFY_CHANGE_LAST_ACCESS
                    | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
            );
        }
        Ok(prepared.after)
    }

    pub(super) fn set_basic_information(&mut self, handle: u64, data: &[u8]) -> u32 {
        let prepared = match self.prepare_basic_information_inner(handle, data, false) {
            Ok(prepared) => prepared,
            Err(status) => return status,
        };
        match self.apply_prepared_basic_information(prepared) {
            Ok(_) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }
}

#[cfg(test)]
#[path = "basic_information/tests.rs"]
mod tests;
