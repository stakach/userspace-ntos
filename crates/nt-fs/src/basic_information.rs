//! `FileBasicInformation` on an open writable-volume File: timestamps and attributes.

use super::*;

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
    pub(super) fn set_basic_information(&mut self, handle: u64, data: &[u8]) -> u32 {
        let Some(node_id) = self.obj(handle).map(|object| object.node_id) else {
            return STATUS_INVALID_HANDLE;
        };
        let change = match BasicInformationChange::parse(data, self.volume.is_dir(node_id)) {
            Ok(change) => change,
            Err(status) => return status,
        };
        if change.is_empty() {
            return STATUS_SUCCESS;
        }
        let now = self.volume.current_time_100ns;
        let Some(node) = self.volume.node_mut(node_id) else {
            return STATUS_INVALID_HANDLE;
        };
        node.creation_time = change.creation_time.unwrap_or(node.creation_time);
        node.last_access_time = change.last_access_time.unwrap_or(node.last_access_time);
        node.last_write_time = change.last_write_time.unwrap_or(node.last_write_time);
        node.attributes = change.attributes.unwrap_or(node.attributes);
        node.change_time = change.change_time.unwrap_or(now);
        self.report_handle_change(
            handle,
            crate::FILE_NOTIFY_CHANGE_ATTRIBUTES
                | crate::FILE_NOTIFY_CHANGE_CREATION
                | crate::FILE_NOTIFY_CHANGE_LAST_ACCESS
                | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
        );
        STATUS_SUCCESS
    }
}

#[cfg(test)]
#[path = "basic_information/tests.rs"]
mod tests;
