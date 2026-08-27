//! Filesystem-owned directory change notification policy.
//!
//! The I/O Manager owns the pending IRP and its user-visible completion surfaces. An FSD owns the
//! watched namespace, change filters, relative names, buffering, and cleanup of requests attached
//! to a `FILE_OBJECT`. This module models that latter boundary without kernel or transport state.

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{
    STATUS_CANCELLED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_NOTIFY_CLEANUP, STATUS_NOTIFY_ENUM_DIR, STATUS_SUCCESS,
};

pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
pub const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
pub const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
pub const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
pub const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x0000_0020;
pub const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x0000_0040;
pub const FILE_NOTIFY_CHANGE_EA: u32 = 0x0000_0080;
pub const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;
pub const FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x0000_0200;
pub const FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x0000_0400;
pub const FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x0000_0800;
pub const FILE_NOTIFY_VALID_MASK: u32 = 0x0000_0fff;

pub const FILE_ACTION_ADDED: u32 = 0x0000_0001;
pub const FILE_ACTION_REMOVED: u32 = 0x0000_0002;
pub const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;
pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x0000_0004;
pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x0000_0005;

const FILE_NOTIFY_INFORMATION_NAME_OFFSET: usize = 12;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectoryNotifyId(u64);

impl DirectoryNotifyId {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryChange<'a> {
    pub full_path: &'a str,
    pub filter: u32,
    pub action: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectoryNotifyRequest<C> {
    id: DirectoryNotifyId,
    file_object: u64,
    directory: String,
    completion_filter: u32,
    watch_tree: bool,
    buffer_length: u32,
    context: C,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryNotifyCompletion<C> {
    pub id: DirectoryNotifyId,
    pub context: C,
    pub status: u32,
    pub information: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DirectoryNotifyTable<C> {
    next_id: u64,
    pending: VecDeque<DirectoryNotifyRequest<C>>,
    completions: VecDeque<DirectoryNotifyCompletion<C>>,
}

impl<C> Default for DirectoryNotifyTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> DirectoryNotifyTable<C> {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            pending: VecDeque::new(),
            completions: VecDeque::new(),
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn register(
        &mut self,
        file_object: u64,
        directory: &str,
        completion_filter: u32,
        watch_tree: bool,
        buffer_length: u32,
        context: C,
    ) -> Result<DirectoryNotifyId, u32> {
        if directory.is_empty()
            || !directory.starts_with('\\')
            || completion_filter == 0
            || completion_filter & !FILE_NOTIFY_VALID_MASK != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.pending
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut normalized = directory.to_string();
        while normalized.len() > 1 && normalized.ends_with('\\') {
            normalized.pop();
        }
        let id = DirectoryNotifyId(self.next_id.max(1));
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.pending.push_back(DirectoryNotifyRequest {
            id,
            file_object,
            directory: normalized,
            completion_filter,
            watch_tree,
            buffer_length,
            context,
        });
        Ok(id)
    }

    pub fn cancel(&mut self, id: DirectoryNotifyId) -> bool {
        self.complete_matching(|request| request.id == id, STATUS_CANCELLED)
    }

    pub fn cleanup_file_object(&mut self, file_object: u64) -> usize {
        let mut completed = 0;
        while self.complete_matching(
            |request| request.file_object == file_object,
            STATUS_NOTIFY_CLEANUP,
        ) {
            completed += 1;
        }
        completed
    }

    pub fn report_change(&mut self, change: DirectoryChange<'_>) -> usize {
        self.report_changes(core::slice::from_ref(&change))
    }

    /// Report one atomic filesystem mutation. A rename supplies the old and new records together
    /// so a waiting request cannot observe half of the namespace transition.
    pub fn report_changes(&mut self, changes: &[DirectoryChange<'_>]) -> usize {
        if changes.is_empty() {
            return 0;
        }
        let mut completed = 0;
        let mut index = 0;
        while index < self.pending.len() {
            let matches = {
                let request = &self.pending[index];
                changes.iter().any(|change| {
                    change.filter & request.completion_filter != 0
                        && relative_name(&request.directory, change.full_path, request.watch_tree)
                            .is_some()
                })
            };
            if !matches {
                index += 1;
                continue;
            }
            let request = self.pending.remove(index).unwrap();
            let bytes = encode_matching_changes(&request, changes);
            let (status, bytes) = match bytes {
                Ok(bytes) if bytes.len() <= request.buffer_length as usize => {
                    (STATUS_SUCCESS, bytes)
                }
                Ok(_) | Err(()) => (STATUS_NOTIFY_ENUM_DIR, Vec::new()),
            };
            let information = bytes.len() as u32;
            self.completions.push_back(DirectoryNotifyCompletion {
                id: request.id,
                context: request.context,
                status,
                information,
                bytes,
            });
            completed += 1;
        }
        completed
    }

    pub fn pop_completion(&mut self) -> Option<DirectoryNotifyCompletion<C>> {
        self.completions.pop_front()
    }

    fn complete_matching(
        &mut self,
        predicate: impl Fn(&DirectoryNotifyRequest<C>) -> bool,
        status: u32,
    ) -> bool {
        let Some(index) = self.pending.iter().position(predicate) else {
            return false;
        };
        let request = self.pending.remove(index).unwrap();
        self.completions.push_back(DirectoryNotifyCompletion {
            id: request.id,
            context: request.context,
            status,
            information: 0,
            bytes: Vec::new(),
        });
        true
    }
}

fn relative_name<'a>(directory: &str, full_path: &'a str, watch_tree: bool) -> Option<&'a str> {
    let suffix = if directory == "\\" {
        full_path.strip_prefix('\\')?
    } else {
        let prefix_len = directory.len();
        if full_path.len() <= prefix_len
            || !full_path[..prefix_len].eq_ignore_ascii_case(directory)
            || full_path.as_bytes().get(prefix_len) != Some(&b'\\')
        {
            return None;
        }
        &full_path[prefix_len + 1..]
    };
    if suffix.is_empty() || (!watch_tree && suffix.contains('\\')) {
        None
    } else {
        Some(suffix)
    }
}

fn encode_matching_changes<C>(
    request: &DirectoryNotifyRequest<C>,
    changes: &[DirectoryChange<'_>],
) -> Result<Vec<u8>, ()> {
    let mut encoded = Vec::new();
    for change in changes {
        if change.filter & request.completion_filter == 0 {
            continue;
        }
        let Some(relative) =
            relative_name(&request.directory, change.full_path, request.watch_tree)
        else {
            continue;
        };
        let utf16_len = relative.encode_utf16().count().checked_mul(2).ok_or(())?;
        let record_len = FILE_NOTIFY_INFORMATION_NAME_OFFSET
            .checked_add(utf16_len)
            .ok_or(())?;
        let aligned_len = record_len.checked_add(3).ok_or(())? & !3;
        encoded.try_reserve(aligned_len).map_err(|_| ())?;
        let record_offset = encoded.len();
        encoded.resize(record_offset + aligned_len, 0);
        encoded[record_offset + 4..record_offset + 8].copy_from_slice(&change.action.to_le_bytes());
        encoded[record_offset + 8..record_offset + 12]
            .copy_from_slice(&(utf16_len as u32).to_le_bytes());
        for (index, unit) in relative.encode_utf16().enumerate() {
            let offset = record_offset + FILE_NOTIFY_INFORMATION_NAME_OFFSET + index * 2;
            encoded[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        if record_offset != 0 {
            let previous = previous_record_offset(&encoded[..record_offset]);
            let next = (record_offset - previous) as u32;
            encoded[previous..previous + 4].copy_from_slice(&next.to_le_bytes());
        }
    }
    if encoded.is_empty() {
        return Err(());
    }
    while encoded.last() == Some(&0) && encoded.len() > FILE_NOTIFY_INFORMATION_NAME_OFFSET {
        let record = previous_record_offset(&encoded);
        let name_len =
            u32::from_le_bytes(encoded[record + 8..record + 12].try_into().unwrap()) as usize;
        let actual_len = record + FILE_NOTIFY_INFORMATION_NAME_OFFSET + name_len;
        if encoded.len() <= actual_len {
            break;
        }
        encoded.pop();
    }
    Ok(encoded)
}

fn previous_record_offset(encoded: &[u8]) -> usize {
    let mut offset = 0;
    loop {
        let next = u32::from_le_bytes(encoded[offset..offset + 4].try_into().unwrap()) as usize;
        if next == 0 {
            return offset;
        }
        offset += next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn names(bytes: &[u8]) -> Vec<(u32, String)> {
        let mut result = Vec::new();
        let mut offset = 0;
        loop {
            let next = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            let action = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            let name_len =
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            let name = String::from_utf16(
                &bytes[offset + 12..offset + 12 + name_len]
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            result.push((action, name));
            if next == 0 {
                return result;
            }
            offset += next;
        }
    }

    #[test]
    fn direct_and_tree_watches_filter_relative_names() {
        let mut table = DirectoryNotifyTable::new();
        table
            .register(
                1,
                r"\Profiles",
                FILE_NOTIFY_CHANGE_FILE_NAME,
                false,
                256,
                10,
            )
            .unwrap();
        table
            .register(2, r"\Profiles", FILE_NOTIFY_CHANGE_FILE_NAME, true, 256, 20)
            .unwrap();
        assert_eq!(
            table.report_change(DirectoryChange {
                full_path: r"\Profiles\Alice\ntuser.dat",
                filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                action: FILE_ACTION_ADDED,
            }),
            1
        );
        let completion = table.pop_completion().unwrap();
        assert_eq!(completion.context, 20);
        assert_eq!(
            names(&completion.bytes),
            vec![(FILE_ACTION_ADDED, "Alice\\ntuser.dat".into())]
        );
        assert_eq!(table.pending_len(), 1);
    }

    #[test]
    fn rename_pair_is_delivered_atomically() {
        let mut table = DirectoryNotifyTable::new();
        table
            .register(7, r"\Temp", FILE_NOTIFY_CHANGE_FILE_NAME, false, 256, 33)
            .unwrap();
        assert_eq!(
            table.report_changes(&[
                DirectoryChange {
                    full_path: r"\Temp\old.txt",
                    filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                    action: FILE_ACTION_RENAMED_OLD_NAME,
                },
                DirectoryChange {
                    full_path: r"\Temp\new.txt",
                    filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                    action: FILE_ACTION_RENAMED_NEW_NAME,
                },
            ]),
            1
        );
        let completion = table.pop_completion().unwrap();
        assert_eq!(completion.status, STATUS_SUCCESS);
        assert_eq!(
            names(&completion.bytes),
            vec![
                (FILE_ACTION_RENAMED_OLD_NAME, "old.txt".into()),
                (FILE_ACTION_RENAMED_NEW_NAME, "new.txt".into()),
            ]
        );
    }

    #[test]
    fn overflow_cleanup_and_cancel_are_terminal_one_shot_results() {
        let mut table = DirectoryNotifyTable::new();
        let overflow = table
            .register(1, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 12, 1)
            .unwrap();
        assert_eq!(
            table.report_change(DirectoryChange {
                full_path: r"\long-name",
                filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                action: FILE_ACTION_ADDED,
            }),
            1
        );
        let completion = table.pop_completion().unwrap();
        assert_eq!(completion.id, overflow);
        assert_eq!(completion.status, STATUS_NOTIFY_ENUM_DIR);
        assert_eq!(completion.information, 0);

        let cancelled = table
            .register(2, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 64, 2)
            .unwrap();
        assert!(table.cancel(cancelled));
        assert_eq!(table.pop_completion().unwrap().status, STATUS_CANCELLED);

        table
            .register(3, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 64, 3)
            .unwrap();
        table
            .register(3, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 64, 4)
            .unwrap();
        assert_eq!(table.cleanup_file_object(3), 2);
        assert_eq!(
            table.pop_completion().unwrap().status,
            STATUS_NOTIFY_CLEANUP
        );
        assert_eq!(
            table.pop_completion().unwrap().status,
            STATUS_NOTIFY_CLEANUP
        );
    }

    #[test]
    fn registration_rejects_invalid_filters_and_paths() {
        let mut table = DirectoryNotifyTable::<u64>::new();
        assert_eq!(
            table.register(1, r"\Temp", 0, false, 64, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            table.register(1, "Temp", FILE_NOTIFY_CHANGE_FILE_NAME, false, 64, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            table.register(1, r"\Temp", 0x1000, false, 64, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
