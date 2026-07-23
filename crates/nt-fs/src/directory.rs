//! Native directory-query state, wildcard matching, and information-record encoding.

use crate::{
    STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_NO_MORE_FILES,
    STATUS_NO_SUCH_FILE, STATUS_QUOTA_EXCEEDED, STATUS_SUCCESS,
};

pub const MAX_DIRECTORY_NAME: usize = 260;
pub const MAX_SHORT_NAME: usize = 12;

pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_NAMES_INFORMATION: u32 = 12;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u32 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u32 = 38;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub attributes: u32,
    pub file_id: u64,
    pub name_len: u16,
    pub name: [u16; MAX_DIRECTORY_NAME],
    pub short_name_len: u8,
    pub short_name: [u16; MAX_SHORT_NAME],
}

impl Default for DirectoryEntry {
    fn default() -> Self {
        Self {
            file_index: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            end_of_file: 0,
            allocation_size: 0,
            attributes: 0,
            file_id: 0,
            name_len: 0,
            name: [0; MAX_DIRECTORY_NAME],
            short_name_len: 0,
            short_name: [0; MAX_SHORT_NAME],
        }
    }
}

impl DirectoryEntry {
    pub fn set_name(&mut self, name: &[u16]) -> bool {
        if name.len() > self.name.len() {
            return false;
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len() as u16;
        true
    }

    pub fn set_short_name(&mut self, name: &[u16]) -> bool {
        if name.len() > self.short_name.len() {
            return false;
        }
        self.short_name[..name.len()].copy_from_slice(name);
        self.short_name_len = name.len() as u8;
        true
    }

    pub fn name(&self) -> &[u16] {
        &self.name[..self.name_len as usize]
    }

    pub fn short_name(&self) -> &[u16] {
        &self.short_name[..self.short_name_len as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryQueryState {
    initialized: bool,
    cursor: u32,
    pattern_len: u16,
    pattern: [u16; MAX_DIRECTORY_NAME],
}

impl Default for DirectoryQueryState {
    fn default() -> Self {
        Self {
            initialized: false,
            cursor: 0,
            pattern_len: 0,
            pattern: [0; MAX_DIRECTORY_NAME],
        }
    }
}

impl DirectoryQueryState {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            cursor: 0,
            pattern_len: 0,
            pattern: [0; MAX_DIRECTORY_NAME],
        }
    }

    pub fn cursor(&self) -> u32 {
        self.cursor
    }

    pub fn pattern(&self) -> &[u16] {
        &self.pattern[..self.pattern_len as usize]
    }

    fn capture_pattern(&mut self, pattern: Option<&[u16]>) -> bool {
        let pattern = pattern.filter(|value| !value.is_empty()).unwrap_or(&[b'*' as u16]);
        if pattern.len() > self.pattern.len() {
            return false;
        }
        self.pattern[..pattern.len()].copy_from_slice(pattern);
        self.pattern_len = pattern.len() as u16;
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryOpen {
    pub first_cluster: u32,
    pub query: DirectoryQueryState,
}

#[derive(Clone, Copy)]
struct DirectoryOpenSlot {
    occupied: bool,
    references: u16,
    open: DirectoryOpen,
}

impl DirectoryOpenSlot {
    const fn empty() -> Self {
        Self {
            occupied: false,
            references: 0,
            open: DirectoryOpen {
                first_cluster: 0,
                query: DirectoryQueryState::new(),
            },
        }
    }
}

pub struct DirectoryOpenTable<const SLOTS: usize> {
    slots: [DirectoryOpenSlot; SLOTS],
}

impl<const SLOTS: usize> DirectoryOpenTable<SLOTS> {
    pub const fn new() -> Self {
        assert!(SLOTS > 0);
        Self {
            slots: [DirectoryOpenSlot::empty(); SLOTS],
        }
    }

    pub fn create(&mut self, first_cluster: u32) -> Result<u32, u32> {
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.occupied)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *slot = DirectoryOpenSlot {
            occupied: true,
            references: 1,
            open: DirectoryOpen {
                first_cluster,
                query: DirectoryQueryState::new(),
            },
        };
        Ok(index as u32)
    }

    pub fn get(&self, id: u32) -> Result<&DirectoryOpen, u32> {
        self.slots
            .get(id as usize)
            .filter(|slot| slot.occupied)
            .map(|slot| &slot.open)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn get_mut(&mut self, id: u32) -> Result<&mut DirectoryOpen, u32> {
        self.slots
            .get_mut(id as usize)
            .filter(|slot| slot.occupied)
            .map(|slot| &mut slot.open)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn retain(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(id as usize)
            .filter(|slot| slot.occupied)
            .ok_or(STATUS_INVALID_HANDLE)?;
        slot.references = slot
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        Ok(())
    }

    pub fn release(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(id as usize)
            .filter(|slot| slot.occupied)
            .ok_or(STATUS_INVALID_HANDLE)?;
        slot.references -= 1;
        if slot.references == 0 {
            *slot = DirectoryOpenSlot::empty();
        }
        Ok(())
    }
}

impl<const SLOTS: usize> Default for DirectoryOpenTable<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryQueryResult {
    pub status: u32,
    pub information: usize,
}

#[derive(Clone, Copy)]
struct RecordLayout {
    name_offset: usize,
    minimum_size: usize,
    short_name: bool,
    file_id_offset: Option<usize>,
    ea_size_offset: Option<usize>,
}

fn record_layout(class: u32) -> Option<RecordLayout> {
    match class {
        FILE_DIRECTORY_INFORMATION => Some(RecordLayout {
            name_offset: 64,
            minimum_size: 72,
            short_name: false,
            file_id_offset: None,
            ea_size_offset: None,
        }),
        FILE_FULL_DIRECTORY_INFORMATION => Some(RecordLayout {
            name_offset: 68,
            minimum_size: 72,
            short_name: false,
            file_id_offset: None,
            ea_size_offset: Some(64),
        }),
        FILE_BOTH_DIRECTORY_INFORMATION => Some(RecordLayout {
            name_offset: 94,
            minimum_size: 96,
            short_name: true,
            file_id_offset: None,
            ea_size_offset: Some(64),
        }),
        FILE_NAMES_INFORMATION => Some(RecordLayout {
            name_offset: 12,
            minimum_size: 16,
            short_name: false,
            file_id_offset: None,
            ea_size_offset: None,
        }),
        FILE_ID_BOTH_DIRECTORY_INFORMATION => Some(RecordLayout {
            name_offset: 104,
            minimum_size: 112,
            short_name: true,
            file_id_offset: Some(96),
            ea_size_offset: Some(64),
        }),
        FILE_ID_FULL_DIRECTORY_INFORMATION => Some(RecordLayout {
            name_offset: 80,
            minimum_size: 88,
            short_name: false,
            file_id_offset: Some(72),
            ea_size_offset: Some(64),
        }),
        _ => None,
    }
}

fn fold(value: u16) -> u16 {
    if value <= 0x7f {
        (value as u8).to_ascii_uppercase() as u16
    } else {
        value
    }
}

fn wildcard_match(pattern: &[u16], name: &[u16]) -> bool {
    fn matches(pattern: &[u16], name: &[u16], pi: usize, ni: usize) -> bool {
        if pi == pattern.len() {
            return ni == name.len();
        }
        match pattern[pi] {
            value if value == b'*' as u16 || value == b'<' as u16 => {
                let mut next = ni;
                loop {
                    if matches(pattern, name, pi + 1, next) {
                        return true;
                    }
                    if next == name.len() {
                        return false;
                    }
                    next += 1;
                }
            }
            value if value == b'?' as u16 => {
                ni < name.len() && matches(pattern, name, pi + 1, ni + 1)
            }
            value if value == b'>' as u16 => {
                matches(pattern, name, pi + 1, ni)
                    || ni < name.len()
                        && name[ni] != b'.' as u16
                        && matches(pattern, name, pi + 1, ni + 1)
            }
            value if value == b'"' as u16 => {
                matches(pattern, name, pi + 1, ni)
                    || ni < name.len()
                        && name[ni] == b'.' as u16
                        && matches(pattern, name, pi + 1, ni + 1)
            }
            value => {
                ni < name.len()
                    && fold(value) == fold(name[ni])
                    && matches(pattern, name, pi + 1, ni + 1)
            }
        }
    }
    matches(pattern, name, 0, 0)
}

fn entry_matches(pattern: &[u16], entry: &DirectoryEntry) -> bool {
    wildcard_match(pattern, entry.name())
        || !entry.short_name().is_empty() && wildcard_match(pattern, entry.short_name())
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn encode_fixed(output: &mut [u8], layout: RecordLayout, entry: &DirectoryEntry) {
    output[..layout.minimum_size].fill(0);
    put_u32(output, 4, entry.file_index);
    if layout.name_offset >= 64 {
        put_u64(output, 8, entry.creation_time);
        put_u64(output, 16, entry.last_access_time);
        put_u64(output, 24, entry.last_write_time);
        put_u64(output, 32, entry.change_time);
        put_u64(output, 40, entry.end_of_file);
        put_u64(output, 48, entry.allocation_size);
        put_u32(output, 56, if entry.attributes == 0 { 0x80 } else { entry.attributes });
        put_u32(output, 60, entry.name_len as u32 * 2);
    } else {
        put_u32(output, 8, entry.name_len as u32 * 2);
    }
    if let Some(offset) = layout.ea_size_offset {
        put_u32(output, offset, 0);
    }
    if layout.short_name {
        output[68] = entry.short_name_len.saturating_mul(2);
        for (index, value) in entry.short_name().iter().enumerate() {
            let offset = 70 + index * 2;
            output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    if let Some(offset) = layout.file_id_offset {
        put_u64(output, offset, entry.file_id);
    }
}

fn copy_name(output: &mut [u8], offset: usize, name: &[u16]) -> usize {
    let count = name.len().min(output.len().saturating_sub(offset) / 2);
    for (index, value) in name[..count].iter().enumerate() {
        let at = offset + index * 2;
        output[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    count * 2
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

pub fn query_directory(
    state: &mut DirectoryQueryState,
    entries: &[DirectoryEntry],
    information_class: u32,
    return_single_entry: bool,
    pattern: Option<&[u16]>,
    restart_scan: bool,
    output: &mut [u8],
) -> DirectoryQueryResult {
    let Some(layout) = record_layout(information_class) else {
        return DirectoryQueryResult {
            status: STATUS_INVALID_INFO_CLASS,
            information: 0,
        };
    };
    if output.len() < layout.minimum_size {
        return DirectoryQueryResult {
            status: STATUS_INFO_LENGTH_MISMATCH,
            information: 0,
        };
    }

    let first_scan = !state.initialized || restart_scan;
    if !state.initialized {
        if !state.capture_pattern(pattern) {
            return DirectoryQueryResult {
                status: STATUS_NO_SUCH_FILE,
                information: 0,
            };
        }
        state.initialized = true;
        state.cursor = 0;
    } else if restart_scan {
        state.cursor = 0;
        if pattern.is_some_and(|value| !value.is_empty()) && !state.capture_pattern(pattern) {
            return DirectoryQueryResult {
                status: STATUS_NO_SUCH_FILE,
                information: 0,
            };
        }
    }

    let mut cursor = state.cursor as usize;
    let mut written = 0usize;
    let mut information = 0usize;
    let mut previous_record = None;
    while cursor < entries.len() {
        let entry = &entries[cursor];
        if !entry_matches(state.pattern(), entry) {
            cursor += 1;
            state.cursor = cursor as u32;
            continue;
        }
        let name_bytes = entry.name_len as usize * 2;
        let record_bytes = layout.name_offset + name_bytes;
        let stride = align8(record_bytes);
        if record_bytes > output.len() - written {
            if written == 0 {
                encode_fixed(&mut output[..layout.minimum_size], layout, entry);
                let copied = copy_name(output, layout.name_offset, entry.name());
                return DirectoryQueryResult {
                    status: STATUS_BUFFER_OVERFLOW,
                    information: layout.name_offset + copied,
                };
            }
            break;
        }
        if let Some(previous) = previous_record {
            put_u32(output, previous, (written - previous) as u32);
        }
        encode_fixed(&mut output[written..written + layout.minimum_size], layout, entry);
        copy_name(
            &mut output[written..written + record_bytes],
            layout.name_offset,
            entry.name(),
        );
        previous_record = Some(written);
        information = written + record_bytes;
        written = (written + stride).min(output.len());
        cursor += 1;
        state.cursor = cursor as u32;
        if return_single_entry {
            break;
        }
    }

    if written == 0 {
        DirectoryQueryResult {
            status: if first_scan { STATUS_NO_SUCH_FILE } else { STATUS_NO_MORE_FILES },
            information: 0,
        }
    } else {
        DirectoryQueryResult {
            status: STATUS_SUCCESS,
            information,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    fn entry(name: &str, short: &str, index: u32) -> DirectoryEntry {
        let mut entry = DirectoryEntry { file_index: index, file_id: index as u64 + 100, ..Default::default() };
        assert!(entry.set_name(&name.encode_utf16().collect::<std::vec::Vec<_>>()));
        assert!(entry.set_short_name(&short.encode_utf16().collect::<std::vec::Vec<_>>()));
        entry
    }

    #[test]
    fn wildcard_matches_long_or_short_names_case_insensitively() {
        let item = entry("amd64_Microsoft.Windows.Common-Controls_6.0.1.manifest", "COMMON~1.MAN", 1);
        assert!(wildcard_match(&"AMD64_*_6.0.*.manifest".encode_utf16().collect::<std::vec::Vec<_>>(), item.name()));
        assert!(entry_matches(&"common~?.man".encode_utf16().collect::<std::vec::Vec<_>>(), &item));
        assert!(!entry_matches(&"x86_*".encode_utf16().collect::<std::vec::Vec<_>>(), &item));
    }

    #[test]
    fn class_three_batches_and_continues() {
        let entries = [entry("one.manifest", "ONE.MAN", 1), entry("two.manifest", "TWO.MAN", 2)];
        let pattern = "*.manifest".encode_utf16().collect::<std::vec::Vec<_>>();
        let mut state = DirectoryQueryState::new();
        let mut first = [0u8; 120];
        let result = query_directory(&mut state, &entries, FILE_BOTH_DIRECTORY_INFORMATION, false, Some(&pattern), true, &mut first);
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(state.cursor(), 1);
        assert_eq!(u32::from_le_bytes(first[0..4].try_into().unwrap()), 0);
        let mut second = [0u8; 120];
        let result = query_directory(&mut state, &entries, FILE_BOTH_DIRECTORY_INFORMATION, false, None, false, &mut second);
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(state.cursor(), 2);
        assert_eq!(u32::from_le_bytes(second[60..64].try_into().unwrap()), 24);
        assert_eq!(query_directory(&mut state, &entries, FILE_BOTH_DIRECTORY_INFORMATION, false, None, false, &mut second).status, STATUS_NO_MORE_FILES);
    }

    #[test]
    fn first_truncated_record_does_not_advance() {
        let entries = [entry("a-very-long-name.manifest", "LONG.MAN", 1)];
        let mut state = DirectoryQueryState::new();
        let mut output = [0u8; 100];
        let result = query_directory(&mut state, &entries, FILE_BOTH_DIRECTORY_INFORMATION, false, None, true, &mut output);
        assert_eq!(result.status, STATUS_BUFFER_OVERFLOW);
        assert_eq!(state.cursor(), 0);
        assert_eq!(u32::from_le_bytes(output[60..64].try_into().unwrap()), 50);
    }

    #[test]
    fn record_layout_offsets_are_native() {
        let item = entry("x", "X", 7);
        for (class, name_offset, minimum) in [
            (FILE_DIRECTORY_INFORMATION, 64, 72),
            (FILE_FULL_DIRECTORY_INFORMATION, 68, 72),
            (FILE_BOTH_DIRECTORY_INFORMATION, 94, 96),
            (FILE_NAMES_INFORMATION, 12, 16),
            (FILE_ID_BOTH_DIRECTORY_INFORMATION, 104, 112),
            (FILE_ID_FULL_DIRECTORY_INFORMATION, 80, 88),
        ] {
            let mut state = DirectoryQueryState::new();
            let mut output = [0u8; 128];
            let result = query_directory(&mut state, &[item], class, true, None, true, &mut output);
            assert_eq!(result, DirectoryQueryResult { status: STATUS_SUCCESS, information: name_offset + 2 });
            assert!(minimum <= output.len());
            assert_eq!(u16::from_le_bytes(output[name_offset..name_offset + 2].try_into().unwrap()), b'x' as u16);
        }
    }

    #[test]
    fn directory_open_references_share_query_state() {
        let mut table = DirectoryOpenTable::<2>::new();
        let shared = table.create(41).unwrap();
        let independent = table.create(41).unwrap();
        table.retain(shared).unwrap();
        table.get_mut(shared).unwrap().query.cursor = 7;
        assert_eq!(table.get(shared).unwrap().query.cursor(), 7);
        assert_eq!(table.get(independent).unwrap().query.cursor(), 0);
        table.release(shared).unwrap();
        assert_eq!(table.get(shared).unwrap().first_cluster, 41);
        table.release(shared).unwrap();
        assert_eq!(table.get(shared), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.create(99).unwrap(), shared);
    }
}
