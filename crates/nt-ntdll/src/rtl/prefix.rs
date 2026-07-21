//! `Pfx*` byte-prefix table helpers.
//!
//! ReactOS leaves the ANSI `Pfx*` routines unimplemented. The public structures are simple enough to
//! provide useful behavior here: a caller-owned table of caller-owned entries, linked through
//! `NextPrefixTree`, with longest-prefix lookup over `STRING` byte buffers.

use core::ptr;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RtlString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct PrefixTableEntry {
    pub node_type_code: i16,
    pub name_length: i16,
    pub next_prefix_tree: *mut PrefixTableEntry,
    pub links: [u64; 3],
    pub prefix: *mut RtlString,
}

#[repr(C)]
#[derive(Debug)]
pub struct PrefixTable {
    pub node_type_code: i16,
    pub name_length: i16,
    pub next_prefix_tree: *mut PrefixTableEntry,
}

/// `PfxInitialize(PPREFIX_TABLE)`.
///
/// # Safety
/// `table` is writable when non-null.
pub unsafe fn initialize(table: *mut PrefixTable) {
    if table.is_null() {
        return;
    }
    unsafe {
        (*table).node_type_code = 0;
        (*table).name_length = 0;
        (*table).next_prefix_tree = ptr::null_mut();
    }
}

/// `PfxInsertPrefix(PPREFIX_TABLE, PSTRING, PPREFIX_TABLE_ENTRY) -> BOOLEAN`.
///
/// # Safety
/// `table`, `prefix`, and `entry` are valid caller-owned objects. The prefix buffer stays live while
/// the entry is in the table.
pub unsafe fn insert(
    table: *mut PrefixTable,
    prefix: *mut RtlString,
    entry: *mut PrefixTableEntry,
) -> bool {
    if table.is_null() || prefix.is_null() || entry.is_null() {
        return false;
    }
    let prefix_bytes = match unsafe { string_bytes(prefix) } {
        Some(bytes) => bytes,
        None => return false,
    };
    let mut current = unsafe { (*table).next_prefix_tree };
    while !current.is_null() {
        let duplicate = unsafe {
            !(*current).prefix.is_null()
                && string_bytes((*current).prefix)
                    .map(|bytes| bytes == prefix_bytes)
                    .unwrap_or(false)
        };
        if duplicate {
            return false;
        }
        current = unsafe { (*current).next_prefix_tree };
    }

    unsafe {
        (*entry).node_type_code = 0;
        (*entry).name_length = prefix_bytes.len().min(i16::MAX as usize) as i16;
        (*entry).links = [0; 3];
        (*entry).prefix = prefix;
        (*entry).next_prefix_tree = (*table).next_prefix_tree;
        (*table).next_prefix_tree = entry;
    }
    true
}

/// `PfxRemovePrefix(PPREFIX_TABLE, PPREFIX_TABLE_ENTRY)`.
///
/// # Safety
/// `table` is valid; `entry` is an entry that may be linked into it.
pub unsafe fn remove(table: *mut PrefixTable, entry: *mut PrefixTableEntry) {
    if table.is_null() || entry.is_null() {
        return;
    }
    let mut link = unsafe { ptr::addr_of_mut!((*table).next_prefix_tree) };
    loop {
        let current = unsafe { *link };
        if current.is_null() {
            return;
        }
        if current == entry {
            unsafe {
                *link = (*current).next_prefix_tree;
                (*current).next_prefix_tree = ptr::null_mut();
            }
            return;
        }
        link = unsafe { ptr::addr_of_mut!((*current).next_prefix_tree) };
    }
}

/// `PfxFindPrefix(PPREFIX_TABLE, PSTRING) -> PPREFIX_TABLE_ENTRY`.
///
/// # Safety
/// `table` and `full_name` are valid objects.
pub unsafe fn find_prefix(
    table: *mut PrefixTable,
    full_name: *mut RtlString,
) -> *mut PrefixTableEntry {
    if table.is_null() || full_name.is_null() {
        return ptr::null_mut();
    }
    let full = match unsafe { string_bytes(full_name) } {
        Some(bytes) => bytes,
        None => return ptr::null_mut(),
    };
    let mut best = ptr::null_mut();
    let mut best_len = 0usize;
    let mut current = unsafe { (*table).next_prefix_tree };
    while !current.is_null() {
        let matched = unsafe {
            if (*current).prefix.is_null() {
                None
            } else {
                string_bytes((*current).prefix)
            }
        };
        if let Some(prefix) = matched {
            if prefix.len() >= best_len && full.starts_with(prefix) {
                best = current;
                best_len = prefix.len();
            }
        }
        current = unsafe { (*current).next_prefix_tree };
    }
    best
}

unsafe fn string_bytes<'a>(string: *mut RtlString) -> Option<&'a [u8]> {
    if string.is_null() {
        return None;
    }
    let (buffer, length) = unsafe { ((*string).buffer as *const u8, (*string).length as usize) };
    if length == 0 {
        return Some(&[]);
    }
    if buffer.is_null() {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(buffer, length) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    fn rtl_string(bytes: &[u8]) -> RtlString {
        RtlString {
            length: bytes.len() as u16,
            maximum_length: bytes.len() as u16,
            buffer: bytes.as_ptr() as u64,
        }
    }

    fn entry() -> PrefixTableEntry {
        PrefixTableEntry {
            node_type_code: -1,
            name_length: -1,
            next_prefix_tree: core::ptr::null_mut(),
            links: [0xcccc; 3],
            prefix: core::ptr::null_mut(),
        }
    }

    #[test]
    fn layout_matches_x64_reactos_types() {
        assert_eq!(size_of::<PrefixTable>(), 16);
        assert_eq!(offset_of!(PrefixTable, node_type_code), 0);
        assert_eq!(offset_of!(PrefixTable, name_length), 2);
        assert_eq!(offset_of!(PrefixTable, next_prefix_tree), 8);

        assert_eq!(size_of::<PrefixTableEntry>(), 48);
        assert_eq!(offset_of!(PrefixTableEntry, node_type_code), 0);
        assert_eq!(offset_of!(PrefixTableEntry, name_length), 2);
        assert_eq!(offset_of!(PrefixTableEntry, next_prefix_tree), 8);
        assert_eq!(offset_of!(PrefixTableEntry, links), 16);
        assert_eq!(offset_of!(PrefixTableEntry, prefix), 40);
    }

    #[test]
    fn insert_find_returns_longest_prefix() {
        let mut table = PrefixTable {
            node_type_code: -1,
            name_length: -1,
            next_prefix_tree: core::ptr::null_mut(),
        };
        let mut win = rtl_string(b"\\Windows");
        let mut system32 = rtl_string(b"\\Windows\\System32");
        let mut query = rtl_string(b"\\Windows\\System32\\ntdll.dll");
        let mut win_entry = entry();
        let mut sys_entry = entry();

        unsafe {
            initialize(&mut table);
            assert!(insert(&mut table, &mut win, &mut win_entry));
            assert!(insert(&mut table, &mut system32, &mut sys_entry));
            assert_eq!(
                find_prefix(&mut table, &mut query),
                ptr::addr_of_mut!(sys_entry)
            );
        }
    }

    #[test]
    fn duplicate_insert_is_rejected_and_remove_unlinks() {
        let mut table = PrefixTable {
            node_type_code: 0,
            name_length: 0,
            next_prefix_tree: core::ptr::null_mut(),
        };
        let mut name = rtl_string(b"abc");
        let mut query = rtl_string(b"abcdef");
        let mut first = entry();
        let mut duplicate = entry();

        unsafe {
            initialize(&mut table);
            assert!(insert(&mut table, &mut name, &mut first));
            assert!(!insert(&mut table, &mut name, &mut duplicate));
            assert_eq!(
                find_prefix(&mut table, &mut query),
                ptr::addr_of_mut!(first)
            );
            remove(&mut table, &mut first);
            assert!(find_prefix(&mut table, &mut query).is_null());
            assert!(first.next_prefix_tree.is_null());
        }
    }
}
