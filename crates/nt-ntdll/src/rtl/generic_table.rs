//! Splay-backed `RTL_GENERIC_TABLE`.
//!
//! The public routines here operate on the byte-exact ReactOS/Windows raw C
//! layout. The caller supplies comparison, allocation, and free callbacks; the
//! table stores each element as `TABLE_ENTRY_HEADER` followed by caller data.

use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut};

use super::splay::{self, SplayLinks};

/// `TABLE_SEARCH_RESULT`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TableSearchResult {
    TableEmptyTree = 0,
    TableFoundNode = 1,
    TableInsertAsLeft = 2,
    TableInsertAsRight = 3,
}

/// `RTL_GENERIC_COMPARE_RESULTS`.
pub const GENERIC_LESS_THAN: u32 = 0;
/// `RTL_GENERIC_COMPARE_RESULTS`.
pub const GENERIC_GREATER_THAN: u32 = 1;
/// `RTL_GENERIC_COMPARE_RESULTS`.
pub const GENERIC_EQUAL: u32 = 2;

/// Offset of `TABLE_ENTRY_HEADER.ListEntry`.
pub const TABLE_ENTRY_LIST_OFFSET: usize = 0x18;
/// Offset of `TABLE_ENTRY_HEADER.UserData`.
pub const TABLE_ENTRY_USER_DATA_OFFSET: usize = 0x28;

/// `LIST_ENTRY`.
#[repr(C)]
#[derive(Debug)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    const fn zeroed() -> Self {
        Self {
            flink: null_mut(),
            blink: null_mut(),
        }
    }
}

/// `RTL_GENERIC_TABLE` compare callback.
pub type CompareRoutine =
    unsafe extern "system" fn(*mut RtlGenericTable, *mut c_void, *mut c_void) -> u32;
/// `RTL_GENERIC_TABLE` allocate callback.
pub type AllocateRoutine = unsafe extern "system" fn(*mut RtlGenericTable, u32) -> *mut c_void;
/// `RTL_GENERIC_TABLE` free callback.
pub type FreeRoutine = unsafe extern "system" fn(*mut RtlGenericTable, *mut c_void);

/// `RTL_GENERIC_TABLE` on x64.
#[repr(C)]
#[derive(Debug)]
pub struct RtlGenericTable {
    pub table_root: *mut SplayLinks,
    pub insert_order_list: ListEntry,
    pub ordered_pointer: *mut ListEntry,
    pub which_ordered_element: u32,
    pub number_generic_table_elements: u32,
    pub compare_routine: Option<CompareRoutine>,
    pub allocate_routine: Option<AllocateRoutine>,
    pub free_routine: Option<FreeRoutine>,
    pub table_context: *mut c_void,
}

impl RtlGenericTable {
    /// A zeroed table. Call `initialize_generic_table` before use.
    pub const fn zeroed() -> Self {
        Self {
            table_root: null_mut(),
            insert_order_list: ListEntry::zeroed(),
            ordered_pointer: null_mut(),
            which_ordered_element: 0,
            number_generic_table_elements: 0,
            compare_routine: None,
            allocate_routine: None,
            free_routine: None,
            table_context: null_mut(),
        }
    }
}

#[inline]
unsafe fn list_for_node(node: *mut SplayLinks) -> *mut ListEntry {
    unsafe { (node as *mut u8).add(TABLE_ENTRY_LIST_OFFSET) as *mut ListEntry }
}

#[inline]
unsafe fn node_for_list(list: *mut ListEntry) -> *mut SplayLinks {
    unsafe { (list as *mut u8).sub(TABLE_ENTRY_LIST_OFFSET) as *mut SplayLinks }
}

#[inline]
unsafe fn user_data_for_node(node: *mut SplayLinks) -> *mut c_void {
    unsafe { (node as *mut u8).add(TABLE_ENTRY_USER_DATA_OFFSET) as *mut c_void }
}

#[inline]
unsafe fn list_head(table: *mut RtlGenericTable) -> *mut ListEntry {
    unsafe { core::ptr::addr_of_mut!((*table).insert_order_list) }
}

unsafe fn initialize_list_head(head: *mut ListEntry) {
    unsafe {
        (*head).flink = head;
        (*head).blink = head;
    }
}

unsafe fn insert_tail_list(head: *mut ListEntry, entry: *mut ListEntry) {
    unsafe {
        let blink = (*head).blink;
        (*entry).flink = head;
        (*entry).blink = blink;
        (*blink).flink = entry;
        (*head).blink = entry;
    }
}

unsafe fn remove_entry_list(entry: *mut ListEntry) {
    unsafe {
        let flink = (*entry).flink;
        let blink = (*entry).blink;
        (*blink).flink = flink;
        (*flink).blink = blink;
        (*entry).flink = null_mut();
        (*entry).blink = null_mut();
    }
}

/// `RtlInitializeGenericTable`.
///
/// # Safety
/// `table` is writable for an `RTL_GENERIC_TABLE`.
pub unsafe fn initialize_generic_table(
    table: *mut RtlGenericTable,
    compare: Option<CompareRoutine>,
    allocate: Option<AllocateRoutine>,
    free: Option<FreeRoutine>,
    context: *mut c_void,
) {
    if table.is_null() {
        return;
    }
    unsafe {
        let head = list_head(table);
        initialize_list_head(head);
        (*table).table_root = null_mut();
        (*table).number_generic_table_elements = 0;
        (*table).which_ordered_element = 0;
        (*table).ordered_pointer = head;
        (*table).compare_routine = compare;
        (*table).allocate_routine = allocate;
        (*table).free_routine = free;
        (*table).table_context = context;
    }
}

/// `RtlIsGenericTableEmpty`.
///
/// # Safety
/// `table` is a valid `RTL_GENERIC_TABLE`.
pub unsafe fn is_generic_table_empty(table: *mut RtlGenericTable) -> bool {
    table.is_null() || unsafe { (*table).table_root.is_null() }
}

/// `RtlNumberGenericTableElements`.
///
/// # Safety
/// `table` is a valid `RTL_GENERIC_TABLE`.
pub unsafe fn number_generic_table_elements(table: *mut RtlGenericTable) -> u32 {
    if table.is_null() {
        return 0;
    }
    unsafe { (*table).number_generic_table_elements }
}

/// ReactOS `RtlpFindGenericTableNodeOrParent`.
///
/// # Safety
/// `table` is initialized and `buffer` points to caller data comparable by the callback.
pub unsafe fn find_generic_table_node_or_parent(
    table: *mut RtlGenericTable,
    buffer: *mut c_void,
    node_or_parent: *mut *mut SplayLinks,
) -> TableSearchResult {
    if table.is_null() || unsafe { (*table).table_root.is_null() } {
        return TableSearchResult::TableEmptyTree;
    }
    let compare = match unsafe { (*table).compare_routine } {
        Some(compare) => compare,
        None => return TableSearchResult::TableEmptyTree,
    };
    unsafe {
        let mut current = (*table).table_root;
        loop {
            let result = compare(table, buffer, user_data_for_node(current));
            if result == GENERIC_LESS_THAN {
                if !(*current).left_child.is_null() {
                    current = (*current).left_child;
                } else {
                    if !node_or_parent.is_null() {
                        *node_or_parent = current;
                    }
                    return TableSearchResult::TableInsertAsLeft;
                }
            } else if result == GENERIC_GREATER_THAN {
                if !(*current).right_child.is_null() {
                    current = (*current).right_child;
                } else {
                    if !node_or_parent.is_null() {
                        *node_or_parent = current;
                    }
                    return TableSearchResult::TableInsertAsRight;
                }
            } else {
                if !node_or_parent.is_null() {
                    *node_or_parent = current;
                }
                return TableSearchResult::TableFoundNode;
            }
        }
    }
}

/// `RtlInsertElementGenericTable`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn insert_element_generic_table(
    table: *mut RtlGenericTable,
    buffer: *mut c_void,
    buffer_size: u32,
    new_element: *mut u8,
) -> *mut c_void {
    let mut node_or_parent = null_mut();
    let result = unsafe { find_generic_table_node_or_parent(table, buffer, &mut node_or_parent) };
    unsafe {
        insert_element_generic_table_full(
            table,
            buffer,
            buffer_size,
            new_element,
            node_or_parent,
            result,
        )
    }
}

/// `RtlInsertElementGenericTableFull`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract. `node_or_parent` and `search_result` must come from
/// `find_generic_table_node_or_parent` for this table and buffer.
pub unsafe fn insert_element_generic_table_full(
    table: *mut RtlGenericTable,
    buffer: *mut c_void,
    buffer_size: u32,
    new_element: *mut u8,
    node_or_parent: *mut SplayLinks,
    search_result: TableSearchResult,
) -> *mut c_void {
    if table.is_null() {
        if !new_element.is_null() {
            unsafe { *new_element = 0 };
        }
        return null_mut();
    }
    unsafe {
        let mut new_node = node_or_parent;
        if search_result != TableSearchResult::TableFoundNode {
            let allocate = match (*table).allocate_routine {
                Some(allocate) => allocate,
                None => {
                    if !new_element.is_null() {
                        *new_element = 0;
                    }
                    return null_mut();
                }
            };
            let total = match buffer_size.checked_add(TABLE_ENTRY_USER_DATA_OFFSET as u32) {
                Some(total) => total,
                None => {
                    if !new_element.is_null() {
                        *new_element = 0;
                    }
                    return null_mut();
                }
            };
            new_node = allocate(table, total) as *mut SplayLinks;
            if new_node.is_null() {
                if !new_element.is_null() {
                    *new_element = 0;
                }
                return null_mut();
            }
            splay::initialize_splay_links(new_node);
            insert_tail_list(list_head(table), list_for_node(new_node));
            (*table).number_generic_table_elements =
                (*table).number_generic_table_elements.saturating_add(1);

            match search_result {
                TableSearchResult::TableEmptyTree => (*table).table_root = new_node,
                TableSearchResult::TableInsertAsLeft => {
                    splay::insert_as_left_child(node_or_parent, new_node)
                }
                TableSearchResult::TableInsertAsRight => {
                    splay::insert_as_right_child(node_or_parent, new_node)
                }
                TableSearchResult::TableFoundNode => {}
            }
            copy_nonoverlapping(
                buffer as *const u8,
                user_data_for_node(new_node) as *mut u8,
                buffer_size as usize,
            );
        }

        (*table).table_root = splay::splay(new_node);
        if !new_element.is_null() {
            *new_element = u8::from(search_result != TableSearchResult::TableFoundNode);
        }
        user_data_for_node(new_node)
    }
}

/// `RtlLookupElementGenericTable`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn lookup_element_generic_table(
    table: *mut RtlGenericTable,
    buffer: *mut c_void,
) -> *mut c_void {
    let mut node_or_parent = null_mut();
    let mut search_result = TableSearchResult::TableEmptyTree;
    unsafe {
        lookup_element_generic_table_full(table, buffer, &mut node_or_parent, &mut search_result)
    }
}

/// `RtlLookupElementGenericTableFull`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn lookup_element_generic_table_full(
    table: *mut RtlGenericTable,
    buffer: *mut c_void,
    node_or_parent: *mut *mut SplayLinks,
    search_result: *mut TableSearchResult,
) -> *mut c_void {
    let result = unsafe { find_generic_table_node_or_parent(table, buffer, node_or_parent) };
    unsafe {
        if !search_result.is_null() {
            *search_result = result;
        }
        if table.is_null()
            || result == TableSearchResult::TableEmptyTree
            || result != TableSearchResult::TableFoundNode
        {
            return null_mut();
        }
        let node = if node_or_parent.is_null() {
            null_mut()
        } else {
            *node_or_parent
        };
        if node.is_null() {
            return null_mut();
        }
        (*table).table_root = splay::splay(node);
        user_data_for_node(node)
    }
}

/// `RtlDeleteElementGenericTable`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn delete_element_generic_table(
    table: *mut RtlGenericTable,
    buffer: *mut c_void,
) -> bool {
    if table.is_null() {
        return false;
    }
    unsafe {
        let mut node_or_parent = null_mut();
        let result = find_generic_table_node_or_parent(table, buffer, &mut node_or_parent);
        if result != TableSearchResult::TableFoundNode {
            return false;
        }

        (*table).table_root = splay::delete(node_or_parent);
        remove_entry_list(list_for_node(node_or_parent));
        (*table).number_generic_table_elements =
            (*table).number_generic_table_elements.saturating_sub(1);
        (*table).which_ordered_element = 0;
        (*table).ordered_pointer = list_head(table);
        if let Some(free) = (*table).free_routine {
            free(table, node_or_parent as *mut c_void);
        }
        true
    }
}

/// `RtlEnumerateGenericTable`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn enumerate_generic_table(table: *mut RtlGenericTable, restart: bool) -> *mut c_void {
    if unsafe { is_generic_table_empty(table) } {
        return null_mut();
    }
    unsafe {
        let mut found = if restart {
            let mut node = (*table).table_root;
            while !(*node).left_child.is_null() {
                node = (*node).left_child;
            }
            node
        } else {
            splay::real_successor((*table).table_root)
        };
        if !found.is_null() {
            found = splay::splay(found);
            (*table).table_root = found;
            user_data_for_node(found)
        } else {
            null_mut()
        }
    }
}

/// `RtlEnumerateGenericTableWithoutSplaying`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn enumerate_generic_table_without_splaying(
    table: *mut RtlGenericTable,
    restart_key: *mut *mut c_void,
) -> *mut c_void {
    if restart_key.is_null() || unsafe { is_generic_table_empty(table) } {
        return null_mut();
    }
    unsafe {
        let found = if (*restart_key).is_null() {
            let mut node = (*table).table_root;
            while !(*node).left_child.is_null() {
                node = (*node).left_child;
            }
            *restart_key = node as *mut c_void;
            node
        } else {
            let node = splay::real_successor(*restart_key as *mut SplayLinks);
            if !node.is_null() {
                *restart_key = node as *mut c_void;
            }
            node
        };
        if found.is_null() {
            null_mut()
        } else {
            user_data_for_node(found)
        }
    }
}

/// `RtlGetElementGenericTable`.
///
/// # Safety
/// Standard `RTL_GENERIC_TABLE` contract.
pub unsafe fn get_element_generic_table(table: *mut RtlGenericTable, index: u32) -> *mut c_void {
    if table.is_null() {
        return null_mut();
    }
    unsafe {
        let next = match index.checked_add(1) {
            Some(next) => next,
            None => return null_mut(),
        };
        if next > (*table).number_generic_table_elements {
            return null_mut();
        }
        let mut ordered = list_head(table);
        for _ in 0..next {
            ordered = (*ordered).flink;
        }
        (*table).ordered_pointer = ordered;
        (*table).which_ordered_element = next;
        user_data_for_node(node_for_list(ordered))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::alloc::Layout;
    use std::alloc::alloc;

    unsafe extern "system" fn compare_i32(
        _table: *mut RtlGenericTable,
        first: *mut c_void,
        second: *mut c_void,
    ) -> u32 {
        let a = unsafe { *(first as *const i32) };
        let b = unsafe { *(second as *const i32) };
        if a < b {
            GENERIC_LESS_THAN
        } else if a > b {
            GENERIC_GREATER_THAN
        } else {
            GENERIC_EQUAL
        }
    }

    unsafe extern "system" fn allocate_node(
        _table: *mut RtlGenericTable,
        byte_size: u32,
    ) -> *mut c_void {
        let layout = Layout::from_size_align(byte_size as usize, 8).unwrap();
        unsafe { alloc(layout) as *mut c_void }
    }

    unsafe extern "system" fn free_node(_table: *mut RtlGenericTable, _buffer: *mut c_void) {
        // The tests leak the tiny allocations; production callers provide the matching free routine.
    }

    #[test]
    fn insert_lookup_duplicate_and_delete() {
        unsafe {
            let mut table = RtlGenericTable::zeroed();
            initialize_generic_table(
                &mut table,
                Some(compare_i32),
                Some(allocate_node),
                Some(free_node),
                null_mut(),
            );
            assert!(is_generic_table_empty(&mut table));

            let mut inserted = 0u8;
            for value in [20i32, 10, 30] {
                let ptr = insert_element_generic_table(
                    &mut table,
                    &value as *const i32 as *mut c_void,
                    core::mem::size_of::<i32>() as u32,
                    &mut inserted,
                );
                assert!(!ptr.is_null());
                assert_eq!(inserted, 1);
            }
            assert_eq!(number_generic_table_elements(&mut table), 3);

            let key = 10i32;
            let found = lookup_element_generic_table(&mut table, &key as *const _ as *mut c_void);
            assert!(!found.is_null());
            assert_eq!(*(found as *const i32), 10);

            let duplicate = 10i32;
            let dup = insert_element_generic_table(
                &mut table,
                &duplicate as *const i32 as *mut c_void,
                core::mem::size_of::<i32>() as u32,
                &mut inserted,
            );
            assert_eq!(inserted, 0);
            assert_eq!(*(dup as *const i32), 10);
            assert_eq!(number_generic_table_elements(&mut table), 3);

            assert!(delete_element_generic_table(
                &mut table,
                &key as *const _ as *mut c_void
            ));
            assert_eq!(number_generic_table_elements(&mut table), 2);
            assert!(
                lookup_element_generic_table(&mut table, &key as *const _ as *mut c_void).is_null()
            );
        }
    }

    #[test]
    fn enumeration_and_get_element_use_insertion_order() {
        unsafe {
            let mut table = RtlGenericTable::zeroed();
            initialize_generic_table(
                &mut table,
                Some(compare_i32),
                Some(allocate_node),
                Some(free_node),
                null_mut(),
            );
            for value in [2i32, 1, 3] {
                insert_element_generic_table(
                    &mut table,
                    &value as *const i32 as *mut c_void,
                    core::mem::size_of::<i32>() as u32,
                    null_mut(),
                );
            }

            let first_sorted = enumerate_generic_table(&mut table, true);
            assert_eq!(*(first_sorted as *const i32), 1);
            let second_sorted = enumerate_generic_table(&mut table, false);
            assert_eq!(*(second_sorted as *const i32), 2);

            let first_inserted = get_element_generic_table(&mut table, 0);
            assert_eq!(*(first_inserted as *const i32), 2);
            let third_inserted = get_element_generic_table(&mut table, 2);
            assert_eq!(*(third_inserted as *const i32), 3);

            let mut restart: *mut c_void = null_mut();
            let no_splay_first = enumerate_generic_table_without_splaying(&mut table, &mut restart);
            assert_eq!(*(no_splay_first as *const i32), 1);
            let no_splay_second =
                enumerate_generic_table_without_splaying(&mut table, &mut restart);
            assert_eq!(*(no_splay_second as *const i32), 2);
        }
    }
}
