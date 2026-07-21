//! AVL-flavoured `RTL_AVL_TABLE` generic-table helpers.
//!
//! The ABI surface here is the ReactOS/Windows raw C layout. The implementation keeps a normal
//! ordered binary tree rooted at `BalancedRoot.RightChild` and preserves the observable RTL
//! contracts: callback allocation/free, collation-order lookup/enumeration, restart keys, and delete
//! accounting. It does not depend on kernel state.

use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut};

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_NO_MATCH`.
pub const STATUS_NO_MATCH: u32 = 0xC000_0272;
/// `STATUS_NO_MORE_MATCHES`.
pub const STATUS_NO_MORE_MATCHES: u32 = 0xC000_0273;

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

/// Offset of `TABLE_ENTRY_HEADER.UserData` for AVL tables.
pub const TABLE_ENTRY_USER_DATA_OFFSET: usize = 0x20;

/// `RTL_BALANCED_LINKS` on x64.
#[repr(C)]
#[derive(Debug)]
pub struct BalancedLinks {
    pub parent: *mut BalancedLinks,
    pub left_child: *mut BalancedLinks,
    pub right_child: *mut BalancedLinks,
    pub balance: i8,
    pub reserved: [u8; 3],
}

impl BalancedLinks {
    /// A detached, zeroed link record.
    pub const fn zeroed() -> Self {
        Self {
            parent: null_mut(),
            left_child: null_mut(),
            right_child: null_mut(),
            balance: 0,
            reserved: [0; 3],
        }
    }
}

/// `RTL_AVL_TABLE` compare callback.
pub type CompareRoutine =
    unsafe extern "system" fn(*mut RtlAvlTable, *mut c_void, *mut c_void) -> u32;
/// `RTL_AVL_TABLE` allocate callback.
pub type AllocateRoutine = unsafe extern "system" fn(*mut RtlAvlTable, u32) -> *mut c_void;
/// `RTL_AVL_TABLE` free callback.
pub type FreeRoutine = unsafe extern "system" fn(*mut RtlAvlTable, *mut c_void);
/// `RTL_AVL_MATCH_FUNCTION`.
pub type MatchRoutine =
    unsafe extern "system" fn(*mut RtlAvlTable, *mut c_void, *mut c_void) -> u32;

/// `RTL_AVL_TABLE` on x64.
#[repr(C)]
#[derive(Debug)]
pub struct RtlAvlTable {
    pub balanced_root: BalancedLinks,
    pub ordered_pointer: *mut c_void,
    pub which_ordered_element: u32,
    pub number_generic_table_elements: u32,
    pub depth_of_tree: u32,
    pub restart_key: *mut BalancedLinks,
    pub delete_count: u32,
    pub compare_routine: Option<CompareRoutine>,
    pub allocate_routine: Option<AllocateRoutine>,
    pub free_routine: Option<FreeRoutine>,
    pub table_context: *mut c_void,
}

impl RtlAvlTable {
    /// A zeroed table. Call `initialize_generic_table_avl` before use.
    pub const fn zeroed() -> Self {
        Self {
            balanced_root: BalancedLinks::zeroed(),
            ordered_pointer: null_mut(),
            which_ordered_element: 0,
            number_generic_table_elements: 0,
            depth_of_tree: 0,
            restart_key: null_mut(),
            delete_count: 0,
            compare_routine: None,
            allocate_routine: None,
            free_routine: None,
            table_context: null_mut(),
        }
    }
}

#[inline]
unsafe fn user_data_for_node(node: *mut BalancedLinks) -> *mut c_void {
    unsafe { (node as *mut u8).add(TABLE_ENTRY_USER_DATA_OFFSET) as *mut c_void }
}

#[inline]
unsafe fn sentinel(table: *mut RtlAvlTable) -> *mut BalancedLinks {
    unsafe { core::ptr::addr_of_mut!((*table).balanced_root) }
}

#[inline]
unsafe fn root(table: *mut RtlAvlTable) -> *mut BalancedLinks {
    unsafe { (*table).balanced_root.right_child }
}

#[inline]
unsafe fn set_root(table: *mut RtlAvlTable, node: *mut BalancedLinks) {
    unsafe {
        (*table).balanced_root.right_child = node;
        if !node.is_null() {
            (*node).parent = sentinel(table);
        }
    }
}

#[inline]
unsafe fn is_left_child(node: *mut BalancedLinks) -> bool {
    if node.is_null() {
        return false;
    }
    unsafe {
        let parent = (*node).parent;
        !parent.is_null() && parent != node && (*parent).left_child == node
    }
}

#[inline]
unsafe fn is_right_child(node: *mut BalancedLinks) -> bool {
    if node.is_null() {
        return false;
    }
    unsafe {
        let parent = (*node).parent;
        !parent.is_null() && parent != node && (*parent).right_child == node
    }
}

unsafe fn leftmost(mut node: *mut BalancedLinks) -> *mut BalancedLinks {
    if node.is_null() {
        return null_mut();
    }
    unsafe {
        while !(*node).left_child.is_null() {
            node = (*node).left_child;
        }
    }
    node
}

unsafe fn rightmost(mut node: *mut BalancedLinks) -> *mut BalancedLinks {
    if node.is_null() {
        return null_mut();
    }
    unsafe {
        while !(*node).right_child.is_null() {
            node = (*node).right_child;
        }
    }
    node
}

unsafe fn subtree_predecessor(node: *mut BalancedLinks) -> *mut BalancedLinks {
    if node.is_null() {
        return null_mut();
    }
    unsafe { rightmost((*node).left_child) }
}

/// `RtlRealPredecessorAvl`.
///
/// This can return the table sentinel when called on the leftmost node, matching the splay helper
/// semantics that ReactOS relies on for delete-safe enumeration.
unsafe fn real_predecessor(node: *mut BalancedLinks) -> *mut BalancedLinks {
    if node.is_null() {
        return null_mut();
    }
    unsafe {
        let subtree = subtree_predecessor(node);
        if !subtree.is_null() {
            return subtree;
        }
        let mut child = node;
        while is_left_child(child) {
            child = (*child).parent;
        }
        if is_right_child(child) {
            (*child).parent
        } else {
            null_mut()
        }
    }
}

unsafe fn successor_in_table(
    table: *mut RtlAvlTable,
    node: *mut BalancedLinks,
) -> *mut BalancedLinks {
    if table.is_null() || node.is_null() {
        return null_mut();
    }
    unsafe {
        let head = sentinel(table);
        if node == head {
            return leftmost(root(table));
        }
        if !(*node).right_child.is_null() {
            return leftmost((*node).right_child);
        }

        let mut child = node;
        let mut parent = (*child).parent;
        while !parent.is_null() && parent != head && (*parent).right_child == child {
            child = parent;
            parent = (*parent).parent;
        }
        if parent.is_null() || parent == head {
            null_mut()
        } else {
            parent
        }
    }
}

unsafe fn compute_depth(node: *mut BalancedLinks) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe {
        let left = compute_depth((*node).left_child);
        let right = compute_depth((*node).right_child);
        1 + if left > right { left } else { right }
    }
}

unsafe fn reset_order_cache(table: *mut RtlAvlTable) {
    unsafe {
        (*table).ordered_pointer = null_mut();
        (*table).which_ordered_element = 0;
    }
}

unsafe fn transplant(
    table: *mut RtlAvlTable,
    old: *mut BalancedLinks,
    new_node: *mut BalancedLinks,
) {
    unsafe {
        let parent = (*old).parent;
        if parent == sentinel(table) {
            set_root(table, new_node);
        } else if (*parent).left_child == old {
            (*parent).left_child = new_node;
            if !new_node.is_null() {
                (*new_node).parent = parent;
            }
        } else {
            (*parent).right_child = new_node;
            if !new_node.is_null() {
                (*new_node).parent = parent;
            }
        }
    }
}

unsafe fn delete_node_from_tree(table: *mut RtlAvlTable, node: *mut BalancedLinks) {
    unsafe {
        if (*node).left_child.is_null() {
            transplant(table, node, (*node).right_child);
        } else if (*node).right_child.is_null() {
            transplant(table, node, (*node).left_child);
        } else {
            let successor = leftmost((*node).right_child);
            if (*successor).parent != node {
                transplant(table, successor, (*successor).right_child);
                (*successor).right_child = (*node).right_child;
                (*(*successor).right_child).parent = successor;
            }
            transplant(table, node, successor);
            (*successor).left_child = (*node).left_child;
            (*(*successor).left_child).parent = successor;
            (*successor).balance = 0;
        }

        (*node).parent = node;
        (*node).left_child = null_mut();
        (*node).right_child = null_mut();
        (*node).balance = 0;
        (*table).depth_of_tree = compute_depth(root(table));
    }
}

/// `RtlInitializeGenericTableAvl`.
///
/// # Safety
/// `table` is writable for an `RTL_AVL_TABLE`.
pub unsafe fn initialize_generic_table_avl(
    table: *mut RtlAvlTable,
    compare: Option<CompareRoutine>,
    allocate: Option<AllocateRoutine>,
    free: Option<FreeRoutine>,
    context: *mut c_void,
) {
    if table.is_null() {
        return;
    }
    unsafe {
        *table = RtlAvlTable::zeroed();
        (*table).balanced_root.parent = sentinel(table);
        (*table).compare_routine = compare;
        (*table).allocate_routine = allocate;
        (*table).free_routine = free;
        (*table).table_context = context;
    }
}

/// ReactOS `RtlpFindAvlTableNodeOrParent`.
///
/// # Safety
/// `table` is initialized and `buffer` is comparable by the callback.
pub unsafe fn find_avl_table_node_or_parent(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
    node_or_parent: *mut *mut BalancedLinks,
) -> TableSearchResult {
    if table.is_null() || unsafe { (*table).number_generic_table_elements == 0 } {
        if !node_or_parent.is_null() {
            unsafe { *node_or_parent = null_mut() };
        }
        return TableSearchResult::TableEmptyTree;
    }
    let compare = match unsafe { (*table).compare_routine } {
        Some(compare) => compare,
        None => {
            if !node_or_parent.is_null() {
                unsafe { *node_or_parent = null_mut() };
            }
            return TableSearchResult::TableEmptyTree;
        }
    };
    unsafe {
        let mut current = root(table);
        while !current.is_null() {
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
    TableSearchResult::TableEmptyTree
}

/// `RtlIsGenericTableEmptyAvl`.
///
/// # Safety
/// `table` is a valid `RTL_AVL_TABLE`.
pub unsafe fn is_generic_table_empty_avl(table: *mut RtlAvlTable) -> bool {
    table.is_null() || unsafe { (*table).number_generic_table_elements == 0 }
}

/// `RtlNumberGenericTableElementsAvl`.
///
/// # Safety
/// `table` is a valid `RTL_AVL_TABLE`.
pub unsafe fn number_generic_table_elements_avl(table: *mut RtlAvlTable) -> u32 {
    if table.is_null() {
        return 0;
    }
    unsafe { (*table).number_generic_table_elements }
}

/// `RtlInsertElementGenericTableAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn insert_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
    buffer_size: u32,
    new_element: *mut u8,
) -> *mut c_void {
    let mut node_or_parent = null_mut();
    let result = unsafe { find_avl_table_node_or_parent(table, buffer, &mut node_or_parent) };
    unsafe {
        insert_element_generic_table_full_avl(
            table,
            buffer,
            buffer_size,
            new_element,
            node_or_parent,
            result,
        )
    }
}

/// `RtlInsertElementGenericTableFullAvl`.
///
/// # Safety
/// `node_or_parent` and `search_result` are from a prior AVL lookup for this table/buffer.
pub unsafe fn insert_element_generic_table_full_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
    buffer_size: u32,
    new_element: *mut u8,
    node_or_parent: *mut BalancedLinks,
    search_result: TableSearchResult,
) -> *mut c_void {
    if table.is_null() {
        if !new_element.is_null() {
            unsafe { *new_element = 0 };
        }
        return null_mut();
    }
    unsafe {
        let mut node = node_or_parent;
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
            node = allocate(table, total) as *mut BalancedLinks;
            if node.is_null() {
                if !new_element.is_null() {
                    *new_element = 0;
                }
                return null_mut();
            }
            core::ptr::write_bytes(node as *mut u8, 0, TABLE_ENTRY_USER_DATA_OFFSET);

            match search_result {
                TableSearchResult::TableEmptyTree => set_root(table, node),
                TableSearchResult::TableInsertAsLeft => {
                    (*node_or_parent).left_child = node;
                    (*node).parent = node_or_parent;
                }
                TableSearchResult::TableInsertAsRight => {
                    (*node_or_parent).right_child = node;
                    (*node).parent = node_or_parent;
                }
                TableSearchResult::TableFoundNode => {}
            }

            if buffer_size != 0 {
                copy_nonoverlapping(
                    buffer as *const u8,
                    user_data_for_node(node) as *mut u8,
                    buffer_size as usize,
                );
            }
            (*table).number_generic_table_elements =
                (*table).number_generic_table_elements.saturating_add(1);
            (*table).depth_of_tree = compute_depth(root(table));
            reset_order_cache(table);
        }

        if !new_element.is_null() {
            *new_element = u8::from(search_result != TableSearchResult::TableFoundNode);
        }
        user_data_for_node(node)
    }
}

/// `RtlLookupElementGenericTableAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn lookup_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
) -> *mut c_void {
    let mut node_or_parent = null_mut();
    let mut search_result = TableSearchResult::TableEmptyTree;
    unsafe {
        lookup_element_generic_table_full_avl(
            table,
            buffer,
            &mut node_or_parent,
            &mut search_result,
        )
    }
}

/// `RtlLookupElementGenericTableFullAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn lookup_element_generic_table_full_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
    node_or_parent: *mut *mut BalancedLinks,
    search_result: *mut TableSearchResult,
) -> *mut c_void {
    let result = unsafe { find_avl_table_node_or_parent(table, buffer, node_or_parent) };
    unsafe {
        if !search_result.is_null() {
            *search_result = result;
        }
        if result != TableSearchResult::TableFoundNode || node_or_parent.is_null() {
            return null_mut();
        }
        let node = *node_or_parent;
        if node.is_null() || node == sentinel(table) {
            null_mut()
        } else {
            user_data_for_node(node)
        }
    }
}

/// `RtlDeleteElementGenericTableAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn delete_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
) -> bool {
    if table.is_null() {
        return false;
    }
    unsafe {
        let mut node = null_mut();
        let result = find_avl_table_node_or_parent(table, buffer, &mut node);
        if result != TableSearchResult::TableFoundNode || node.is_null() {
            return false;
        }

        if node == (*table).restart_key {
            (*table).restart_key = real_predecessor(node);
        }
        (*table).delete_count = (*table).delete_count.wrapping_add(1);
        delete_node_from_tree(table, node);
        (*table).number_generic_table_elements =
            (*table).number_generic_table_elements.saturating_sub(1);
        reset_order_cache(table);
        if let Some(free) = (*table).free_routine {
            free(table, node as *mut c_void);
        }
        true
    }
}

/// `RtlEnumerateGenericTableAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn enumerate_generic_table_avl(table: *mut RtlAvlTable, restart: bool) -> *mut c_void {
    if table.is_null() {
        return null_mut();
    }
    unsafe {
        if restart {
            (*table).restart_key = null_mut();
        }
        enumerate_generic_table_without_splaying_avl(
            table,
            core::ptr::addr_of_mut!((*table).restart_key) as *mut *mut c_void,
        )
    }
}

/// `RtlEnumerateGenericTableWithoutSplayingAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn enumerate_generic_table_without_splaying_avl(
    table: *mut RtlAvlTable,
    restart_key: *mut *mut c_void,
) -> *mut c_void {
    if table.is_null() || restart_key.is_null() || unsafe { is_generic_table_empty_avl(table) } {
        return null_mut();
    }
    unsafe {
        let node = if (*restart_key).is_null() {
            let first = leftmost(root(table));
            *restart_key = first as *mut c_void;
            first
        } else {
            let next = successor_in_table(table, *restart_key as *mut BalancedLinks);
            if next.is_null() {
                return null_mut();
            } else {
                *restart_key = next as *mut c_void;
                next
            }
        };
        if node.is_null() {
            null_mut()
        } else {
            user_data_for_node(node)
        }
    }
}

/// `RtlLookupFirstMatchingElementGenericTableAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn lookup_first_matching_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
    restart_key: *mut *mut c_void,
) -> *mut c_void {
    if restart_key.is_null() {
        return null_mut();
    }
    unsafe {
        *restart_key = null_mut();
        let mut node = null_mut();
        let result = find_avl_table_node_or_parent(table, buffer, &mut node);
        if result != TableSearchResult::TableFoundNode || node.is_null() {
            return null_mut();
        }
        let compare = match (*table).compare_routine {
            Some(compare) => compare,
            None => return null_mut(),
        };
        let mut first = node;
        loop {
            let previous = real_predecessor(first);
            if previous.is_null() || (*previous).parent == previous {
                break;
            }
            if compare(table, buffer, user_data_for_node(previous)) != GENERIC_EQUAL {
                break;
            }
            first = previous;
        }
        *restart_key = first as *mut c_void;
        user_data_for_node(first)
    }
}

/// `RtlGetElementGenericTableAvl`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
pub unsafe fn get_element_generic_table_avl(table: *mut RtlAvlTable, index: u32) -> *mut c_void {
    if table.is_null() || index == u32::MAX {
        return null_mut();
    }
    unsafe {
        if index >= (*table).number_generic_table_elements {
            return null_mut();
        }
        let mut node = leftmost(root(table));
        for _ in 0..index {
            node = successor_in_table(table, node);
            if node.is_null() {
                return null_mut();
            }
        }
        (*table).ordered_pointer = node as *mut c_void;
        (*table).which_ordered_element = index + 1;
        user_data_for_node(node)
    }
}

/// `RtlEnumerateGenericTableLikeADirectory`.
///
/// # Safety
/// Standard `RTL_AVL_TABLE` contract.
#[allow(clippy::too_many_arguments)]
pub unsafe fn enumerate_generic_table_like_a_directory(
    table: *mut RtlAvlTable,
    match_function: Option<MatchRoutine>,
    match_data: *mut c_void,
    mut next_flag: u32,
    restart_key: *mut *mut c_void,
    delete_count: *mut u32,
    buffer: *mut c_void,
) -> *mut c_void {
    if table.is_null() || restart_key.is_null() || delete_count.is_null() {
        return null_mut();
    }
    unsafe {
        if is_generic_table_empty_avl(table) {
            *restart_key = null_mut();
            *delete_count = (*table).delete_count;
            return null_mut();
        }

        let mut node = *restart_key as *mut BalancedLinks;
        if *delete_count != (*table).delete_count {
            node = null_mut();
        }

        if node.is_null() {
            let mut lookup_node = null_mut();
            let lookup = find_avl_table_node_or_parent(table, buffer, &mut lookup_node);
            node = lookup_node;
            if lookup != TableSearchResult::TableFoundNode {
                next_flag = 0;
                if lookup == TableSearchResult::TableInsertAsRight && !node.is_null() {
                    node = successor_in_table(table, node);
                }
            }
        }

        if next_flag != 0 && !node.is_null() {
            node = successor_in_table(table, node);
        }

        while !node.is_null() && node != sentinel(table) {
            let status = match match_function {
                Some(match_function) => match_function(table, user_data_for_node(node), match_data),
                None => STATUS_SUCCESS,
            };
            if status == STATUS_NO_MATCH {
                node = successor_in_table(table, node);
                continue;
            }

            *restart_key = node as *mut c_void;
            *delete_count = (*table).delete_count;
            if status == STATUS_SUCCESS {
                return user_data_for_node(node);
            }
            return null_mut();
        }

        *restart_key = null_mut();
        *delete_count = (*table).delete_count;
        null_mut()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::alloc::Layout;
    use std::alloc::alloc;

    unsafe extern "system" fn compare_i32(
        _table: *mut RtlAvlTable,
        first: *mut c_void,
        second: *mut c_void,
    ) -> u32 {
        let a = unsafe { *(first as *const i32) };
        let b = unsafe { *(second as *const i32) };
        let (ak, bk) = if a < 0 { (-a, b / 10) } else { (a, b) };
        if ak < bk {
            GENERIC_LESS_THAN
        } else if ak > bk {
            GENERIC_GREATER_THAN
        } else {
            GENERIC_EQUAL
        }
    }

    unsafe extern "system" fn allocate_node(
        _table: *mut RtlAvlTable,
        byte_size: u32,
    ) -> *mut c_void {
        let layout = Layout::from_size_align(byte_size as usize, 8).unwrap();
        unsafe { alloc(layout) as *mut c_void }
    }

    unsafe extern "system" fn free_node(_table: *mut RtlAvlTable, _buffer: *mut c_void) {
        // The tests leak these tiny allocations; production callers provide the matching free.
    }

    unsafe fn initialize_test_table(table: *mut RtlAvlTable) {
        unsafe {
            initialize_generic_table_avl(
                table,
                Some(compare_i32),
                Some(allocate_node),
                Some(free_node),
                null_mut(),
            );
        }
    }

    #[test]
    fn insert_lookup_duplicate_and_delete() {
        unsafe {
            let mut table = RtlAvlTable::zeroed();
            initialize_test_table(&mut table);
            assert!(is_generic_table_empty_avl(&mut table));

            let mut inserted = 0u8;
            for value in [20i32, 10, 30] {
                let ptr = insert_element_generic_table_avl(
                    &mut table,
                    &value as *const i32 as *mut c_void,
                    core::mem::size_of::<i32>() as u32,
                    &mut inserted,
                );
                assert!(!ptr.is_null());
                assert_eq!(inserted, 1);
            }
            assert_eq!(number_generic_table_elements_avl(&mut table), 3);
            assert_eq!(table.depth_of_tree, 2);

            let key = 10i32;
            let found =
                lookup_element_generic_table_avl(&mut table, &key as *const _ as *mut c_void);
            assert!(!found.is_null());
            assert_eq!(*(found as *const i32), 10);

            let dup = insert_element_generic_table_avl(
                &mut table,
                &key as *const i32 as *mut c_void,
                core::mem::size_of::<i32>() as u32,
                &mut inserted,
            );
            assert_eq!(inserted, 0);
            assert_eq!(*(dup as *const i32), 10);
            assert_eq!(number_generic_table_elements_avl(&mut table), 3);

            assert!(delete_element_generic_table_avl(
                &mut table,
                &key as *const _ as *mut c_void
            ));
            assert_eq!(number_generic_table_elements_avl(&mut table), 2);
            assert!(
                lookup_element_generic_table_avl(&mut table, &key as *const _ as *mut c_void)
                    .is_null()
            );
        }
    }

    #[test]
    fn enumeration_and_get_element_are_collation_ordered() {
        unsafe {
            let mut table = RtlAvlTable::zeroed();
            initialize_test_table(&mut table);
            for value in [2i32, 1, 3] {
                insert_element_generic_table_avl(
                    &mut table,
                    &value as *const i32 as *mut c_void,
                    core::mem::size_of::<i32>() as u32,
                    null_mut(),
                );
            }

            let first = enumerate_generic_table_avl(&mut table, true);
            assert_eq!(*(first as *const i32), 1);
            let second = enumerate_generic_table_avl(&mut table, false);
            assert_eq!(*(second as *const i32), 2);
            let third = enumerate_generic_table_avl(&mut table, false);
            assert_eq!(*(third as *const i32), 3);
            let end = enumerate_generic_table_avl(&mut table, false);
            assert!(
                end.is_null(),
                "end-of-enumeration returned {}",
                *(end as *const i32)
            );

            assert_eq!(
                *(get_element_generic_table_avl(&mut table, 0) as *const i32),
                1
            );
            assert_eq!(
                *(get_element_generic_table_avl(&mut table, 2) as *const i32),
                3
            );
            assert!(get_element_generic_table_avl(&mut table, 3).is_null());

            let mut restart: *mut c_void = null_mut();
            let no_splay_first =
                enumerate_generic_table_without_splaying_avl(&mut table, &mut restart);
            assert_eq!(*(no_splay_first as *const i32), 1);
            let no_splay_second =
                enumerate_generic_table_without_splaying_avl(&mut table, &mut restart);
            assert_eq!(*(no_splay_second as *const i32), 2);
        }
    }

    #[test]
    fn full_lookup_feeds_full_insert() {
        unsafe {
            let mut table = RtlAvlTable::zeroed();
            initialize_test_table(&mut table);
            let existing = 10i32;
            insert_element_generic_table_avl(
                &mut table,
                &existing as *const i32 as *mut c_void,
                core::mem::size_of::<i32>() as u32,
                null_mut(),
            );

            let missing = 5i32;
            let mut node_or_parent = null_mut();
            let mut result = TableSearchResult::TableEmptyTree;
            assert!(lookup_element_generic_table_full_avl(
                &mut table,
                &missing as *const _ as *mut c_void,
                &mut node_or_parent,
                &mut result,
            )
            .is_null());
            assert_eq!(result, TableSearchResult::TableInsertAsLeft);

            let mut inserted = 0u8;
            let added = insert_element_generic_table_full_avl(
                &mut table,
                &missing as *const _ as *mut c_void,
                core::mem::size_of::<i32>() as u32,
                &mut inserted,
                node_or_parent,
                result,
            );
            assert_eq!(inserted, 1);
            assert_eq!(*(added as *const i32), 5);
        }
    }

    #[test]
    fn lookup_first_matching_walks_to_leftmost_equal_match() {
        unsafe {
            let mut table = RtlAvlTable::zeroed();
            initialize_test_table(&mut table);
            for value in [20i32, 11, 10, 12, 30] {
                insert_element_generic_table_avl(
                    &mut table,
                    &value as *const i32 as *mut c_void,
                    core::mem::size_of::<i32>() as u32,
                    null_mut(),
                );
            }

            let key = -1i32;
            let mut restart: *mut c_void = null_mut();
            let first = lookup_first_matching_element_generic_table_avl(
                &mut table,
                &key as *const _ as *mut c_void,
                &mut restart,
            );
            assert_eq!(*(first as *const i32), 10);
            let restart_data =
                (restart as *const u8).add(TABLE_ENTRY_USER_DATA_OFFSET) as *const i32;
            assert_eq!(*restart_data, 10);
        }
    }

    unsafe extern "system" fn even_match(
        _table: *mut RtlAvlTable,
        user_data: *mut c_void,
        _match_data: *mut c_void,
    ) -> u32 {
        let value = unsafe { *(user_data as *const i32) };
        if value % 2 == 0 {
            STATUS_SUCCESS
        } else {
            STATUS_NO_MATCH
        }
    }

    #[test]
    fn like_a_directory_filters_and_recovers_after_delete() {
        unsafe {
            let mut table = RtlAvlTable::zeroed();
            initialize_test_table(&mut table);
            for value in [1i32, 2, 3, 4] {
                insert_element_generic_table_avl(
                    &mut table,
                    &value as *const i32 as *mut c_void,
                    core::mem::size_of::<i32>() as u32,
                    null_mut(),
                );
            }

            let mut restart: *mut c_void = null_mut();
            let mut delete_count = 0u32;
            let start = 1i32;
            let first_even = enumerate_generic_table_like_a_directory(
                &mut table,
                Some(even_match),
                null_mut(),
                0,
                &mut restart,
                &mut delete_count,
                &start as *const _ as *mut c_void,
            );
            assert_eq!(*(first_even as *const i32), 2);

            let delete = 2i32;
            assert!(delete_element_generic_table_avl(
                &mut table,
                &delete as *const _ as *mut c_void
            ));
            let next_even = enumerate_generic_table_like_a_directory(
                &mut table,
                Some(even_match),
                null_mut(),
                1,
                &mut restart,
                &mut delete_count,
                &delete as *const _ as *mut c_void,
            );
            assert_eq!(*(next_even as *const i32), 4);
            assert_eq!(delete_count, table.delete_count);
        }
    }
}
