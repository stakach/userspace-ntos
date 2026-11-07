//! A released x64 driver supplies Win64 AVL callbacks even on a non-Windows host.

#![cfg(target_arch = "x86_64")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use nt_compat_exports::avl_table::{
    find_avl_table_node_or_parent, initialize_generic_table_avl, BalancedLinks, CompareRoutine,
    RtlAvlTable, TableSearchResult, GENERIC_EQUAL,
};

static SEEN_TABLE: AtomicUsize = AtomicUsize::new(0);
static SEEN_LEFT: AtomicUsize = AtomicUsize::new(0);
static SEEN_RIGHT: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct Entry {
    links: BalancedLinks,
    payload: usize,
}

unsafe extern "win64" fn driver_compare(
    table: *mut RtlAvlTable,
    left: *mut c_void,
    right: *mut c_void,
) -> u32 {
    // Deliberately avoid dereferencing: the old SysV call puts these in the
    // wrong registers and must fail an assertion rather than fault the host.
    SEEN_TABLE.store(table as usize, Ordering::SeqCst);
    SEEN_LEFT.store(left as usize, Ordering::SeqCst);
    SEEN_RIGHT.store(right as usize, Ordering::SeqCst);
    GENERIC_EQUAL
}

#[test]
fn avl_invokes_released_driver_compare_with_win64_arguments() {
    let mut table = RtlAvlTable::zeroed();
    let mut entry = Entry {
        links: BalancedLinks::zeroed(),
        payload: 7,
    };
    let mut lookup = 7usize;
    let mut found = core::ptr::null_mut();
    let table_ptr = &mut table as *mut RtlAvlTable;
    let lookup_ptr = &mut lookup as *mut usize as *mut c_void;
    let entry_ptr = &mut entry.payload as *mut usize as *mut c_void;
    let entry_links = &mut entry.links as *mut BalancedLinks;
    let callback: CompareRoutine = driver_compare;
    unsafe {
        initialize_generic_table_avl(table_ptr, Some(callback), None, None, core::ptr::null_mut());
        (*table_ptr).balanced_root.right_child = entry_links;
        (*table_ptr).number_generic_table_elements = 1;
        assert_eq!(
            find_avl_table_node_or_parent(table_ptr, lookup_ptr, &mut found),
            TableSearchResult::TableFoundNode,
        );
    }
    assert_eq!(found, entry_links);
    assert_eq!(SEEN_TABLE.load(Ordering::SeqCst), table_ptr as usize);
    assert_eq!(SEEN_LEFT.load(Ordering::SeqCst), lookup_ptr as usize);
    assert_eq!(SEEN_RIGHT.load(Ordering::SeqCst), entry_ptr as usize);
}
