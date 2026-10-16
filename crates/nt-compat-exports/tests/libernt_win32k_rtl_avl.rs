//! The pinned LiberNT win32k imports the four native AVL generic-table entry points.
//! This exercises their shared RTL owner through the x64 callback ABI, independent of
//! the executive's import bindings.

use core::ffi::c_void;
use nt_compat_exports::avl_table::{
    delete_element_generic_table_avl, initialize_generic_table_avl,
    insert_element_generic_table_avl, lookup_element_generic_table_avl, RtlAvlTable,
    GENERIC_EQUAL, GENERIC_GREATER_THAN, GENERIC_LESS_THAN,
};

unsafe extern "system" fn compare(
    _table: *mut RtlAvlTable,
    left: *mut c_void,
    right: *mut c_void,
) -> u32 {
    let (left, right) = unsafe { (*(left as *const u32), *(right as *const u32)) };
    if left < right {
        GENERIC_LESS_THAN
    } else if left > right {
        GENERIC_GREATER_THAN
    } else {
        GENERIC_EQUAL
    }
}

unsafe extern "system" fn allocate(_table: *mut RtlAvlTable, bytes: u32) -> *mut c_void {
    let layout = std::alloc::Layout::from_size_align(bytes as usize, 8).unwrap();
    unsafe { std::alloc::alloc(layout) as *mut c_void }
}

unsafe extern "system" fn free(_table: *mut RtlAvlTable, _node: *mut c_void) {
    // The small test allocation is intentionally retained because the RTL callback has no size.
}

#[test]
fn four_libernt_avl_imports_share_one_ordered_table() {
    let mut table = RtlAvlTable::zeroed();
    unsafe {
        initialize_generic_table_avl(
            &mut table,
            Some(compare),
            Some(allocate),
            Some(free),
            core::ptr::null_mut(),
        );
        for value in [30u32, 10, 20] {
            let mut inserted = 0u8;
            let element = insert_element_generic_table_avl(
                &mut table,
                &value as *const u32 as *mut c_void,
                4,
                &mut inserted,
            );
            assert!(!element.is_null());
            assert_eq!(inserted, 1);
        }
        let key = 20u32;
        let element = lookup_element_generic_table_avl(
            &mut table,
            &key as *const u32 as *mut c_void,
        );
        assert!(!element.is_null());
        assert_eq!(*(element as *const u32), key);

        let mut duplicate = 1u8;
        let same = insert_element_generic_table_avl(
            &mut table,
            &key as *const u32 as *mut c_void,
            4,
            &mut duplicate,
        );
        assert_eq!(same, element);
        assert_eq!(duplicate, 0);
        assert_eq!(table.number_generic_table_elements, 3);

        assert!(delete_element_generic_table_avl(
            &mut table,
            &key as *const u32 as *mut c_void,
        ));
        assert!(lookup_element_generic_table_avl(
            &mut table,
            &key as *const u32 as *mut c_void,
        )
        .is_null());
        assert_eq!(table.number_generic_table_elements, 2);
    }
}
