//! Native `RTL_AVL_TABLE` exports shared by hosted driver and win32k domains.

use core::ffi::c_void;
use nt_compat_exports::{avl_table, DriverExportRegistry};

type RtlAvlTable = avl_table::RtlAvlTable;

pub(crate) extern "win64" fn rtl_initialize_generic_table_avl(
    table: *mut RtlAvlTable,
    compare: Option<avl_table::CompareRoutine>,
    allocate: Option<avl_table::AllocateRoutine>,
    free: Option<avl_table::FreeRoutine>,
    context: *mut c_void,
) {
    unsafe { avl_table::initialize_generic_table_avl(table, compare, allocate, free, context) }
}

pub(crate) extern "win64" fn rtl_insert_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
    buffer_size: u32,
    new_element: *mut u8,
) -> *mut c_void {
    unsafe { avl_table::insert_element_generic_table_avl(table, buffer, buffer_size, new_element) }
}

pub(crate) extern "win64" fn rtl_lookup_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
) -> *mut c_void {
    unsafe { avl_table::lookup_element_generic_table_avl(table, buffer) }
}

pub(crate) extern "win64" fn rtl_delete_element_generic_table_avl(
    table: *mut RtlAvlTable,
    buffer: *mut c_void,
) -> u8 {
    unsafe { avl_table::delete_element_generic_table_avl(table, buffer) as u8 }
}

pub(crate) extern "win64" fn rtl_number_generic_table_elements_avl(
    table: *mut RtlAvlTable,
) -> u32 {
    unsafe { avl_table::number_generic_table_elements_avl(table) }
}

pub(crate) fn bind_rtl_avl_exports(reg: &mut DriverExportRegistry) {
    reg.bind("RtlInitializeGenericTableAvl", rtl_initialize_generic_table_avl as usize as u64);
    reg.bind("RtlInsertElementGenericTableAvl", rtl_insert_element_generic_table_avl as usize as u64);
    reg.bind("RtlLookupElementGenericTableAvl", rtl_lookup_element_generic_table_avl as usize as u64);
    reg.bind("RtlDeleteElementGenericTableAvl", rtl_delete_element_generic_table_avl as usize as u64);
    reg.bind("RtlNumberGenericTableElementsAvl", rtl_number_generic_table_elements_avl as usize as u64);
}
