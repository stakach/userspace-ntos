//! Host tests for the x64 layout crate.
//!
//! The load-bearing checks are the `const _: () = assert!(offset_of!(...))` in `lib.rs` (they fail
//! the BUILD on drift). These runtime tests re-assert the same offsets so `cargo test` reports them
//! explicitly, and add a few size/round-trip sanity checks.

use super::*;
use core::mem::{align_of, offset_of, size_of};

#[test]
fn peb_offsets() {
    assert_eq!(offset_of!(Peb, mutant), 0x08);
    assert_eq!(offset_of!(Peb, image_base_address), 0x10);
    assert_eq!(offset_of!(Peb, ldr), 0x18);
    assert_eq!(offset_of!(Peb, process_parameters), 0x20);
    assert_eq!(offset_of!(Peb, process_heap), 0x30);
    assert_eq!(offset_of!(Peb, fast_peb_lock), 0x38);
    assert_eq!(offset_of!(Peb, ansi_code_page_data), 0xA0);
    assert_eq!(offset_of!(Peb, oem_code_page_data), 0xA8);
    assert_eq!(offset_of!(Peb, unicode_case_table_data), 0xB0);
    assert_eq!(offset_of!(Peb, nt_global_flag), 0xBC);
    assert_eq!(offset_of!(Peb, session_id), 0x2C0);
    assert_eq!(offset_of!(Peb, activation_context_data), 0x2F8);
    assert_eq!(offset_of!(Peb, process_assembly_storage_map), 0x300);
    assert_eq!(
        offset_of!(Peb, system_default_activation_context_data),
        0x308
    );
    assert_eq!(offset_of!(Peb, system_assembly_storage_map), 0x310);
}

#[test]
fn teb_offsets() {
    assert_eq!(offset_of!(Teb, nt_tib), 0x000);
    assert_eq!(offset_of!(Teb, environment_pointer), 0x038);
    assert_eq!(offset_of!(Teb, client_id), 0x040);
    assert_eq!(offset_of!(Teb, thread_local_storage_pointer), 0x058);
    assert_eq!(offset_of!(Teb, process_environment_block), 0x060);
    assert_eq!(offset_of!(Teb, last_error_value), 0x068);
    assert_eq!(offset_of!(Teb, exception_code), 0x2C0);
    assert_eq!(offset_of!(Teb, activation_context_stack_pointer), 0x2C8);
    assert_eq!(offset_of!(Teb, last_status_value), 0x1250);
    assert_eq!(offset_of!(Teb, static_unicode_string), 0x1258);
    assert_eq!(offset_of!(Teb, static_unicode_buffer), 0x1268);
    assert_eq!(offset_of!(Teb, deallocation_stack), 0x1478);
    assert_eq!(offset_of!(Teb, vdm), 0x1690);
    assert_eq!(offset_of!(Teb, hard_error_mode), 0x16B0);
    assert_eq!(offset_of!(Teb, gdi_batch_count), 0x1740);
    assert_eq!(offset_of!(Teb, waiting_on_loader_lock), 0x1760);
    assert_eq!(offset_of!(Teb, tls_expansion_slots), 0x1780);
    assert_eq!(offset_of!(Teb, current_transaction_handle), 0x17B8);
    assert_eq!(offset_of!(Teb, active_frame), 0x17C0);
    assert_eq!(offset_of!(Teb, same_teb_flags), 0x17EE);
}

#[test]
fn ldr_offsets() {
    assert_eq!(offset_of!(PebLdrData, in_load_order_module_list), 0x10);
    assert_eq!(offset_of!(PebLdrData, in_memory_order_module_list), 0x20);
    assert_eq!(
        offset_of!(PebLdrData, in_initialization_order_module_list),
        0x30
    );
    assert_eq!(offset_of!(LdrDataTableEntry, in_memory_order_links), 0x10);
    assert_eq!(offset_of!(LdrDataTableEntry, dll_base), 0x30);
    assert_eq!(offset_of!(LdrDataTableEntry, entry_point), 0x38);
    assert_eq!(offset_of!(LdrDataTableEntry, full_dll_name), 0x48);
    assert_eq!(offset_of!(LdrDataTableEntry, base_dll_name), 0x58);
    assert_eq!(offset_of!(LdrDataTableEntry, time_date_stamp), 0x80);
    assert_eq!(
        offset_of!(LdrDataTableEntry, entry_point_activation_context),
        0x88
    );
    assert_eq!(offset_of!(LdrDataTableEntry, patch_information), 0x90);
    assert_eq!(size_of::<LdrDataTableEntry>(), 0x98);
}

#[test]
fn process_params_offsets() {
    assert_eq!(offset_of!(RtlUserProcessParameters, length), 0x04);
    assert_eq!(offset_of!(RtlUserProcessParameters, standard_input), 0x20);
    assert_eq!(
        offset_of!(RtlUserProcessParameters, current_directory_dospath),
        0x38
    );
    assert_eq!(offset_of!(RtlUserProcessParameters, dll_path), 0x50);
    assert_eq!(offset_of!(RtlUserProcessParameters, image_path_name), 0x60);
    assert_eq!(offset_of!(RtlUserProcessParameters, command_line), 0x70);
    assert_eq!(offset_of!(RtlUserProcessParameters, environment), 0x80);
    assert_eq!(offset_of!(RtlUserProcessParameters, window_title), 0xB0);
}

#[test]
fn primitive_sizes_and_alignment() {
    assert_eq!(size_of::<ListEntry>(), 0x10);
    assert_eq!(size_of::<UnicodeString>(), 0x10);
    assert_eq!(size_of::<ClientId>(), 0x10);
    assert_eq!(size_of::<NtTib>(), 0x38);
    // Everything is 8-byte aligned on x64.
    assert_eq!(align_of::<Peb>(), 8);
    assert_eq!(align_of::<Teb>(), 8);
}

#[test]
fn unicode_string_field_layout() {
    // length/maximum_length are the first two u16, then 4 pad bytes, then the 8-byte buffer ptr.
    assert_eq!(offset_of!(UnicodeString, length), 0x0);
    assert_eq!(offset_of!(UnicodeString, maximum_length), 0x2);
    assert_eq!(offset_of!(UnicodeString, buffer), 0x8);
}
