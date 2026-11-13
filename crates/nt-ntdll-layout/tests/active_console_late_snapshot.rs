//! A process created after console activation must inherit the current KUSER value.

use nt_ntdll_layout::kuser::{
    initialize_page_with_active_console, read_active_console_id, StaticInformation,
    ACTIVE_CONSOLE_ID, NT_MAJOR_VERSION, PAGE_SIZE,
};

#[test]
fn late_kuser_snapshot_inherits_active_console_without_changing_other_fields() {
    let mut page = [0xa5; PAGE_SIZE];
    initialize_page_with_active_console(
        &mut page,
        StaticInformation {
            nt_product_type: 1,
            nt_major_version: 10,
            nt_minor_version: 0,
            image_number_low: 0x014c,
            image_number_high: 0x8664,
            number_of_physical_pages: 65536,
            active_processor_count: 1,
            processor_feature_bits: 0,
            cookie: 0x1234_5678,
        },
        10_000,
        20_000,
        b"C:\\Windows",
        7,
    );
    assert_eq!(read_active_console_id(&page), 7);
    assert_eq!(&page[ACTIVE_CONSOLE_ID..ACTIVE_CONSOLE_ID + 4], &7u32.to_le_bytes());
    assert_eq!(&page[NT_MAJOR_VERSION..NT_MAJOR_VERSION + 4], &10u32.to_le_bytes());
    assert_eq!(&page[ACTIVE_CONSOLE_ID + 4..ACTIVE_CONSOLE_ID + 8], &[0; 4]);
}
