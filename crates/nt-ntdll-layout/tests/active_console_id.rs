//! The pinned LiberNT kernel setter writes KUSER_SHARED_DATA.ActiveConsoleId at +0x2d8.

use nt_ntdll_layout::kuser::{
    initialize_page, read_active_console_id, write_active_console_id, StaticInformation,
    ACTIVE_CONSOLE_ID, PAGE_SIZE,
};

#[test]
fn active_console_update_is_visible_in_the_shared_page_without_clobbering_version() {
    assert_eq!(ACTIVE_CONSOLE_ID, 0x2d8);
    let mut page = [0u8; PAGE_SIZE];
    initialize_page(
        &mut page,
        StaticInformation {
            nt_product_type: 1,
            nt_major_version: 10,
            nt_minor_version: 0,
            image_number_low: 0x14c,
            image_number_high: 0x8664,
            number_of_physical_pages: 65536,
            active_processor_count: 1,
            processor_feature_bits: 0,
            cookie: 0x1234_5678,
        },
        10_000,
        20_000,
        b"C:\\Windows",
    );
    let previous = page;
    write_active_console_id(&mut page, 7);
    assert_eq!(read_active_console_id(&page), 7);
    assert_eq!(&page[ACTIVE_CONSOLE_ID..ACTIVE_CONSOLE_ID + 4], &7u32.to_le_bytes());
    assert_eq!(&page[..ACTIVE_CONSOLE_ID], &previous[..ACTIVE_CONSOLE_ID]);
    assert_eq!(&page[ACTIVE_CONSOLE_ID + 4..], &previous[ACTIVE_CONSOLE_ID + 4..]);
}
