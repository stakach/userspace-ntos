use nt_nls::ValidatedAnsiSbcs;

fn cp1252_page() -> Vec<u16> {
    // RtlInitCodePageTable's header and complete SBCS wide-character table.
    let header_words = 13usize;
    let multibyte_index = header_words + 1;
    let wide_index = multibyte_index + 257;
    let mut page = vec![0u16; wide_index + 0x1_0000 / 2];
    page[0] = header_words as u16;
    page[1] = 1252;
    page[2] = 1;
    page[header_words] = 257;
    for byte in 0u16..=255 {
        page[multibyte_index + byte as usize] = byte;
    }
    page[multibyte_index + 0x80] = 0x20ac;
    page[wide_index + 0x20ac / 2] = 0x80;
    page
}

#[test]
fn cp1252_single_char_uses_published_table() {
    let page = cp1252_page();
    let ansi = ValidatedAnsiSbcs::from_cp1252_words(&page).unwrap();
    assert_eq!(ansi.ansi_char_to_unicode(0x80), 0x20ac);
    assert_eq!(ansi.ansi_char_to_unicode(b'A'), b'A' as u16);
}

#[test]
fn counted_conversion_honours_destination_bytes_and_reports_written_bytes() {
    let page = cp1252_page();
    let ansi = ValidatedAnsiSbcs::from_cp1252_words(&page).unwrap();
    let mut output = [0xdead; 3];
    assert_eq!(
        ansi.multibyte_to_unicode_n(&[b'A', 0x80, b'Z'], 5, &mut output),
        Some(4)
    );
    assert_eq!(output, [b'A' as u16, 0x20ac, 0xdead]);
    assert_eq!(ansi.multibyte_to_unicode_n(&[], 0, &mut output), Some(0));
}

#[test]
fn size_contract_uses_actual_sbcs_page_and_checks_overflow() {
    let page = cp1252_page();
    let ansi = ValidatedAnsiSbcs::from_cp1252_words(&page).unwrap();
    assert_eq!(ansi.multibyte_to_unicode_size(3), Some(6));
    assert_eq!(ansi.multibyte_to_unicode_size(u32::MAX), None);
    assert_eq!(ansi.unicode_to_multibyte_size(5), 2);
    assert_eq!(ansi.unicode_to_multibyte_size(0), 0);
}

#[test]
fn rejects_wrong_or_incomplete_published_page() {
    let mut page = cp1252_page();
    assert!(ValidatedAnsiSbcs::from_cp1252_words(&page).is_some());
    page[1] = 437;
    assert!(ValidatedAnsiSbcs::from_cp1252_words(&page).is_none());
    page[1] = 1252;
    page[14 + 0x80] = 0x80;
    assert!(ValidatedAnsiSbcs::from_cp1252_words(&page).is_none());
    page[14 + 0x80] = 0x20ac;
    assert!(ValidatedAnsiSbcs::from_cp1252_words(&page[..page.len() - 1]).is_none());
}
