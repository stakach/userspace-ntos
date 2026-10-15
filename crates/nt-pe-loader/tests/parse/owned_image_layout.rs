use super::*;
use nt_pe_loader::PeLayout;

#[test]
fn owned_metadata_preserves_all_image_page_plans_without_payload() {
    let bytes = build_pe(
        BASE,
        0x1000,
        0x5000,
        &[
            text_section(0x1000, vec![0xcc; 0x1800]),
            Sec {
                name: *b".shared\0",
                va: 0x3000,
                chars: 0xd0000040,
                data: vec![0x55; 0x200],
            },
        ],
        &[],
    );
    let pe = PeFile::parse(&bytes).unwrap();
    let header_end = pe.headers().section_table_offset() + pe.sections().len() * 40;
    let layout = PeLayout::parse(&bytes[..header_end]).unwrap();
    assert_eq!(layout.headers().nt_offset, pe.headers().nt_offset);
    assert_eq!(layout.headers().image_base, pe.image_base());
    assert_eq!(layout.sections().len(), pe.sections().len());
    for (owned, borrowed) in layout.sections().iter().zip(pe.sections()) {
        assert_eq!(owned.virtual_address, borrowed.virtual_address);
        assert_eq!(owned.virtual_size, borrowed.virtual_size);
        assert_eq!(owned.pointer_to_raw_data, borrowed.pointer_to_raw_data);
        assert_eq!(owned.size_of_raw_data, borrowed.size_of_raw_data);
        assert_eq!(owned.characteristics, borrowed.characteristics);
    }
    for rva in (0..pe.size_of_image()).step_by(0x1000) {
        assert_eq!(
            layout.image_page_fill_plan(rva, bytes.len() as u64),
            pe.image_page_fill_plan(rva, bytes.len() as u64)
        );
        assert_eq!(layout.image_protection_at(rva), pe.image_protection_at(rva));
    }
    let owned = pe.into_layout();
    drop(bytes);
    assert_eq!(owned.size_of_image(), 0x5000);
    assert_eq!(
        owned.image_protection_at(0x1000),
        ImageProtection::ExecuteWriteCopy
    );
    assert_eq!(
        owned.image_protection_at(0x3000),
        ImageProtection::ReadWrite
    );
}

#[test]
fn owned_metadata_uses_the_existing_header_and_table_rejections() {
    let bytes = build_pe(
        BASE,
        0x1000,
        0x3000,
        &[text_section(0x1000, vec![0xcc; 0x200])],
        &[],
    );
    for length in [0, 0x3f, OPT_OFF + 111, SECTION_TABLE + 39] {
        let expected = PeFile::parse(&bytes[..length]).unwrap_err();
        assert_eq!(PeLayout::parse(&bytes[..length]).unwrap_err(), expected);
    }
    let mut too_many = bytes;
    put_u16(&mut too_many, NT_OFF + 6, 97);
    assert_eq!(
        PeLayout::parse(&too_many).unwrap_err(),
        PeError::TooManySections(97)
    );
}
