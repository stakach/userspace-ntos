use super::*;

fn routed(protection: u32, size: u64) -> (GenericSectionTable, usize, SectionIdentity) {
    let mut table = GenericSectionTable::new();
    let file = SectionFileIdentity { mount: SectionMountIds::new().allocate().unwrap(), file_id: 9 };
    let backing = GenericSectionBacking::routed(RoutedSectionLease::new(11).unwrap(), file, 0x1800);
    let section = table
        .create(2, 0x40, size, protection, SECTION_ATTR_SEC_COMMIT, backing)
        .unwrap();
    let identity = table.section_identity(section).unwrap();
    (table, section, identity)
}

#[test]
fn extension_never_shrinks_and_reports_the_current_size() {
    let (table, _, identity) = routed(crate::PAGE_READWRITE, 0x1800);
    assert_eq!(table.plan_section_extension(identity, 0x1000), Ok(SectionExtension::Unchanged(0x1800)));
    assert_eq!(table.plan_section_extension(identity, 0x1800), Ok(SectionExtension::Unchanged(0x1800)));
}

#[test]
fn a_section_smaller_than_its_file_grows_without_a_file_effect() {
    let (mut table, section, identity) = routed(crate::PAGE_READONLY, 0x1000);
    assert_eq!(
        table.plan_section_extension(identity, 0x1800),
        Ok(SectionExtension::Grow { new_size: 0x1800, end_of_file: 0x1800 })
    );
    assert_eq!(table.commit_section_extension(identity, 0x1800, 0x1800), Ok(0x1800));
    assert_eq!(table.section(section).unwrap().size, 0x1800);
}

#[test]
fn growing_past_the_file_sets_its_end_of_file_first() {
    let (mut table, section, identity) = routed(crate::PAGE_READWRITE, 0x1800);
    assert_eq!(
        table.plan_section_extension(identity, 0x5000),
        Ok(SectionExtension::ExtendFile { new_size: 0x5000 })
    );
    // MmExtendSection refuses a section created without write access (extsect.c).
    let (readonly, _, readonly_identity) = routed(crate::PAGE_READONLY, 0x1800);
    assert_eq!(readonly.plan_section_extension(readonly_identity, 0x5000), Err(STATUS_SECTION_NOT_EXTENDED));
    // The filesystem's new end of file must cover the section.
    assert_eq!(
        table.commit_section_extension(identity, 0x5000, 0x4fff),
        Err(crate::data_section::STATUS_IO_DEVICE_ERROR)
    );
    assert_eq!(table.commit_section_extension(identity, 0x5000, 0x5000), Ok(0x5000));
    assert_eq!(table.section(section).unwrap().size, 0x5000);
    assert!(table.map_view(3, section, 0x10000, 0x5000, 0), "views may cover the larger section");
    assert_eq!(table.plan_section_extension(identity, 0x5000), Ok(SectionExtension::Unchanged(0x5000)));
}

#[test]
fn image_and_page_file_sections_are_not_extended() {
    let mut table = GenericSectionTable::new();
    let anonymous = table
        .create(2, 0x40, 0x1000, crate::PAGE_READWRITE, SECTION_ATTR_SEC_COMMIT, GenericSectionBacking::anonymous())
        .unwrap();
    let identity = table.section_identity(anonymous).unwrap();
    assert_eq!(table.plan_section_extension(identity, 0x2000), Err(STATUS_SECTION_NOT_EXTENDED));
    let (table, _, identity) = routed(crate::PAGE_READWRITE, 0x1800);
    assert_eq!(
        table.plan_section_extension(identity, crate::data_section::MAX_DATA_SECTION_SIZE + 0x1000),
        Err(crate::STATUS_SECTION_TOO_BIG)
    );
}
