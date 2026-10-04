use nt_memory_manager::{GenericSectionBacking, GenericSectionTable, SectionFileIdentity,
    SectionMountIds, SectionRetirementResource, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT};

#[test]
fn explicit_namespace_reference_keeps_data_backing_until_exact_name_owner_release() {
    let mut mounts = SectionMountIds::new();
    let file = SectionFileIdentity { mount: mounts.allocate().unwrap(), file_id: 41 };
    let backing = GenericSectionBacking::disk(7, 4096, file);
    let mut table = GenericSectionTable::new();
    let index = table.create(3, 0x40, 4096, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT, backing).unwrap();
    let identity = table.section_identity(index).unwrap();
    let name_owner = table.retain_section(identity).unwrap();
    assert!(table.release_handle(index));
    assert_eq!(table.section(index).unwrap().backing, backing);
    assert!(table.next_retirement().is_none());
    let open_owner = table.retain_section_reference(name_owner).unwrap();
    assert!(table.release_section_reference(name_owner));
    assert!(table.retain_section_reference(name_owner).is_none());
    assert!(table.next_retirement().is_none());
    assert!(table.release_section_reference(open_owner));
    let retirement = table.next_retirement().unwrap();
    assert_eq!(retirement.identity(), identity);
    assert_eq!(retirement.resource, SectionRetirementResource::Backing(backing));
    assert!(!table.release_section_reference(name_owner));
    assert_eq!(table.next_retirement(), Some(retirement));
    assert!(table.complete_retirement(retirement));
    assert!(table.next_retirement().is_none());
}
