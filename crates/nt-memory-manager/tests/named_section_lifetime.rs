use nt_memory_manager::{
    GenericSectionBacking, GenericSectionTable, MemoryLifetime, ProcessGeneration, ProcessIdentity,
    SectionRetirementResource, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT,
};

fn create(table: &mut GenericSectionTable, handle: u64) -> usize {
    table
        .create(
            3,
            handle,
            4096,
            PAGE_READONLY,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap()
}

#[test]
fn retained_name_owner_allows_repeated_close_and_exact_handle_reopen() {
    let mut table = GenericSectionTable::new();
    let index = create(&mut table, 0x40);
    let identity = table.section_identity(index).unwrap();
    let name = table.retain_section(identity).unwrap();
    assert!(table.release_handle(index));

    for handle in [0x44, 0x48] {
        let opened = table.retain_section_reference(name).unwrap();
        assert_eq!(opened.identity(), identity);
        assert_eq!(table.section_identity(index), Some(opened.identity()));
        assert!(table.bind_section_reference_handle(opened, handle));
        assert_eq!(table.index_for_handle(3, handle), Some(index));
        assert!(table.release_section_reference(opened));
        assert!(table.release_handle(index));
        assert_eq!(table.section_identity(index), Some(identity));
        assert!(table.next_retirement().is_none());
    }

    assert!(table.release_section_reference(name));
    let retirement = table.next_retirement().unwrap();
    assert_eq!(retirement.identity(), identity);
    assert!(matches!(
        retirement.resource,
        SectionRetirementResource::Backing(_)
    ));
    assert!(table.complete_retirement(retirement));
    assert!(table.section_identity(index).is_none());
}

#[test]
fn removing_temporary_name_keeps_backing_until_the_last_exact_view_unmaps() {
    let mut table = GenericSectionTable::new();
    let index = create(&mut table, 0x40);
    let identity = table.section_identity(index).unwrap();
    let name = table.retain_section(identity).unwrap();
    let lifetime = MemoryLifetime::Process(ProcessIdentity {
        pid: 304,
        generation: ProcessGeneration::Hosted(2),
    });
    assert!(table.map_view_with_lifetime(3, lifetime, index, 0x10000, 4096, 0));
    let (_, view) = table.view_for_page(3, 0x10000).unwrap();
    assert!(table.release_handle(index));
    assert!(table.release_section_reference(name));
    assert!(table.retain_section_reference(name).is_none());
    assert!(table.next_retirement().is_none());
    assert_eq!(table.section_identity(index), Some(identity));
    assert_eq!(table.view_for_page(3, 0x10000).unwrap().1, view);

    assert_eq!(table.unmap_view_identity(view), Some(view));
    let retirement = table.next_retirement().unwrap();
    assert_eq!(retirement.identity(), identity);
    assert!(table.complete_retirement(retirement));
    assert!(table.unmap_view_identity(view).is_none());
    assert!(table.next_retirement().is_none());
}

#[test]
fn retired_name_reference_cannot_reopen_or_release_a_reused_section_index() {
    let mut table = GenericSectionTable::new();
    let old_index = create(&mut table, 0x40);
    let old_identity = table.section_identity(old_index).unwrap();
    let old_name = table.retain_section(old_identity).unwrap();
    assert!(table.release_handle(old_index));
    assert!(table.release_section_reference(old_name));
    let retirement = table.next_retirement().unwrap();
    assert!(table.complete_retirement(retirement));

    let new_index = create(&mut table, 0x44);
    let new_identity = table.section_identity(new_index).unwrap();
    assert_eq!(new_index, old_index);
    assert_ne!(new_identity, old_identity);
    assert!(table.retain_section(old_identity).is_none());
    assert!(table.retain_section_reference(old_name).is_none());
    assert!(!table.release_section_reference(old_name));
    assert!(!table.bind_section_reference_handle(old_name, 0x4c));
    assert_eq!(table.index_for_handle(3, 0x44), Some(new_index));
    assert_eq!(table.section_identity(new_index), Some(new_identity));
    assert!(table.next_retirement().is_none());

    let new_name = table.retain_section(new_identity).unwrap();
    assert!(table.release_handle(new_index));
    let reopened = table.retain_section_reference(new_name).unwrap();
    assert_eq!(table.section_identity(new_index), Some(reopened.identity()));
    assert!(table.bind_section_reference_handle(reopened, 0x48));
    assert!(table.release_section_reference(reopened));
    assert_eq!(table.index_for_handle(3, 0x48), Some(new_index));
}

#[test]
fn handle_binding_requires_an_owned_lease_not_a_consumed_copy() {
    let mut table = GenericSectionTable::new();
    let index = create(&mut table, 0x40);
    let identity = table.section_identity(index).unwrap();
    let name = table.retain_section(identity).unwrap();
    assert!(table.release_handle(index));
    let consumed = table.retain_section_reference(name).unwrap();
    assert!(table.release_section_reference(consumed));
    assert!(!table.bind_section_reference_handle(consumed, 0x44));
    assert_eq!(table.section(index).unwrap().handle, 0);
    assert!(table.next_retirement().is_none());
    let current = table.retain_section_reference(name).unwrap();
    assert!(table.bind_section_reference_handle(current, 0x48));
    assert_eq!(table.index_for_handle(3, 0x48), Some(index));
}

#[test]
fn foreign_table_reference_cannot_bind_coincident_section_identity() {
    let mut first = GenericSectionTable::new();
    let mut second = GenericSectionTable::new();
    let first_index = create(&mut first, 0x40);
    let second_index = create(&mut second, 0x44);
    let first_identity = first.section_identity(first_index).unwrap();
    let second_identity = second.section_identity(second_index).unwrap();
    assert_eq!(first_identity, second_identity);
    let foreign = first.retain_section(first_identity).unwrap();
    let local = second.retain_section(second_identity).unwrap();
    assert!(second.release_handle(second_index));
    assert!(!second.bind_section_reference_handle(foreign, 0x48));
    assert_eq!(second.section(second_index).unwrap().handle, 0);
    assert_eq!(first.index_for_handle(3, 0x40), Some(first_index));
    assert!(second.bind_section_reference_handle(local, 0x4c));
    assert_eq!(second.index_for_handle(3, 0x4c), Some(second_index));
}

#[test]
fn zero_handle_refusal_preserves_the_exact_reference_and_section() {
    let mut table = GenericSectionTable::new();
    let index = create(&mut table, 0x40);
    let identity = table.section_identity(index).unwrap();
    let name = table.retain_section(identity).unwrap();
    assert!(table.release_handle(index));
    let before = table.section(index).unwrap();
    assert!(!table.bind_section_reference_handle(name, 0));
    assert_eq!(table.section(index), Some(before));
    assert!(table.next_retirement().is_none());
    let opened = table.retain_section_reference(name).unwrap();
    assert!(table.bind_section_reference_handle(opened, 0x44));
    assert!(table.release_section_reference(opened));
    assert_eq!(table.index_for_handle(3, 0x44), Some(index));
}
