use nt_memory_manager::{
    GenericSectionBacking, GenericSectionTable, RoutedSectionLease, SectionFileIdentity,
    SectionMountIds, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT,
};

fn file() -> SectionFileIdentity {
    SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id: 41,
    }
}

fn create(table: &mut GenericSectionTable, backing: GenericSectionBacking) -> Option<usize> {
    table.create(3, 0, 4096, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT, backing)
}

#[test]
fn local_file_lease_is_admitted_only_for_disk_backing() {
    let lease = RoutedSectionLease::new(1).unwrap();
    let mut table = GenericSectionTable::new();
    for mut backing in [
        GenericSectionBacking::anonymous(),
        GenericSectionBacking::overlay(7, file(), 4096),
        GenericSectionBacking::routed(RoutedSectionLease::new(2).unwrap(), file(), 4096),
    ] {
        backing.local_lease = Some(lease);
        assert!(create(&mut table, backing).is_none());
    }
    let mut backing = GenericSectionBacking::disk(7, 4096, file());
    backing.local_lease = Some(lease);
    assert!(create(&mut table, backing).is_some());
}

#[test]
fn a_local_lease_cannot_attach_twice_or_escape_pending_retirement() {
    let mut table = GenericSectionTable::new();
    let mut backing = GenericSectionBacking::disk(7, 4096, file());
    backing.local_lease = Some(RoutedSectionLease::new(1).unwrap());
    let index = create(&mut table, backing).unwrap();
    let old_identity = table.section_identity(index).unwrap();
    assert!(create(&mut table, backing).is_none());
    assert!(table.release_handle(index));
    let retirement = table.next_retirement().unwrap();
    assert!(create(&mut table, backing).is_none());
    assert!(table.complete_retirement(retirement));

    backing.local_lease = Some(RoutedSectionLease::new(2).unwrap());
    let next = create(&mut table, backing).unwrap();
    assert_ne!(table.section_identity(next), Some(old_identity));
    assert_eq!(
        table.section(next).unwrap().backing.local_lease,
        backing.local_lease
    );
}
