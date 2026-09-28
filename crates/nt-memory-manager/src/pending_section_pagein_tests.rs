use super::*;
use crate::data_section::plan_data_section_page_read;
use crate::{GenericSectionBacking, GenericSectionTable, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT};
use alloc::boxed::Box;

fn section() -> SectionIdentity {
    let mut table = GenericSectionTable::new();
    let index = table
        .create(
            2,
            0x40,
            0x3000,
            PAGE_READONLY,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap();
    table.section_identity(index).unwrap()
}

fn lease() -> RoutedSectionLease {
    RoutedSectionLease::new(7).unwrap()
}

#[test]
fn terminal_output_is_staged_exactly_before_backend_ack() {
    let section = section();
    let plan = plan_data_section_page_read(2, 0x3000, 0x2100).unwrap();
    let mut reads = PendingSectionPageReads::<Box<u32>, (u64, u64)>::new();
    let id = reads
        .reserve(section, lease(), 2, plan, Box::new(17))
        .unwrap();
    let key = (41, 91);
    assert_eq!(reads.identity(id), Some((section, lease(), 2)));
    assert!(reads.bind(id, key));
    assert!(!reads.bind(id, key));
    assert!(!reads.terminal(id, key, STATUS_PENDING, 0));
    assert!(reads.ready_page(id, key).is_none());
    assert!(reads.terminal(id, key, 0, plan.length() as u64));
    assert!(!reads.append(id, (41, 92), 0, &[1]));
    assert!(!reads.append(id, key, 1, &[1]));
    assert!(reads.append(id, key, 0, &[0xa5; 0x80]));
    assert!(reads.ready_page(id, key).is_none());
    assert!(!reads.acknowledge_backend(id, key));
    assert!(!reads.append(id, key, 0, &[0xa5; 0x80]));
    assert!(reads.append(id, key, 0x80, &[0x5a; 0x80]));
    let page = reads.ready_page(id, key).unwrap();
    assert_eq!(&page[..0x80], &[0xa5; 0x80]);
    assert_eq!(&page[0x80..0x100], &[0x5a; 0x80]);
    assert!(page[0x100..].iter().all(|byte| *byte == 0));
    assert!(reads.take_acknowledged(id, key).is_none());
    assert!(reads.acknowledge_backend(id, key));
    assert!(!reads.acknowledge_backend(id, key));
    assert!(reads.take_acknowledged(id, (41, 92)).is_none());
    let (owner, bytes) = reads.take_acknowledged(id, key).unwrap();
    assert_eq!(*owner, 17);
    assert_eq!(bytes.unwrap().len(), DATA_PAGE_SIZE);
    assert!(reads.identity(id).is_none());
}

#[test]
fn short_or_failed_terminal_never_exposes_a_page() {
    let plan = plan_data_section_page_read(0, 0x1000, 0x1000).unwrap();
    for (status, information, expected) in [
        (0, (DATA_PAGE_SIZE - 1) as u64, STATUS_IO_DEVICE_ERROR),
        (0xc000_0008, DATA_PAGE_SIZE as u64, 0xc000_0008),
    ] {
        let mut reads = PendingSectionPageReads::<Box<u32>, u64>::new();
        let id = reads
            .reserve(section(), lease(), 0, plan, Box::new(23))
            .unwrap();
        assert!(reads.bind(id, 81));
        assert!(!reads.terminal(id, 82, status, information));
        assert!(reads.terminal(id, 81, status, information));
        assert_eq!(reads.failure(id, 81), Some(expected));
        assert!(reads.ready_page(id, 81).is_none());
        assert!(!reads.append(id, 81, 0, &[1]));
        assert!(reads.take_acknowledged(id, 81).is_none());
        assert!(reads.acknowledge_backend(id, 81));
        let (owner, result) = reads.take_acknowledged(id, 81).unwrap();
        assert_eq!(*owner, 23);
        assert_eq!(result, Err(expected));
    }
}

#[test]
fn cancelled_and_reused_slots_reject_stale_ids_and_foreign_stores() {
    let plan = plan_data_section_page_read(0, 0x1000, 0x1000).unwrap();
    let mut first = PendingSectionPageReads::<Box<u32>, u64>::new();
    let old = first
        .reserve(section(), lease(), 0, plan, Box::new(11))
        .unwrap();
    assert_eq!(first.cancel_reserved(old).map(|owner| *owner), Some(11));
    assert!(first.identity(old).is_none());
    let replacement = first
        .reserve(section(), lease(), 0, plan, Box::new(12))
        .unwrap();
    assert_ne!(old, replacement);
    assert!(!first.bind(old, 71));
    assert!(first.bind(replacement, 71));
    assert!(first.cancel_reserved(replacement).is_none());

    let mut second = PendingSectionPageReads::<Box<u32>, u64>::new();
    let foreign = second
        .reserve(section(), lease(), 0, plan, Box::new(13))
        .unwrap();
    assert!(!second.bind(replacement, 72));
    assert!(!first.bind(foreign, 72));
    assert!(second.bind(foreign, 72));
}

#[test]
fn one_provider_key_cannot_own_two_live_page_reads() {
    let plan = plan_data_section_page_read(0, 0x1000, 0x1000).unwrap();
    let mut reads = PendingSectionPageReads::<Box<u32>, (u64, u64)>::new();
    let first = reads
        .reserve(section(), lease(), 0, plan, Box::new(1))
        .unwrap();
    let second = reads
        .reserve(section(), lease(), 0, plan, Box::new(2))
        .unwrap();
    let key = (41, 91);
    assert!(reads.bind(first, key));
    assert!(!reads.bind(second, key));
    assert!(reads.bind(second, (41, 92)));
    assert!(!reads.terminal(first, (41, 92), 0, plan.length() as u64));
    assert!(reads.terminal(first, key, 0xc000_0008, 0));
    assert!(!reads.terminal(first, key, 0, plan.length() as u64));
}

#[test]
fn invalid_geometry_and_generation_exhaustion_return_the_owner() {
    let plan = plan_data_section_page_read(1, 0x2000, 0x2000).unwrap();
    let mut reads = PendingSectionPageReads::<Box<u32>, u64>::new();
    assert_eq!(
        reads
            .reserve(section(), lease(), 0, plan, Box::new(31))
            .map_err(|owner| *owner),
        Err(31),
    );
    reads.next_generation = u64::MAX;
    assert_eq!(
        reads
            .reserve(section(), lease(), 1, plan, Box::new(32))
            .map_err(|owner| *owner),
        Err(32),
    );
}
