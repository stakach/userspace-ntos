use super::*;
use crate::{
    admit_private_page_retirement, ClientFrameReclaimError, ClientFrameReclaimIntent,
    ClientFrameReclaimIo, MemoryLifetime, PagefilePage, ProcessGeneration, ProcessIdentity,
    STATUS_INVALID_HANDLE,
};
use alloc::vec::Vec;

fn process(generation: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(generation),
    }
}

fn resident(frames: &mut ClientFrameRegistry, pi: u64, page: u64, generation: u64, owned: bool) {
    frames
        .insert(
            pi,
            MemoryLifetime::Process(process(generation)),
            page,
            page + 1,
            0,
            0,
            0,
            owned,
        )
        .unwrap();
}

fn transition(store: &mut PagefileStore, pi: u64, page: u64, generation: u64) {
    let plan = store
        .prepare_publish(PagefilePage {
            owner: pi,
            lifetime: MemoryLifetime::Process(process(generation)),
            page,
            protection: 4,
            backing: page + 2,
        })
        .unwrap();
    store.commit_publish(plan).unwrap();
}

#[test]
fn sparse_multi_gib_range_returns_only_lowest_existing_pages() {
    let base = 0x1_0000_0000;
    let end = 0x8_0000_0000;
    let mut frames = ClientFrameRegistry::new();
    let mut pagefile = PagefileStore::new();
    resident(&mut frames, 7, end - 0x1000, 1, true);
    resident(&mut frames, 7, base + 0x1000, 1, true);
    transition(&mut pagefile, 7, 0x4_0000_0000, 1);
    let mut cursor = base;
    let mut selected = Vec::new();
    while let Some(page) = next_private_page_in_range(7, cursor, end, &frames, &pagefile).unwrap() {
        selected.push(page);
        assert!(selected.len() <= 3, "no absent-page walking");
        cursor = page + 0x1000;
    }
    assert_eq!(selected, [base + 0x1000, 0x4_0000_0000, end - 0x1000]);
    assert_eq!(frames.len(), 2);
    assert_eq!(pagefile.stats().pages, 1);
}

#[test]
fn pagefile_only_and_duplicate_backings_share_one_selected_address() {
    let mut frames = ClientFrameRegistry::new();
    let mut pagefile = PagefileStore::new();
    transition(&mut pagefile, 7, 0x2000, 1);
    assert_eq!(
        next_private_page_in_range(7, 0x1000, 0x5000, &frames, &pagefile),
        Ok(Some(0x2000))
    );
    resident(&mut frames, 7, 0x2000, 1, true);
    transition(&mut pagefile, 7, 0x4000, 1);
    assert_eq!(
        next_private_page_in_range(7, 0x1000, 0x5000, &frames, &pagefile),
        Ok(Some(0x2000))
    );
    assert_eq!(
        next_private_page_in_range(7, 0x3000, 0x5000, &frames, &pagefile),
        Ok(Some(0x4000))
    );
}

#[test]
fn foreign_generation_is_enumerated_then_rejected_by_exact_retirement_admission() {
    let mut frames = ClientFrameRegistry::new();
    let mut pagefile = PagefileStore::new();
    resident(&mut frames, 7, 0x1000, 1, true);
    transition(&mut pagefile, 7, 0x2000, 1);
    for page in [0x1000, 0x2000] {
        assert_eq!(
            next_private_page_in_range(7, page, 0x3000, &frames, &pagefile),
            Ok(Some(page))
        );
        assert_eq!(
            admit_private_page_retirement(7, process(2), page, &frames, &pagefile),
            Err(STATUS_INVALID_HANDLE)
        );
    }
}

#[test]
fn other_slots_are_excluded_but_non_owning_client_mappings_remain_visible() {
    let mut frames = ClientFrameRegistry::new();
    let mut pagefile = PagefileStore::new();
    resident(&mut frames, 8, 0x1000, 1, true);
    transition(&mut pagefile, 8, 0x2000, 1);
    resident(&mut frames, 7, 0x3000, 1, false);
    assert_eq!(
        next_private_page_in_range(7, 0, 0x4000, &frames, &pagefile),
        Ok(Some(0x3000))
    );
    assert_eq!(
        next_private_page_in_range(9, 0, 0x4000, &frames, &pagefile),
        Ok(None)
    );
}

#[test]
fn reclaiming_and_retiring_records_are_not_filtered_as_absent() {
    let mut frames = ClientFrameRegistry::new();
    let mut pagefile = PagefileStore::new();
    resident(&mut frames, 7, 0x1000, 1, true);
    let record = frames.get(7, 0x1000).unwrap();
    let retained = frames
        .begin_reclaim_exact(record, ClientFrameReclaimIntent::Release)
        .unwrap();
    assert!(retained.is_reclaiming());
    assert!(!retained.is_resident());
    transition(&mut pagefile, 7, 0x2000, 1);
    let retirement = pagefile.begin_retirement(7, 0x2000).unwrap().unwrap();
    assert!(!retirement.cleanup_complete());
    assert_eq!(
        next_private_page_in_range(7, 0, 0x3000, &frames, &pagefile),
        Ok(Some(0x1000))
    );
    assert_eq!(
        next_private_page_in_range(7, 0x2000, 0x3000, &frames, &pagefile),
        Ok(Some(0x2000))
    );
    assert_eq!(frames.get(7, 0x1000), Some(retained));
    assert_eq!(pagefile.retirements().next(), Some(retirement));
}

#[test]
fn half_open_bounds_include_base_exclude_end_and_allow_empty_range() {
    let mut frames = ClientFrameRegistry::new();
    let mut pagefile = PagefileStore::new();
    resident(&mut frames, 7, 0x1000, 1, true);
    transition(&mut pagefile, 7, 0x2000, 1);
    resident(&mut frames, 7, 0x3000, 1, true);
    assert_eq!(
        next_private_page_in_range(7, 0x2000, 0x3000, &frames, &pagefile),
        Ok(Some(0x2000))
    );
    assert_eq!(
        next_private_page_in_range(7, 0x3000, 0x3000, &frames, &pagefile),
        Ok(None)
    );
    assert_eq!(
        next_private_page_in_range(7, 0x4000, 0x5000, &frames, &pagefile),
        Ok(None)
    );
}

#[test]
fn reversed_and_unaligned_ranges_are_invalid_even_without_backings() {
    let frames = ClientFrameRegistry::new();
    let pagefile = PagefileStore::new();
    for (base, end) in [(0x2000, 0x1000), (1, 0x2000), (0x1000, 0x2001), (1, 1)] {
        assert_eq!(
            next_private_page_in_range(7, base, end, &frames, &pagefile),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}

#[test]
fn failed_cleanup_keeps_exact_page_visible_instead_of_advancing_to_successor() {
    struct RefuseUnmap {
        calls: usize,
    }
    impl ClientFrameReclaimIo for RefuseUnmap {
        fn unmap(&mut self, _: u64) -> Result<(), u32> {
            self.calls += 1;
            Err(0xC000_009A)
        }
        fn delete(&mut self, _: u64) -> Result<(), u32> {
            panic!("failed unmap cannot authorize deletion")
        }
        fn recycle_empty(&mut self, _: u64) -> Result<(), u32> {
            panic!("failed unmap cannot authorize recycling")
        }
        fn revoke(&mut self, _: u64) -> Result<(), u32> {
            panic!("failed unmap cannot authorize revocation")
        }
    }
    let mut frames = ClientFrameRegistry::new();
    let pagefile = PagefileStore::new();
    resident(&mut frames, 7, 0x1000, 1, true);
    resident(&mut frames, 7, 0x2000, 1, true);
    let page = next_private_page_in_range(7, 0, 0x3000, &frames, &pagefile)
        .unwrap()
        .unwrap();
    let original = frames.get(7, page).unwrap();
    let intent = ClientFrameReclaimIntent::Release;
    let retained = frames.begin_reclaim_exact(original, intent).unwrap();
    let mut backend = RefuseUnmap { calls: 0 };
    assert_eq!(
        frames.cleanup_reclaim_exact(retained, intent, &mut backend),
        Err(ClientFrameReclaimError::Backend(0xC000_009A))
    );
    assert_eq!(backend.calls, 1);
    assert_eq!(frames.get(7, page), Some(retained));
    assert_eq!(frames.len(), 2);
    assert_eq!(
        next_private_page_in_range(7, 0, 0x3000, &frames, &pagefile),
        Ok(Some(page))
    );
    assert_eq!(page, 0x1000);
}

#[test]
fn empty_multi_gib_range_has_no_candidate() {
    let frames = ClientFrameRegistry::new();
    let pagefile = PagefileStore::new();
    assert_eq!(
        next_private_page_in_range(7, 0x1_0000_0000, 0x8_0000_0000, &frames, &pagefile),
        Ok(None)
    );
}

#[test]
fn highest_aligned_end_allows_page_cursor_advance_without_overflow() {
    let end = u64::MAX & !(WORKING_SET_PAGE_SIZE - 1);
    let base = end - WORKING_SET_PAGE_SIZE;
    let mut frames = ClientFrameRegistry::new();
    let pagefile = PagefileStore::new();
    resident(&mut frames, 7, base, 1, true);
    let page = next_private_page_in_range(7, base, end, &frames, &pagefile)
        .unwrap()
        .unwrap();
    assert_eq!(page, base);
    assert_eq!(page.checked_add(WORKING_SET_PAGE_SIZE), Some(end));
    assert_eq!(
        next_private_page_in_range(7, page + WORKING_SET_PAGE_SIZE, end, &frames, &pagefile),
        Ok(None)
    );
}
