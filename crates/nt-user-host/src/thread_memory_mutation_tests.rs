//! Exercise exclusion inputs using the real VM planners, not hand-normalized request ranges.
use super::*;
use nt_address_space::{
    VmCommittedRange, VmCommittedRangeTable, VmRegionMap, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE,
    MEM_RESERVE, MEM_RESET, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE,
};

fn private_map() -> VmRegionMap<16> {
    let mut map = VmRegionMap::new(0x10000, 0x100000);
    map.allocate(
        Some(0x10000),
        0x10000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    map
}

fn pending_middle_page() -> [ThreadRuntimeSlot<Runtime>; 1] {
    let mut owner = runtime(2, ProcessGeneration::Hosted(7));
    owner.bottom = 0x12000;
    owner.top = 0x13000;
    [pending(owner)]
}

#[test]
fn zero_size_free_checks_the_entire_resolved_allocation() {
    let slots = pending_middle_page();
    let before = private_map();
    assert_eq!(check(&slots, 2, 0x10000, 0), Ok(()));
    for kind in [MEM_RELEASE, MEM_DECOMMIT] {
        let mut after = before;
        let plan = after.free(0x10000, 0, kind).unwrap();
        let (base, size) = plan.ownership_range(&before).unwrap();
        assert_eq!((base, size), (0x10000, 0x10000));
        assert!(matches!(
            check(&slots, 2, base, size),
            Err(ThreadMemoryAccessError::Excluded(_))
        ));
        assert_eq!(before.private_committed_bytes(), 0x10000);
    }
}

#[test]
fn partial_release_checks_identity_changes_outside_unmapped_pages() {
    let slots = pending_middle_page();
    let before = private_map();
    for page in [0x10000, 0x11000, 0x13000] {
        let mut after = before;
        let plan = after.free(page, 0x1000, MEM_RELEASE).unwrap();
        assert_eq!(check(&slots, 2, plan.base, plan.size), Ok(()));
        let (base, size) = plan.ownership_range(&before).unwrap();
        assert_eq!((base, size), (0x10000, 0x10000));
        assert!(check(&slots, 2, base, size).is_err());
    }
}

#[test]
fn decommit_checks_rounded_pages_without_excluding_the_whole_vad() {
    let slots = pending_middle_page();
    let before = private_map();
    let mut after = before;
    let adjacent = after.free(0x11001, 1, MEM_DECOMMIT).unwrap();
    let (base, size) = adjacent.ownership_range(&before).unwrap();
    assert_eq!((base, size), (0x11000, 0x1000));
    assert_eq!(check(&slots, 2, base, size), Ok(()));
    let mut after = before;
    let crossing = after.free(0x11fff, 2, MEM_DECOMMIT).unwrap();
    let (base, size) = crossing.ownership_range(&before).unwrap();
    assert_eq!((base, size), (0x11000, 0x2000));
    assert!(check(&slots, 2, base, size).is_err());
}

#[test]
fn private_protection_checks_all_normalized_pages_before_publication() {
    let slots = pending_middle_page();
    let before = private_map();
    for new_protection in [PAGE_READONLY, PAGE_READWRITE | PAGE_GUARD] {
        let mut after = before;
        let plan = after.protect(0x11fff, 2, new_protection).unwrap();
        assert_eq!((plan.base, plan.size), (0x11000, 0x2000));
        assert!(check(&slots, 2, plan.base, plan.size).is_err());
        assert_eq!(before.protection_at(0x12000), Some(PAGE_READWRITE));
    }
}

#[test]
fn committed_view_protection_uses_the_same_exclusion_range() {
    let slots = pending_middle_page();
    for image in [false, true] {
        let mut before = VmCommittedRangeTable::<8>::new();
        let range = if image {
            VmCommittedRange::image_region(0x10000, 0x10000, 0x10000, PAGE_READWRITE)
        } else {
            VmCommittedRange::mapped(0x10000, 0x10000, PAGE_READWRITE)
        };
        before.register(range).unwrap();
        let mut after = before;
        let plan = after.protect(0x11fff, 2, PAGE_READONLY).unwrap();
        assert_eq!((plan.base, plan.size), (0x11000, 0x2000));
        assert!(check(&slots, 2, plan.base, plan.size).is_err());
        assert_eq!(before.query_basic(0x12000).unwrap().protect, PAGE_READWRITE);
    }
}

#[test]
fn unmap_interior_address_checks_the_complete_view() {
    let slots = pending_middle_page();
    let mut before = VmRegionMap::<16>::new(0x10000, 0x100000);
    before
        .allocate_mapped_between(
            Some(0x10000),
            0x10000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            0x10000,
            0x100000,
        )
        .unwrap();
    for address in [0x10000, 0x11080, 0x1ffff] {
        assert_eq!(check(&slots, 2, address, 1), Ok(()));
        let mut after = before;
        let plan = after.unmap_mapped(address).unwrap();
        assert_eq!((plan.base, plan.size), (0x10000, 0x10000));
        assert!(check(&slots, 2, plan.base, plan.size).is_err());
    }
}

#[test]
fn recommit_and_reset_cannot_bypass_pending_ownership() {
    let slots = pending_middle_page();
    let before = private_map();
    for kind in [MEM_COMMIT, MEM_RESET] {
        let mut after = before;
        let plan = after
            .allocate(Some(0x12001), 1, kind, PAGE_READONLY)
            .unwrap();
        assert_eq!((plan.base, plan.size), (0x12000, 0x1000));
        assert!(check(&slots, 2, plan.base, plan.size).is_err());
        assert_eq!(check(&slots, 3, plan.base, plan.size), Ok(()));
    }
}

#[test]
fn malformed_free_plan_has_no_release_ownership_range() {
    let before = private_map();
    assert!(nt_address_space::VmFreePlan {
        base: 0x20000,
        size: 0x1000,
        free_type: MEM_RELEASE
    }
    .ownership_range(&before)
    .is_none());
    assert!(nt_address_space::VmFreePlan {
        base: 0x10000,
        size: 0x1000,
        free_type: 0
    }
    .ownership_range(&before)
    .is_none());
}
