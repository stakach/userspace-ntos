use super::*;
use crate::thread_rollback::{ThreadRollback, ThreadRollbackIdentity};

fn layout() -> ThreadMemoryLayout {
    ThreadMemoryLayout::new(0x10000, 2, 0x12000, 0x13000, 0x16000).unwrap()
}

fn resources() -> ThreadMemoryResources<3> {
    let mut resources = ThreadMemoryResources::new(27, layout()).unwrap();
    resources.stack_owner = [10, 20, 0];
    resources.stack_target = [11, 21, 0];
    resources.stack_mirror = [12, 22, 0];
    resources.teb_owner = 30;
    resources.teb_target = 31;
    resources.teb_scratch = 32;
    resources.teb2_owner = 40;
    resources.teb2_target = 41;
    resources.teb2_scratch = 42;
    resources.acs_owner = 50;
    resources.acs_target = 51;
    resources.ipc_owner = 60;
    resources.tramp_owner = 70;
    resources.tramp_target = 71;
    resources
}

#[test]
fn layout_retains_every_target_range_and_accepts_adjacent_pages() {
    let layout = layout();
    assert_eq!(
        layout.ranges(),
        [
            ThreadMemoryRange {
                base: 0x10000,
                size: 0x2000
            },
            ThreadMemoryRange {
                base: 0x12000,
                size: 0x1000
            },
            ThreadMemoryRange {
                base: 0x13000,
                size: 0x3000
            },
            ThreadMemoryRange {
                base: 0x16000,
                size: 0x1000
            },
        ]
    );
    assert_eq!(layout.ipc().base, 0x12000);
    assert_eq!(layout.trampoline().base, 0x16000);
    assert_eq!(layout.teb().size, 3 * PAGE_SIZE);
    assert_eq!(layout.stack().size, 2 * PAGE_SIZE);
}

#[test]
fn layout_does_not_require_a_fixed_address_order() {
    assert!(ThreadMemoryLayout::new(0x16000, 2, 0x14000, 0x10000, 0x15000).is_some());
}

#[test]
fn every_range_pair_rejects_overlap() {
    let original = [0x10000, 0x20000, 0x30000, 0x40000];
    for first in 0..4 {
        for second in 0..4 {
            if first == second {
                continue;
            }
            let mut bases = original;
            bases[second] = bases[first];
            assert!(ThreadMemoryLayout::new(bases[0], 2, bases[1], bases[2], bases[3]).is_none());
        }
    }
    assert!(ThreadMemoryLayout::new(0x10000, 2, 0x20000, 0x30000, 0x32000).is_none());
    assert!(ThreadMemoryLayout::new(0x10000, 2, 0x11000, 0x30000, 0x40000).is_none());
}

#[test]
fn invalid_alignment_zero_pages_and_overflow_are_rejected() {
    for index in 0..4 {
        for invalid in [0, 0x10001, u64::MAX & !0xfff] {
            let mut bases = [0x10000, 0x20000, 0x30000, 0x40000];
            bases[index] = invalid;
            assert!(ThreadMemoryLayout::new(bases[0], 2, bases[1], bases[2], bases[3]).is_none());
        }
    }
    for pages in [0, u64::MAX, u64::MAX / PAGE_SIZE + 1] {
        assert!(ThreadMemoryLayout::new(0x10000, pages, 0x20000, 0x30000, 0x40000).is_none());
    }
}

#[test]
fn resource_capacity_is_checked_without_truncating_stack_geometry() {
    assert!(ThreadMemoryResources::<1>::new(0, layout()).is_none());
    assert!(ThreadMemoryResources::<2>::new(0, layout()).is_some());
    assert!(ThreadMemoryResources::<0>::new(0, layout()).is_none());
}

#[test]
fn range_checks_cover_ipc_acs_and_trampoline_and_preserve_half_open_edges() {
    let layout = ThreadMemoryLayout::new(0x10000, 2, 0x20000, 0x30000, 0x40000).unwrap();
    for range in layout.ranges() {
        assert!(layout.overlaps(range.base, 1));
        assert!(layout.overlaps(range.base + range.size - 1, 1));
        assert!(layout.overlaps(range.base - 1, 2));
        assert!(!layout.overlaps(range.base - 1, 1));
        assert!(!layout.overlaps(range.base + range.size, 1));
        assert!(!layout.overlaps(range.base, 0));
    }
    assert!(layout.overlaps(0x32000, PAGE_SIZE));
    assert!(layout.overlaps(u64::MAX, 2));
    assert!(!layout.overlaps(0x50000, PAGE_SIZE));
}

#[test]
fn empty_and_partial_construction_preserve_geometry_without_inventing_caps() {
    let empty = ThreadMemoryResources::<3>::empty();
    assert!(!empty.is_live());
    assert_eq!(empty.layout(), None);
    assert_eq!(
        (empty.stack_base(), empty.stack_frames(), empty.teb_va()),
        (0, 0, 0)
    );
    assert!(empty.rollback_resources().unwrap().is_empty());
    let mut partial = ThreadMemoryResources::<3>::new(27, layout()).unwrap();
    partial.stack_owner[0] = 10;
    assert!(partial.is_live());
    assert_eq!(partial.layout(), Some(layout()));
    assert_eq!(
        partial.rollback_resources().unwrap(),
        [ThreadRollbackResource {
            cap: 10,
            kind: ThreadRollbackResourceKind::Frame
        }]
    );
}

#[test]
fn complete_inventory_has_exactly_one_physical_owner_per_page_including_ipc() {
    use ThreadRollbackResourceKind::{Alias, Frame};
    let resources = resources();
    let inventory = resources.rollback_resources().unwrap();
    let owners: Vec<_> = inventory
        .iter()
        .filter(|entry| entry.kind == Frame)
        .map(|entry| entry.cap)
        .collect();
    let aliases: Vec<_> = inventory
        .iter()
        .filter(|entry| entry.kind == Alias)
        .map(|entry| entry.cap)
        .collect();
    assert_eq!(owners, [10, 20, 30, 40, 50, 60, 70]);
    assert_eq!(aliases, [11, 12, 21, 22, 31, 32, 41, 42, 51, 71]);
    let owner = ThreadRollback::prepare(
        ThreadRollbackIdentity {
            pi: 27,
            pid: 90,
            process_generation: 7,
            tid: 301,
        },
        1000,
        &inventory,
    )
    .unwrap();
    assert_eq!(owner.pending_resources().collect::<Vec<_>>(), inventory);
    assert_eq!(resources.ipc_owner, 60); // Taking the inventory is not an ownership transfer.
}

#[test]
fn repeated_references_within_one_frame_group_are_not_second_owners() {
    let mut resources = resources();
    resources.teb_target = resources.teb_owner;
    resources.teb_scratch = resources.teb_owner;
    resources.stack_mirror[0] = resources.stack_target[0];
    let inventory = resources.rollback_resources().unwrap();
    assert_eq!(inventory.iter().filter(|entry| entry.cap == 30).count(), 1);
    assert_eq!(inventory.iter().filter(|entry| entry.cap == 11).count(), 1);
    assert_eq!(
        inventory.iter().find(|entry| entry.cap == 30).unwrap().kind,
        ThreadRollbackResourceKind::Frame
    );
}

#[test]
fn cross_page_frame_or_alias_reuse_is_rejected() {
    let base = resources();
    for cap in [
        base.stack_owner[0],
        base.stack_target[0],
        base.stack_mirror[0],
    ] {
        let mut resources = base;
        resources.teb_owner = cap;
        assert_eq!(
            resources.rollback_resources(),
            Err(ThreadRollbackError::ConflictingOwnership)
        );
        resources = base;
        resources.teb_target = cap;
        assert_eq!(
            resources.rollback_resources(),
            Err(ThreadRollbackError::ConflictingOwnership)
        );
    }
}

#[test]
fn aliases_without_a_physical_owner_are_rejected() {
    let mut resources = resources();
    resources.teb_owner = 0;
    assert_eq!(
        resources.rollback_resources(),
        Err(ThreadRollbackError::ConflictingOwnership)
    );
    resources = ThreadMemoryResources::<3>::new(27, layout()).unwrap();
    resources.stack_target[0] = 11;
    assert_eq!(
        resources.rollback_resources(),
        Err(ThreadRollbackError::ConflictingOwnership)
    );
}

#[test]
fn caps_outside_the_retained_layout_are_rejected() {
    let mut resources = resources();
    resources.stack_owner[2] = 100;
    assert_eq!(
        resources.rollback_resources(),
        Err(ThreadRollbackError::InvalidIdentity)
    );
    let mut empty = ThreadMemoryResources::<3>::empty();
    empty.ipc_owner = 100;
    assert_eq!(
        empty.rollback_resources(),
        Err(ThreadRollbackError::InvalidIdentity)
    );
}
