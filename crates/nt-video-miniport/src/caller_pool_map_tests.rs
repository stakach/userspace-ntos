use crate::caller_pool_map::{BackingSelection, PoolMapIdentity, PoolMapPhase, PoolMapPlan, PoolMapTransaction};

fn identity() -> PoolMapIdentity {
    PoolMapIdentity {
        device: 0x51,
        provider_domain: 3,
        provider_generation: 7,
        pool_base: 0x1000_e800_0000,
        pool_frames: 2048,
        pool_frame_base: 0x8000,
        allocation_base: 0x1000_e800_1000,
        allocation_capacity: 0x301000,
        allocation_generation: 11,
        provider_pointer: 0x1000_e800_1220,
        length: 0x300000,
        caller_domain: 4,
        caller_generation: 9,
        caller_vspace: 0x9000,
        alias_page: 0x1000_0900_0000,
        alias_limit: 0x1000_0a00_0000,
    }
}

#[test]
fn maps_only_the_exact_pinned_pool_span_and_preserves_pointer_offset() {
    let plan = PoolMapPlan::new(identity()).unwrap();
    assert_eq!(plan.alias_pointer(), 0x1000_0900_0220);
    assert_eq!(plan.pages(), 769);
    assert_eq!(plan.frame_slot(0), Some(0x8001));
    assert_eq!(plan.frame_slot(768), Some(0x8301));
    assert_eq!(plan.frame_slot(769), None);
    assert_eq!(plan.translate_alias_range(plan.alias_pointer(), 0x300000), Some(identity().provider_pointer));
    assert_eq!(plan.translate_alias_range(plan.alias_pointer() + 1, 0x300000), None);
}

#[test]
fn stale_allocation_generation_and_insufficient_capacity_are_rejected() {
    let mut stale = identity();
    stale.allocation_generation = 0;
    assert!(PoolMapPlan::new(stale).is_err());
    let mut short = identity();
    short.allocation_capacity = 0x2fffff;
    assert!(PoolMapPlan::new(short).is_err());
    let mut wrong_arena = identity();
    wrong_arena.provider_pointer = wrong_arena.pool_base + wrong_arena.pool_frames * 0x1000;
    assert!(PoolMapPlan::new(wrong_arena).is_err());
    let mut wrapped_frames = identity();
    wrapped_frames.pool_frame_base = u64::MAX - 1;
    assert!(PoolMapPlan::new(wrapped_frames).is_err());
}

#[test]
fn caller_pointer_is_published_only_after_all_pages_are_mapped() {
    let mut map = PoolMapTransaction::new(PoolMapPlan::new(identity()).unwrap());
    map.pin_allocation().unwrap();
    for page in 0..map.plan().pages() {
        map.own_frame_cap(page).unwrap();
        map.begin_map(page).unwrap();
        assert!(!map.publishable());
        map.ack_map(page).unwrap();
    }
    map.commit().unwrap();
    assert!(map.publishable());
    map.publish().unwrap();
    assert_eq!(map.phase(), PoolMapPhase::Published);
}

#[test]
fn unmap_revokes_alias_before_pool_free_and_never_replays_uncertain_effect() {
    let mut map = PoolMapTransaction::new(PoolMapPlan::new(identity()).unwrap());
    map.pin_allocation().unwrap();
    for page in 0..map.plan().pages() {
        map.own_frame_cap(page).unwrap();
        map.begin_map(page).unwrap();
        map.ack_map(page).unwrap();
    }
    map.commit().unwrap();
    map.publish().unwrap();
    map.claim_unmap().unwrap();
    assert!(!map.provider_unmap_admissible());
    map.revoke_alias().unwrap();
    assert!(!map.provider_unmap_admissible());
    map.release_pin().unwrap();
    assert!(map.provider_unmap_admissible());
    map.begin_provider_unmap().unwrap();
    assert!(!map.provider_unmap_admissible());
    map.unknown_provider_unmap().unwrap();
    assert_eq!(map.phase(), PoolMapPhase::Quarantined);
    assert!(map.begin_provider_unmap().is_err());
}

#[test]
fn selects_only_one_exact_backing_owner_even_when_virtual_ranges_overlap() {
    // An address can name different physical pages in the provider and executive
    // VSpaces. Only retained owner receipts may select the source frame run.
    assert_eq!(BackingSelection::from_pins(true, false), BackingSelection::Pool);
    assert_eq!(BackingSelection::from_pins(false, true), BackingSelection::Projection);
    assert_eq!(BackingSelection::from_pins(false, false), BackingSelection::Missing);
    assert_eq!(BackingSelection::from_pins(true, true), BackingSelection::Ambiguous);
}
