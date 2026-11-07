//! Contract for a provider-only, demand-mapped large allocation arena.
//!
//! The native adapter owns seL4 effects. This pure ledger must reserve exact virtual extents,
//! authorize faults by allocation generation, and retain uncertain map/unmap effects.

use nt_memory_manager::provider_large_arena::{
    LargeAllocation, LargeArena, LargeArenaError, LargePublication, PageMapDecision,
    MAX_ALLOCATIONS, MAX_PAGES, PAGE_SIZE,
};

const BASE: u64 = 0x0000_0100_4000_0000;
const BYTES: u64 = 64 * 1024 * 1024;

fn publish(arena: &mut LargeArena, allocation: LargeAllocation) {
    arena.publish(allocation, LargePublication {
        arena_id: 4,
        arena_generation: 1,
        allocation_id: allocation.generation,
        allocation_generation: 1,
    }, allocation.base, allocation.capacity).unwrap();
}

fn with_large_stack(name: &'static str, case: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(8 * 1024 * 1024)
        .spawn(case)
        .expect("spawn large-arena test thread")
        .join()
        .expect("large-arena test thread panicked");
}

#[test]
fn large_request_reserves_disjoint_pages_and_rejects_unowned_faults() {
    with_large_stack("large_request_reserves_disjoint_pages_and_rejects_unowned_faults", large_request_case);
}

fn large_request_case() {
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let splash = arena.reserve(14_745_600).unwrap();
    let other = arena.reserve(PAGE_SIZE).unwrap();
    publish(&mut arena, splash);
    publish(&mut arena, other);

    assert_eq!(splash.base, BASE);
    assert_eq!(splash.capacity, 14_745_600);
    assert_eq!(other.base, splash.base + splash.capacity);
    assert_eq!(arena.authorize_fault(splash.base, 0), Ok(splash));
    assert_eq!(arena.authorize_fault(splash.base + splash.capacity - 1, 2), Ok(splash));
    assert_eq!(arena.authorize_fault(other.base, 0), Ok(other));
    assert_eq!(
        arena.authorize_fault(other.base + other.capacity, 0),
        Err(LargeArenaError::UnreservedPage)
    );
    assert_eq!(
        arena.authorize_fault(BASE + BYTES, 0),
        Err(LargeArenaError::OutsideArena)
    );
    assert_eq!(
        arena.authorize_fault(splash.base, 0x10),
        Err(LargeArenaError::Protection)
    );
}

#[test]
fn page_cap_is_recorded_before_map_and_a_queued_fault_is_acknowledged() {
    with_large_stack("page_cap_is_recorded_before_map_and_a_queued_fault_is_acknowledged", page_cap_case);
}

fn page_cap_case() {
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let allocation = arena.reserve(2 * PAGE_SIZE).unwrap();
    publish(&mut arena, allocation);
    let page = allocation.base + PAGE_SIZE;

    assert_eq!(arena.begin_page_map(allocation, page, 0xCAFE), Ok(PageMapDecision::Map));
    assert_eq!(arena.page_cap(allocation, page), Ok(Some(0xCAFE)));
    assert_eq!(
        arena.begin_page_map(allocation, page, 0xBEEF),
        Err(LargeArenaError::EffectInProgress)
    );
    arena.complete_page_map(allocation, page).unwrap();
    assert_eq!(arena.authorize_fault(page + 7, 2), Ok(allocation));
    assert_eq!(arena.begin_page_map(allocation, page, 0xBEEF), Ok(PageMapDecision::AlreadyMapped));
    assert_eq!(arena.page_cap(allocation, page), Ok(Some(0xCAFE)));
}

#[test]
fn uncertain_map_and_unmap_quarantine_the_exact_extent() {
    with_large_stack("uncertain_map_and_unmap_quarantine_the_exact_extent", uncertain_map_case);
}

fn uncertain_map_case() {
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let allocation = arena.reserve(PAGE_SIZE).unwrap();
    publish(&mut arena, allocation);
    arena.begin_page_map(allocation, allocation.base, 0xCAFE).unwrap();
    arena.quarantine_page_map(allocation, allocation.base).unwrap();

    assert_eq!(arena.page_cap(allocation, allocation.base), Ok(Some(0xCAFE)));
    assert_eq!(
        arena.begin_page_map(allocation, allocation.base, 0xBEEF),
        Err(LargeArenaError::Quarantined)
    );
    assert_eq!(arena.begin_retirement(allocation), Err(LargeArenaError::Quarantined));
    assert_eq!(arena.reserve(BYTES), Err(LargeArenaError::OutOfSpace));

    let mut second = LargeArena::new(BASE, BYTES).unwrap();
    let mapped = second.reserve(PAGE_SIZE).unwrap();
    publish(&mut second, mapped);
    second.begin_page_map(mapped, mapped.base, 0xCAFE).unwrap();
    second.complete_page_map(mapped, mapped.base).unwrap();
    second.begin_retirement(mapped).unwrap();
    second.begin_page_unmap(mapped, mapped.base).unwrap();
    second.quarantine_page_unmap(mapped, mapped.base).unwrap();
    assert_eq!(second.complete_retirement(mapped), Err(LargeArenaError::Quarantined));
    assert_eq!(second.page_cap(mapped, mapped.base), Ok(Some(0xCAFE)));
}

#[test]
fn retirement_waits_for_confirmed_page_unmaps_and_fences_stale_generation() {
    with_large_stack("retirement_waits_for_confirmed_page_unmaps_and_fences_stale_generation", retirement_case);
}

fn retirement_case() {
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let first = arena.reserve(BYTES).unwrap();
    publish(&mut arena, first);
    let page = first.base + 3 * PAGE_SIZE;
    arena.begin_page_map(first, page, 0xCAFE).unwrap();
    arena.complete_page_map(first, page).unwrap();

    arena.begin_retirement(first).unwrap();
    assert_eq!(arena.authorize_fault(page, 0), Err(LargeArenaError::Retiring));
    assert_eq!(arena.complete_retirement(first), Err(LargeArenaError::EffectInProgress));
    arena.begin_page_unmap(first, page).unwrap();
    assert_eq!(arena.page_cap(first, page), Ok(Some(0xCAFE)));
    arena.complete_page_unmap(first, page).unwrap();
    arena.complete_retirement(first).unwrap();

    let reused = arena.reserve(BYTES).unwrap();
    publish(&mut arena, reused);
    assert_eq!(reused.base, first.base);
    assert_ne!(reused.generation, first.generation);
    assert_eq!(arena.begin_retirement(first), Err(LargeArenaError::StaleAllocation));
    assert_eq!(arena.begin_page_map(first, page, 0xBEEF), Err(LargeArenaError::StaleAllocation));
    assert_eq!(arena.authorize_fault(page, 0), Ok(reused));
}

#[test]
fn exact_base_and_generation_are_required_for_free() {
    with_large_stack("exact_base_and_generation_are_required_for_free", exact_free_case);
}

fn exact_free_case() {
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let allocation = arena.reserve(PAGE_SIZE).unwrap();
    publish(&mut arena, allocation);
    let interior = nt_memory_manager::provider_large_arena::LargeAllocation {
        base: allocation.base + 1,
        ..allocation
    };
    assert_eq!(arena.begin_retirement(interior), Err(LargeArenaError::StaleAllocation));
    arena.begin_retirement(allocation).unwrap();
    arena.complete_retirement(allocation).unwrap();
    assert_eq!(arena.begin_retirement(allocation), Err(LargeArenaError::StaleAllocation));
}

#[test]
fn unpublished_or_mismatched_catalog_snapshot_cannot_authorize_a_fault() {
    with_large_stack("unpublished_or_mismatched_catalog_snapshot_cannot_authorize_a_fault", publication_case);
}

fn publication_case() {
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let allocation = arena.reserve(PAGE_SIZE).unwrap();
    assert_eq!(arena.authorize_fault(allocation.base, 2), Err(LargeArenaError::Unpublished));
    let witness = LargePublication {
        arena_id: 4, arena_generation: 1, allocation_id: 7, allocation_generation: 2,
    };
    assert_eq!(arena.publish(allocation, witness, allocation.base + PAGE_SIZE, allocation.capacity),
        Err(LargeArenaError::InvalidPublication));
    assert_eq!(arena.authorize_fault(allocation.base, 2), Err(LargeArenaError::Unpublished));
    arena.publish(allocation, witness, allocation.base, allocation.capacity).unwrap();
    assert_eq!(arena.publication(allocation), Ok(witness));
    arena.begin_retirement(allocation).unwrap();
    assert_eq!(arena.publication(allocation), Err(LargeArenaError::Retiring));
    assert_eq!(arena.retiring_snapshot(allocation.base, allocation.generation),
        Ok((allocation, witness)));
    assert_eq!(arena.retiring_snapshot(allocation.base, allocation.generation + 1),
        Err(LargeArenaError::StaleAllocation));
    arena.complete_retirement(allocation).unwrap();
    assert_eq!(arena.retiring_snapshot(allocation.base, allocation.generation),
        Err(LargeArenaError::StaleAllocation));
}

#[test]
fn inline_metadata_survives_context_move_without_a_heap_pointer() {
    with_large_stack("inline_metadata_survives_context_move_without_a_heap_pointer", inline_metadata_case);
}

fn inline_metadata_case() {
    assert!(!core::mem::needs_drop::<LargeArena>());
    assert!(core::mem::size_of::<LargeArena>() > 100_000);
    let mut arena = LargeArena::new(BASE, BYTES).unwrap();
    let allocation = arena.reserve(PAGE_SIZE).unwrap();
    publish(&mut arena, allocation);
    arena.begin_page_map(allocation, allocation.base, 0xCAFE).unwrap();
    arena.complete_page_map(allocation, allocation.base).unwrap();
    let moved = arena;
    assert_eq!(moved.authorize_fault(allocation.base, 2), Ok(allocation));
    assert_eq!(moved.page_cap(allocation, allocation.base), Ok(Some(0xCAFE)));
}

#[test]
fn page_count_does_not_outgrow_record_capacity() {
    with_large_stack("page_count_does_not_outgrow_record_capacity", record_capacity_case);
}

fn record_capacity_case() {
    assert_eq!(MAX_ALLOCATIONS, MAX_PAGES);
    // Cross the old 8,192-record ceiling with disjoint single-page allocations.
    let mut arena = LargeArena::new(BASE, 8_193 * PAGE_SIZE).unwrap();
    let mut last = None;
    for _ in 0..8_193 {
        last = Some(arena.reserve(PAGE_SIZE).unwrap());
    }
    assert_eq!(arena.allocation_count(), 8_193);
    assert_eq!(last.unwrap().base, BASE + 8_192 * PAGE_SIZE);
}
