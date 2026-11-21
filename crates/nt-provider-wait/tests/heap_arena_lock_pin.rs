//! A push lock inside a heap-arena allocation is leased through its exact catalog allocation.
//!
//! win32k's lookaside fallback allocates GDI objects (each with an EX_PUSH_LOCK) from its root
//! heap arena, and that arena registers every block in the same provider allocation catalog as
//! pool. A contended lock's lease pins the containing allocation for the slow path: the block
//! cannot retire beneath the waiters, and each access revalidates that it is still active.

use nt_provider_wait::*;

const HEAP_ARENA: ProviderArenaIdentity = ProviderArenaIdentity { id: 1, generation: 7 };
const OBJECT: u64 = 0x0000_0100_0740_2c00;
const LOCK: u64 = OBJECT + 0x50;

#[test]
fn a_heap_arena_lock_lease_keeps_its_allocation_live() {
    let mut catalog = ProviderAllocationCatalog::new();
    let object = catalog.register(HEAP_ARENA, OBJECT, 0x100).unwrap();
    let (pinned, pin) = catalog.pin_containing(LOCK, 8).unwrap();
    assert_eq!(pinned.identity, object.identity, "the lease pins the exact containing block");
    assert_eq!(catalog.validate_retirement(object.identity), Err(ProviderAllocationError::Pinned),
        "the object cannot be freed while a push-lock slow path holds it");
    let live = catalog.snapshot_active(pin.identity()).unwrap();
    assert!(live.offset_of(LOCK).is_some_and(|offset| offset + 8 <= live.capacity));
    catalog.release_pin(pin).unwrap();
    assert!(catalog.retire(object.identity).is_ok());
}

#[test]
fn a_lock_outside_any_registered_block_is_not_leased() {
    let mut catalog = ProviderAllocationCatalog::new();
    catalog.register(HEAP_ARENA, OBJECT, 0x40).unwrap();
    assert!(catalog.pin_containing(LOCK, 8).is_err(), "no allocation contains the lock");
    assert!(catalog.pin_containing(OBJECT + 0x3c, 8).is_err(), "the lock must lie wholly inside");
}
