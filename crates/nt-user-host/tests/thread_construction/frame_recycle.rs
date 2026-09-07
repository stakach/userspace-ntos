use super::*;
use nt_address_space::{FramePoolError, RecycledFramePool};
use nt_user_host::frame_recycle::{FrameRecycleError, FrameRecycleState};

#[test]
fn checked_frame_publication_and_rejection_allocate_nothing_or_release_pending_runtime() {
    let (mut slot, ticket, partial, _) = fixture(None, true);
    let frame = partial.memory.stack_owner[0];
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let state = FrameRecycleState {
        start: frame,
        end: frame + 1,
        live: &[1],
        pinned: &[0],
        retype_bytes: &[4096],
        free_slots: &[],
        free_slot_count: 0,
        live_bytes: 4096,
    };
    let mut pool = RecycledFramePool::new();
    assert!(pool.reserve(1));
    without_allocation(|| state.check_reserved(frame, &pool)).unwrap();
    without_allocation(|| state.publish_reserved(frame, &mut pool)).unwrap();
    assert_eq!(
        without_allocation(|| state.publish_reserved(frame, &mut pool)),
        Err(FrameRecycleError::Pool(FramePoolError::AlreadyPublished))
    );
    assert_eq!(without_allocation(|| pool.acquire()), Some(frame));
    assert_protected(&mut slot, id);
}

#[test]
fn failed_frame_pool_reservation_retains_pending_owner_for_retry() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_ALLOCATIONS.with(|flag| flag.set(false));
        }
    }
    let (mut slot, ticket, partial, _) = fixture(None, true);
    let frame = partial.memory.stack_owner[0];
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let mut pool = RecycledFramePool::new();
    FAIL_ALLOCATIONS.with(|flag| flag.set(true));
    let reset = Reset;
    let reserved = pool.reserve(1);
    drop(reset);
    assert!(!reserved);
    assert_eq!(pool.stats().live, 0);
    assert_eq!(pool.stats().capacity, 0);
    assert_eq!(pool.stats().allocation_failures, 1);
    assert_protected(&mut slot, id);
    assert!(pool.reserve(1));
    pool.publish_reserved(frame).unwrap();
    assert_eq!(pool.acquire(), Some(frame));
}
