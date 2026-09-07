//! Checked allocator publication, separate from capability deletion and retained owner phases.
use super::*;
use nt_user_host::slot_recycle::{RecycleError, SlotRecycleState};

/// The caller owns an allocated-empty or delete-acknowledged slot and retains it on error.
/// Executive execution must stay serialized: no syscall, IPC, allocation or callback may occur
/// while this view borrows the allocator arrays and commits its counters.
pub(super) unsafe fn publish_empty(slot: u64) -> Result<(), RecycleError> {
    publish(slot, false)
}

/// Copied aliases and failed memory construction must not carry retype-byte ownership.
pub(super) unsafe fn publish_unretyped(slot: u64) -> Result<(), RecycleError> {
    publish(slot, true)
}

unsafe fn publish(slot: u64, unretyped: bool) -> Result<(), RecycleError> {
    let mut state = SlotRecycleState {
        start: ROOT_CSPACE_START.load(Ordering::Relaxed),
        end: ROOT_CSPACE_END.load(Ordering::Relaxed),
        live: &mut *core::ptr::addr_of_mut!(ROOT_SLOT_LIVE_BITS),
        pinned: &*core::ptr::addr_of!(ROOT_SLOT_PINNED_BITS),
        retype_bytes: &mut *core::ptr::addr_of_mut!(ROOT_SLOT_RETYPE_BYTES),
        free: &mut *core::ptr::addr_of_mut!(ROOT_SLOT_RECYCLE),
        count: ROOT_SLOT_RECYCLE_N.load(Ordering::Relaxed),
        live_bytes: UT_RETYPE_LIVE_BYTES.load(Ordering::Relaxed),
        released_bytes: UT_RETYPE_RELEASED_BYTES.load(Ordering::Relaxed),
    };
    if unretyped {
        state.publish_unretyped(slot)?;
    } else {
        state.publish_empty(slot)?;
    }
    UT_RETYPE_LIVE_BYTES.store(state.live_bytes, Ordering::Relaxed);
    UT_RETYPE_RELEASED_BYTES.store(state.released_bytes, Ordering::Relaxed);
    ROOT_SLOT_RECYCLE_N.store(state.count, Ordering::Relaxed);
    note_high_water(&ROOT_SLOT_RECYCLE_HW, state.count);
    Ok(())
}
