//! Frame-pool admission for retained cleanup; never delete a rejected frame as a fallback.
use super::*;
use nt_user_host::frame_recycle::FrameRecycleState;

unsafe fn state() -> FrameRecycleState<'static> {
    FrameRecycleState {
        start: ROOT_CSPACE_START.load(Ordering::Relaxed),
        end: ROOT_CSPACE_END.load(Ordering::Relaxed),
        live: &*core::ptr::addr_of!(ROOT_SLOT_LIVE_BITS),
        pinned: &*core::ptr::addr_of!(ROOT_SLOT_PINNED_BITS),
        retype_bytes: &*core::ptr::addr_of!(ROOT_SLOT_RETYPE_BYTES),
        free_slots: &*core::ptr::addr_of!(ROOT_SLOT_RECYCLE),
        free_slot_count: ROOT_SLOT_RECYCLE_N.load(Ordering::Relaxed),
        live_bytes: UT_RETYPE_LIVE_BYTES.load(Ordering::Relaxed),
    }
}

/// Capacity growth precedes release effects; drop allocator borrows before any capability syscall.
pub(super) unsafe fn prepare(frame: u64) -> Result<(), u32> {
    if !temporary_frame_alias::backing_release_available() {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    state()
        .validate_owner(frame)
        .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)?;
    let free = &mut *core::ptr::addr_of_mut!(VM_FREE_FRAMES);
    match free.check_reserved(frame) {
        Ok(()) => {}
        Err(nt_address_space::FramePoolError::Full) => {
            let _durable = allocator::enter_durable();
            if !free.reserve(1) {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
        }
        Err(_) => return Err(nt_address_space::STATUS_INVALID_PARAMETER),
    }
    state()
        .check_reserved(frame, free)
        .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
}

/// Caller retains the exact owner on error; on success it must acknowledge the transfer without
/// allocation, IPC or callback before another frame can be acquired from the pool.
pub(super) unsafe fn publish(frame: u64) -> Result<(), u32> {
    if !temporary_frame_alias::backing_release_available() {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    state()
        .publish_reserved(frame, &mut *core::ptr::addr_of_mut!(VM_FREE_FRAMES))
        .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
}
