//! Retain pooled frames and failed retype slots until acquisition has fully completed.
use super::*;
use nt_memory_manager::frame_acquisition::{
    FrameAcquisition, FrameAcquisitionError, FrameAcquisitionIo,
};

static mut OWNER: FrameAcquisition = FrameAcquisition::new();
static BORROWED: AtomicBool = AtomicBool::new(false);

struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

struct Io {
    scratch_base: u64,
}
impl FrameAcquisitionIo for Io {
    fn acquire_cached(&mut self) -> Option<u64> {
        unsafe { (&mut *core::ptr::addr_of_mut!(VM_FREE_FRAMES)).acquire() }
    }

    fn reserve_slot(&mut self) -> Result<u64, u32> {
        try_alloc_slot().ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }

    fn retype_frame(&mut self, slot: u64) -> Result<(), u32> {
        // This boot capability is non-device untyped. Successful retype zeros the frame before
        // publishing its cap; failure leaves our pre-reserved destination empty.
        let error =
            unsafe { untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, slot) };
        if error == 0 {
            Ok(())
        } else {
            Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }

    fn recycle_empty(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }
            .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
    }

    fn zero_cached(&mut self, frame: u64) -> Result<(), u32> {
        unsafe {
            temporary_frame_alias::with_scratch_range(
                frame,
                self.scratch_base,
                0..0x1000,
                true,
                |address| core::ptr::write_bytes(address as *mut u8, 0, 0x1000),
            )
        }
    }

    fn unmap_cached(&mut self, frame: u64) -> Result<(), u32> {
        unsafe {
            frame_recycle::validate_acquisition(frame)?;
        }
        if unsafe { page_unmap_r(frame) } == 0 {
            Ok(())
        } else {
            Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}

pub(super) unsafe fn acquire(scratch_base: u64) -> Result<u64, u32> {
    let _borrow = Borrow::acquire()?;
    (&mut *core::ptr::addr_of_mut!(OWNER))
        .acquire(&mut Io { scratch_base })
        .map_err(|error| match error {
            FrameAcquisitionError::Backend(status) => status,
            FrameAcquisitionError::InvalidCapability => nt_address_space::STATUS_INVALID_PARAMETER,
        })
}

pub(super) fn owns_root_cap(cap: u64) -> bool {
    if cap == 0 {
        return false;
    }
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    unsafe { (&*core::ptr::addr_of!(OWNER)).owns_root_cap(cap) }
}
