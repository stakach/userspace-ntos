//! Caller-owned cache-aware rundown descriptor used by storage class drivers.
//!
//! The descriptor and its per-processor references live in the driver's allocation. It follows
//! the x64 `EX_RUNDOWN_REF_CACHE_AWARE` layout and uses the same one-word rundown protocol as
//! ordinary `EX_RUNDOWN_REF`. The caller must keep the allocation resident through a wait.

use core::mem::{align_of, size_of};

use crate::{ExRundownRef, ExRundownWaitBlock};

const MAX_PROCESSORS: usize = 64;
const CALLER_OWNED_POOL: usize = 0x0bad_ca11;

#[repr(C)]
pub struct ExCacheAwareRundownRef {
    run_refs: *mut ExRundownRef,
    pool_to_free: *mut u8,
    run_ref_size: u32,
    number: u32,
}

impl ExCacheAwareRundownRef {
    pub fn required_size(processors: usize, alignment: usize) -> Option<usize> {
        if !(1..=MAX_PROCESSORS).contains(&processors)
            || !alignment.is_power_of_two()
            || alignment < align_of::<ExRundownRef>()
        {
            return None;
        }
        if processors == 1 {
            size_of::<Self>().checked_add(size_of::<ExRundownRef>())
        } else if alignment < size_of::<ExRundownRef>() {
            None
        } else {
            processors.checked_add(1)?.checked_mul(alignment)?.checked_add(size_of::<Self>())
        }
    }

    /// Initialize the descriptor and every slot inside a caller-owned allocation.
    ///
    /// # Safety
    /// `ptr` must identify a writable, exclusively owned allocation of at least `size` bytes,
    /// and that allocation must remain resident until rundown has completed.
    pub unsafe fn initialize_in_place(
        ptr: *mut Self,
        size: usize,
        processors: usize,
        alignment: usize,
    ) -> bool {
        let Some(required) = Self::required_size(processors, alignment) else { return false };
        if ptr.is_null() || (ptr as usize) % align_of::<Self>() != 0 || size != required {
            return false;
        }
        let Some(end) = (ptr as usize).checked_add(size) else { return false };
        let Some(after_header) = (ptr as usize).checked_add(size_of::<Self>()) else { return false };
        let (first, stride) = if processors == 1 {
            (after_header, size_of::<ExRundownRef>())
        } else {
            let Some(first) = after_header.checked_add(alignment - 1)
                .map(|address| address & !(alignment - 1)) else { return false };
            (first, alignment)
        };
        let Some(last_end) = (processors - 1).checked_mul(stride)
            .and_then(|span| first.checked_add(span))
            .and_then(|last| last.checked_add(size_of::<ExRundownRef>())) else { return false };
        if last_end > end { return false; }
        for index in 0..processors {
            let address = first + index * stride;
            unsafe { core::ptr::write(address as *mut ExRundownRef, ExRundownRef::new()) };
        }
        unsafe {
            core::ptr::write(ptr, Self {
                run_refs: first as *mut ExRundownRef,
                pool_to_free: CALLER_OWNED_POOL as *mut u8,
                run_ref_size: stride as u32,
                number: processors as u32,
            });
        }
        true
    }

    fn slot(&self, processor: usize) -> &ExRundownRef {
        let count = self.number as usize;
        assert!((1..=MAX_PROCESSORS).contains(&count), "invalid cache-aware rundown count");
        assert!(!self.run_refs.is_null(), "null cache-aware rundown slots");
        let stride = self.run_ref_size as usize;
        assert!(stride >= size_of::<ExRundownRef>(), "invalid cache-aware rundown stride");
        let offset = (processor % count).checked_mul(stride).expect("cache-aware slot overflow");
        let address = (self.run_refs as usize).checked_add(offset).expect("cache-aware slot overflow");
        assert_eq!(address % align_of::<ExRundownRef>(), 0, "unaligned cache-aware slot");
        // SAFETY: initialize_in_place establishes the in-allocation slot layout. The driver
        // retains that allocation until wait and reinitialization have completed.
        unsafe { &*(address as *const ExRundownRef) }
    }

    pub fn acquire(&self, processor: usize) -> bool {
        self.slot(processor).acquire()
    }

    /// # Safety
    /// The caller must hold one reference acquired for this processor slot.
    pub unsafe fn release(&self, processor: usize) {
        let _ = unsafe { self.slot(processor).release() };
    }

    /// Close admission on every slot before waiting for any holder. One waiter may call this
    /// method, and the descriptor allocation must remain live throughout the call.
    pub fn wait_for_release_with(&self, mut yield_now: impl FnMut()) {
        let count = self.number as usize;
        assert!((1..=MAX_PROCESSORS).contains(&count), "invalid cache-aware rundown count");
        let waiters: [ExRundownWaitBlock; MAX_PROCESSORS] =
            core::array::from_fn(|_| ExRundownWaitBlock::new());
        let mut armed = [false; MAX_PROCESSORS];
        for index in 0..count {
            // SAFETY: each stack wait block stays at this address until finish_wait below.
            armed[index] = unsafe { self.slot(index).begin_wait(&waiters[index]) };
        }
        while (0..count).any(|index| armed[index] && waiters[index].remaining() != 0) {
            yield_now();
        }
        for index in 0..count {
            if armed[index] {
                // SAFETY: the exact waiter has drained and remains at its original address.
                unsafe { self.slot(index).finish_wait(&waiters[index]) };
            }
        }
    }

    /// Reopen only a fully completed descriptor. A caller must exclude a concurrent wait.
    pub fn reinitialize(&self) -> bool {
        let count = self.number as usize;
        assert!((1..=MAX_PROCESSORS).contains(&count), "invalid cache-aware rundown count");
        if (0..count).any(|index| !self.slot(index).is_completed()) { return false; }
        for index in 0..count {
            assert!(self.slot(index).reinitialize(), "cache-aware rundown changed during reinit");
        }
        true
    }
}
