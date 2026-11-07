//! Stable, owned image bytes for each dynamic `NtLoadKey` selector.

use crate::*;

/// A load owns the slot until it publishes a `HiveMount`; a failed load releases it on return.
pub(super) struct Claim {
    slot: usize,
    published: bool,
}

impl Claim {
    /// # Safety
    /// Called by the single-threaded executive after selecting a free, unreferenced slot.
    pub(super) unsafe fn new(slot: usize, image: alloc::vec::Vec<u8>) -> Self {
        assert!(slot < USER_HIVE_SLOTS);
        let buffers = &mut *core::ptr::addr_of_mut!(USER_HIVE_BUF);
        assert!(buffers[slot].is_none());
        assert_eq!(USER_HIVE_SLOT_USED.load(Ordering::Relaxed) & (1u64 << slot), 0);
        buffers[slot] = Some(image);
        USER_HIVE_SLOT_USED.fetch_or(1u64 << slot, Ordering::Relaxed);
        Self { slot, published: false }
    }

    /// # Safety
    /// The slot remains owned and its `Vec` is never mutated while the returned view lives.
    pub(super) unsafe fn bytes(&self) -> &'static [u8] {
        let image = (*core::ptr::addr_of!(USER_HIVE_BUF))[self.slot]
            .as_ref()
            .expect("claimed hive image");
        core::slice::from_raw_parts(image.as_ptr(), image.len())
    }

    pub(super) fn publish(mut self) {
        self.published = true;
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if !self.published {
            unsafe { release(self.slot) };
        }
    }
}

/// # Safety
/// All `RegfHive` views into this slot have already been dropped.
unsafe fn release(slot: usize) {
    (*core::ptr::addr_of_mut!(USER_HIVE_BUF))[slot] = None;
    USER_HIVE_SLOT_USED.fetch_and(!(1u64 << slot), Ordering::Relaxed);
}

impl Drop for HiveMount {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            // The borrowed navigator must die before its backing allocation.
            drop(self.hive.take());
            unsafe { release(slot) };
        }
    }
}
