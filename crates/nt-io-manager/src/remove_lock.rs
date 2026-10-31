//! The common, in-driver prefix of an NT `IO_REMOVE_LOCK`.
//!
//! The descriptor lives in the driver's own memory. The initialization reference and the
//! removing IRP's reference are both discharged by `IoReleaseRemoveLockAndWaitEx`.

use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

/// x64 free and checked `IO_REMOVE_LOCK` sizes in the released driver ABI.
pub const fn valid_remove_lock_size(size: u32) -> bool {
    matches!(size, 32 | 120)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acquire {
    Acquired,
    DeletePending { wake_remove_waiter: bool },
}

/// `Removed` (offset 0) and `IoCount` (offset 4) in `IO_REMOVE_LOCK_COMMON_BLOCK`.
/// The native adapter initializes and waits on the trailing `KEVENT` at offset 8.
#[repr(C)]
pub struct RemoveLockState {
    removed: AtomicU8,
    reserved: [u8; 3],
    io_count: AtomicI32,
}

impl Default for RemoveLockState {
    fn default() -> Self { Self::new() }
}

impl RemoveLockState {
    pub const fn new() -> Self {
        Self {
            removed: AtomicU8::new(0),
            reserved: [0; 3],
            io_count: AtomicI32::new(1), // initialization reference
        }
    }

    /// A release requires an initialized descriptor with a live reference.
    /// This check precedes native checked-build tracking-list access.
    pub fn has_live_reference(&self) -> bool {
        self.removed.load(Ordering::SeqCst) <= 1
            && self.io_count.load(Ordering::SeqCst) > 0
    }

    /// Admit an I/O reference before checking removal, so an in-flight acquisition is counted.
    pub fn acquire(&self) -> Acquire {
        let mut count = self.io_count.load(Ordering::SeqCst);
        loop {
            assert!(count >= 0 && count < i32::MAX, "remove lock count overflow");
            match self.io_count.compare_exchange_weak(count, count + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        if self.removed.load(Ordering::SeqCst) == 0 {
            Acquire::Acquired
        } else {
            Acquire::DeletePending { wake_remove_waiter: self.drop_reference() }
        }
    }

    /// Release one admitted I/O reference. True means the removal waiter must be signalled.
    pub fn release(&self) -> bool {
        let count = self.io_count.load(Ordering::SeqCst);
        assert!(count > 0, "remove lock double release");
        self.drop_reference()
    }

    /// Close admission and drop the initialization and removing-IRP references.
    /// True means no other I/O is outstanding; false requires waiting for the event.
    pub fn begin_remove_and_wait(&self) -> bool {
        assert_eq!(self.removed.swap(1, Ordering::SeqCst), 0, "remove lock removed twice");
        let mut count = self.io_count.load(Ordering::SeqCst);
        loop {
            assert!(count >= 2, "remove lock removal has no caller reference");
            match self.io_count.compare_exchange_weak(count, count - 2, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return count == 2,
                Err(current) => count = current,
            }
        }
    }

    /// Count excluding the initialization reference, for checked-build high-water diagnostics.
    pub fn outstanding(&self) -> u32 {
        self.io_count.load(Ordering::SeqCst).saturating_sub(1).max(0) as u32
    }

    fn drop_reference(&self) -> bool {
        let mut count = self.io_count.load(Ordering::SeqCst);
        loop {
            assert!(count > 0, "remove lock double release");
            match self.io_count.compare_exchange_weak(count, count - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return count == 1 && self.removed.load(Ordering::SeqCst) != 0,
                Err(current) => count = current,
            }
        }
    }
}

const _: () = assert!(core::mem::size_of::<RemoveLockState>() == 8);
