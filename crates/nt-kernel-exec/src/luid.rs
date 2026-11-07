//! One local LUID namespace for kernel and user-mode allocation.

use core::sync::atomic::{AtomicU64, Ordering};

/// ReactOS `ExpLuid` returns the old value of an atomic increment. An exhausted
/// namespace must fail rather than wrap and reissue an identifier.
pub struct LocalLuidAllocator {
    next: AtomicU64,
}

impl LocalLuidAllocator {
    pub const fn new(first: u64) -> Self {
        Self { next: AtomicU64::new(first) }
    }

    pub fn allocate(&self) -> Option<u64> {
        self.next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_add(1))
            .ok()
    }
}
