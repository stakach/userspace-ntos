//! Root-only allocator walk observations. Isolated services share the image's read-only `.bss`;
//! their caller must pass the component-local heap-profile result before any counter is touched.

use core::sync::atomic::{AtomicU64, Ordering};

pub(super) struct WalkCounter {
    operations: AtomicU64,
    visited: AtomicU64,
    max_visited: AtomicU64,
    ticks: AtomicU64,
}

#[derive(Clone, Copy, Default)]
pub struct WalkSample {
    pub operations: u64,
    pub visited: u64,
    pub max_visited: u64,
    /// TSC ticks spent in the walked list operation, including its node updates.
    pub ticks: u64,
}

impl WalkCounter {
    pub(super) const fn new() -> Self {
        Self {
            operations: AtomicU64::new(0),
            visited: AtomicU64::new(0),
            max_visited: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
        }
    }

    pub(super) fn record(&self, root_heap: bool, visited: usize, ticks: u64) {
        if !root_heap {
            return;
        }
        self.operations.fetch_add(1, Ordering::Relaxed);
        self.visited.fetch_add(visited as u64, Ordering::Relaxed);
        self.max_visited.fetch_max(visited as u64, Ordering::Relaxed);
        self.ticks.fetch_add(ticks, Ordering::Relaxed);
    }

    pub(super) fn sample(&self, root_heap: bool) -> WalkSample {
        if !root_heap {
            return WalkSample::default();
        }
        WalkSample {
            operations: self.operations.load(Ordering::Relaxed),
            visited: self.visited.load(Ordering::Relaxed),
            max_visited: self.max_visited.load(Ordering::Relaxed),
            ticks: self.ticks.load(Ordering::Relaxed),
        }
    }
}
