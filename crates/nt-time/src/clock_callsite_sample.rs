//! Bounded attribution for calls to a native clock reader.
//!
//! Sampling observes where time is requested; it never supplies or changes a clock value.

use core::panic::Location;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

const SAMPLE_MASK: u64 = 1024 - 1;

struct Slot {
    location: AtomicPtr<Location<'static>>,
    samples: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Self {
            location: AtomicPtr::new(ptr::null_mut()),
            samples: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClockCallsiteSample {
    pub location: &'static Location<'static>,
    pub samples: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ClockCallsiteSnapshot<const TOP: usize> {
    pub calls: u64,
    pub sampled: u64,
    pub overflow: u64,
    /// Highest sampled counts first. Empty entries follow populated entries.
    pub top: [Option<ClockCallsiteSample>; TOP],
}

/// One relaxed increment per clock call and bounded work on one in 1024 calls.
///
/// Each static caller location is retained without allocating. A full table counts overflow
/// rather than evicting an existing caller, so a snapshot never attributes samples to a
/// different file and line. The location pointers live for the duration of the program.
pub struct ClockCallsiteSampler<const SLOTS: usize> {
    calls: AtomicU64,
    sampled: AtomicU64,
    overflow: AtomicU64,
    slots: [Slot; SLOTS],
}

impl<const SLOTS: usize> ClockCallsiteSampler<SLOTS> {
    pub const fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            sampled: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            slots: [const { Slot::new() }; SLOTS],
        }
    }

    /// Record the caller of the clock entry point. Mark that entry point `#[track_caller]`
    /// too, so this method observes its actual caller instead of the wrapper's own line.
    #[track_caller]
    #[inline]
    pub fn observe(&self) {
        let ordinal = self.calls.fetch_add(1, Ordering::Relaxed);
        if ordinal & SAMPLE_MASK != 0 {
            return;
        }
        self.sampled.fetch_add(1, Ordering::Relaxed);
        let location = Location::caller();
        let wanted = ptr::from_ref(location).cast_mut();
        for slot in &self.slots {
            let existing = slot.location.load(Ordering::Acquire);
            if existing.is_null() {
                match slot.location.compare_exchange(
                    ptr::null_mut(), wanted, Ordering::AcqRel, Ordering::Acquire,
                ) {
                    Ok(_) => {
                        slot.samples.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(other) if same_location(other, location) => {
                        slot.samples.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(_) => continue,
                }
            }
            if same_location(existing, location) {
                slot.samples.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Copy a diagnostic snapshot without blocking clock callers. Concurrent updates can make
    /// the counters adjacent rather than simultaneous; they cannot change a caller's identity.
    pub fn snapshot<const TOP: usize>(&self) -> ClockCallsiteSnapshot<TOP> {
        let mut top: [Option<ClockCallsiteSample>; TOP] = [None; TOP];
        for slot in &self.slots {
            let pointer = slot.location.load(Ordering::Acquire);
            if pointer.is_null() {
                continue;
            }
            // Only a &'static Location obtained from Location::caller is ever published. Slots
            // are never cleared, so an acquired pointer cannot expire or be replaced.
            let location = unsafe { &*pointer };
            let mut candidate = Some(ClockCallsiteSample {
                location,
                samples: slot.samples.load(Ordering::Relaxed),
            });
            for entry in &mut top {
                if let Some(sample) = candidate {
                    if entry.is_none_or(|current| sample.samples > current.samples) {
                        core::mem::swap(entry, &mut candidate);
                    }
                }
            }
        }
        ClockCallsiteSnapshot {
            calls: self.calls.load(Ordering::Relaxed),
            sampled: self.sampled.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
            top,
        }
    }
}

impl<const SLOTS: usize> Default for ClockCallsiteSampler<SLOTS> {
    fn default() -> Self { Self::new() }
}

fn same_location(pointer: *mut Location<'static>, location: &'static Location<'static>) -> bool {
    if pointer.is_null() {
        return false;
    }
    // The acquired pointer is a permanent Location published by observe().
    let existing = unsafe { &*pointer };
    existing.file() == location.file()
        && existing.line() == location.line()
        && existing.column() == location.column()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Arc;

    #[track_caller]
    fn wrapped_clock<const SLOTS: usize>(counter: &ClockCallsiteSampler<SLOTS>) {
        counter.observe();
    }

    #[test]
    fn samples_exact_static_callers_and_sorts_top_counts() {
        let counter = ClockCallsiteSampler::<4>::new();
        for _ in 0..4096 { wrapped_clock(&counter); }
        for _ in 0..2048 { wrapped_clock(&counter); }
        let snapshot = counter.snapshot::<3>();
        assert_eq!((snapshot.calls, snapshot.sampled, snapshot.overflow), (6144, 6, 0));
        assert_eq!(snapshot.top[0].unwrap().samples, 4);
        assert_eq!(snapshot.top[1].unwrap().samples, 2);
        assert_eq!(snapshot.top[2].map(|sample| sample.samples), None);
        assert!(snapshot.top[0].unwrap().location.file().ends_with("clock_callsite_sample.rs"));
        assert_ne!(snapshot.top[0].unwrap().location.line(),
            snapshot.top[1].unwrap().location.line());
    }

    #[test]
    fn full_table_counts_overflow_without_relabeling_an_existing_caller() {
        let counter = ClockCallsiteSampler::<1>::new();
        wrapped_clock(&counter);
        for _ in 0..1023 { wrapped_clock(&counter); }
        wrapped_clock(&counter);
        let snapshot = counter.snapshot::<2>();
        assert_eq!((snapshot.calls, snapshot.sampled, snapshot.overflow), (1025, 2, 1));
        assert_eq!(snapshot.top[0].unwrap().samples, 1);
        assert!(snapshot.top[1].is_none());
    }

    #[test]
    fn concurrent_callers_never_lose_a_slot_or_exceed_the_sample_bound() {
        let counter = Arc::new(ClockCallsiteSampler::<8>::new());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let counter = Arc::clone(&counter);
                scope.spawn(move || {
                    for _ in 0..4096 { wrapped_clock(&counter); }
                });
            }
        });
        let snapshot = counter.snapshot::<8>();
        assert_eq!(snapshot.calls, 16_384);
        assert_eq!(snapshot.sampled, 16);
        assert_eq!(snapshot.overflow, 0);
        assert_eq!(snapshot.top.iter().flatten().map(|sample| sample.samples).sum::<u64>(), 16);
    }
}
