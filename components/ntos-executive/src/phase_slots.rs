//! Lock-free ownership of a fixed set of slots shared by the root and hosted completion paths.
//!
//! Each slot's phase is the owner: only the thread that moved a slot into a phase with
//! [`PhaseSlots::transition`] (or [`PhaseSlots::claim`]) may touch the slot's other data until
//! it publishes the next phase. No path ever waits on another, so a holder that is preempted,
//! parked or blocked can never make another context spin; an observer that meets a slot in a
//! transitional phase simply sees it as unavailable.

use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const EMPTY: u64 = 0;
/// A claimer is filling the slot; no observer may read its data.
pub(crate) const CLAIMING: u64 = u64::MAX;

pub(crate) struct PhaseSlots<const N: usize> {
    phases: [AtomicU64; N],
    keys: [AtomicU64; N],
}

impl<const N: usize> PhaseSlots<N> {
    pub(crate) const fn new() -> Self {
        Self {
            phases: [const { AtomicU64::new(EMPTY) }; N],
            keys: [const { AtomicU64::new(0) }; N],
        }
    }

    /// Claim an empty slot for `key`. Refuses a key that another published slot already owns.
    pub(crate) fn claim(&self, key: u64) -> Option<usize> {
        if key == 0 || self.find_published(key).is_some() {
            return None;
        }
        (0..N).find(|&index| {
            self.phases[index]
                .compare_exchange(EMPTY, CLAIMING, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
                && {
                    self.keys[index].store(key, Ordering::Release);
                    true
                }
        })
    }

    /// The published slot owned by `key` and its phase. Transitional phases are skipped.
    pub(crate) fn find_published(&self, key: u64) -> Option<(usize, u64)> {
        (0..N).find_map(|index| {
            let phase = self.phases[index].load(Ordering::Acquire);
            (phase != EMPTY && phase != CLAIMING && self.keys[index].load(Ordering::Acquire) == key)
                .then_some((index, phase))
        })
    }

    /// Any slot, published or transitional, is owned by `key`.
    pub(crate) fn owned(&self, key: u64) -> bool {
        (0..N).any(|index| {
            self.phases[index].load(Ordering::Acquire) != EMPTY
                && self.keys[index].load(Ordering::Acquire) == key
        })
    }

    /// Move `index` from `from` to `to` iff it is still in `from`.
    pub(crate) fn transition(&self, index: usize, from: u64, to: u64) -> bool {
        self.phases[index]
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Publish the owner's next phase. Only the current phase owner may call this.
    pub(crate) fn publish(&self, index: usize, phase: u64) {
        if phase == EMPTY {
            self.keys[index].store(0, Ordering::Release);
        }
        self.phases[index].store(phase, Ordering::Release);
    }

    pub(crate) fn phase(&self, index: usize) -> u64 {
        self.phases[index].load(Ordering::Acquire)
    }
}
