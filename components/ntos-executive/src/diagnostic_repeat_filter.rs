//! Allocation-free first-sighting filter for repeated diagnostic observations only.
//!
//! A serial record costs tens of thousands of TSC ticks per byte, so a guest that polls the
//! same missing name must not pay for the same record on every call. The first sighting of
//! each fingerprint is reported; repeats are only counted. A full probe window reports the
//! observation as untracked so the caller can fall back to a bounded receipt budget.
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const REPEAT_FILTER_SLOTS: usize = 1024;
const PROBE_LIMIT: usize = 16;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sighting {
    First,
    Repeat,
    Untracked,
}

/// Fingerprint the exact observation fields. Each field is length-delimited so adjacent
/// fields cannot alias; zero is the empty-slot marker and is never returned.
pub(crate) fn fingerprint(fields: &[&[u8]]) -> u64 {
    let mut hash = FNV_OFFSET;
    for field in fields {
        for byte in (field.len() as u64).to_le_bytes().iter().chain(field.iter()) {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
        }
    }
    hash.max(1)
}

pub(crate) struct RepeatFilter {
    slots: [AtomicU64; REPEAT_FILTER_SLOTS],
    first: AtomicU64,
    repeats: AtomicU64,
    untracked: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RepeatCounts {
    pub(crate) first: u64,
    pub(crate) repeats: u64,
    pub(crate) untracked: u64,
}

impl RepeatFilter {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { AtomicU64::new(0) }; REPEAT_FILTER_SLOTS],
            first: AtomicU64::new(0),
            repeats: AtomicU64::new(0),
            untracked: AtomicU64::new(0),
        }
    }

    pub(crate) fn observe(&self, fingerprint: u64) -> Sighting {
        let fingerprint = fingerprint.max(1);
        let start = (fingerprint as usize) % REPEAT_FILTER_SLOTS;
        for probe in 0..PROBE_LIMIT {
            let slot = &self.slots[(start + probe) % REPEAT_FILTER_SLOTS];
            let current = match slot.compare_exchange(
                0, fingerprint, Ordering::AcqRel, Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.first.fetch_add(1, Ordering::Relaxed);
                    return Sighting::First;
                }
                Err(current) => current,
            };
            if current == fingerprint {
                self.repeats.fetch_add(1, Ordering::Relaxed);
                return Sighting::Repeat;
            }
        }
        self.untracked.fetch_add(1, Ordering::Relaxed);
        Sighting::Untracked
    }

    pub(crate) fn counts(&self) -> RepeatCounts {
        RepeatCounts {
            first: self.first.load(Ordering::Relaxed),
            repeats: self.repeats.load(Ordering::Relaxed),
            untracked: self.untracked.load(Ordering::Relaxed),
        }
    }
}
