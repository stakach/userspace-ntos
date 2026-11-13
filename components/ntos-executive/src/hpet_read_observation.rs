//! Bounded observation of the existing HPET main-counter read.
//!
//! The counters are diagnostic only. They never select a clock or change scheduling.

use core::arch::asm;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

const SAMPLE_MASK: u64 = 1024 - 1;

static READS: AtomicU64 = AtomicU64::new(0);
static SAMPLES: AtomicU64 = AtomicU64::new(0);
static TSC_REGRESSIONS: AtomicU64 = AtomicU64::new(0);
static TOTAL_CYCLES: AtomicU64 = AtomicU64::new(0);
static MAX_CYCLES: AtomicU64 = AtomicU64::new(0);
// <= 1k, <= 10k, <= 100k, <= 1m, and > 1m cycles.
static BUCKETS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// LFENCE orders earlier instructions before RDTSC and keeps later instructions
/// behind it. Both timestamps include fence overhead; an interrupt or VM exit
/// between them also contributes to the observed duration.
#[inline]
fn ordered_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | low as u64
}

/// Read the mapped main counter exactly once. One in 1024 calls is timed; every
/// call pays only one relaxed atomic increment beyond the original volatile read.
///
/// # Safety
/// `counter` must address a mapped, readable HPET main-counter register.
#[inline]
pub(crate) unsafe fn read_counter(counter: *const u64) -> u64 {
    let ordinal = READS.fetch_add(1, Ordering::Relaxed);
    if ordinal & SAMPLE_MASK != 0 {
        return unsafe { core::ptr::read_volatile(counter) };
    }

    let before = ordered_tsc();
    let value = unsafe { core::ptr::read_volatile(counter) };
    let after = ordered_tsc();
    SAMPLES.fetch_add(1, Ordering::Relaxed);
    if let Some(cycles) = after.checked_sub(before) {
        TOTAL_CYCLES.fetch_add(cycles, Ordering::Relaxed);
        MAX_CYCLES.fetch_max(cycles, Ordering::Relaxed);
        let bucket = match cycles {
            0..=1_000 => 0,
            1_001..=10_000 => 1,
            10_001..=100_000 => 2,
            100_001..=1_000_000 => 3,
            _ => 4,
        };
        BUCKETS[bucket].fetch_add(1, Ordering::Relaxed);
    } else {
        TSC_REGRESSIONS.fetch_add(1, Ordering::Relaxed);
    }
    value
}

/// Append a bounded snapshot to the caller's existing record. Relaxed reads may
/// see adjacent counters at slightly different instants, which is acceptable for
/// this observation and avoids a lock in the clock path.
pub(crate) fn append_census(record: &mut nt_printf::record::RecordBuffer<4096>) {
    let _ = writeln!(
        record,
        "[hpet-read] calls={} sampled={} regressions={} cycles_total={} cycles_max={} buckets_1k_10k_100k_1m_over=[{},{},{},{},{}]",
        READS.load(Ordering::Relaxed),
        SAMPLES.load(Ordering::Relaxed),
        TSC_REGRESSIONS.load(Ordering::Relaxed),
        TOTAL_CYCLES.load(Ordering::Relaxed),
        MAX_CYCLES.load(Ordering::Relaxed),
        BUCKETS[0].load(Ordering::Relaxed),
        BUCKETS[1].load(Ordering::Relaxed),
        BUCKETS[2].load(Ordering::Relaxed),
        BUCKETS[3].load(Ordering::Relaxed),
        BUCKETS[4].load(Ordering::Relaxed),
    );
}
