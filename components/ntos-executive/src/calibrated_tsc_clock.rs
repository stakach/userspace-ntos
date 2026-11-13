//! The TSC fast path of the real HPET monotonic clock.
//!
//! CPUID and the kernel's PIT calibration admit the counter for measurement only.
//! `nt_delay_execution::DisciplinedTsc` then measures it against HPET, serves
//! projections between bounded reference checks, and withdraws them when the
//! counter leaves its rate tolerance. HPET stays the reference and the fallback:
//! every reading that is not a checked projection is a real HPET reading, and one
//! publication rule keeps time monotonic across both sources and all readers.

use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use nt_delay_execution::{
    DisciplinedTsc, MonotonicTime, ReferenceSample, TscClockError, TscObservation, TscPhase,
    TscRead,
};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const ADMITTED: u8 = 2;
const NO_INVARIANT_TSC: u8 = 3;
const NO_CALIBRATION: u8 = 4;
const FAILED: u8 = 5;

static ADMISSION: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static CLOCK: ExclusiveClock = ExclusiveClock::new();
static PUBLISHED: MonotonicTime = MonotonicTime::new();
static LAST_HPET_TIME_100NS: AtomicU64 = AtomicU64::new(0);
static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FAST_READS: AtomicU64 = AtomicU64::new(0);
static HPET_READS: AtomicU64 = AtomicU64::new(0);
static CONTENDED: AtomicU64 = AtomicU64::new(0);
static FALLBACK_RECONCILIATIONS: AtomicU64 = AtomicU64::new(0);
static FAST_BEHIND_PUBLISHED: AtomicU64 = AtomicU64::new(0);

/// The discipline, owned by whichever reader holds the flag. A reader never waits
/// for it: executive threads share a CPU, so a preempted holder could not release
/// it while another reader spun. A reader that finds it held reads HPET instead.
struct ExclusiveClock {
    held: AtomicBool,
    tsc: UnsafeCell<Option<DisciplinedTsc>>,
}

// SAFETY: `tsc` is reached only through a `ClockHold`, and `held` admits one at a time.
unsafe impl Sync for ExclusiveClock {}

struct ClockHold<'a>(&'a ExclusiveClock);

impl ExclusiveClock {
    const fn new() -> Self {
        Self { held: AtomicBool::new(false), tsc: UnsafeCell::new(None) }
    }

    fn try_hold(&self) -> Option<ClockHold<'_>> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| ClockHold(self))
    }
}

impl ClockHold<'_> {
    fn tsc(&mut self) -> &mut Option<DisciplinedTsc> {
        // SAFETY: this hold is the only one, and the borrow cannot outlive it.
        unsafe { &mut *self.0.tsc.get() }
    }
}

impl Drop for ClockHold<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

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
    (u64::from(high) << 32) | u64::from(low)
}

fn invariant_tsc() -> bool {
    // Extended leaf 0x80000007 EDX[8] is the architectural invariant-TSC bit.
    // A frequency estimate alone says nothing about cross-state clock stability.
    unsafe {
        __cpuid(0x8000_0000).eax >= 0x8000_0007
            && (__cpuid(0x8000_0007).edx & (1 << 8)) != 0
    }
}

/// Admit an invariant, calibrated counter for measurement against HPET. The
/// rootserver calls this once, after its HPET epoch is ready. No reading is
/// served from the counter until the discipline has measured its rate.
pub(crate) fn admit(seed_frequency_hz: u64) {
    if ADMISSION.compare_exchange(
        UNINITIALIZED, INITIALIZING, Ordering::AcqRel, Ordering::Acquire,
    ).is_err() {
        return;
    }
    let admission = match DisciplinedTsc::admit(invariant_tsc(), seed_frequency_hz) {
        Ok(tsc) => match CLOCK.try_hold() {
            Some(mut clock) => {
                *clock.tsc() = Some(tsc);
                ADMITTED
            }
            // Nothing holds the clock before it is admitted.
            None => UNINITIALIZED,
        },
        Err(TscClockError::Uncalibrated) => NO_CALIBRATION,
        Err(_) => NO_INVARIANT_TSC,
    };
    ADMISSION.store(admission, Ordering::Release);
}

/// Publish a real HPET reading. If it is behind a reading already returned, that
/// reading is returned again until HPET catches up, and the hold is counted.
fn publish_hpet(real: u64) -> u64 {
    HPET_READS.fetch_add(1, Ordering::Relaxed);
    LAST_HPET_TIME_100NS.fetch_max(real, Ordering::AcqRel);
    let published = PUBLISHED.publish(real);
    if published.held {
        FALLBACK_RECONCILIATIONS.fetch_add(1, Ordering::Relaxed);
    }
    published.time_100ns
}

/// Read the monotonic clock. The HPET callback runs at most once: for a reference
/// check, which is bracketed by counter readings, or whenever the counter is not
/// serving. A projection never becomes a reading without the discipline's consent.
#[inline]
pub(crate) fn now_or_hpet(hpet_now: impl FnOnce() -> u64) -> u64 {
    if ADMISSION.load(Ordering::Acquire) != ADMITTED {
        return publish_hpet(hpet_now());
    }
    let ordinal = ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let Some(mut clock) = CLOCK.try_hold() else {
        CONTENDED.fetch_add(1, Ordering::Relaxed);
        return publish_hpet(hpet_now());
    };
    let Some(tsc) = clock.tsc() else {
        return publish_hpet(hpet_now());
    };
    let tsc_before = ordered_tsc();
    if let TscRead::Fast(time) = tsc.read(tsc_before, ordinal) {
        drop(clock);
        FAST_READS.fetch_add(1, Ordering::Relaxed);
        let published = PUBLISHED.publish(time);
        if published.held {
            FAST_BEHIND_PUBLISHED.fetch_add(1, Ordering::Relaxed);
        }
        return published.time_100ns;
    }
    let reference_100ns = hpet_now();
    let sample = ReferenceSample { tsc_before, reference_100ns, tsc_after: ordered_tsc() };
    if let TscObservation::Failed(_) = tsc.observe(sample, ordinal) {
        ADMISSION.store(FAILED, Ordering::Release);
    }
    drop(clock);
    publish_hpet(reference_100ns)
}

pub(crate) fn append_census(record: &mut nt_printf::record::RecordBuffer<4096>) {
    // The clock is held only once it is admitted, so a census cannot be in `admit`'s way.
    let admission = ADMISSION.load(Ordering::Acquire);
    let tsc = if matches!(admission, ADMITTED | FAILED) {
        CLOCK.try_hold().and_then(|mut clock| *clock.tsc())
    } else {
        None
    };
    let state = match (admission, tsc.map(|tsc| tsc.phase())) {
        (UNINITIALIZED, _) => "uninitialized",
        (INITIALIZING, _) => "initializing",
        (NO_INVARIANT_TSC, _) => "no-invariant-tsc",
        (NO_CALIBRATION, _) => "no-calibration",
        // Another reader holds the discipline, so its fields below read as zero.
        (_, None) => "held",
        (_, Some(TscPhase::Measuring)) => "measuring",
        (_, Some(TscPhase::Disciplined)) => "ready",
        (_, Some(TscPhase::Failed(error))) => match error {
            TscClockError::NotInvariant => "no-invariant-tsc",
            TscClockError::Uncalibrated => "no-calibration",
            TscClockError::CounterRegressed => "counter-regressed",
            TscClockError::TimeOverflow => "time-overflow",
            TscClockError::Unstable => "unstable",
        },
    };
    let discipline = |field: fn(&DisciplinedTsc) -> u64| tsc.as_ref().map_or(0, field);
    let _ = writeln!(
        record,
        "[tsc-clock] state={} attempts={} fast={} hpet={} anchors={} excursions={} uncertain={} contended={} hz={} seed-hz={} rate-ppm={} max-rate-ppm={} max-offset-100ns={} fast-behind={} reconciled={} last-hpet={} published={}",
        state,
        ATTEMPTS.load(Ordering::Relaxed),
        FAST_READS.load(Ordering::Relaxed),
        HPET_READS.load(Ordering::Relaxed),
        discipline(DisciplinedTsc::anchors),
        discipline(DisciplinedTsc::excursions),
        discipline(DisciplinedTsc::uncertain_samples),
        CONTENDED.load(Ordering::Relaxed),
        discipline(DisciplinedTsc::frequency_hz),
        discipline(DisciplinedTsc::seed_frequency_hz),
        discipline(DisciplinedTsc::last_rate_error_ppm),
        discipline(DisciplinedTsc::max_rate_error_ppm),
        discipline(DisciplinedTsc::max_offset_100ns),
        FAST_BEHIND_PUBLISHED.load(Ordering::Relaxed),
        FALLBACK_RECONCILIATIONS.load(Ordering::Relaxed),
        LAST_HPET_TIME_100NS.load(Ordering::Acquire),
        PUBLISHED.latest(),
    );
}
