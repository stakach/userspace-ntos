//! A guarded TSC projection of the real HPET monotonic clock.
//!
//! CPUID and the rootserver's PIT calibration admit the fast path. HPET remains
//! the reference and fallback. The atomics publish one monotonic time across
//! readers; a refused projection never becomes an accepted clock reading.

use core::arch::{asm, x86_64::__cpuid};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use nt_delay_execution::{CalibratedTscEpoch, TscClockError, TscDrift};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const NO_INVARIANT_TSC: u8 = 3;
const NO_CALIBRATION: u8 = 4;
const UNCERTAIN_EPOCH: u8 = 5;
const COUNTER_REGRESSED: u8 = 6;
const TIME_REGRESSED: u8 = 7;
const TIME_OVERFLOW: u8 = 8;
const REFERENCE_REGRESSED: u8 = 9;
const DRIFT_EXCEEDED: u8 = 10;

// Check at least once per 1024 reads, and before the fast projection moves a
// millisecond beyond the last independent HPET reading. A sudden TSC jump is
// checked before publication, even if the call-count interval has not elapsed.
const CHECK_MASK: u64 = 1024 - 1;
const MAX_UNCHECKED_100NS: u64 = 10_000;
const DRIFT_TOLERANCE_100NS: u64 = 10_000;

static STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static FREQUENCY_HZ: AtomicU64 = AtomicU64::new(0);
static EPOCH_TSC: AtomicU64 = AtomicU64::new(0);
static EPOCH_TIME_100NS: AtomicU64 = AtomicU64::new(0);
static LAST_TSC: AtomicU64 = AtomicU64::new(0);
static LAST_FAST_TIME_100NS: AtomicU64 = AtomicU64::new(0);
static LAST_HPET_TIME_100NS: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_TIME_100NS: AtomicU64 = AtomicU64::new(0);
static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FAST_READS: AtomicU64 = AtomicU64::new(0);
static HPET_READS: AtomicU64 = AtomicU64::new(0);
static DRIFT_CHECKS: AtomicU64 = AtomicU64::new(0);
static MAX_DRIFT_100NS: AtomicU64 = AtomicU64::new(0);
static EPOCH_BRACKET_CYCLES: AtomicU64 = AtomicU64::new(0);
static FALLBACK_RECONCILIATIONS: AtomicU64 = AtomicU64::new(0);
static FAST_BEHIND_PUBLISHED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TscAdmission {
    Ready,
    NoInvariantTsc,
    NoCalibration,
    UncertainEpoch,
    AlreadyInitialized,
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

/// Establish a real HPET epoch before publishing fast clock availability.
/// The rootserver calls this once after its HPET epoch is ready. A preempted
/// calibration bracket wider than 1 ms refuses TSC for this boot.
pub(crate) fn try_initialize(
    frequency_hz: u64,
    hpet_now: impl FnOnce() -> u64,
) -> TscAdmission {
    if STATE.compare_exchange(
        UNINITIALIZED, INITIALIZING, Ordering::AcqRel, Ordering::Acquire,
    ).is_err() {
        return TscAdmission::AlreadyInitialized;
    }
    if frequency_hz == 0 {
        STATE.store(NO_CALIBRATION, Ordering::Release);
        return TscAdmission::NoCalibration;
    }
    if !invariant_tsc() {
        STATE.store(NO_INVARIANT_TSC, Ordering::Release);
        return TscAdmission::NoInvariantTsc;
    }
    let before = ordered_tsc();
    let reference = hpet_now();
    let after = ordered_tsc();
    let Some(span) = after.checked_sub(before) else {
        STATE.store(UNCERTAIN_EPOCH, Ordering::Release);
        return TscAdmission::UncertainEpoch;
    };
    if span > frequency_hz / 1_000 {
        STATE.store(UNCERTAIN_EPOCH, Ordering::Release);
        return TscAdmission::UncertainEpoch;
    }
    let Some(epoch_tsc) = before.checked_add(span / 2) else {
        STATE.store(UNCERTAIN_EPOCH, Ordering::Release);
        return TscAdmission::UncertainEpoch;
    };
    if CalibratedTscEpoch::admit(true, frequency_hz, epoch_tsc, reference).is_err() {
        STATE.store(UNCERTAIN_EPOCH, Ordering::Release);
        return TscAdmission::UncertainEpoch;
    }
    FREQUENCY_HZ.store(frequency_hz, Ordering::Relaxed);
    EPOCH_BRACKET_CYCLES.store(span, Ordering::Relaxed);
    EPOCH_TSC.store(epoch_tsc, Ordering::Relaxed);
    EPOCH_TIME_100NS.store(reference, Ordering::Relaxed);
    LAST_TSC.store(epoch_tsc, Ordering::Relaxed);
    LAST_FAST_TIME_100NS.store(reference, Ordering::Relaxed);
    // A concurrent HPET fallback during INITIALIZING may already have published
    // a later value. Admission must never move either observable clock backward.
    LAST_HPET_TIME_100NS.fetch_max(reference, Ordering::AcqRel);
    PUBLISHED_TIME_100NS.fetch_max(reference, Ordering::AcqRel);
    STATE.store(READY, Ordering::Release);
    TscAdmission::Ready
}

fn disable(reason: u8) {
    let _ = STATE.compare_exchange(READY, reason, Ordering::AcqRel, Ordering::Acquire);
}

fn disable_for(error: TscClockError) {
    let reason = match error {
        TscClockError::CounterRegressed => COUNTER_REGRESSED,
        TscClockError::TimeRegressed => TIME_REGRESSED,
        TscClockError::TimeOverflow => TIME_OVERFLOW,
        TscClockError::ReferenceRegressed => REFERENCE_REGRESSED,
        TscClockError::NotInvariant => NO_INVARIANT_TSC,
        TscClockError::Uncalibrated => NO_CALIBRATION,
    };
    disable(reason);
}

/// Publish a real HPET reading. If it is briefly behind a previously returned
/// fast reading, retain that last accepted time until HPET catches up. This is
/// a counted fallback reconciliation, not a successful TSC projection.
fn publish_hpet(real: u64) -> u64 {
    HPET_READS.fetch_add(1, Ordering::Relaxed);
    LAST_HPET_TIME_100NS.fetch_max(real, Ordering::AcqRel);
    let prior = PUBLISHED_TIME_100NS.fetch_max(real, Ordering::AcqRel);
    if prior > real {
        FALLBACK_RECONCILIATIONS.fetch_add(1, Ordering::Relaxed);
        prior
    } else {
        real
    }
}

fn fallback(hpet_sample: Option<u64>, hpet_now: &mut impl FnMut() -> u64) -> u64 {
    publish_hpet(hpet_sample.unwrap_or_else(hpet_now))
}

/// Read the checked TSC projection. The HPET callback is called only for one
/// bounded reference check or a fallback; one invocation never repeats the
/// same HPET read. A disabled clock stays disabled for this boot.
#[inline]
pub(crate) fn now_or_hpet(mut hpet_now: impl FnMut() -> u64) -> u64 {
    if STATE.load(Ordering::Acquire) != READY {
        return fallback(None, &mut hpet_now);
    }
    let ordinal = ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let epoch = match CalibratedTscEpoch::admit(
        true,
        FREQUENCY_HZ.load(Ordering::Relaxed),
        EPOCH_TSC.load(Ordering::Relaxed),
        EPOCH_TIME_100NS.load(Ordering::Relaxed),
    ) {
        Ok(epoch) => epoch,
        Err(error) => {
            disable_for(error);
            return fallback(None, &mut hpet_now);
        }
    };
    let tsc = ordered_tsc();
    let time = match epoch.time_100ns_after(
        tsc,
        LAST_TSC.load(Ordering::Acquire),
        LAST_FAST_TIME_100NS.load(Ordering::Acquire),
    ) {
        Ok(time) => time,
        Err(error) => {
            disable_for(error);
            return fallback(None, &mut hpet_now);
        }
    };

    let mut reference = None;
    if ordinal & CHECK_MASK == 0
        || time.saturating_sub(LAST_HPET_TIME_100NS.load(Ordering::Acquire))
            > MAX_UNCHECKED_100NS
    {
        let real = hpet_now();
        reference = Some(real);
        DRIFT_CHECKS.fetch_add(1, Ordering::Relaxed);
        match epoch.drift_100ns(tsc, real, DRIFT_TOLERANCE_100NS) {
            Ok(TscDrift::Within(error)) => {
                MAX_DRIFT_100NS.fetch_max(error, Ordering::Relaxed);
                LAST_HPET_TIME_100NS.fetch_max(real, Ordering::AcqRel);
            }
            Ok(TscDrift::Exceeded(error)) => {
                MAX_DRIFT_100NS.fetch_max(error, Ordering::Relaxed);
                disable(DRIFT_EXCEEDED);
                return fallback(reference, &mut hpet_now);
            }
            Err(error) => {
                disable_for(error);
                return fallback(reference, &mut hpet_now);
            }
        }
    }

    if LAST_TSC.fetch_max(tsc, Ordering::AcqRel) > tsc {
        disable(COUNTER_REGRESSED);
        return fallback(reference, &mut hpet_now);
    }
    if LAST_FAST_TIME_100NS.fetch_max(time, Ordering::AcqRel) > time {
        disable(TIME_REGRESSED);
        return fallback(reference, &mut hpet_now);
    }
    if STATE.load(Ordering::Acquire) != READY {
        return fallback(reference, &mut hpet_now);
    }
    let prior = PUBLISHED_TIME_100NS.fetch_max(time, Ordering::AcqRel);
    if prior > time {
        FAST_BEHIND_PUBLISHED.fetch_add(1, Ordering::Relaxed);
        return fallback(reference, &mut hpet_now);
    }
    FAST_READS.fetch_add(1, Ordering::Relaxed);
    time
}

pub(crate) fn append_census(record: &mut nt_printf::record::RecordBuffer<4096>) {
    let state = match STATE.load(Ordering::Acquire) {
        UNINITIALIZED => "uninitialized",
        INITIALIZING => "initializing",
        READY => "ready",
        NO_INVARIANT_TSC => "no-invariant-tsc",
        NO_CALIBRATION => "no-calibration",
        UNCERTAIN_EPOCH => "uncertain-epoch",
        COUNTER_REGRESSED => "counter-regressed",
        TIME_REGRESSED => "time-regressed",
        TIME_OVERFLOW => "time-overflow",
        REFERENCE_REGRESSED => "reference-regressed",
        DRIFT_EXCEEDED => "drift-exceeded",
        _ => "invalid-state",
    };
    let _ = writeln!(
        record,
        "[tsc-clock] state={} attempts={} fast={} hpet={} checks={} max-drift-100ns={} epoch-bracket-cycles={} fast-behind={} reconciled={} last-hpet={} published={}",
        state,
        ATTEMPTS.load(Ordering::Relaxed),
        FAST_READS.load(Ordering::Relaxed),
        HPET_READS.load(Ordering::Relaxed),
        DRIFT_CHECKS.load(Ordering::Relaxed),
        MAX_DRIFT_100NS.load(Ordering::Relaxed),
        EPOCH_BRACKET_CYCLES.load(Ordering::Relaxed),
        FAST_BEHIND_PUBLISHED.load(Ordering::Relaxed),
        FALLBACK_RECONCILIATIONS.load(Ordering::Relaxed),
        LAST_HPET_TIME_100NS.load(Ordering::Acquire),
        PUBLISHED_TIME_100NS.load(Ordering::Acquire),
    );
}
