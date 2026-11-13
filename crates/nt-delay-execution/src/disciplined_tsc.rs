//! Discipline of an invariant TSC against the real reference clock.
//!
//! A boot-time frequency estimate is only a seed. Any fixed estimate is wrong by some parts per
//! million, and an error measured from one fixed epoch grows without bound. This policy
//! therefore measures the counter's rate against the reference itself, moves the projection
//! anchor to every accepted reference sample so that error is bounded per check interval, and
//! judges the counter by its rate since the previous anchor.
//!
//! The type neither reads a clock nor publishes a time. The native adapter serialises access,
//! takes the bracketed reference samples this policy asks for, and publishes every returned
//! reading through [`MonotonicTime`].

use core::sync::atomic::{AtomicU64, Ordering};

use crate::calibrated_tsc::{CalibratedTscEpoch, TscClockError};

/// A fast reading is never projected further than this past the last accepted reference sample.
pub const CHECK_INTERVAL_100NS: u64 = 100_000;
/// A counter that advances too slowly to reach the interval is still checked after this many
/// reads, so a stalled counter cannot hold time still.
pub const CHECK_READS: u64 = 1024;
/// A reference read bracketed by counter readings further apart than this was delayed. It says
/// nothing about the counter and is neither an anchor nor a verdict.
pub const MAX_BRACKET_100NS: u64 = 1_000;
/// The counter may differ from the reference by this rate since the previous anchor. It covers
/// the reference's own slewing; a larger difference is a discontinuity or a wrong rate.
pub const RATE_TOLERANCE_PPM: u64 = 500;
/// The rate is measured over reference spans of at least this length.
pub const RATE_WINDOW_100NS: u64 = 10_000_000;
/// Consecutive rate windows that must agree before the fast path is served.
pub const CLEAN_WINDOWS_TO_ADMIT: u32 = 2;
/// More excursions than this without a sustained clean run mark the counter unreliable.
pub const MAX_EXCURSIONS: u32 = 8;
/// Consecutive clean windows while disciplined after which earlier excursions are forgiven.
pub const FORGIVENESS_WINDOWS: u32 = 64;

/// One reference reading taken between two counter readings by the same thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceSample {
    pub tsc_before: u64,
    pub reference_100ns: u64,
    pub tsc_after: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TscPhase {
    /// The reference serves every read while the counter's rate is measured against it.
    Measuring,
    /// The fast path is served between reference checks.
    Disciplined,
    /// The counter is unreliable for this boot.
    Failed(TscClockError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TscRead {
    /// A projection within one check interval of the last accepted reference sample.
    Fast(u64),
    /// The caller must take a bracketed reference sample, pass it to
    /// [`DisciplinedTsc::observe`], and return the reference reading.
    NeedsReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TscObservation {
    /// The bracket was too wide to place the reference reading. Nothing changed.
    Uncertain,
    /// The fast path is not served yet.
    Measuring,
    /// The projection now starts at this sample. `offset_100ns` is how far the previous
    /// projection was from it.
    Anchored { offset_100ns: u64 },
    /// The counter left the rate tolerance. The fast path is withdrawn until it is re-measured.
    Excursion { offset_100ns: u64, allowed_100ns: u64 },
    Failed(TscClockError),
}

/// An accepted reference sample: the reference reading placed at the middle of its bracket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Mark {
    tsc: u64,
    time_100ns: u64,
    /// How far the reading may really be from `tsc`: half the bracket, plus rounding.
    uncertainty_100ns: u64,
    ordinal: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisciplinedTsc {
    phase: TscPhase,
    seed_frequency_hz: u64,
    frequency_hz: u64,
    /// The last accepted sample. While disciplined it is where the projection starts.
    anchor: Option<Mark>,
    /// Where the current rate window starts.
    window: Option<Mark>,
    /// Consecutive windows whose rate agreed with the estimate.
    clean_windows: u32,
    /// Excursions not yet forgiven by a sustained clean run.
    strikes: u32,
    rate_measured: bool,
    anchors: u64,
    excursions: u64,
    uncertain_samples: u64,
    last_rate_error_ppm: u64,
    max_rate_error_ppm: u64,
    max_offset_100ns: u64,
}

impl DisciplinedTsc {
    /// Start measuring. The seed only sizes the first brackets and is the rate the first
    /// window is compared with; the fast path waits for the measured rate.
    pub const fn admit(invariant_tsc: bool, seed_frequency_hz: u64) -> Result<Self, TscClockError> {
        if !invariant_tsc {
            return Err(TscClockError::NotInvariant);
        }
        if seed_frequency_hz == 0 {
            return Err(TscClockError::Uncalibrated);
        }
        Ok(Self {
            phase: TscPhase::Measuring,
            seed_frequency_hz,
            frequency_hz: seed_frequency_hz,
            anchor: None,
            window: None,
            clean_windows: 0,
            strikes: 0,
            rate_measured: false,
            anchors: 0,
            excursions: 0,
            uncertain_samples: 0,
            last_rate_error_ppm: 0,
            max_rate_error_ppm: 0,
            max_offset_100ns: 0,
        })
    }

    pub const fn phase(&self) -> TscPhase { self.phase }
    /// The current rate estimate: the seed until the first window is measured.
    pub const fn frequency_hz(&self) -> u64 { self.frequency_hz }
    pub const fn seed_frequency_hz(&self) -> u64 { self.seed_frequency_hz }
    /// Reference samples the projection was moved to while disciplined.
    pub const fn anchors(&self) -> u64 { self.anchors }
    /// Every excursion since admission, forgiven or not.
    pub const fn excursions(&self) -> u64 { self.excursions }
    pub const fn uncertain_samples(&self) -> u64 { self.uncertain_samples }
    /// How far the last measured window was from the estimate it replaced.
    pub const fn last_rate_error_ppm(&self) -> u64 { self.last_rate_error_ppm }
    /// The largest such difference, not counting the first window's distance from the seed.
    pub const fn max_rate_error_ppm(&self) -> u64 { self.max_rate_error_ppm }
    /// The furthest a projection has been from a reference sample it was checked against.
    pub const fn max_offset_100ns(&self) -> u64 { self.max_offset_100ns }

    /// One fast reading, or a request for a reference sample. Never changes the discipline.
    pub fn read(&self, tsc: u64, ordinal: u64) -> TscRead {
        let (TscPhase::Disciplined, Some(anchor)) = (self.phase, self.anchor) else {
            return TscRead::NeedsReference;
        };
        if ordinal.wrapping_sub(anchor.ordinal) >= CHECK_READS {
            return TscRead::NeedsReference;
        }
        match self.project(anchor, tsc) {
            Ok(time) if time - anchor.time_100ns <= CHECK_INTERVAL_100NS => TscRead::Fast(time),
            _ => TscRead::NeedsReference,
        }
    }

    /// Judge the counter against one bracketed reference sample. The caller returns the
    /// sample's reference reading whatever the verdict.
    pub fn observe(&mut self, sample: ReferenceSample, ordinal: u64) -> TscObservation {
        if let TscPhase::Failed(error) = self.phase {
            return TscObservation::Failed(error);
        }
        let Some(bracket) = sample.tsc_after.checked_sub(sample.tsc_before) else {
            return self.fail(TscClockError::CounterRegressed);
        };
        if let Some(anchor) = self.anchor {
            if sample.tsc_before < anchor.tsc {
                return self.fail(TscClockError::CounterRegressed);
            }
            if sample.reference_100ns < anchor.time_100ns {
                return self.fail(TscClockError::ReferenceRegressed);
            }
        }
        let bracket_100ns = ceil_div(
            u128::from(bracket) * HUNDRED_NS_PER_SECOND, u128::from(self.frequency_hz));
        if bracket_100ns > u128::from(MAX_BRACKET_100NS) {
            self.uncertain_samples += 1;
            return TscObservation::Uncertain;
        }
        let mark = Mark {
            tsc: sample.tsc_before + bracket / 2,
            time_100ns: sample.reference_100ns,
            // Bounded by the bracket check above; one more for the projection's rounding.
            uncertainty_100ns: bracket_100ns as u64 / 2 + 1,
            ordinal,
        };
        match (self.phase, self.anchor) {
            (TscPhase::Disciplined, Some(anchor)) => self.check(anchor, mark),
            _ => {
                self.anchor = Some(mark);
                if self.measure_window(mark) && self.clean_windows >= CLEAN_WINDOWS_TO_ADMIT {
                    self.phase = TscPhase::Disciplined;
                    self.clean_windows = 0;
                }
                TscObservation::Measuring
            }
        }
    }

    fn project(&self, from: Mark, tsc: u64) -> Result<u64, TscClockError> {
        CalibratedTscEpoch::admit(true, self.frequency_hz, from.tsc, from.time_100ns)?
            .time_100ns(tsc)
    }

    /// While disciplined: is the counter still within the rate tolerance since the anchor?
    fn check(&mut self, anchor: Mark, mark: Mark) -> TscObservation {
        let projected = match self.project(anchor, mark.tsc) {
            Ok(projected) => projected,
            Err(error) => return self.fail(error),
        };
        let offset_100ns = projected.abs_diff(mark.time_100ns);
        let elapsed = u128::from(mark.time_100ns - anchor.time_100ns);
        let allowed = u128::from(anchor.uncertainty_100ns + mark.uncertainty_100ns)
            + ceil_div(elapsed * u128::from(RATE_TOLERANCE_PPM), PPM);
        self.max_offset_100ns = self.max_offset_100ns.max(offset_100ns);
        if u128::from(offset_100ns) > allowed {
            return self.excursion(mark, offset_100ns, allowed.min(u128::from(u64::MAX)) as u64);
        }
        self.anchor = Some(mark);
        self.anchors += 1;
        if self.measure_window(mark) && self.clean_windows >= FORGIVENESS_WINDOWS {
            self.strikes = 0;
        }
        TscObservation::Anchored { offset_100ns }
    }

    /// Withdraw the fast path and measure the counter again from this sample.
    fn excursion(&mut self, mark: Mark, offset_100ns: u64, allowed_100ns: u64) -> TscObservation {
        self.excursions += 1;
        self.strikes += 1;
        if self.strikes > MAX_EXCURSIONS {
            return self.fail(TscClockError::Unstable);
        }
        self.phase = TscPhase::Measuring;
        self.anchor = Some(mark);
        self.window = Some(mark);
        self.clean_windows = 0;
        TscObservation::Excursion { offset_100ns, allowed_100ns }
    }

    fn fail(&mut self, error: TscClockError) -> TscObservation {
        self.phase = TscPhase::Failed(error);
        TscObservation::Failed(error)
    }

    /// Once the window is long enough, replace the rate estimate with the rate measured across
    /// it and start the next window. Returns whether a window completed.
    fn measure_window(&mut self, mark: Mark) -> bool {
        let Some(start) = self.window else {
            self.window = Some(mark);
            return false;
        };
        let span = mark.time_100ns - start.time_100ns;
        if span < RATE_WINDOW_100NS {
            return false;
        }
        self.window = Some(mark);
        let measured = u128::from(mark.tsc - start.tsc) * HUNDRED_NS_PER_SECOND / u128::from(span);
        let Some(measured) = u64::try_from(measured).ok().filter(|hz| *hz != 0) else {
            // A counter that did not count across a whole window has no rate to adopt.
            self.clean_windows = 0;
            return true;
        };
        let error_ppm = u128::from(measured.abs_diff(self.frequency_hz)) * PPM
            / u128::from(self.frequency_hz);
        let placement_ppm = ceil_div(
            u128::from(start.uncertainty_100ns + mark.uncertainty_100ns) * PPM, u128::from(span));
        self.clean_windows = if error_ppm <= u128::from(RATE_TOLERANCE_PPM) + placement_ppm {
            self.clean_windows.saturating_add(1)
        } else {
            0
        };
        self.last_rate_error_ppm = error_ppm.min(u128::from(u64::MAX)) as u64;
        if self.rate_measured {
            self.max_rate_error_ppm = self.max_rate_error_ppm.max(self.last_rate_error_ppm);
        }
        self.rate_measured = true;
        self.frequency_hz = measured;
        true
    }
}

const HUNDRED_NS_PER_SECOND: u128 = 10_000_000;
const PPM: u128 = 1_000_000;

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator.div_ceil(denominator)
}

/// What a caller is given for one clock reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Published {
    pub time_100ns: u64,
    /// The reading was behind a time already returned, which was returned again instead.
    pub held: bool,
}

/// The one publication rule for every clock source: a returned time is never earlier than a
/// time already returned to any reader.
#[derive(Debug, Default)]
pub struct MonotonicTime(AtomicU64);

impl MonotonicTime {
    pub const fn new() -> Self { Self(AtomicU64::new(0)) }

    pub fn publish(&self, reading_100ns: u64) -> Published {
        let latest = self.0.fetch_max(reading_100ns, Ordering::AcqRel);
        Published { time_100ns: latest.max(reading_100ns), held: latest > reading_100ns }
    }

    pub fn latest(&self) -> u64 { self.0.load(Ordering::Acquire) }
}
