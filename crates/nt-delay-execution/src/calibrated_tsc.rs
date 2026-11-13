//! Pure conversion from an invariant TSC reading to time, from one reference point.
//!
//! `DisciplinedTsc` decides which reference point and frequency to convert with, and whether
//! a conversion may be served at all. This type neither reads a clock nor claims a native
//! effect.

const HUNDRED_NS_PER_SECOND: u128 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TscClockError {
    NotInvariant,
    Uncalibrated,
    CounterRegressed,
    TimeOverflow,
    /// The counter kept leaving the rate tolerance of the reference clock.
    Unstable,
}

/// One checked relation between a TSC counter and a real reference-clock reading. A
/// frequency alone is insufficient: both readings come from one bracketed reference sample,
/// and invariant-TSC capability is verified separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibratedTscEpoch {
    frequency_hz: u64,
    epoch_tsc: u64,
    epoch_time_100ns: u64,
}

impl CalibratedTscEpoch {
    pub const fn admit(
        invariant_tsc: bool,
        frequency_hz: u64,
        epoch_tsc: u64,
        epoch_time_100ns: u64,
    ) -> Result<Self, TscClockError> {
        if !invariant_tsc {
            return Err(TscClockError::NotInvariant);
        }
        if frequency_hz == 0 {
            return Err(TscClockError::Uncalibrated);
        }
        Ok(Self { frequency_hz, epoch_tsc, epoch_time_100ns })
    }

    pub const fn frequency_hz(self) -> u64 { self.frequency_hz }
    pub const fn epoch_tsc(self) -> u64 { self.epoch_tsc }
    pub const fn epoch_time_100ns(self) -> u64 { self.epoch_time_100ns }

    /// Round fractional cycles down, as a clock read cannot report a future time.
    /// Both multiplication and epoch addition are checked; overflow never saturates into
    /// a plausible-looking timestamp.
    pub fn time_100ns(self, tsc_now: u64) -> Result<u64, TscClockError> {
        let cycles = tsc_now.checked_sub(self.epoch_tsc)
            .ok_or(TscClockError::CounterRegressed)?;
        let elapsed = (u128::from(cycles) * HUNDRED_NS_PER_SECOND)
            / u128::from(self.frequency_hz);
        let total = u128::from(self.epoch_time_100ns) + elapsed;
        u64::try_from(total).map_err(|_| TscClockError::TimeOverflow)
    }
}
