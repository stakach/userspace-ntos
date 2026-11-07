//! Pure conversion for an admitted, PIT-calibrated invariant TSC clock.
//!
//! The native adapter owns CPUID admission, the live HPET reference, atomic monotonic
//! publication, and the fallback decision. This type neither reads a clock nor claims a
//! native effect. Refusals require the adapter to sample its real HPET clock.

const HUNDRED_NS_PER_SECOND: u128 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TscClockError {
    NotInvariant,
    Uncalibrated,
    CounterRegressed,
    TimeRegressed,
    TimeOverflow,
    ReferenceRegressed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TscDrift {
    Within(u64),
    Exceeded(u64),
}

/// One checked relation between a TSC counter and a real HPET-derived monotonic epoch.
/// A frequency alone is insufficient; the native adapter must establish both readings at
/// one bounded calibration point and separately verify invariant-TSC capability.
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

    /// Verify caller-retained monotonic evidence before accepting another fast reading.
    /// The native adapter must retain/publish the prior sample atomically across readers.
    pub fn time_100ns_after(
        self,
        tsc_now: u64,
        prior_tsc: u64,
        prior_time_100ns: u64,
    ) -> Result<u64, TscClockError> {
        if tsc_now < prior_tsc {
            return Err(TscClockError::CounterRegressed);
        }
        let time = self.time_100ns(tsc_now)?;
        if time < prior_time_100ns {
            return Err(TscClockError::TimeRegressed);
        }
        Ok(time)
    }

    /// Compare the fast projection with an independent real HPET sample. An exceeded bound
    /// is a verdict for the native adapter to disable TSC and use HPET, not a new timestamp.
    pub fn drift_100ns(
        self,
        tsc_now: u64,
        hpet_now_100ns: u64,
        tolerance_100ns: u64,
    ) -> Result<TscDrift, TscClockError> {
        if hpet_now_100ns < self.epoch_time_100ns {
            return Err(TscClockError::ReferenceRegressed);
        }
        let projected = self.time_100ns(tsc_now)?;
        let error = projected.abs_diff(hpet_now_100ns);
        Ok(if error <= tolerance_100ns {
            TscDrift::Within(error)
        } else {
            TscDrift::Exceeded(error)
        })
    }
}
