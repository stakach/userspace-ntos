#![no_std]

/// Largest system time accepted by NT's clock-setting path.
///
/// The native kernel requires the high nibble of the signed `LARGE_INTEGER`
/// system time to be clear before publishing it through shared user data.
pub const MAX_SYSTEM_TIME_100NS: u64 = 0x0fff_ffff_ffff_ffff;
pub const UNIX_EPOCH_IN_NT_SECONDS: i64 = 11_644_473_600;
pub const TICKS_PER_SECOND: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcDateTime {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Sunday is zero, matching NT's `TIME_FIELDS.Weekday`.
    pub weekday: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeSnapshot {
    pub monotonic_100ns: u64,
    pub system_time_100ns: u64,
    pub clock_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    InvalidSystemTime,
    MonotonicRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemTimeChange {
    pub previous_100ns: u64,
    pub current_100ns: u64,
    pub delta_100ns: i128,
    pub clock_generation: u64,
}

/// Adjustable NT system time anchored to an independent monotonic clock.
///
/// Changing system time moves only the system-time anchor. It never changes
/// the monotonic counter used by relative delays and scheduler accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdjustableClock {
    anchor_monotonic_100ns: u64,
    anchor_system_time_100ns: u64,
    generation: u64,
}

impl AdjustableClock {
    pub const fn new(monotonic_100ns: u64, system_time_100ns: u64) -> Self {
        Self {
            anchor_monotonic_100ns: monotonic_100ns,
            anchor_system_time_100ns: system_time_100ns,
            generation: 0,
        }
    }

    pub fn try_new(monotonic_100ns: u64, system_time_100ns: u64) -> Result<Self, ClockError> {
        validate_system_time(system_time_100ns)?;
        Ok(Self::new(monotonic_100ns, system_time_100ns))
    }

    pub fn snapshot(&self, monotonic_100ns: u64) -> TimeSnapshot {
        let elapsed = monotonic_100ns.saturating_sub(self.anchor_monotonic_100ns);
        TimeSnapshot {
            monotonic_100ns,
            system_time_100ns: self
                .anchor_system_time_100ns
                .saturating_add(elapsed)
                .min(MAX_SYSTEM_TIME_100NS),
            clock_generation: self.generation,
        }
    }

    pub fn set_system_time(
        &mut self,
        monotonic_100ns: u64,
        system_time_100ns: u64,
    ) -> Result<SystemTimeChange, ClockError> {
        validate_system_time(system_time_100ns)?;
        if monotonic_100ns < self.anchor_monotonic_100ns {
            return Err(ClockError::MonotonicRegression);
        }

        let previous_100ns = self.snapshot(monotonic_100ns).system_time_100ns;
        self.anchor_monotonic_100ns = monotonic_100ns;
        self.anchor_system_time_100ns = system_time_100ns;
        self.generation = self.generation.wrapping_add(1);

        Ok(SystemTimeChange {
            previous_100ns,
            current_100ns: system_time_100ns,
            delta_100ns: system_time_100ns as i128 - previous_100ns as i128,
            clock_generation: self.generation,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

pub fn validate_system_time(system_time_100ns: u64) -> Result<(), ClockError> {
    if system_time_100ns > MAX_SYSTEM_TIME_100NS {
        Err(ClockError::InvalidSystemTime)
    } else {
        Ok(())
    }
}

/// Convert a UTC Unix timestamp into NT's 100ns epoch (1601-01-01).
pub fn system_time_from_unix_seconds(unix_seconds: i64) -> Result<u64, ClockError> {
    let nt_seconds = i128::from(unix_seconds) + i128::from(UNIX_EPOCH_IN_NT_SECONDS);
    let ticks = nt_seconds
        .checked_mul(i128::from(TICKS_PER_SECOND))
        .ok_or(ClockError::InvalidSystemTime)?;
    if ticks < 0 || ticks > i128::from(MAX_SYSTEM_TIME_100NS) {
        return Err(ClockError::InvalidSystemTime);
    }
    Ok(ticks as u64)
}

pub fn unix_seconds_from_system_time(system_time_100ns: u64) -> Result<i64, ClockError> {
    validate_system_time(system_time_100ns)?;
    let nt_seconds = system_time_100ns / TICKS_PER_SECOND;
    i64::try_from(nt_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_sub(UNIX_EPOCH_IN_NT_SECONDS))
        .ok_or(ClockError::InvalidSystemTime)
}

pub fn system_time_from_utc_date_time(value: UtcDateTime) -> Result<u64, ClockError> {
    if value.year < 1601
        || !(1..=12).contains(&value.month)
        || value.day == 0
        || value.day > days_in_month(value.year, value.month)
        || value.hour > 23
        || value.minute > 59
        || value.second > 59
    {
        return Err(ClockError::InvalidSystemTime);
    }
    let days = days_from_civil(value.year, value.month, value.day);
    let seconds = i128::from(days) * 86_400
        + i128::from(value.hour) * 3_600
        + i128::from(value.minute) * 60
        + i128::from(value.second);
    let seconds = i64::try_from(seconds).map_err(|_| ClockError::InvalidSystemTime)?;
    system_time_from_unix_seconds(seconds)
}

pub fn utc_date_time_from_system_time(system_time_100ns: u64) -> Result<UtcDateTime, ClockError> {
    let unix_seconds = unix_seconds_from_system_time(system_time_100ns)?;
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Ok(UtcDateTime {
        year,
        month,
        day,
        hour: (seconds / 3_600) as u8,
        minute: (seconds % 3_600 / 60) as u8,
        second: (seconds % 60) as u8,
        weekday: (days + 4).rem_euclid(7) as u8,
    })
}

const fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let adjusted_year = i64::from(year) - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = shifted_month + if shifted_month < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

/// Deadline domain retained for the full lifetime of an NT wait or timer.
///
/// Relative deadlines remain tied to monotonic time. Absolute deadlines remain
/// tied to system time and are projected again whenever the system clock moves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Deadline {
    Infinite,
    Relative { monotonic_100ns: u64 },
    Absolute { system_time_100ns: u64 },
}

impl Default for Deadline {
    fn default() -> Self {
        Self::Infinite
    }
}

impl Deadline {
    pub fn from_nt_timeout(interval_100ns: Option<i64>, now: TimeSnapshot) -> Self {
        match interval_100ns {
            None => Self::Infinite,
            Some(interval) if interval < 0 => Self::Relative {
                monotonic_100ns: now.monotonic_100ns.saturating_add(interval.unsigned_abs()),
            },
            Some(interval) => Self::Absolute {
                system_time_100ns: interval as u64,
            },
        }
    }

    pub fn is_due(self, now: TimeSnapshot) -> bool {
        match self {
            Self::Infinite => false,
            Self::Relative { monotonic_100ns } => monotonic_100ns <= now.monotonic_100ns,
            Self::Absolute { system_time_100ns } => system_time_100ns <= now.system_time_100ns,
        }
    }

    /// Current monotonic comparator target for the deadline.
    ///
    /// An already-due absolute deadline projects to `now`, while an infinite
    /// deadline has no comparator target.
    pub fn monotonic_target(self, now: TimeSnapshot) -> Option<u64> {
        match self {
            Self::Infinite => None,
            Self::Relative { monotonic_100ns } => Some(monotonic_100ns),
            Self::Absolute { system_time_100ns } => {
                Some(if system_time_100ns <= now.system_time_100ns {
                    now.monotonic_100ns
                } else {
                    now.monotonic_100ns
                        .saturating_add(system_time_100ns - now.system_time_100ns)
                })
            }
        }
    }

    /// Signed monotonic projection used to order mixed deadline domains.
    ///
    /// Unlike the hardware comparator target, this retains ordering between
    /// multiple absolute deadlines that became overdue after a forward jump.
    pub fn ordering_key(self, now: TimeSnapshot) -> i128 {
        match self {
            Self::Infinite => i128::MAX,
            Self::Relative { monotonic_100ns } => monotonic_100ns as i128,
            Self::Absolute { system_time_100ns } => {
                now.monotonic_100ns as i128 + system_time_100ns as i128
                    - now.system_time_100ns as i128
            }
        }
    }

    pub fn remaining_100ns(self, now: TimeSnapshot) -> Option<u64> {
        match self {
            Self::Infinite => None,
            Self::Relative { monotonic_100ns } => {
                Some(monotonic_100ns.saturating_sub(now.monotonic_100ns))
            }
            Self::Absolute { system_time_100ns } => {
                Some(system_time_100ns.saturating_sub(now.system_time_100ns))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjustable_clock_changes_only_the_system_time_anchor() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        assert_eq!(
            clock.snapshot(150),
            TimeSnapshot {
                monotonic_100ns: 150,
                system_time_100ns: 1_050,
                clock_generation: 0,
            }
        );

        let change = clock.set_system_time(150, 5_000).unwrap();
        assert_eq!(change.previous_100ns, 1_050);
        assert_eq!(change.current_100ns, 5_000);
        assert_eq!(change.delta_100ns, 3_950);
        assert_eq!(change.clock_generation, 1);
        assert_eq!(clock.snapshot(175).system_time_100ns, 5_025);
        assert_eq!(clock.snapshot(175).monotonic_100ns, 175);
    }

    #[test]
    fn unix_epoch_conversion_enforces_nt_bounds() {
        assert_eq!(
            system_time_from_unix_seconds(0),
            Ok(116_444_736_000_000_000)
        );
        assert_eq!(
            system_time_from_unix_seconds(-UNIX_EPOCH_IN_NT_SECONDS),
            Ok(0)
        );
        assert_eq!(
            system_time_from_unix_seconds(-UNIX_EPOCH_IN_NT_SECONDS - 1),
            Err(ClockError::InvalidSystemTime)
        );
        assert_eq!(
            system_time_from_unix_seconds(i64::MAX),
            Err(ClockError::InvalidSystemTime)
        );
        assert_eq!(
            unix_seconds_from_system_time(116_444_736_000_000_000),
            Ok(0)
        );
    }

    #[test]
    fn utc_calendar_conversion_handles_epoch_and_gregorian_boundaries() {
        for value in [
            UtcDateTime {
                year: 1601,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                weekday: 1,
            },
            UtcDateTime {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                weekday: 4,
            },
            UtcDateTime {
                year: 2000,
                month: 2,
                day: 29,
                hour: 23,
                minute: 59,
                second: 58,
                weekday: 2,
            },
            UtcDateTime {
                year: 2100,
                month: 3,
                day: 1,
                hour: 12,
                minute: 34,
                second: 56,
                weekday: 1,
            },
        ] {
            let encoded = system_time_from_utc_date_time(value).unwrap();
            assert_eq!(utc_date_time_from_system_time(encoded).unwrap(), value);
        }
        assert_eq!(
            system_time_from_utc_date_time(UtcDateTime {
                year: 2100,
                month: 2,
                day: 29,
                hour: 0,
                minute: 0,
                second: 0,
                weekday: 0,
            }),
            Err(ClockError::InvalidSystemTime)
        );
    }

    #[test]
    fn clock_rejects_invalid_time_and_monotonic_regression() {
        assert_eq!(
            AdjustableClock::try_new(0, MAX_SYSTEM_TIME_100NS + 1),
            Err(ClockError::InvalidSystemTime)
        );

        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        assert_eq!(
            clock.set_system_time(99, 2_000),
            Err(ClockError::MonotonicRegression)
        );
        assert_eq!(clock.generation(), 0);
    }

    #[test]
    fn relative_deadline_is_invariant_under_system_clock_changes() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let deadline = Deadline::from_nt_timeout(Some(-500), clock.snapshot(100));
        assert_eq!(
            deadline,
            Deadline::Relative {
                monotonic_100ns: 600
            }
        );

        clock.set_system_time(200, 50_000).unwrap();
        assert_eq!(deadline.monotonic_target(clock.snapshot(200)), Some(600));
        assert_eq!(deadline.remaining_100ns(clock.snapshot(200)), Some(400));
        assert!(!deadline.is_due(clock.snapshot(599)));
        assert!(deadline.is_due(clock.snapshot(600)));

        clock.set_system_time(600, 10).unwrap();
        assert!(deadline.is_due(clock.snapshot(600)));
    }

    #[test]
    fn absolute_deadline_reprojects_after_forward_and_backward_changes() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let deadline = Deadline::from_nt_timeout(Some(2_000), clock.snapshot(100));
        assert_eq!(deadline.monotonic_target(clock.snapshot(100)), Some(1_100));

        clock.set_system_time(200, 1_900).unwrap();
        assert_eq!(deadline.monotonic_target(clock.snapshot(200)), Some(300));
        assert!(!deadline.is_due(clock.snapshot(299)));
        assert!(deadline.is_due(clock.snapshot(300)));

        clock.set_system_time(300, 500).unwrap();
        assert_eq!(deadline.monotonic_target(clock.snapshot(300)), Some(1_800));
        assert!(!deadline.is_due(clock.snapshot(1_799)));
        assert!(deadline.is_due(clock.snapshot(1_800)));
    }

    #[test]
    fn forward_jump_preserves_overdue_absolute_ordering() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let first = Deadline::from_nt_timeout(Some(2_000), clock.snapshot(100));
        let second = Deadline::from_nt_timeout(Some(3_000), clock.snapshot(100));
        clock.set_system_time(200, 4_000).unwrap();
        let now = clock.snapshot(200);

        assert!(first.is_due(now));
        assert!(second.is_due(now));
        assert_eq!(first.monotonic_target(now), Some(200));
        assert_eq!(second.monotonic_target(now), Some(200));
        assert!(first.ordering_key(now) < second.ordering_key(now));
    }

    #[test]
    fn absent_timeout_is_infinite_and_zero_is_due_absolute_time() {
        let now = TimeSnapshot {
            monotonic_100ns: 50,
            system_time_100ns: 500,
            clock_generation: 3,
        };
        let infinite = Deadline::from_nt_timeout(None, now);
        let zero = Deadline::from_nt_timeout(Some(0), now);

        assert_eq!(infinite, Deadline::Infinite);
        assert_eq!(Deadline::default(), Deadline::Infinite);
        assert!(!infinite.is_due(now));
        assert_eq!(infinite.monotonic_target(now), None);
        assert_eq!(infinite.remaining_100ns(now), None);
        assert!(zero.is_due(now));
        assert_eq!(zero.monotonic_target(now), Some(50));
        assert_eq!(zero.remaining_100ns(now), Some(0));
    }

    #[test]
    fn arithmetic_saturates_at_native_bounds() {
        let clock = AdjustableClock::try_new(u64::MAX - 5, MAX_SYSTEM_TIME_100NS - 2).unwrap();
        assert_eq!(
            clock.snapshot(u64::MAX).system_time_100ns,
            MAX_SYSTEM_TIME_100NS
        );

        let relative = Deadline::from_nt_timeout(
            Some(i64::MIN),
            TimeSnapshot {
                monotonic_100ns: u64::MAX - 1,
                system_time_100ns: 0,
                clock_generation: 0,
            },
        );
        assert_eq!(
            relative,
            Deadline::Relative {
                monotonic_100ns: u64::MAX
            }
        );
    }
}
