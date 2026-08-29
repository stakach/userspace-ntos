#![no_std]

/// Largest system time accepted by NT's clock-setting path.
///
/// The native kernel requires the high nibble of the signed `LARGE_INTEGER`
/// system time to be clear before publishing it through shared user data.
pub const MAX_SYSTEM_TIME_100NS: u64 = 0x0fff_ffff_ffff_ffff;

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
