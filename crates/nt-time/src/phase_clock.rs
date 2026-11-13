//! One clock reading shared by the consumers of one phase of work.
//!
//! Bookkeeping that runs back to back does not need distinct instants. The first consumer of a
//! phase reads the clock and the rest reuse that reading. Whoever blocks or runs long work ends
//! the phase, so nothing after it sees a reading taken before it. Arming, comparing and expiring
//! a deadline after such work take their own fresh reading and do not use this type.

#[derive(Debug, Default)]
pub struct PhaseClock {
    reading: Option<u64>,
}

impl PhaseClock {
    pub const fn new() -> Self {
        Self { reading: None }
    }

    /// The phase's reading. `clock` runs only for the first consumer of the phase.
    pub fn now(&mut self, clock: impl FnOnce() -> u64) -> u64 {
        *self.reading.get_or_insert_with(clock)
    }

    /// A blocking or long operation is about to run or has returned: forget the reading.
    pub fn end_phase(&mut self) {
        self.reading = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumers_of_one_phase_share_one_reading() {
        let mut reads = 0;
        let mut clock = PhaseClock::new();
        let first = clock.now(|| { reads += 1; 100 });
        let second = clock.now(|| { reads += 1; 200 });
        let third = clock.now(|| { reads += 1; 300 });
        assert_eq!((first, second, third), (100, 100, 100));
        assert_eq!(reads, 1, "back-to-back bookkeeping may cost one clock read");
    }

    #[test]
    fn a_phase_nobody_times_reads_nothing() {
        let mut clock = PhaseClock::new();
        clock.end_phase();
        clock.end_phase();
        assert_eq!(clock.reading, None);
    }

    #[test]
    fn ending_a_phase_forces_a_fresh_reading() {
        let mut reads = 0;
        let mut clock = PhaseClock::new();
        assert_eq!(clock.now(|| { reads += 1; 100 }), 100);
        clock.end_phase();
        assert_eq!(clock.now(|| { reads += 1; 250 }), 250,
            "a reading taken before a blocking operation must not describe what follows it");
        assert_eq!(clock.now(|| { reads += 1; 900 }), 250);
        assert_eq!(reads, 2);
    }
}
