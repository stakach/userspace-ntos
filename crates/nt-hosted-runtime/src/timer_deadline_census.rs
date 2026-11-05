//! Bounded diagnostic of the live deadline selected at a timer notification scan.
//!
//! A notification can be stale after a rearm, so this records the live selection immediately
//! before the due-work scan rather than attributing the previous programmed shot.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimerDeadlineSample {
    pub scans: u64,
    pub due: u64,
    pub early: u64,
    pub work_units: u64,
    pub lateness_total_100ns: u64,
    pub lateness_max_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerDeadlineCensus {
    samples: [TimerDeadlineSample; Self::BUCKETS],
}

impl TimerDeadlineCensus {
    /// Bucket 0 has no live deadline; 1..=28 are the executive's current sources; 29 is overflow.
    pub const SOURCE_LIMIT: usize = 28;
    pub const OVERFLOW: usize = Self::SOURCE_LIMIT + 1;
    pub const BUCKETS: usize = Self::OVERFLOW + 1;

    pub const fn new() -> Self {
        Self { samples: [TimerDeadlineSample {
            scans: 0, due: 0, early: 0, work_units: 0,
            lateness_total_100ns: 0, lateness_max_100ns: 0,
        }; Self::BUCKETS] }
    }

    pub const fn bucket(source: Option<u64>) -> usize {
        match source {
            None => 0,
            Some(source) if source <= Self::SOURCE_LIMIT as u64 => source as usize,
            Some(_) => Self::OVERFLOW,
        }
    }

    /// Observe the exact pre-drain selection and post-drain work units. The work count is a
    /// correlation, since one scan can service more than the selected deadline owner.
    pub fn observe(&mut self, selected: Option<(u64, u64)>, now_100ns: u64, work_units: u64) {
        let bucket = Self::bucket(selected.map(|(_, source)| source));
        let sample = &mut self.samples[bucket];
        sample.scans = sample.scans.saturating_add(1);
        sample.work_units = sample.work_units.saturating_add(work_units);
        if let Some((deadline, _)) = selected {
            if now_100ns >= deadline {
                let lateness = now_100ns - deadline;
                sample.due = sample.due.saturating_add(1);
                sample.lateness_total_100ns =
                    sample.lateness_total_100ns.saturating_add(lateness);
                sample.lateness_max_100ns = sample.lateness_max_100ns.max(lateness);
            } else {
                sample.early = sample.early.saturating_add(1);
            }
        }
    }

    pub const fn sample(&self, source: Option<u64>) -> TimerDeadlineSample {
        self.samples[Self::bucket(source)]
    }
}

impl Default for TimerDeadlineCensus {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_live_due_and_early_deadlines_separately() {
        let mut census = TimerDeadlineCensus::new();
        census.observe(Some((100, 6)), 130, 2);
        census.observe(Some((150, 6)), 140, 0);
        census.observe(Some((140, 6)), 140, 3);
        assert_eq!(census.sample(Some(6)), TimerDeadlineSample {
            scans: 3, due: 2, early: 1, work_units: 5,
            lateness_total_100ns: 30, lateness_max_100ns: 30,
        });
    }

    #[test]
    fn missing_or_unknown_source_stays_bounded() {
        let mut census = TimerDeadlineCensus::new();
        census.observe(None, 100, 0);
        census.observe(Some((80, u64::MAX)), 100, 1);
        census.observe(Some((70, 29)), 100, 2);
        assert_eq!(census.sample(None).scans, 1);
        assert_eq!(census.sample(None).due, 0);
        assert_eq!(census.sample(Some(24)), TimerDeadlineSample::default());
        assert_eq!(census.sample(Some(u64::MAX)).scans, 2);
        assert_eq!(census.sample(Some(29)).lateness_total_100ns, 50);
    }

    #[test]
    fn section_retry_owners_have_distinct_live_deadline_buckets() {
        // One section-metadata deadline currently covers all four retry owners. The live
        // diagnostic must keep their due scans separate before changing retry policy.
        let sources = [21, 26, 27, 28];
        let mut census = TimerDeadlineCensus::new();
        for source in sources {
            census.observe(Some((100, source)), 120, 1);
        }
        for source in sources {
            assert_eq!(census.sample(Some(source)).scans, 1, "source {source}");
            assert_eq!(census.sample(Some(source)).due, 1, "source {source}");
        }
        assert_eq!(census.sample(Some(u64::MAX)).scans, 0);
    }

    #[test]
    fn counters_saturate_without_affecting_other_sources() {
        let mut census = TimerDeadlineCensus::new();
        census.observe(Some((0, 1)), u64::MAX, u64::MAX);
        census.observe(Some((0, 1)), 100, 5);
        assert_eq!(census.sample(Some(1)), TimerDeadlineSample {
            scans: 2, due: 2, early: 0, work_units: u64::MAX,
            lateness_total_100ns: u64::MAX, lateness_max_100ns: u64::MAX,
        });
        assert_eq!(census.sample(Some(2)), TimerDeadlineSample::default());
    }
}
