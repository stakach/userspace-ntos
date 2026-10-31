//! Elapsed time in the shared ingress receive syscall, separated by execution owner.
//!
//! A blocking receive can return immediately. These timings include syscall overhead and do not
//! prove that the executive slept. Dispatch-owned receives may also be inside a native syscall
//! dispatch, so their elapsed time must not be added to the outer dispatch timing.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedReceiveOwner {
    Idle,
    Dispatch,
    Startup,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedReceiveSample {
    pub count: u64,
    pub total_ticks: u64,
    pub max_ticks: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedReceiveCensus {
    samples: [SharedReceiveSample; 6],
}

impl SharedReceiveCensus {
    pub const BUCKETS: usize = 6;

    pub const fn new() -> Self {
        Self { samples: [SharedReceiveSample { count: 0, total_ticks: 0, max_ticks: 0 }; Self::BUCKETS] }
    }

    pub const fn bucket(owner: SharedReceiveOwner, blocking: bool) -> usize {
        let owner_index = match owner {
            SharedReceiveOwner::Idle => 0,
            SharedReceiveOwner::Dispatch => 1,
            SharedReceiveOwner::Startup => 2,
        };
        owner_index * 2 + if blocking { 0 } else { 1 }
    }

    /// The caller brackets only the receive syscall, after admission and before capture.
    pub fn observe(&mut self, owner: SharedReceiveOwner, blocking: bool, start: u64, end: u64) {
        let elapsed = end.wrapping_sub(start);
        let sample = &mut self.samples[Self::bucket(owner, blocking)];
        sample.count = sample.count.saturating_add(1);
        sample.total_ticks = sample.total_ticks.saturating_add(elapsed);
        sample.max_ticks = sample.max_ticks.max(elapsed);
    }

    pub const fn sample(&self, owner: SharedReceiveOwner, blocking: bool) -> SharedReceiveSample {
        self.samples[Self::bucket(owner, blocking)]
    }
}

impl Default for SharedReceiveCensus {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_owner_and_mode_buckets_remain_distinct() {
        let mut census = SharedReceiveCensus::new();
        for (owner_index, owner) in [SharedReceiveOwner::Idle, SharedReceiveOwner::Dispatch,
            SharedReceiveOwner::Startup].into_iter().enumerate() {
            for (mode_index, blocking) in [true, false].into_iter().enumerate() {
                let bucket = owner_index * 2 + mode_index;
                assert_eq!(SharedReceiveCensus::bucket(owner, blocking), bucket);
                census.observe(owner, blocking, 100, 101 + bucket as u64);
            }
        }
        for (owner_index, owner) in [SharedReceiveOwner::Idle, SharedReceiveOwner::Dispatch,
            SharedReceiveOwner::Startup].into_iter().enumerate() {
            for (mode_index, blocking) in [true, false].into_iter().enumerate() {
                let elapsed = 1 + (owner_index * 2 + mode_index) as u64;
                assert_eq!(census.sample(owner, blocking), SharedReceiveSample {
                    count: 1, total_ticks: elapsed, max_ticks: elapsed,
                });
            }
        }
    }

    #[test]
    fn repeated_and_wrapping_intervals_update_count_total_and_max() {
        let mut census = SharedReceiveCensus::new();
        census.observe(SharedReceiveOwner::Idle, true, 10, 15);
        census.observe(SharedReceiveOwner::Idle, true, u64::MAX - 3, 4);
        census.observe(SharedReceiveOwner::Idle, true, 20, 22);
        assert_eq!(census.sample(SharedReceiveOwner::Idle, true), SharedReceiveSample {
            count: 3, total_ticks: 15, max_ticks: 8,
        });
        assert_eq!(census.sample(SharedReceiveOwner::Dispatch, true), SharedReceiveSample::default());
    }

    #[test]
    fn arithmetic_saturates_without_corrupting_another_bucket() {
        let mut census = SharedReceiveCensus::new();
        census.observe(SharedReceiveOwner::Startup, false, 0, u64::MAX);
        census.observe(SharedReceiveOwner::Startup, false, 1, 4);
        assert_eq!(census.sample(SharedReceiveOwner::Startup, false), SharedReceiveSample {
            count: 2, total_ticks: u64::MAX, max_ticks: u64::MAX,
        });
        assert_eq!(census.sample(SharedReceiveOwner::Idle, false), SharedReceiveSample::default());
    }
}
