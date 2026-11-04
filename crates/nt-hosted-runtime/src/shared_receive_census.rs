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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedReceiveReturn {
    Call,
    Timer,
    OtherNotification,
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
    idle_returns: [SharedReceiveSample; 3],
    sequence: u64,
    pending: Option<(u64, u64, SharedReceiveOwner, bool)>,
}

impl SharedReceiveCensus {
    pub const BUCKETS: usize = 6;

    pub const fn new() -> Self {
        Self {
            samples: [SharedReceiveSample { count: 0, total_ticks: 0, max_ticks: 0 }; Self::BUCKETS],
            idle_returns: [SharedReceiveSample { count: 0, total_ticks: 0, max_ticks: 0 }; 3],
            sequence: 0,
            pending: None,
        }
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
    pub fn observe(&mut self, owner: SharedReceiveOwner, blocking: bool, start: u64, end: u64) -> u64 {
        let elapsed = end.wrapping_sub(start);
        let sample = &mut self.samples[Self::bucket(owner, blocking)];
        sample.count = sample.count.saturating_add(1);
        sample.total_ticks = sample.total_ticks.saturating_add(elapsed);
        sample.max_ticks = sample.max_ticks.max(elapsed);
        self.sequence = self.sequence.wrapping_add(1);
        self.pending = Some((self.sequence, elapsed, owner, blocking));
        self.sequence
    }

    /// Attribute the exact returned receive once classification has authenticated Call versus
    /// notification. An intervening receive invalidates the older token rather than mischarging it.
    pub fn classify_return(&mut self, sequence: u64, reason: SharedReceiveReturn) -> bool {
        let Some((pending_sequence, elapsed, owner, blocking)) = self.pending else {
            return false;
        };
        if pending_sequence != sequence {
            return false;
        }
        self.pending = None;
        if owner == SharedReceiveOwner::Idle && blocking {
            let index = match reason {
                SharedReceiveReturn::Call => 0,
                SharedReceiveReturn::Timer => 1,
                SharedReceiveReturn::OtherNotification => 2,
            };
            let sample = &mut self.idle_returns[index];
            sample.count = sample.count.saturating_add(1);
            sample.total_ticks = sample.total_ticks.saturating_add(elapsed);
            sample.max_ticks = sample.max_ticks.max(elapsed);
        }
        true
    }

    pub const fn idle_return(&self, reason: SharedReceiveReturn) -> SharedReceiveSample {
        let index = match reason {
            SharedReceiveReturn::Call => 0,
            SharedReceiveReturn::Timer => 1,
            SharedReceiveReturn::OtherNotification => 2,
        };
        self.idle_returns[index]
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

    #[test]
    fn idle_returns_charge_exact_elapsed_once_after_classification() {
        let mut census = SharedReceiveCensus::new();
        let timer = census.observe(SharedReceiveOwner::Idle, true, 10, 110);
        assert_eq!(census.idle_return(SharedReceiveReturn::Timer), SharedReceiveSample::default());
        assert!(census.classify_return(timer, SharedReceiveReturn::Timer));
        assert!(!census.classify_return(timer, SharedReceiveReturn::Call));
        let call = census.observe(SharedReceiveOwner::Idle, true, u64::MAX - 3, 4);
        assert!(census.classify_return(call, SharedReceiveReturn::Call));
        let other = census.observe(SharedReceiveOwner::Idle, true, 20, 23);
        assert!(census.classify_return(other, SharedReceiveReturn::OtherNotification));
        assert_eq!(census.idle_return(SharedReceiveReturn::Timer), SharedReceiveSample {
            count: 1, total_ticks: 100, max_ticks: 100,
        });
        assert_eq!(census.idle_return(SharedReceiveReturn::Call), SharedReceiveSample {
            count: 1, total_ticks: 8, max_ticks: 8,
        });
        assert_eq!(census.idle_return(SharedReceiveReturn::OtherNotification), SharedReceiveSample {
            count: 1, total_ticks: 3, max_ticks: 3,
        });
    }

    #[test]
    fn overwritten_and_nonidle_receives_do_not_mischarge_idle_returns() {
        let mut census = SharedReceiveCensus::new();
        let old = census.observe(SharedReceiveOwner::Idle, true, 1, 100);
        let next = census.observe(SharedReceiveOwner::Idle, true, 2, 5);
        assert!(!census.classify_return(old, SharedReceiveReturn::Timer));
        assert!(census.classify_return(next, SharedReceiveReturn::Call));
        let dispatch = census.observe(SharedReceiveOwner::Dispatch, true, 1, 50);
        assert!(census.classify_return(dispatch, SharedReceiveReturn::Timer));
        assert_eq!(census.idle_return(SharedReceiveReturn::Call).total_ticks, 3);
        assert_eq!(census.idle_return(SharedReceiveReturn::Timer), SharedReceiveSample::default());
    }

    #[test]
    fn classified_return_totals_saturate() {
        let mut census = SharedReceiveCensus::new();
        let first = census.observe(SharedReceiveOwner::Idle, true, 0, u64::MAX);
        assert!(census.classify_return(first, SharedReceiveReturn::Timer));
        let second = census.observe(SharedReceiveOwner::Idle, true, 0, 10);
        assert!(census.classify_return(second, SharedReceiveReturn::Timer));
        assert_eq!(census.idle_return(SharedReceiveReturn::Timer), SharedReceiveSample {
            count: 2, total_ticks: u64::MAX, max_ticks: u64::MAX,
        });
    }
}
