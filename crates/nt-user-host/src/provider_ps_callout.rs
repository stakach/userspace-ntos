//! Ps exit callouts whose provider stack is parked in a provider wait.
//!
//! The initiating retirement cannot stay on root's stack while such a callout waits: the wait's
//! owner may need a hosted call or its own service terminal, and only the service loop
//! dispatches those. The callout therefore stays here, keyed by the retirement that issued it,
//! until that same retirement comes back and takes its real return exactly once.

use alloc::vec::Vec;

/// A parked kernel-job wait is reported once per five seconds of monotonic time.
pub const KERNEL_JOB_WAIT_HEARTBEAT_100NS: u64 = 50_000_000;

/// Pacing only. A report never changes, releases or resumes the wait it describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelJobWaitHeartbeat {
    origin: u64,
    reported: u64,
}

impl KernelJobWaitHeartbeat {
    pub const fn new(now: u64) -> Self {
        Self { origin: now, reported: now }
    }

    /// The wait's age when a further period has elapsed since the previous report.
    pub fn due(&mut self, now: u64) -> Option<u64> {
        if now.checked_sub(self.reported)? < KERNEL_JOB_WAIT_HEARTBEAT_100NS {
            return None;
        }
        self.reported = now;
        Some(now.saturating_sub(self.origin))
    }
}

/// What a retirement finds when it asks for the callout it issued earlier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PsCalloutState {
    /// No callout is retained for this retirement; it may issue one.
    Absent,
    /// The callout is still parked or executing. Issuing it again would replay it.
    Pending,
    /// The provider really returned. This result is handed over exactly once.
    Returned(u32),
}

struct Row<K, J> {
    key: K,
    job: J,
    heartbeat: KernelJobWaitHeartbeat,
}

/// `K` identifies one retirement's callout; `J` is the retained result slot of its kernel job.
pub struct PendingPsCallouts<K, J> {
    rows: Vec<Row<K, J>>,
}

impl<K: PartialEq, J> PendingPsCallouts<K, J> {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Keep a parked callout for its retirement. A second callout for the same retirement, or
    /// an allocation failure, returns both values unchanged.
    pub fn retain(&mut self, key: K, job: J, now: u64) -> Result<(), (K, J)> {
        if self.rows.iter().any(|row| row.key == key) || self.rows.try_reserve(1).is_err() {
            return Err((key, job));
        }
        self.rows.push(Row { key, job, heartbeat: KernelJobWaitHeartbeat::new(now) });
        Ok(())
    }

    pub fn job(&self, key: &K) -> Option<&J> {
        self.rows.iter().find(|row| row.key == *key).map(|row| &row.job)
    }

    pub fn job_mut(&mut self, key: &K) -> Option<&mut J> {
        self.rows.iter_mut().find(|row| row.key == *key).map(|row| &mut row.job)
    }

    pub fn contains(&self, mut matches: impl FnMut(&K) -> bool) -> bool {
        self.rows.iter().any(|row| matches(&row.key))
    }

    /// The retirement asks for its callout. Only a real return releases the row.
    pub fn settle(&mut self, key: &K, returned: impl Fn(&J) -> Option<u32>) -> PsCalloutState {
        let Some(index) = self.rows.iter().position(|row| row.key == *key) else {
            return PsCalloutState::Absent;
        };
        match returned(&self.rows[index].job) {
            None => PsCalloutState::Pending,
            Some(status) => {
                self.rows.swap_remove(index);
                PsCalloutState::Returned(status)
            }
        }
    }

    /// A returned callout whose retirement has not yet come back for it.
    pub fn next_returned(&self, returned: impl Fn(&J) -> Option<u32>) -> Option<&K> {
        self.nth_returned(0, returned)
    }

    /// The returned callout after `skip` others, so one pass can visit each of them once even
    /// when a retirement is still blocked elsewhere and leaves its result here.
    pub fn nth_returned(&self, skip: usize, returned: impl Fn(&J) -> Option<u32>) -> Option<&K> {
        self.rows.iter().filter(|row| returned(&row.job).is_some()).nth(skip).map(|row| &row.key)
    }

    /// The next still-waiting callout that is due a report, with its age.
    pub fn next_heartbeat(
        &mut self,
        now: u64,
        returned: impl Fn(&J) -> Option<u32>,
    ) -> Option<(&K, u64)> {
        self.rows.iter_mut().find_map(|row| {
            if returned(&row.job).is_some() {
                return None;
            }
            row.heartbeat.due(now).map(|age| (&row.key, age))
        })
    }
}

impl<K: PartialEq, J> Default for PendingPsCallouts<K, J> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "provider_ps_callout_tests.rs"]
mod tests;
