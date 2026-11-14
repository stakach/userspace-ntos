//! Scheduler yields of an entered kernel job, as seen by the root that runs it.
//!
//! A provider lane keeps executing across a scheduler yield, so it still holds the running
//! token that serializes the component's shared state. Root can service interrupt work and
//! receive on the same lane again; it cannot give the lane to anyone else. A job whose
//! provider sends nothing between yields is therefore either computing or polling for
//! something root cannot deliver from here. This watch counts those yields and paces their
//! report; it never changes, releases or resumes the job.

use crate::provider_ps_callout::KernelJobWaitHeartbeat;

/// One due report of a job that keeps yielding without a provider message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SilentYieldReport {
    /// Scheduler yields since the job was entered.
    pub yields: u64,
    /// Consecutive yields whose pump segment handled no provider message.
    pub silent_yields: u64,
    /// Time since the provider last sent anything, or since entry.
    pub silent_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelJobYieldWatch {
    heartbeat: KernelJobWaitHeartbeat,
    silent_since: u64,
    yields: u64,
    silent_yields: u64,
}

impl KernelJobYieldWatch {
    pub const fn new(now: u64) -> Self {
        Self {
            heartbeat: KernelJobWaitHeartbeat::new(now),
            silent_since: now,
            yields: 0,
            silent_yields: 0,
        }
    }

    /// One scheduler yield came back. `provider_messages` is what the provider delivered to
    /// root in the pump segment that ended with it.
    pub fn observe(&mut self, now: u64, provider_messages: u64) -> Option<SilentYieldReport> {
        self.yields = self.yields.saturating_add(1);
        if provider_messages != 0 {
            *self = Self { yields: self.yields, ..Self::new(now) };
            return None;
        }
        self.silent_yields = self.silent_yields.saturating_add(1);
        self.heartbeat.due(now)?;
        Some(SilentYieldReport {
            yields: self.yields,
            silent_yields: self.silent_yields,
            silent_100ns: now.saturating_sub(self.silent_since),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_ps_callout::KERNEL_JOB_WAIT_HEARTBEAT_100NS as PERIOD;

    #[test]
    fn a_job_that_yields_with_no_provider_message_is_reported_once_per_period() {
        let mut watch = KernelJobYieldWatch::new(1_000);
        assert_eq!(watch.observe(1_000 + PERIOD - 1, 0), None);
        assert_eq!(
            watch.observe(1_000 + PERIOD, 0),
            Some(SilentYieldReport { yields: 2, silent_yields: 2, silent_100ns: PERIOD })
        );
        assert_eq!(watch.observe(1_000 + PERIOD + 1, 0), None);
        assert_eq!(
            watch.observe(1_000 + 2 * PERIOD, 0),
            Some(SilentYieldReport { yields: 4, silent_yields: 4, silent_100ns: 2 * PERIOD })
        );
    }

    #[test]
    fn a_provider_message_ends_the_silence_and_restarts_its_period() {
        let mut watch = KernelJobYieldWatch::new(0);
        assert_eq!(watch.observe(PERIOD - 1, 0), None);
        // The provider talked to root in this pump segment: the job is not silent.
        assert_eq!(watch.observe(PERIOD, 3), None);
        assert_eq!(watch.observe(2 * PERIOD - 1, 0), None);
        assert_eq!(
            watch.observe(2 * PERIOD, 0),
            Some(SilentYieldReport { yields: 4, silent_yields: 2, silent_100ns: PERIOD })
        );
    }

    #[test]
    fn a_job_whose_provider_keeps_talking_is_never_reported() {
        let mut watch = KernelJobYieldWatch::new(0);
        for pass in 1..=64u64 {
            assert_eq!(watch.observe(pass * PERIOD, 1), None);
        }
    }
}
