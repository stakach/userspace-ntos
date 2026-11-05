//! Finite, exact-owner admission for observation-only startup thread samples.
//!
//! A sample claim grants no thread control or Reply authority. The native
//! adapter must read the current published binding and PM lifetime before
//! each claim, then perform the register read outside any table borrow.

use crate::thread_binding::ThreadBinding;
use nt_process::ThreadLifetime;

pub struct StartupThreadSampleGate<R> {
    owner: ThreadBinding<R>,
    lifetime: ThreadLifetime,
    interval_100ns: u64,
    cap: u64,
    samples: u64,
    last_at_100ns: Option<u64>,
}

impl<R: Copy + Eq> StartupThreadSampleGate<R> {
    pub fn new(
        owner: ThreadBinding<R>,
        lifetime: ThreadLifetime,
        interval_100ns: u64,
        cap: u64,
    ) -> Option<Self> {
        if owner.tcb <= 1
            || owner.tid == 0
            || !owner.process.is_valid()
            || owner.tid != u64::from(lifetime.thread_id())
            || owner.process.pid != lifetime.process_id()
            || interval_100ns == 0
            || cap == 0
        {
            return None;
        }
        Some(Self {
            owner, lifetime, interval_100ns, cap, samples: 0, last_at_100ns: None,
        })
    }

    /// Return a one-based sample ordinal only for the exact current owner.
    /// Stale, missing, premature, and over-budget observations consume nothing.
    pub fn claim_sample(
        &mut self,
        current: Option<ThreadBinding<R>>,
        lifetime: Option<ThreadLifetime>,
        now_100ns: u64,
    ) -> Option<u64> {
        if current != Some(self.owner)
            || lifetime != Some(self.lifetime)
            || self.samples >= self.cap
            || self.last_at_100ns.is_some_and(|last| {
                now_100ns.checked_sub(last).is_none_or(|elapsed| elapsed < self.interval_100ns)
            })
        {
            return None;
        }
        self.samples += 1;
        self.last_at_100ns = Some(now_100ns);
        Some(self.samples)
    }

    pub const fn owner(&self) -> ThreadBinding<R> { self.owner }
}
