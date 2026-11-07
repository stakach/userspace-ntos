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

    pub fn matches_owner(&self, owner: ThreadBinding<R>, lifetime: ThreadLifetime) -> bool {
        self.owner == owner && self.lifetime == lifetime
    }
}

/// Separate finite diagnostic budgets for a fixed set of startup roles. Replacing a
/// process or thread starts a fresh exact-owner gate without restoring the role budget.
pub struct StartupThreadSampleRoster<R, const N: usize> {
    gates: [Option<StartupThreadSampleGate<R>>; N],
    samples: [u64; N],
    interval_100ns: u64,
    cap_per_role: u64,
}

impl<R: Copy + Eq, const N: usize> StartupThreadSampleRoster<R, N> {
    pub fn new(interval_100ns: u64, cap_per_role: u64) -> Option<Self> {
        if N == 0 || interval_100ns == 0 || cap_per_role == 0 { return None; }
        Some(Self {
            gates: core::array::from_fn(|_| None),
            samples: [0; N], interval_100ns, cap_per_role,
        })
    }

    /// A claim is observation only. Absent or invalid owners spend no sample budget.
    pub fn claim(
        &mut self, role: usize, current: Option<ThreadBinding<R>>,
        lifetime: Option<ThreadLifetime>, now_100ns: u64,
    ) -> Option<u64> {
        if role >= N || self.samples[role] >= self.cap_per_role { return None; }
        let (Some(owner), Some(lifetime)) = (current, lifetime) else { return None; };
        if self.gates[role].as_ref().is_none_or(|gate| !gate.matches_owner(owner, lifetime)) {
            self.gates[role] = StartupThreadSampleGate::new(
                owner, lifetime, self.interval_100ns, self.cap_per_role,
            );
        }
        self.gates[role].as_mut()?.claim_sample(
            Some(owner), Some(lifetime), now_100ns,
        )?;
        self.samples[role] += 1;
        Some(self.samples[role])
    }
}
