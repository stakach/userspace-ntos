//! Retained timer readiness for work that must execute at an outer scheduling boundary.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One timer notification for retained work until its outer owner runs. Publication and retry
/// scheduling are serialized with the backing work rows; the timer only observes readiness.
pub struct CoalescedRetryWake {
    deadline: AtomicU64,
    notified: AtomicBool,
    publication: AtomicU64,
    writer: AtomicBool,
}

#[must_use = "the exact outer redrive must settle its retry decision"]
pub struct RetryWakeAttempt<'a> {
    owner: &'a CoalescedRetryWake,
    publication: u64,
}

impl RetryWakeAttempt<'_> {
    /// Consumes the attempt; a nested publication keeps its own earlier demand.
    pub fn retry_at(self, deadline: u64) -> bool {
        self.owner.retry_after(self.publication, deadline)
    }
}

struct RetryWakeWriter<'a>(&'a AtomicBool);

impl Drop for RetryWakeWriter<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

impl CoalescedRetryWake {
    pub const fn new() -> Self {
        Self {
            deadline: AtomicU64::new(0), notified: AtomicBool::new(false),
            publication: AtomicU64::new(0), writer: AtomicBool::new(false),
        }
    }

    fn writer(&self) -> RetryWakeWriter<'_> {
        while self.writer.compare_exchange(false, true, Ordering::Acquire,
            Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        RetryWakeWriter(&self.writer)
    }

    /// A new retained work item or completed outer attempt may request another timer wake.
    pub fn publish(&self, deadline: u64) {
        let _writer = self.writer();
        self.deadline.store(deadline, Ordering::Release);
        self.publication.fetch_add(1, Ordering::Release);
        self.notified.store(false, Ordering::Release);
    }

    pub fn next_deadline(&self, has_work: bool) -> Option<u64> {
        (has_work && !self.notified.load(Ordering::Acquire))
            .then(|| self.deadline.load(Ordering::Acquire))
    }

    /// Readiness for an independent outer owner. Timer notification suppresses another IRQ,
    /// but does not consume the retained work or its already-published deadline.
    pub fn due_for_outer(&self, now: u64, has_work: bool) -> bool {
        let _writer = self.writer();
        has_work && now >= self.deadline.load(Ordering::Acquire)
    }

    /// Defer the clock read until the caller has found a retained owner. The due decision
    /// still uses a fresh sample and the latest deadline under the same writer lock.
    pub fn due_for_outer_with_clock(
        &self,
        has_work: bool,
        clock: impl FnOnce() -> u64,
    ) -> bool {
        if !has_work { return false; }
        self.due_for_outer(clock(), true)
    }

    /// The timer may announce due work once; it never claims or drops the retained owner.
    pub fn wake_due(&self, now: u64, has_work: bool) -> bool {
        let _writer = self.writer();
        has_work && now >= self.deadline.load(Ordering::Acquire)
            && !self.notified.swap(true, Ordering::AcqRel)
    }

    /// The outer owner can act on a delivered wake even after timer rearming is suppressed.
    pub fn begin_redrive(&self, now: u64, has_work: bool) -> Option<RetryWakeAttempt<'_>> {
        let _writer = self.writer();
        (has_work && now >= self.deadline.load(Ordering::Acquire))
            .then(|| RetryWakeAttempt {
                owner: self,
                publication: self.publication.load(Ordering::Acquire),
            })
    }

    /// Preserve the same time sample for the due decision and the next retry deadline.
    pub fn begin_redrive_with_clock(
        &self,
        has_work: bool,
        clock: impl FnOnce() -> u64,
    ) -> Option<(RetryWakeAttempt<'_>, u64)> {
        if !has_work { return None; }
        let now = clock();
        self.begin_redrive(now, has_work).map(|attempt| (attempt, now))
    }

    /// An attempted redrive may schedule a later retry only if no nested callback published
    /// newer work. Both mutations are serialized; a newer earlier deadline remains authoritative.
    fn retry_after(&self, publication: u64, deadline: u64) -> bool {
        let _writer = self.writer();
        if self.publication.load(Ordering::Acquire) != publication { return false; }
        self.deadline.store(deadline, Ordering::Release);
        self.publication.fetch_add(1, Ordering::Release);
        self.notified.store(false, Ordering::Release);
        true
    }
}

impl Default for CoalescedRetryWake {
    fn default() -> Self { Self::new() }
}


/// Diagnostic cohort only; epochs never authorize a timer, sector claim or native effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakeLatencySample {
    pub publish_to_claim_100ns: u64,
    pub due_to_claim_100ns: Option<u64>,
    pub service_to_claim_100ns: Option<u64>,
    pub coalesced_publications: u64,
}

#[derive(Clone, Copy)]
pub struct WakeLatencySnapshot {
    pub samples: u64,
    pub empty_epochs: u64,
    pub coalesced_publications: u64,
    pub unknown_epochs: u64,
    pub follow_on_samples: u64,
    pub published_total_100ns: u64,
    pub follow_on_total_100ns: u64,
    pub due_total_100ns: u64,
    pub due_samples: u64,
    pub service_total_100ns: u64,
    pub service_samples: u64,
    pub published_buckets: [u64; 6],
    pub follow_on_buckets: [u64; 6],
}

impl WakeLatencySnapshot {
    /// Approximate percentile boundary; MAX denotes the open >=50 ms bucket.
    pub fn percentile_bound(bins: &[u64; 6], count: u64, percent: u8) -> Option<u64> {
        if count == 0 || !(1..=100).contains(&percent) { return None; }
        let rank = ((u128::from(count) * u128::from(percent) + 99) / 100) as u64;
        let mut seen = 0u64;
        for (i, n) in bins.iter().enumerate() {
            seen = seen.saturating_add(*n);
            if seen >= rank { return Some([10_000, 50_000, 100_000, 200_000, 500_000, u64::MAX][i]); }
        }
        None
    }
}

struct WakeLatencyState {
    epoch: u64, active: bool, follow_on: bool, first: u64, deadline: u64,
    due: Option<u64>, service: Option<u64>, nested: u64, totals: WakeLatencySnapshot,
}

/// Short independent lock, never held across a callback or physical operation.
pub struct RetainedWakeLatency {
    writer: AtomicBool,
    state: core::cell::UnsafeCell<WakeLatencyState>,
}
// The writer lock serializes every UnsafeCell access.
unsafe impl Sync for RetainedWakeLatency {}

impl RetainedWakeLatency {
    pub const fn new() -> Self {
        Self { writer: AtomicBool::new(false), state: core::cell::UnsafeCell::new(WakeLatencyState {
            epoch: 0, active: false, follow_on: false, first: 0, deadline: 0,
            due: None, service: None, nested: 0,
            totals: WakeLatencySnapshot { samples: 0, empty_epochs: 0,
                coalesced_publications: 0, unknown_epochs: 0, follow_on_samples: 0,
                published_total_100ns: 0, follow_on_total_100ns: 0,
                due_total_100ns: 0, due_samples: 0, service_total_100ns: 0,
                service_samples: 0, published_buckets: [0; 6], follow_on_buckets: [0; 6] },
        }) }
    }
    fn edit<T>(&self, f: impl FnOnce(&mut WakeLatencyState) -> T) -> T {
        while self.writer.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        let _guard = RetryWakeWriter(&self.writer);
        f(unsafe { &mut *self.state.get() })
    }
    pub fn publish(&self, now: u64, deadline: u64) -> u64 { self.start(now, deadline, false) }
    pub fn follow_on(&self, now: u64, deadline: u64) -> u64 { self.start(now, deadline, true) }
    fn start(&self, now: u64, deadline: u64, follow_on: bool) -> u64 {
        self.edit(|s| {
            if s.active {
                s.deadline = deadline; s.due = None; s.nested = s.nested.saturating_add(1);
                s.totals.coalesced_publications = s.totals.coalesced_publications.saturating_add(1);
                return s.epoch;
            }
            let Some(epoch) = s.epoch.checked_add(1) else {
                s.totals.unknown_epochs = s.totals.unknown_epochs.saturating_add(1); return 0;
            };
            s.epoch = epoch; s.active = true; s.follow_on = follow_on;
            s.first = now; s.deadline = deadline; s.due = None; s.service = None; s.nested = 0;
            epoch
        })
    }
    pub fn current_epoch(&self) -> Option<u64> { self.edit(|s| s.active.then_some(s.epoch)) }
    pub fn due(&self, epoch: u64, now: u64) -> bool { self.edit(|s| {
        if !s.active || epoch == 0 || s.epoch != epoch || now < s.deadline { return false; }
        if s.due.is_none() { s.due = Some(now); } true
    }) }
    pub fn service(&self, epoch: u64, now: u64) -> bool { self.edit(|s| {
        if !s.active || epoch == 0 || s.epoch != epoch { return false; }
        if s.service.is_none() { s.service = Some(now); } true
    }) }
    pub fn reschedule(&self, epoch: u64, deadline: u64) -> bool { self.edit(|s| {
        if !s.active || epoch == 0 || s.epoch != epoch { return false; }
        s.deadline = deadline; s.due = None; true
    }) }
    pub fn empty(&self, epoch: u64) -> bool { self.edit(|s| {
        if !s.active || epoch == 0 || s.epoch != epoch { return false; }
        s.active = false; s.totals.empty_epochs = s.totals.empty_epochs.saturating_add(1); true
    }) }
    pub fn claim_sector(&self, epoch: u64, now: u64) -> Option<WakeLatencySample> {
        self.edit(|s| {
            if !s.active || epoch == 0 || s.epoch != epoch { return None; }
            s.active = false;
            let Some(elapsed) = now.checked_sub(s.first) else {
                s.totals.unknown_epochs = s.totals.unknown_epochs.saturating_add(1); return None;
            };
            let due = s.due.and_then(|t| now.checked_sub(t));
            s.totals.samples = s.totals.samples.saturating_add(1);
            let bucket = [10_000, 50_000, 100_000, 200_000, 500_000]
                .iter().position(|bound| elapsed < *bound).unwrap_or(5);
            if s.follow_on {
                s.totals.follow_on_samples = s.totals.follow_on_samples.saturating_add(1);
                s.totals.follow_on_total_100ns = s.totals.follow_on_total_100ns.saturating_add(elapsed);
                s.totals.follow_on_buckets[bucket] = s.totals.follow_on_buckets[bucket].saturating_add(1);
            } else {
                s.totals.published_total_100ns = s.totals.published_total_100ns.saturating_add(elapsed);
                s.totals.published_buckets[bucket] = s.totals.published_buckets[bucket].saturating_add(1);
            }
            if let Some(delay) = due {
                s.totals.due_samples = s.totals.due_samples.saturating_add(1);
                s.totals.due_total_100ns = s.totals.due_total_100ns.saturating_add(delay);
            }
            let service = s.service.and_then(|t| now.checked_sub(t));
            if let Some(delay) = service {
                s.totals.service_samples = s.totals.service_samples.saturating_add(1);
                s.totals.service_total_100ns = s.totals.service_total_100ns.saturating_add(delay);
            }
            Some(WakeLatencySample { publish_to_claim_100ns: elapsed,
                due_to_claim_100ns: due, service_to_claim_100ns: service,
                coalesced_publications: s.nested })
        })
    }
    pub fn snapshot(&self) -> WakeLatencySnapshot { self.edit(|s| s.totals) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Waiting { deadline: u64 },
    Ready,
    Running,
}

/// Scheduling metadata only; the enclosing owner must retain and validate resource identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredWorkWake {
    state: State,
}

impl DeferredWorkWake {
    pub const fn new(deadline: u64) -> Self {
        Self {
            state: State::Waiting { deadline },
        }
    }

    /// Ready work wakes an eligible outer owner, but never repeatedly interrupts a blocked one.
    /// The caller must reconcile again before receiving when outer execution becomes eligible.
    pub fn next_deadline(&self, now: u64, outer_eligible: bool) -> Option<u64> {
        match self.state {
            State::Waiting { deadline } => Some(deadline),
            State::Ready if outer_eligible => Some(now),
            State::Ready | State::Running => None,
        }
    }

    /// Publish readiness once without claiming execution or acknowledging the backing resource.
    pub fn wake_due(&mut self, now: u64) -> bool {
        if matches!(self.state, State::Waiting { deadline } if deadline <= now) {
            self.state = State::Ready;
            true
        } else {
            false
        }
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    pub fn claim(&mut self) -> bool {
        if !self.is_ready() {
            return false;
        }
        self.state = State::Running;
        true
    }

    /// Only the execution owner may reschedule a refused attempt. Success retires its record.
    pub fn retry_at(&mut self, deadline: u64) -> bool {
        if self.state != State::Running {
            return false;
        }
        self.state = State::Waiting { deadline };
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_survives_blocked_outer_owner_without_timer_churn() {
        let mut wake = DeferredWorkWake::new(100);
        assert_eq!(wake.next_deadline(99, false), Some(100));
        assert!(!wake.wake_due(99));
        assert!(wake.wake_due(100));
        for now in 100..110 {
            assert!(!wake.wake_due(now));
            assert!(wake.is_ready());
            assert_eq!(wake.next_deadline(now, false), None);
        }
        assert_eq!(wake.next_deadline(110, true), Some(110));
        assert!(wake.claim());
        assert!(!wake.claim());
        assert!(!wake.wake_due(u64::MAX));
        assert_eq!(wake.next_deadline(120, true), None);
    }

    #[test]
    fn refusal_rearms_only_after_a_claim_and_preserves_backoff() {
        let mut wake = DeferredWorkWake::new(100);
        assert!(!wake.retry_at(0));
        assert!(wake.wake_due(100));
        assert!(!wake.retry_at(0));
        assert!(wake.claim());
        assert!(wake.retry_at(200));
        assert_eq!(wake.next_deadline(150, true), Some(200));
        assert!(!wake.wake_due(199));
        assert!(wake.wake_due(200));
    }

    #[test]
    fn new_ready_work_during_a_running_attempt_remains_schedulable() {
        let mut first = DeferredWorkWake::new(100);
        let mut second = DeferredWorkWake::new(110);
        assert!(first.wake_due(100));
        assert!(first.claim());
        assert!(second.wake_due(110));
        assert!(!first.wake_due(110));
        assert_eq!(second.next_deadline(110, false), None);
        assert!(first.retry_at(200));
        assert_eq!(second.next_deadline(120, true), Some(120));
        assert_eq!(first.next_deadline(120, true), Some(200));
    }

    #[test]
    fn delivered_timer_still_exposes_due_work_to_independent_outer_owner() {
        let wake = CoalescedRetryWake::new();
        wake.publish(100);
        assert!(!wake.due_for_outer(99, true));
        assert!(wake.wake_due(100, true));
        assert_eq!(wake.next_deadline(true), None);
        assert!(wake.due_for_outer(100, true));
        assert!(wake.due_for_outer(100, true));
        assert!(!wake.due_for_outer(100, false));
        wake.publish(200);
        assert!(!wake.due_for_outer(199, true));
        assert!(wake.due_for_outer(200, true));
    }

    #[test]
    fn empty_outer_probe_skips_clock_and_due_probe_uses_current_publication() {
        use core::cell::Cell;

        let wake = CoalescedRetryWake::new();
        let reads = Cell::new(0);
        assert!(!wake.due_for_outer_with_clock(false, || {
            reads.set(reads.get() + 1);
            100
        }));
        assert_eq!(reads.get(), 0);

        wake.publish(100);
        assert!(!wake.due_for_outer_with_clock(true, || {
            reads.set(reads.get() + 1);
            99
        }));
        assert_eq!(reads.get(), 1);
        assert!(wake.due_for_outer_with_clock(true, || {
            reads.set(reads.get() + 1);
            100
        }));
        assert_eq!(reads.get(), 2);

        // The callback is outside the deadline lock; a new publication wins the check.
        assert!(!wake.due_for_outer_with_clock(true, || {
            wake.publish(200);
            100
        }));
        assert!(wake.due_for_outer_with_clock(true, || 200));
    }

    #[test]
    fn empty_outer_redrive_does_not_read_clock_and_retains_new_publication() {
        use core::cell::Cell;

        let wake = CoalescedRetryWake::new();
        let reads = Cell::new(0);
        let clock = || { reads.set(reads.get() + 1); 100 };
        assert!(wake.begin_redrive_with_clock(false, clock).is_none());
        assert_eq!(reads.get(), 0);

        wake.publish(100);
        assert!(wake.begin_redrive_with_clock(true, || 99).is_none());
        let (attempt, now) = wake.begin_redrive_with_clock(true, || 100).unwrap();
        assert_eq!(now, 100);
        wake.publish(150);
        assert!(!attempt.retry_at(now + 50));
        assert_eq!(wake.next_deadline(true), Some(150));

        // A producer can publish while the clock callback runs. The due decision must observe
        // the later authoritative deadline rather than claim the older work.
        assert!(wake.begin_redrive_with_clock(true, || { wake.publish(300); 200 }).is_none());
        assert_eq!(wake.next_deadline(true), Some(300));
    }

    #[test]
    fn observed_wake_latency_keeps_the_first_publication_and_excludes_empty_epochs() {
        let observation = RetainedWakeLatency::new();
        // All times are in 100 ns units. A nested publication moves the real retry
        // deadline but must not erase how long the oldest queued sector waited.
        let first = observation.publish(1_000_000, 1_100_000);
        assert_eq!(observation.publish(1_040_000, 1_140_000), first);
        assert!(!observation.due(first, 1_100_000));
        assert!(observation.due(first, 1_140_000));
        assert!(observation.service(first, 1_160_000));
        let sample = observation.claim_sector(first, 1_190_000).unwrap();
        assert_eq!(sample.publish_to_claim_100ns, 190_000); // 19 ms
        assert_eq!(sample.due_to_claim_100ns, Some(50_000)); // 5 ms
        assert_eq!(sample.service_to_claim_100ns, Some(30_000)); // 3 ms
        assert_eq!(sample.coalesced_publications, 1);

        // Queue cancellation does not turn an empty interval into latency for a
        // later, unrelated sector. A stale callback cannot tag the new epoch.
        let empty = observation.publish(2_000_000, 2_100_000);
        assert!(observation.empty(empty));
        let next = observation.publish(3_000_000, 3_100_000);
        assert_ne!(next, empty);
        assert!(!observation.due(empty, 3_000_000));
        let next_sample = observation.claim_sector(next, 3_010_000).unwrap();
        assert_eq!(next_sample.publish_to_claim_100ns, 10_000); // 1 ms
        assert_eq!(next_sample.due_to_claim_100ns, None);
        let totals = observation.snapshot();
        assert_eq!(totals.samples, 2);
        assert_eq!(totals.empty_epochs, 1);
        assert_eq!(totals.coalesced_publications, 1);
    }

    #[test]
    fn follow_on_sector_has_its_own_observation_after_an_accepted_retry() {
        let observation = RetainedWakeLatency::new();
        let first = observation.publish(1_000_000, 1_100_000);
        observation.claim_sector(first, 1_120_000).unwrap();
        let follow = observation.follow_on(2_000_000, 2_100_000);
        assert_ne!(follow, first);
        assert!(!observation.due(first, 2_100_000));
        observation.claim_sector(follow, 2_110_000).unwrap();
        let totals = observation.snapshot();
        assert_eq!(totals.samples, 2);
        assert_eq!(totals.follow_on_samples, 1);
        assert_eq!(totals.published_total_100ns, 120_000);
        assert_eq!(totals.follow_on_total_100ns, 110_000);
    }

    #[test]
    fn wake_latency_percentiles_keep_a_small_slow_tail_visible() {
        let observation = RetainedWakeLatency::new();
        for index in 0..100u64 {
            let start = index * 1_000_000;
            let epoch = observation.publish(start, start);
            let elapsed = if index < 94 { 20_000 } else { 600_000 };
            observation.claim_sector(epoch, start + elapsed).unwrap();
        }
        let snapshot = observation.snapshot();
        assert_eq!(snapshot.samples, 100);
        assert_eq!(WakeLatencySnapshot::percentile_bound(
            &snapshot.published_buckets, 100, 50), Some(50_000));
        assert_eq!(WakeLatencySnapshot::percentile_bound(
            &snapshot.published_buckets, 100, 95), Some(u64::MAX));
    }

    #[test]
    fn saturated_retry_is_retained_but_not_claimed_without_a_new_scan() {
        let mut wake = DeferredWorkWake::new(u64::MAX);
        assert!(wake.wake_due(u64::MAX));
        assert!(wake.claim());
        assert!(wake.retry_at(u64::MAX));
        assert!(!wake.claim());
        assert!(wake.wake_due(u64::MAX));
        assert!(wake.claim());
    }
}
