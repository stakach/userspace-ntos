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
