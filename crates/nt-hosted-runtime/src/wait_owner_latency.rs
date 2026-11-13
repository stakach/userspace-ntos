//! Bounded attribution of authenticated wait transitions, never scheduling authority.
//!
//! `ReplyDelivered -> NextIngress` measures the next observed ingress, not CPU runnable time.
//! A copied badge, timer notification, or elapsed deadline cannot advance a wait here.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitLatencyKey {
    pub process_index: u64,
    pub process_generation: u64,
    pub thread_id: u64,
    pub thread_generation: u64,
    pub badge: u64,
    pub tcb: u64,
    pub wait_sequence: u64,
    pub reply: u64,
}

impl WaitLatencyKey {
    pub const fn is_valid(self) -> bool {
        self.process_generation != 0 && self.thread_id != 0
            && self.thread_generation != 0 && self.tcb != 0
            && self.wait_sequence != 0 && self.reply != 0
    }

    pub const fn thread_identity(self) -> WaitLatencyThreadIdentity {
        WaitLatencyThreadIdentity {
            process_index: self.process_index,
            process_generation: self.process_generation,
            thread_id: self.thread_id,
            thread_generation: self.thread_generation,
            tcb: self.tcb,
        }
    }
}

/// Exact live thread identity available at ingress, before its next Reply is allocated.
/// A badge alone cannot identify a thread or authorize a latency transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitLatencyThreadIdentity {
    pub process_index: u64,
    pub process_generation: u64,
    pub thread_id: u64,
    pub thread_generation: u64,
    pub tcb: u64,
}

impl WaitLatencyThreadIdentity {
    pub const fn is_valid(self) -> bool {
        self.process_generation != 0 && self.thread_id != 0
            && self.thread_generation != 0 && self.tcb != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WaitLatencyRole {
    Unknown,
    System,
    SessionManager,
    ClientServer,
    Winlogon,
    Services,
    Userinit,
    Explorer,
    Other,
}

impl WaitLatencyRole {
    pub const COUNT: usize = 9;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Unknown, Self::System, Self::SessionManager, Self::ClientServer,
        Self::Winlogon, Self::Services, Self::Userinit, Self::Explorer, Self::Other,
    ];
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Unknown => b"unknown", Self::System => b"system",
            Self::SessionManager => b"smss", Self::ClientServer => b"csrss",
            Self::Winlogon => b"winlogon", Self::Services => b"services",
            Self::Userinit => b"userinit", Self::Explorer => b"explorer",
            Self::Other => b"other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WaitLatencyOwner {
    Unknown,
    Object,
    Lpc,
    Provider,
    Receive,
    Service,
    Delay,
    IoCompletion,
    Other,
}

impl WaitLatencyOwner {
    pub const COUNT: usize = 9;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Unknown, Self::Object, Self::Lpc, Self::Provider, Self::Receive,
        Self::Service, Self::Delay, Self::IoCompletion, Self::Other,
    ];
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Unknown => b"unknown", Self::Object => b"object",
            Self::Lpc => b"lpc", Self::Provider => b"provider",
            Self::Receive => b"receive", Self::Service => b"service",
            Self::Delay => b"delay", Self::IoCompletion => b"iocp",
            Self::Other => b"other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitLatencyInterval {
    ParkToSelected,
    SelectedToReply,
    /// The next ingress is an observable proxy, not a CPU runnable timestamp.
    ReplyToNextIngress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitLatencyPhase {
    Parked,
    Selected,
    ReplyDelivered,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitLatencySample {
    pub count: u64,
    pub total_100ns: u64,
    pub max_100ns: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitLatencyCounters {
    pub invalid_identity: u64,
    pub unmatched: u64,
    pub ambiguous_ingress: u64,
    pub phase_refusal: u64,
    pub capacity_overflow: u64,
    pub clock_regression: u64,
    pub unknown_intervals: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitLatencyError {
    InvalidIdentity,
    Duplicate,
    NotFound,
    Ambiguous,
    WrongPhase,
    NoCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitLatencyLive {
    pub key: WaitLatencyKey,
    pub role: WaitLatencyRole,
    pub owner: WaitLatencyOwner,
    pub phase: WaitLatencyPhase,
    pub parked_at_100ns: u64,
}

#[derive(Clone, Copy)]
struct Row {
    live: WaitLatencyLive,
    phase_at_100ns: u64,
}

const BUCKETS: usize = WaitLatencyRole::COUNT * WaitLatencyOwner::COUNT;

/// Fixed-capacity live waits and aggregate counters. No operation allocates or enters an effect.
pub struct WaitLatencyLedger<const CAPACITY: usize> {
    rows: [Option<Row>; CAPACITY],
    samples: [[WaitLatencySample; BUCKETS]; 3],
    counters: WaitLatencyCounters,
}

impl<const CAPACITY: usize> WaitLatencyLedger<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            rows: [None; CAPACITY],
            samples: [[WaitLatencySample { count: 0, total_100ns: 0, max_100ns: 0 }; BUCKETS]; 3],
            counters: WaitLatencyCounters {
                invalid_identity: 0, unmatched: 0, ambiguous_ingress: 0, phase_refusal: 0,
                capacity_overflow: 0, clock_regression: 0, unknown_intervals: 0,
            },
        }
    }

    const fn bucket(role: WaitLatencyRole, owner: WaitLatencyOwner) -> usize {
        role as usize * WaitLatencyOwner::COUNT + owner as usize
    }

    const fn interval_index(interval: WaitLatencyInterval) -> usize {
        match interval {
            WaitLatencyInterval::ParkToSelected => 0,
            WaitLatencyInterval::SelectedToReply => 1,
            WaitLatencyInterval::ReplyToNextIngress => 2,
        }
    }

    pub const fn counters(&self) -> WaitLatencyCounters { self.counters }

    pub const fn sample(
        &self, role: WaitLatencyRole, owner: WaitLatencyOwner,
        interval: WaitLatencyInterval,
    ) -> WaitLatencySample {
        self.samples[Self::interval_index(interval)][Self::bucket(role, owner)]
    }

    pub fn live_count(&self) -> usize {
        self.rows.iter().filter(|row| row.is_some()).count()
    }

    pub fn oldest_live(&self) -> Option<WaitLatencyLive> {
        self.rows.iter().flatten().min_by_key(|row| row.live.parked_at_100ns)
            .map(|row| row.live)
    }

    /// Only the caller that owns the exact wait may publish this observation.
    pub fn park(
        &mut self, key: WaitLatencyKey, role: WaitLatencyRole,
        owner: WaitLatencyOwner, now_100ns: u64,
    ) -> Result<(), WaitLatencyError> {
        if !key.is_valid() {
            self.counters.invalid_identity = self.counters.invalid_identity.saturating_add(1);
            return Err(WaitLatencyError::InvalidIdentity);
        }
        if self.rows.iter().flatten().any(|row| row.live.key == key) {
            self.counters.phase_refusal = self.counters.phase_refusal.saturating_add(1);
            return Err(WaitLatencyError::Duplicate);
        }
        let Some(slot) = self.rows.iter_mut().find(|row| row.is_none()) else {
            self.counters.capacity_overflow = self.counters.capacity_overflow.saturating_add(1);
            return Err(WaitLatencyError::NoCapacity);
        };
        *slot = Some(Row {
            live: WaitLatencyLive { key, role, owner, phase: WaitLatencyPhase::Parked,
                parked_at_100ns: now_100ns },
            phase_at_100ns: now_100ns,
        });
        Ok(())
    }

    fn find(&mut self, key: WaitLatencyKey) -> Result<usize, WaitLatencyError> {
        if !key.is_valid() {
            self.counters.invalid_identity = self.counters.invalid_identity.saturating_add(1);
            return Err(WaitLatencyError::InvalidIdentity);
        }
        self.rows.iter().position(|row| row.is_some_and(|row| row.live.key == key))
            .ok_or_else(|| {
                self.counters.unmatched = self.counters.unmatched.saturating_add(1);
                WaitLatencyError::NotFound
            })
    }

    fn observe_interval(
        &mut self, row: Row, interval: WaitLatencyInterval, now_100ns: u64,
    ) {
        if let Some(elapsed) = now_100ns.checked_sub(row.phase_at_100ns) {
            let sample = &mut self.samples[Self::interval_index(interval)]
                [Self::bucket(row.live.role, row.live.owner)];
            sample.count = sample.count.saturating_add(1);
            sample.total_100ns = sample.total_100ns.saturating_add(elapsed);
            sample.max_100ns = sample.max_100ns.max(elapsed);
        } else {
            self.counters.clock_regression = self.counters.clock_regression.saturating_add(1);
            self.counters.unknown_intervals = self.counters.unknown_intervals.saturating_add(1);
        }
    }

    fn advance(
        &mut self, key: WaitLatencyKey, from: WaitLatencyPhase,
        to: Option<WaitLatencyPhase>, interval: WaitLatencyInterval, now_100ns: u64,
    ) -> Result<(), WaitLatencyError> {
        let index = self.find(key)?;
        let Some(row) = self.rows[index] else {
            self.counters.unmatched = self.counters.unmatched.saturating_add(1);
            return Err(WaitLatencyError::NotFound);
        };
        if row.live.phase != from {
            self.counters.phase_refusal = self.counters.phase_refusal.saturating_add(1);
            return Err(WaitLatencyError::WrongPhase);
        }
        self.observe_interval(row, interval, now_100ns);
        if let Some(next) = to {
            self.rows[index] = Some(Row {
                live: WaitLatencyLive { phase: next, ..row.live },
                phase_at_100ns: now_100ns,
            });
        } else {
            self.rows[index] = None;
        }
        Ok(())
    }

    pub fn selected(&mut self, key: WaitLatencyKey, now_100ns: u64)
        -> Result<(), WaitLatencyError>
    {
        self.advance(key, WaitLatencyPhase::Parked, Some(WaitLatencyPhase::Selected),
            WaitLatencyInterval::ParkToSelected, now_100ns)
    }

    pub fn reply_delivered(&mut self, key: WaitLatencyKey, now_100ns: u64)
        -> Result<(), WaitLatencyError>
    {
        self.advance(key, WaitLatencyPhase::Selected, Some(WaitLatencyPhase::ReplyDelivered),
            WaitLatencyInterval::SelectedToReply, now_100ns)
    }

    pub fn next_ingress(&mut self, key: WaitLatencyKey, now_100ns: u64)
        -> Result<(), WaitLatencyError>
    {
        self.advance(key, WaitLatencyPhase::ReplyDelivered, None,
            WaitLatencyInterval::ReplyToNextIngress, now_100ns)
    }

    /// Attribute the next observed ingress after this wait's Reply was delivered. The caller
    /// must authenticate this exact live thread independently; the new Call need not have an
    /// allocated Reply or wait sequence yet.
    /// Only a unique ReplyDelivered row is eligible; ambiguity cannot complete either wait.
    /// This interval is an ingress proxy, not a CPU runnable timestamp.
    pub fn next_ingress_for_thread(
        &mut self, thread: WaitLatencyThreadIdentity, now_100ns: u64,
    ) -> Result<(), WaitLatencyError> {
        if !thread.is_valid() {
            self.counters.invalid_identity = self.counters.invalid_identity.saturating_add(1);
            return Err(WaitLatencyError::InvalidIdentity);
        }
        let mut matching_key = None;
        for row in self.rows.iter().flatten() {
            if row.live.phase != WaitLatencyPhase::ReplyDelivered
                || row.live.key.thread_identity() != thread
            {
                continue;
            }
            if matching_key.is_some() {
                self.counters.ambiguous_ingress =
                    self.counters.ambiguous_ingress.saturating_add(1);
                return Err(WaitLatencyError::Ambiguous);
            }
            matching_key = Some(row.live.key);
        }
        let Some(key) = matching_key else {
            self.counters.unmatched = self.counters.unmatched.saturating_add(1);
            return Err(WaitLatencyError::NotFound);
        };
        self.next_ingress(key, now_100ns)
    }

    /// Explicitly remove an exact owner whose work ended before its next ingress. This never
    /// manufactures a completed interval from an interrupted or uncertain wait.
    pub fn retire_incomplete(&mut self, key: WaitLatencyKey) -> Result<(), WaitLatencyError> {
        let index = self.find(key)?;
        let Some(row) = self.rows[index] else {
            self.counters.unmatched = self.counters.unmatched.saturating_add(1);
            return Err(WaitLatencyError::NotFound);
        };
        let remaining = match row.live.phase {
            WaitLatencyPhase::Parked => 3,
            WaitLatencyPhase::Selected => 2,
            WaitLatencyPhase::ReplyDelivered => 1,
        };
        self.counters.unknown_intervals = self.counters.unknown_intervals.saturating_add(remaining);
        self.rows[index] = None;
        Ok(())
    }
}

impl<const CAPACITY: usize> Default for WaitLatencyLedger<CAPACITY> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(process_generation: u64, thread_generation: u64, wait_sequence: u64) -> WaitLatencyKey {
        WaitLatencyKey { process_index: 9, process_generation, thread_id: 44,
            thread_generation, badge: 18, tcb: 0x2000, wait_sequence, reply: 0x3000 }
    }

    #[test]
    fn interleaved_roles_and_owners_keep_exact_intervals() {
        let mut ledger = WaitLatencyLedger::<2>::new();
        let a = key(1, 1, 1);
        let b = key(2, 1, 1);
        ledger.park(a, WaitLatencyRole::ClientServer, WaitLatencyOwner::Lpc, 100).unwrap();
        ledger.park(b, WaitLatencyRole::Services, WaitLatencyOwner::Object, 120).unwrap();
        ledger.selected(b, 130).unwrap();
        ledger.selected(a, 160).unwrap();
        ledger.reply_delivered(a, 170).unwrap();
        ledger.reply_delivered(b, 190).unwrap();
        ledger.next_ingress(b, 195).unwrap();
        ledger.next_ingress(a, 200).unwrap();
        assert_eq!(ledger.live_count(), 0);
        assert_eq!(ledger.sample(WaitLatencyRole::ClientServer, WaitLatencyOwner::Lpc,
            WaitLatencyInterval::ParkToSelected).total_100ns, 60);
        assert_eq!(ledger.sample(WaitLatencyRole::ClientServer, WaitLatencyOwner::Lpc,
            WaitLatencyInterval::SelectedToReply).total_100ns, 10);
        assert_eq!(ledger.sample(WaitLatencyRole::ClientServer, WaitLatencyOwner::Lpc,
            WaitLatencyInterval::ReplyToNextIngress).total_100ns, 30);
        assert_eq!(ledger.sample(WaitLatencyRole::Services, WaitLatencyOwner::Object,
            WaitLatencyInterval::ParkToSelected).total_100ns, 10);
        assert_eq!(ledger.sample(WaitLatencyRole::Services, WaitLatencyOwner::Object,
            WaitLatencyInterval::SelectedToReply).total_100ns, 60);
        assert_eq!(ledger.sample(WaitLatencyRole::Services, WaitLatencyOwner::Object,
            WaitLatencyInterval::ReplyToNextIngress).total_100ns, 5);
    }

    #[test]
    fn stale_generation_and_duplicate_selection_cannot_charge_another_wait() {
        let mut ledger = WaitLatencyLedger::<1>::new();
        let old = key(1, 1, 1);
        let current = key(2, 1, 1);
        ledger.park(old, WaitLatencyRole::Winlogon, WaitLatencyOwner::Object, 1).unwrap();
        ledger.retire_incomplete(old).unwrap();
        ledger.park(current, WaitLatencyRole::Winlogon, WaitLatencyOwner::Object, 10).unwrap();
        assert_eq!(ledger.selected(old, 20), Err(WaitLatencyError::NotFound));
        assert_eq!(ledger.selected(WaitLatencyKey { reply: 0x3001, ..current }, 20),
            Err(WaitLatencyError::NotFound));
        assert_eq!(ledger.park(current, WaitLatencyRole::Winlogon, WaitLatencyOwner::Object, 20),
            Err(WaitLatencyError::Duplicate));
        ledger.selected(current, 30).unwrap();
        assert_eq!(ledger.selected(current, 40), Err(WaitLatencyError::WrongPhase));
        assert_eq!(ledger.reply_delivered(old, 50), Err(WaitLatencyError::NotFound));
        ledger.reply_delivered(current, 60).unwrap();
        assert_eq!(ledger.sample(WaitLatencyRole::Winlogon, WaitLatencyOwner::Object,
            WaitLatencyInterval::ParkToSelected).count, 1);
        assert_eq!(ledger.sample(WaitLatencyRole::Winlogon, WaitLatencyOwner::Object,
            WaitLatencyInterval::SelectedToReply).total_100ns, 30);
        assert_eq!(ledger.counters().unmatched, 3);
        assert_eq!(ledger.counters().phase_refusal, 2);
    }

    #[test]
    fn clock_regression_marks_only_the_unknown_interval() {
        let mut ledger = WaitLatencyLedger::<1>::new();
        let wait = key(1, 1, 1);
        ledger.park(wait, WaitLatencyRole::Unknown, WaitLatencyOwner::Provider, 100).unwrap();
        ledger.selected(wait, 90).unwrap();
        ledger.reply_delivered(wait, 95).unwrap();
        ledger.next_ingress(wait, 110).unwrap();
        assert_eq!(ledger.counters().clock_regression, 1);
        assert_eq!(ledger.counters().unknown_intervals, 1);
        assert_eq!(ledger.sample(WaitLatencyRole::Unknown, WaitLatencyOwner::Provider,
            WaitLatencyInterval::ParkToSelected).count, 0);
        assert_eq!(ledger.sample(WaitLatencyRole::Unknown, WaitLatencyOwner::Provider,
            WaitLatencyInterval::SelectedToReply).total_100ns, 5);
        assert_eq!(ledger.sample(WaitLatencyRole::Unknown, WaitLatencyOwner::Provider,
            WaitLatencyInterval::ReplyToNextIngress).total_100ns, 15);
    }

    #[test]
    fn capacity_and_incomplete_retirement_are_explicit() {
        let mut ledger = WaitLatencyLedger::<1>::new();
        let first = key(1, 1, 1);
        let second = key(1, 1, 2);
        ledger.park(first, WaitLatencyRole::Other, WaitLatencyOwner::Delay, 10).unwrap();
        assert_eq!(ledger.oldest_live().unwrap().key, first);
        assert_eq!(ledger.park(second, WaitLatencyRole::Other, WaitLatencyOwner::Delay, 20),
            Err(WaitLatencyError::NoCapacity));
        assert_eq!(ledger.counters().capacity_overflow, 1);
        ledger.retire_incomplete(first).unwrap();
        assert_eq!(ledger.counters().unknown_intervals, 3);
        ledger.park(second, WaitLatencyRole::Other, WaitLatencyOwner::Delay, 30).unwrap();
        assert_eq!(ledger.live_count(), 1);
        assert_eq!(ledger.retire_incomplete(first), Err(WaitLatencyError::NotFound));
    }

    #[test]
    fn next_ingress_matches_prior_wait_by_exact_thread_when_reply_changes() {
        let mut ledger = WaitLatencyLedger::<2>::new();
        let old_wait = key(4, 5, 20);
        let new_wait = WaitLatencyKey { wait_sequence: 21, reply: 0x3001, ..old_wait };
        ledger.park(old_wait, WaitLatencyRole::Explorer, WaitLatencyOwner::Object, 10).unwrap();
        ledger.selected(old_wait, 20).unwrap();
        ledger.reply_delivered(old_wait, 30).unwrap();
        assert_eq!(ledger.next_ingress(new_wait, 40), Err(WaitLatencyError::NotFound));
        ledger.next_ingress_for_thread(new_wait.thread_identity(), 40).unwrap();
        assert_eq!(ledger.live_count(), 0);
        assert_eq!(ledger.sample(WaitLatencyRole::Explorer, WaitLatencyOwner::Object,
            WaitLatencyInterval::ReplyToNextIngress).total_100ns, 10);
    }

    #[test]
    fn next_ingress_refuses_stale_generation_and_ambiguous_delivered_waits() {
        let mut ledger = WaitLatencyLedger::<2>::new();
        let first = key(4, 5, 20);
        let second = WaitLatencyKey { wait_sequence: 21, reply: 0x3001, ..first };
        for wait in [first, second] {
            ledger.park(wait, WaitLatencyRole::Explorer, WaitLatencyOwner::Object, 10).unwrap();
            ledger.selected(wait, 20).unwrap();
            ledger.reply_delivered(wait, 30).unwrap();
        }
        assert_eq!(ledger.next_ingress_for_thread(
            WaitLatencyThreadIdentity { process_generation: 3, ..first.thread_identity() }, 40),
            Err(WaitLatencyError::NotFound));
        assert_eq!(ledger.next_ingress_for_thread(
            WaitLatencyThreadIdentity { thread_generation: 4, ..first.thread_identity() }, 40),
            Err(WaitLatencyError::NotFound));
        assert_eq!(ledger.next_ingress_for_thread(
            WaitLatencyThreadIdentity { tcb: 0x2001, ..first.thread_identity() }, 40),
            Err(WaitLatencyError::NotFound));
        assert_eq!(ledger.next_ingress_for_thread(first.thread_identity(), 40),
            Err(WaitLatencyError::Ambiguous));
        assert_eq!(ledger.live_count(), 2);
        assert_eq!(ledger.counters().ambiguous_ingress, 1);
        assert_eq!(ledger.sample(WaitLatencyRole::Explorer, WaitLatencyOwner::Object,
            WaitLatencyInterval::ReplyToNextIngress).count, 0);
        ledger.next_ingress(first, 50).unwrap();
        ledger.next_ingress_for_thread(second.thread_identity(), 60).unwrap();
        assert_eq!(ledger.live_count(), 0);
    }
}
