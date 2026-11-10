//! Bounded, value-only observation of exact installer-child native table calls.

const SSN_CAP: usize = 512;
const STATUS_PENDING: u32 = 0x103;

/// One diagnostic sample per completed periodic census epoch after activation.
/// The current epoch is primed without consuming the bounded sample budget.
pub struct CensusEpochGate {
    last_epoch: u64,
    emitted: u64,
    limit: u64,
    primed: bool,
}

impl CensusEpochGate {
    pub const fn new(limit: u64) -> Self {
        Self { last_epoch: 0, emitted: 0, limit, primed: false }
    }

    pub fn prime(&mut self, epoch: u64) {
        if !self.primed {
            self.last_epoch = epoch;
            self.primed = true;
        }
    }

    pub fn admit(&mut self, epoch: u64) -> bool {
        if epoch == 0 || epoch <= self.last_epoch || self.emitted >= self.limit {
            return false;
        }
        self.last_epoch = epoch;
        self.emitted += 1;
        true
    }

    pub fn emitted(&self) -> u64 { self.emitted }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanOwner {
    pub process_index: usize,
    pub process_generation: u64,
    pub thread_id: u64,
    pub thread_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSample {
    pub ssn: u32,
    pub age_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SsnTotal {
    pub ssn: u32,
    pub calls: u64,
    pub total_100ns: u64,
    pub max_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSnapshot<const TOP: usize> {
    pub owner: SpanOwner,
    pub completed: u64,
    pub retained_pending: u64,
    pub unresolved_replaced: u64,
    pub total_gap_100ns: u64,
    pub max_gap_100ns: u64,
    pub last_return_age_100ns: Option<u64>,
    pub active: Option<SpanSample>,
    pub pending: Option<SpanSample>,
    pub top: [Option<SsnTotal>; TOP],
    /// Distinct observed SSNs omitted from `top`.
    pub overflow_ssns: u64,
    /// Completed calls outside the fixed canonical SSN range.
    pub unindexed_calls: u64,
}

#[derive(Clone, Copy)]
struct ActiveSpan { ssn: u32, at_100ns: u64 }

#[derive(Clone, Copy)]
struct Counter { calls: u64, total_100ns: u64, max_100ns: u64 }

impl Counter { const EMPTY: Self = Self { calls: 0, total_100ns: 0, max_100ns: 0 }; }

#[derive(Clone, Copy)]
struct Row {
    owner: Option<SpanOwner>,
    active: Option<ActiveSpan>,
    pending: Option<ActiveSpan>,
    last_return_at: Option<u64>,
    completed: u64,
    retained_pending: u64,
    unresolved_replaced: u64,
    total_gap_100ns: u64,
    max_gap_100ns: u64,
    unindexed_calls: u64,
    counters: [Counter; SSN_CAP],
}

impl Row {
    const EMPTY: Self = Self {
        owner: None, active: None, pending: None, last_return_at: None,
        completed: 0, retained_pending: 0, unresolved_replaced: 0,
        total_gap_100ns: 0, max_gap_100ns: 0, unindexed_calls: 0,
        counters: [Counter::EMPTY; SSN_CAP],
    };

    fn snapshot<const TOP: usize>(&self, owner: SpanOwner, now: u64) -> SpanSnapshot<TOP> {
        let mut top: [Option<SsnTotal>; TOP] = [None; TOP];
        let mut distinct = 0u64;
        for (ssn, counter) in self.counters.iter().enumerate() {
            if counter.calls == 0 { continue; }
            distinct += 1;
            let item = SsnTotal { ssn: ssn as u32, calls: counter.calls,
                total_100ns: counter.total_100ns, max_100ns: counter.max_100ns };
            let Some(position) = top.iter().position(|slot| slot.is_none_or(|prior|
                (item.total_100ns, item.calls, core::cmp::Reverse(item.ssn))
                    > (prior.total_100ns, prior.calls, core::cmp::Reverse(prior.ssn))))
                else { continue; };
            for index in (position + 1..TOP).rev() { top[index] = top[index - 1]; }
            top[position] = Some(item);
        }
        SpanSnapshot {
            owner, completed: self.completed, retained_pending: self.retained_pending,
            unresolved_replaced: self.unresolved_replaced,
            total_gap_100ns: self.total_gap_100ns, max_gap_100ns: self.max_gap_100ns,
            last_return_age_100ns: self.last_return_at.map(|at| now.saturating_sub(at)),
            active: self.active.map(|span| SpanSample { ssn: span.ssn,
                age_100ns: now.saturating_sub(span.at_100ns) }),
            pending: self.pending.map(|span| SpanSample { ssn: span.ssn,
                age_100ns: now.saturating_sub(span.at_100ns) }),
            top, overflow_ssns: distinct.saturating_sub(TOP as u64),
            unindexed_calls: self.unindexed_calls,
        }
    }
}

/// Fixed-capacity diagnostic. Only an exact observed owner may update its row.
pub struct InstallerSyscallSpans<const N: usize, const TOP: usize> {
    rows: [Row; N],
    activation_overflow: u64,
}

impl<const N: usize, const TOP: usize> InstallerSyscallSpans<N, TOP> {
    pub const fn new() -> Self {
        Self { rows: [Row::EMPTY; N], activation_overflow: 0 }
    }

    pub fn activate(&mut self, owner: SpanOwner) -> bool {
        if owner.process_generation == 0 || owner.thread_id == 0 || owner.thread_generation == 0 {
            return false;
        }
        if self.rows.iter().any(|row| row.owner == Some(owner)) { return true; }
        // A reused process slot never inherits a previous generation's timings.
        for row in &mut self.rows {
            if row.owner.is_some_and(|old| old.process_index == owner.process_index
                && (old.process_generation != owner.process_generation
                    || (old.thread_id == owner.thread_id
                        && old.thread_generation != owner.thread_generation))) {
                *row = Row::EMPTY;
            }
        }
        if let Some(row) = self.rows.iter_mut().find(|row| row.owner.is_none()) {
            row.owner = Some(owner);
            return true;
        }
        self.activation_overflow = self.activation_overflow.saturating_add(1);
        false
    }

    pub fn activation_overflow(&self) -> u64 { self.activation_overflow }

    pub fn retire(&mut self, owner: SpanOwner) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.owner == Some(owner)) else {
            return false;
        };
        *row = Row::EMPTY;
        true
    }

    pub fn begin(&mut self, owner: SpanOwner, ssn: u32, now: u64) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.owner == Some(owner)) else {
            return false;
        };
        if row.active.is_some() || row.pending.take().is_some() {
            row.unresolved_replaced = row.unresolved_replaced.saturating_add(1);
        }
        if let Some(last) = row.last_return_at.take() {
            let gap = now.saturating_sub(last);
            row.total_gap_100ns = row.total_gap_100ns.saturating_add(gap);
            row.max_gap_100ns = row.max_gap_100ns.max(gap);
        }
        row.active = Some(ActiveSpan { ssn, at_100ns: now });
        true
    }

    /// A pending dispatch return transfers ownership; it is never a terminal Reply.
    pub fn return_from_dispatch(&mut self, owner: SpanOwner, ssn: u32,
        status: u32, now: u64) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.owner == Some(owner)) else {
            return false;
        };
        let Some(active) = row.active.filter(|active| active.ssn == ssn) else {
            return false;
        };
        row.active = None;
        if status == STATUS_PENDING {
            row.retained_pending = row.retained_pending.saturating_add(1);
            row.pending = Some(active);
            return true;
        }
        let elapsed = now.saturating_sub(active.at_100ns);
        row.completed = row.completed.saturating_add(1);
        row.last_return_at = Some(now);
        if let Some(counter) = row.counters.get_mut(ssn as usize) {
            counter.calls = counter.calls.saturating_add(1);
            counter.total_100ns = counter.total_100ns.saturating_add(elapsed);
            counter.max_100ns = counter.max_100ns.max(elapsed);
        } else {
            row.unindexed_calls = row.unindexed_calls.saturating_add(1);
        }
        true
    }

    pub fn snapshot(&self, owner: SpanOwner, now: u64) -> Option<SpanSnapshot<TOP>> {
        self.rows.iter().find(|row| row.owner == Some(owner))
            .map(|row| row.snapshot(owner, now))
    }

    pub fn owners(&self) -> impl Iterator<Item = SpanOwner> + '_ {
        self.rows.iter().filter_map(|row| row.owner)
    }
}

impl<const N: usize, const TOP: usize> Default for InstallerSyscallSpans<N, TOP> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn census_epoch_gate_uses_only_distinct_periodic_epochs_after_activation() {
        let mut gate = CensusEpochGate::new(16);
        gate.prime(31);
        assert!(!gate.admit(0));
        assert!(!gate.admit(31));
        assert!(!gate.admit(31));
        for epoch in 32..48 {
            assert!(gate.admit(epoch));
            assert!(!gate.admit(epoch));
        }
        assert!(!gate.admit(48));
        assert!(!gate.admit(49));
        assert_eq!(gate.emitted(), 16);
    }

    #[test]
    fn census_epoch_gate_rejects_stale_and_zero_epochs() {
        let mut gate = CensusEpochGate::new(2);
        assert!(!gate.admit(0));
        assert!(gate.admit(1));
        assert!(!gate.admit(1));
        assert!(gate.admit(3));
        assert!(!gate.admit(2));
        assert_eq!(gate.emitted(), 2);
    }

    const A: SpanOwner = SpanOwner { process_index: 18, process_generation: 17,
        thread_id: 560, thread_generation: 1 };

    #[test]
    fn pending_dispatch_is_never_counted_as_terminal() {
        let mut ledger = InstallerSyscallSpans::<2, 2>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, 191, 100));
        assert!(ledger.return_from_dispatch(A, 191, 0x103, 200));
        let snapshot = ledger.snapshot(A, 300).unwrap();
        assert_eq!(snapshot.completed, 0);
        assert_eq!(snapshot.retained_pending, 1);
        assert_eq!(snapshot.pending.map(|span| span.ssn), Some(191));
        assert_eq!(snapshot.pending.map(|span| span.age_100ns), Some(200));
        assert!(ledger.begin(A, 185, 400));
        let snapshot = ledger.snapshot(A, 400).unwrap();
        assert_eq!(snapshot.completed, 0);
        assert_eq!(snapshot.unresolved_replaced, 1);
        assert_eq!(snapshot.pending, None);
        assert_eq!(snapshot.active.map(|span| span.ssn), Some(185));
    }

    #[test]
    fn generation_and_thread_rollover_do_not_inherit_gaps() {
        let mut ledger = InstallerSyscallSpans::<2, 2>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, 191, 100));
        assert!(ledger.return_from_dispatch(A, 191, 0, 200));
        let newer = SpanOwner { process_generation: 18, ..A };
        assert!(ledger.activate(newer));
        assert!(ledger.begin(newer, 191, 10_000));
        assert!(ledger.return_from_dispatch(newer, 191, 0, 10_100));
        assert_eq!(ledger.snapshot(newer, 10_100).unwrap().total_gap_100ns, 0);
        assert_eq!(ledger.snapshot(A, 10_100), None);
        let other_thread = SpanOwner { thread_id: 568, thread_generation: 2, ..newer };
        assert!(ledger.activate(other_thread));
        assert!(ledger.begin(other_thread, 191, 20_000));
        assert_eq!(ledger.snapshot(other_thread, 20_000).unwrap().total_gap_100ns, 0);
        let recycled_thread = SpanOwner { thread_generation: 3, ..other_thread };
        assert!(ledger.activate(recycled_thread));
        assert_eq!(ledger.snapshot(other_thread, 20_000), None);
        assert!(ledger.retire(recycled_thread));
        assert_eq!(ledger.snapshot(recycled_thread, 20_000), None);
    }

    #[test]
    fn top_ssn_is_deterministic_and_reports_overflow() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));
        for (ssn, start) in [(284, 100), (191, 300), (39, 500)] {
            assert!(ledger.begin(A, ssn, start));
            assert!(ledger.return_from_dispatch(A, ssn, 0, start + 50));
        }
        let snapshot = ledger.snapshot(A, 600).unwrap();
        assert_eq!(snapshot.completed, 3);
        assert_eq!(snapshot.total_gap_100ns, 300);
        assert_eq!(snapshot.top[0].map(|item| item.ssn), Some(39));
        assert_eq!(snapshot.top[1].map(|item| item.ssn), Some(191));
        assert_eq!(snapshot.overflow_ssns, 1);
    }
}
