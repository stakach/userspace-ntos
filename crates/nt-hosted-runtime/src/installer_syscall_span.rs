//! Bounded, value-only observation of exact installer-child native table calls.

const SSN_CAP: usize = 512;
const PAIR_CAP: usize = 128;
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

/// Exact cumulative time from one nonpending table-dispatch return to the
/// following table-dispatch entry for the same owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionPairTotal {
    pub from_ssn: u32,
    pub to_ssn: u32,
    pub calls: u64,
    pub total_100ns: u64,
    pub max_100ns: u64,
}

/// The largest observed interval between a nonpending table-dispatch return
/// and the next table-dispatch entry for one exact installer child. Pending returns have no
/// terminal timestamp here and cannot create this receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongestGap {
    pub owner: SpanOwner,
    pub from_ssn: u32,
    pub from_status: u32,
    pub to_ssn: u32,
    pub from_at_100ns: u64,
    pub to_at_100ns: u64,
}

impl LongestGap {
    pub fn duration_100ns(self) -> u64 {
        self.to_at_100ns.saturating_sub(self.from_at_100ns)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSnapshot<const TOP: usize> {
    pub owner: SpanOwner,
    pub completed: u64,
    pub retained_pending: u64,
    pub unresolved_replaced: u64,
    pub total_gap_100ns: u64,
    pub max_gap_100ns: u64,
    pub longest_gap: Option<LongestGap>,
    pub last_return_age_100ns: Option<u64>,
    pub active: Option<SpanSample>,
    pub pending: Option<SpanSample>,
    pub top: [Option<SsnTotal>; TOP],
    /// Return-to-next-entry gaps where both completed calls have the same SSN.
    pub same_ssn_gaps: [Option<SsnTotal>; TOP],
    /// Exact observed pairs ranked by cumulative gap time.
    pub top_transition_pairs: [Option<TransitionPairTotal>; TOP],
    /// Tracked distinct pairs omitted from `top_transition_pairs`.
    pub overflow_transition_pairs: u64,
    /// Gap observations omitted when the fixed pair table was full.
    pub untracked_transition_gaps: u64,
    pub untracked_transition_gap_100ns: u64,
    /// Distinct observed SSNs omitted from `top`.
    pub overflow_ssns: u64,
    /// Completed calls outside the fixed canonical SSN range.
    pub unindexed_calls: u64,
}

#[derive(Clone, Copy)]
struct ActiveSpan { ssn: u32, at_100ns: u64 }

#[derive(Clone, Copy)]
struct LastReturn { ssn: u32, status: u32, at_100ns: u64 }

#[derive(Clone, Copy)]
struct Counter { calls: u64, total_100ns: u64, max_100ns: u64 }

impl Counter { const EMPTY: Self = Self { calls: 0, total_100ns: 0, max_100ns: 0 }; }

#[derive(Clone, Copy)]
struct PairCounter { key: Option<(u32, u32)>, counter: Counter }

impl PairCounter {
    const EMPTY: Self = Self { key: None, counter: Counter::EMPTY };

    fn observe(&mut self, from_ssn: u32, to_ssn: u32, gap: u64) {
        self.key = Some((from_ssn, to_ssn));
        self.counter.calls = self.counter.calls.saturating_add(1);
        self.counter.total_100ns = self.counter.total_100ns.saturating_add(gap);
        self.counter.max_100ns = self.counter.max_100ns.max(gap);
    }
}

#[derive(Clone, Copy)]
struct Row {
    owner: Option<SpanOwner>,
    active: Option<ActiveSpan>,
    pending: Option<ActiveSpan>,
    last_return: Option<LastReturn>,
    completed: u64,
    retained_pending: u64,
    unresolved_replaced: u64,
    total_gap_100ns: u64,
    longest_gap: Option<LongestGap>,
    unindexed_calls: u64,
    counters: [Counter; SSN_CAP],
    same_ssn_gap_counters: [Counter; SSN_CAP],
    transition_pairs: [PairCounter; PAIR_CAP],
    untracked_transition_gaps: u64,
    untracked_transition_gap_100ns: u64,
}

impl Row {
    const EMPTY: Self = Self {
        owner: None, active: None, pending: None, last_return: None,
        completed: 0, retained_pending: 0, unresolved_replaced: 0,
        total_gap_100ns: 0, longest_gap: None, unindexed_calls: 0,
        counters: [Counter::EMPTY; SSN_CAP],
        same_ssn_gap_counters: [Counter::EMPTY; SSN_CAP],
        transition_pairs: [PairCounter::EMPTY; PAIR_CAP],
        untracked_transition_gaps: 0, untracked_transition_gap_100ns: 0,
    };

    fn snapshot<const TOP: usize>(&self, owner: SpanOwner, now: u64) -> SpanSnapshot<TOP> {
        let (top, distinct) = top_counters(&self.counters);
        let (same_ssn_gaps, _) = top_counters(&self.same_ssn_gap_counters);
        let (top_transition_pairs, tracked_pairs) = top_transition_pairs(&self.transition_pairs);
        SpanSnapshot {
            owner, completed: self.completed, retained_pending: self.retained_pending,
            unresolved_replaced: self.unresolved_replaced,
            total_gap_100ns: self.total_gap_100ns,
            max_gap_100ns: self.longest_gap.map_or(0, LongestGap::duration_100ns),
            longest_gap: self.longest_gap,
            last_return_age_100ns: self.last_return.map(|last| now.saturating_sub(last.at_100ns)),
            active: self.active.map(|span| SpanSample { ssn: span.ssn,
                age_100ns: now.saturating_sub(span.at_100ns) }),
            pending: self.pending.map(|span| SpanSample { ssn: span.ssn,
                age_100ns: now.saturating_sub(span.at_100ns) }),
            top, same_ssn_gaps, top_transition_pairs,
            overflow_transition_pairs: tracked_pairs.saturating_sub(TOP as u64),
            untracked_transition_gaps: self.untracked_transition_gaps,
            untracked_transition_gap_100ns: self.untracked_transition_gap_100ns,
            overflow_ssns: distinct.saturating_sub(TOP as u64),
            unindexed_calls: self.unindexed_calls,
        }
    }

    fn observe_transition_pair(&mut self, from_ssn: u32, to_ssn: u32, gap: u64) {
        if let Some(pair) = self.transition_pairs.iter_mut()
            .find(|pair| pair.key == Some((from_ssn, to_ssn))) {
            pair.observe(from_ssn, to_ssn, gap);
        } else if let Some(pair) = self.transition_pairs.iter_mut()
            .find(|pair| pair.key.is_none()) {
            pair.observe(from_ssn, to_ssn, gap);
        } else {
            self.untracked_transition_gaps = self.untracked_transition_gaps.saturating_add(1);
            self.untracked_transition_gap_100ns =
                self.untracked_transition_gap_100ns.saturating_add(gap);
        }
    }
}

fn top_counters<const TOP: usize>(counters: &[Counter; SSN_CAP])
    -> ([Option<SsnTotal>; TOP], u64) {
    let mut top = [None; TOP];
    let mut distinct = 0u64;
    for (ssn, counter) in counters.iter().enumerate() {
        if counter.calls == 0 { continue; }
        distinct += 1;
        let item = SsnTotal { ssn: ssn as u32, calls: counter.calls,
            total_100ns: counter.total_100ns, max_100ns: counter.max_100ns };
        let Some(position) = top.iter().position(|slot: &Option<SsnTotal>| slot.is_none_or(|prior|
            (item.total_100ns, item.calls, core::cmp::Reverse(item.ssn))
                > (prior.total_100ns, prior.calls, core::cmp::Reverse(prior.ssn))))
            else { continue; };
        for index in (position + 1..TOP).rev() { top[index] = top[index - 1]; }
        top[position] = Some(item);
    }
    (top, distinct)
}

fn top_transition_pairs<const TOP: usize>(pairs: &[PairCounter; PAIR_CAP])
    -> ([Option<TransitionPairTotal>; TOP], u64) {
    let mut top = [None; TOP];
    let mut distinct = 0u64;
    for pair in pairs {
        let Some((from_ssn, to_ssn)) = pair.key else { continue; };
        distinct += 1;
        let item = TransitionPairTotal {
            from_ssn, to_ssn, calls: pair.counter.calls,
            total_100ns: pair.counter.total_100ns,
            max_100ns: pair.counter.max_100ns,
        };
        let Some(position) = top.iter().position(|slot: &Option<TransitionPairTotal>|
            slot.is_none_or(|prior| (item.total_100ns, item.calls,
                core::cmp::Reverse((item.from_ssn, item.to_ssn)))
                > (prior.total_100ns, prior.calls,
                    core::cmp::Reverse((prior.from_ssn, prior.to_ssn)))))
            else { continue; };
        for index in (position + 1..TOP).rev() { top[index] = top[index - 1]; }
        top[position] = Some(item);
    }
    (top, distinct)
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
        if let Some(last) = row.last_return.take() {
            let gap = now.saturating_sub(last.at_100ns);
            row.total_gap_100ns = row.total_gap_100ns.saturating_add(gap);
            row.observe_transition_pair(last.ssn, ssn, gap);
            if row.longest_gap.is_none_or(|prior| gap > prior.duration_100ns()) {
                row.longest_gap = Some(LongestGap {
                    owner, from_ssn: last.ssn, from_status: last.status, to_ssn: ssn,
                    from_at_100ns: last.at_100ns, to_at_100ns: now,
                });
            }
            if last.ssn == ssn {
                if let Some(counter) = row.same_ssn_gap_counters.get_mut(ssn as usize) {
                    counter.calls = counter.calls.saturating_add(1);
                    counter.total_100ns = counter.total_100ns.saturating_add(gap);
                    counter.max_100ns = counter.max_100ns.max(gap);
                }
            }
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
            row.last_return = None;
            return true;
        }
        let elapsed = now.saturating_sub(active.at_100ns);
        row.completed = row.completed.saturating_add(1);
        row.last_return = Some(LastReturn { ssn, status, at_100ns: now });
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
        assert_eq!(ledger.snapshot(newer, 10_100).unwrap().longest_gap, None);
        assert_eq!(ledger.snapshot(A, 10_100), None);
        let other_thread = SpanOwner { thread_id: 568, thread_generation: 2, ..newer };
        assert!(ledger.activate(other_thread));
        assert!(ledger.begin(other_thread, 191, 20_000));
        assert_eq!(ledger.snapshot(other_thread, 20_000).unwrap().total_gap_100ns, 0);
        assert_eq!(ledger.snapshot(other_thread, 20_000).unwrap().longest_gap, None);
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

    #[test]
    fn consecutive_same_ssn_gaps_exclude_other_calls_and_pending_returns() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));
        for (ssn, start, status) in [
            (148, 100, 0), (148, 200, 0), (39, 400, 0),
            (148, 600, 0), (148, 900, 0x103), (148, 1_200, 0),
            (148, 1_400, 0),
        ] {
            assert!(ledger.begin(A, ssn, start));
            assert!(ledger.return_from_dispatch(A, ssn, status, start + 10));
        }
        let snapshot = ledger.snapshot(A, 1_500).unwrap();
        assert_eq!(snapshot.same_ssn_gaps[0].map(|item| item.ssn), Some(148));
        assert_eq!(snapshot.same_ssn_gaps[0].map(|item| item.calls), Some(3));
        assert_eq!(snapshot.same_ssn_gaps[0].map(|item| item.total_100ns), Some(570));
        assert_eq!(snapshot.same_ssn_gaps[0].map(|item| item.max_100ns), Some(290));
    }

    #[test]
    fn longest_completed_return_to_next_entry_gap_keeps_exact_context() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));
        let status = 0xC000_0034u32;
        assert!(ledger.begin(A, 191, 1_000_000));
        assert!(ledger.return_from_dispatch(A, 191, status, 1_000_100));
        assert!(ledger.begin(A, 149, 1_250_100)); // 250,000 ticks after a completed return.
        assert!(ledger.return_from_dispatch(A, 149, STATUS_PENDING, 1_250_200));
        assert!(ledger.begin(A, 148, 1_900_000)); // Pending is not a terminal return/gap.
        assert!(ledger.return_from_dispatch(A, 148, 0, 1_900_100));
        assert!(ledger.begin(A, 39, 1_900_200)); // A shorter gap cannot replace the maximum.

        let snapshot = ledger.snapshot(A, 1_900_200).unwrap();
        assert_eq!(snapshot.owner, A);
        assert_eq!(snapshot.max_gap_100ns, 250_000);
        assert_eq!(snapshot.retained_pending, 1);
        assert_eq!(snapshot.unresolved_replaced, 1);
        let gap = LongestGap { owner: A, from_ssn: 191, from_status: status,
            to_ssn: 149, from_at_100ns: 1_000_100, to_at_100ns: 1_250_100 };
        assert_eq!(snapshot.longest_gap, Some(gap));
        assert_eq!(gap.duration_100ns(), snapshot.max_gap_100ns);
    }

    #[test]
    fn transition_pairs_use_only_nonpending_returns_from_the_exact_owner() {
        let mut ledger = InstallerSyscallSpans::<2, 2>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, 700, 100));
        assert!(ledger.return_from_dispatch(A, 700, 0xC000_0034, 110));
        assert!(ledger.begin(A, 701, 210));
        assert!(ledger.return_from_dispatch(A, 701, STATUS_PENDING, 220));
        assert!(ledger.begin(A, 702, 1_220));
        assert!(ledger.return_from_dispatch(A, 702, 0, 1_230));
        assert!(ledger.begin(A, 700, 1_430));
        let snapshot = ledger.snapshot(A, 1_430).unwrap();
        assert_eq!(snapshot.top_transition_pairs[0], Some(TransitionPairTotal {
            from_ssn: 702, to_ssn: 700, calls: 1,
            total_100ns: 200, max_100ns: 200,
        }));
        assert_eq!(snapshot.top_transition_pairs[1], Some(TransitionPairTotal {
            from_ssn: 700, to_ssn: 701, calls: 1,
            total_100ns: 100, max_100ns: 100,
        }));
        assert_eq!(snapshot.total_gap_100ns, 300);

        let newer = SpanOwner { process_generation: A.process_generation + 1, ..A };
        assert!(ledger.activate(newer));
        assert!(!ledger.begin(A, 701, 2_000));
        assert_eq!(ledger.snapshot(A, 2_000), None);
        assert!(ledger.begin(newer, 701, 2_100));
        assert!(ledger.return_from_dispatch(newer, 701, 0, 2_110));
        assert!(ledger.begin(newer, 702, 2_160));
        let snapshot = ledger.snapshot(newer, 2_160).unwrap();
        assert_eq!(snapshot.top_transition_pairs[0], Some(TransitionPairTotal {
            from_ssn: 701, to_ssn: 702, calls: 1,
            total_100ns: 50, max_100ns: 50,
        }));
        assert_eq!(snapshot.top_transition_pairs[1], None);

        let recycled = SpanOwner { thread_generation: newer.thread_generation + 1, ..newer };
        assert!(ledger.activate(recycled));
        assert_eq!(ledger.snapshot(newer, 2_200), None);
        assert_eq!(ledger.snapshot(recycled, 2_200).unwrap().top_transition_pairs[0], None);
    }

    #[test]
    fn transition_pairs_accumulate_rank_and_report_bounded_overflow() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));
        for (ssn, start) in [(900, 100), (901, 210), (900, 300),
            (901, 530), (900, 600), (901, 840)] {
            assert!(ledger.begin(A, ssn, start));
            assert!(ledger.return_from_dispatch(A, ssn, 0, start + 10));
        }
        let snapshot = ledger.snapshot(A, 850).unwrap();
        assert_eq!(snapshot.top_transition_pairs[0], Some(TransitionPairTotal {
            from_ssn: 900, to_ssn: 901, calls: 3,
            total_100ns: 550, max_100ns: 230,
        }));
        assert_eq!(snapshot.top_transition_pairs[1], Some(TransitionPairTotal {
            from_ssn: 901, to_ssn: 900, calls: 2,
            total_100ns: 80 + 60, max_100ns: 80,
        }));
        assert_eq!(snapshot.overflow_transition_pairs, 0);
        assert_eq!(snapshot.untracked_transition_gaps, 0);

        let mut bounded = InstallerSyscallSpans::<1, 2>::new();
        assert!(bounded.activate(A));
        for i in 0..(PAIR_CAP + 2) {
            let start = 10 + i as u64 * 10;
            let ssn = 1_000 + i as u32;
            assert!(bounded.begin(A, ssn, start));
            assert!(bounded.return_from_dispatch(A, ssn, 0, start + 1));
        }
        let snapshot = bounded.snapshot(A, 10_000).unwrap();
        assert_eq!(snapshot.top_transition_pairs[0].unwrap().from_ssn, 1_000);
        assert_eq!(snapshot.top_transition_pairs[1].unwrap().from_ssn, 1_001);
        assert_eq!(snapshot.overflow_transition_pairs, (PAIR_CAP - 2) as u64);
        assert_eq!(snapshot.untracked_transition_gaps, 1);
        assert_eq!(snapshot.untracked_transition_gap_100ns, 9);
        assert_eq!(snapshot.total_gap_100ns, (PAIR_CAP as u64 + 1) * 9);
    }
}
