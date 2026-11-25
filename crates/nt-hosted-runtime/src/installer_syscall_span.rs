//! Bounded, value-only observation of exact installer-child native table calls.

const SSN_CAP: usize = 512;
const PAIR_CAP: usize = 128;
const STATUS_PENDING: u32 = 0x103;
const SSN_NT_CLOSE: u32 = 27;
const SSN_NT_UNMAP_VIEW_OF_SECTION: u32 = 277;

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

/// A value-only witness minted at fault admission. The Reply number can be reused; only
/// this exact owner and sequence can complete the observation that admitted it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerFaultTicket {
    owner: SpanOwner,
    reply: u64,
    sequence: u64,
}

impl InstallerFaultTicket {
    pub const fn owner(self) -> SpanOwner { self.owner }
    pub const fn reply(self) -> u64 { self.reply }
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

/// Cumulative, capability-scoped runtime read for one exact hosted thread.
/// The scheduling-context cap is part of the observation identity, not authority to act.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSample {
    pub sched_context: u64,
    pub bound_us: u64,
    pub donated_us: u64,
}

/// Independent reads at one exact table boundary. A failed read of either SC must not
/// discard the other observation; both remain diagnostic and confer no scheduling authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PairedRuntimeSample {
    pub child: Option<RuntimeSample>,
    pub root: Option<RuntimeSample>,
}

impl PairedRuntimeSample {
    fn has_any(self) -> bool { self.child.is_some() || self.root.is_some() }
}

/// Closed Close→Unmap intervals. Runtime and fault totals are separate observations;
/// donated execution may overlap an acknowledged fault and must not be subtracted twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseUnmapRuntimeTotals {
    pub pairs: u64,
    pub classified: u64,
    pub wall_100ns: u64,
    pub fault_100ns: u64,
    pub bound_us: u64,
    pub donated_us: u64,
    pub unclassified_100ns: u64,
    pub failed_read: u64,
    pub changed_context: u64,
    pub counter_regression: u64,
    /// Root SC bound time is a lower bound for root TCB execution: a hosted caller can
    /// donate another SC to the root. It must not be subtracted from child or fault time.
    pub root_classified: u64,
    pub root_bound_us: u64,
    pub root_donated_us: u64,
    pub root_unclassified_100ns: u64,
    pub root_failed_read: u64,
    pub root_changed_context: u64,
    pub root_counter_regression: u64,
}

impl CloseUnmapRuntimeTotals {
    const EMPTY: Self = Self { pairs: 0, classified: 0, wall_100ns: 0,
        fault_100ns: 0, bound_us: 0, donated_us: 0, unclassified_100ns: 0,
        failed_read: 0, changed_context: 0, counter_regression: 0,
        root_classified: 0, root_bound_us: 0, root_donated_us: 0,
        root_unclassified_100ns: 0, root_failed_read: 0,
        root_changed_context: 0, root_counter_regression: 0 };

    fn observe(&mut self, gap: u64, fault: u64,
        returned: PairedRuntimeSample, entered: PairedRuntimeSample) {
        self.pairs = self.pairs.saturating_add(1);
        self.wall_100ns = self.wall_100ns.saturating_add(gap);
        self.fault_100ns = self.fault_100ns.saturating_add(fault);
        let child_classified = match (returned.child, entered.child) {
            (Some(start), Some(end)) if start.sched_context != end.sched_context => {
                self.changed_context = self.changed_context.saturating_add(1);
                false
            }
            (Some(start), Some(end)) if end.bound_us < start.bound_us
                || end.donated_us < start.donated_us => {
                self.counter_regression = self.counter_regression.saturating_add(1);
                false
            }
            (Some(start), Some(end)) if start.sched_context != 0 => {
                self.classified = self.classified.saturating_add(1);
                self.bound_us = self.bound_us.saturating_add(end.bound_us - start.bound_us);
                self.donated_us = self.donated_us.saturating_add(end.donated_us - start.donated_us);
                true
            }
            _ => {
                self.failed_read = self.failed_read.saturating_add(1);
                false
            }
        };
        if !child_classified {
            self.unclassified_100ns = self.unclassified_100ns.saturating_add(gap);
        }
        match (returned.root, entered.root) {
            (Some(start), Some(end)) if start.sched_context != end.sched_context => {
                self.root_changed_context = self.root_changed_context.saturating_add(1);
            }
            (Some(start), Some(end)) if end.bound_us < start.bound_us
                || end.donated_us < start.donated_us => {
                self.root_counter_regression = self.root_counter_regression.saturating_add(1);
            }
            (Some(start), Some(end)) if start.sched_context != 0 => {
                self.root_classified = self.root_classified.saturating_add(1);
                self.root_bound_us = self.root_bound_us.saturating_add(end.bound_us - start.bound_us);
                self.root_donated_us = self.root_donated_us.saturating_add(end.donated_us - start.donated_us);
                return;
            }
            _ => { self.root_failed_read = self.root_failed_read.saturating_add(1); }
        }
        self.root_unclassified_100ns = self.root_unclassified_100ns.saturating_add(gap);
    }
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
    /// Acknowledged, instrumented fault time in closed return-to-next-entry gaps.
    pub completed_fault_gap_100ns: u64,
    /// Closed gap time not covered by an instrumented fault; includes unobserved faults.
    pub residual_gap_100ns: u64,
    /// Faults still awaiting an acknowledged Reply, never counted as completed time.
    pub unresolved_faults: u64,
    /// Diagnostic fault admissions refused without an unused exact witness.
    pub fault_admission_overflow: u64,
    pub max_gap_100ns: u64,
    pub longest_gap: Option<LongestGap>,
    pub close_unmap: CloseUnmapRuntimeTotals,
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
struct CloseReturnRuntime { at_100ns: u64, sample: PairedRuntimeSample }

#[derive(Clone, Copy)]
struct ActiveFault {
    ticket: InstallerFaultTicket,
    entered_at_100ns: u64,
    crossed_next_entry: bool,
}

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
    close_return_runtime: Option<CloseReturnRuntime>,
    close_unmap: CloseUnmapRuntimeTotals,
    active_fault: Option<ActiveFault>,
    completed_fault_open_gap_100ns: u64,
    completed_fault_gap_100ns: u64,
    fault_admission_overflow: u64,
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
        close_return_runtime: None, close_unmap: CloseUnmapRuntimeTotals::EMPTY,
        active_fault: None,
        completed_fault_open_gap_100ns: 0, completed_fault_gap_100ns: 0,
        fault_admission_overflow: 0,
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
            completed_fault_gap_100ns: self.completed_fault_gap_100ns,
            residual_gap_100ns: self.total_gap_100ns.saturating_sub(self.completed_fault_gap_100ns),
            unresolved_faults: u64::from(self.active_fault.is_some()),
            fault_admission_overflow: self.fault_admission_overflow,
            max_gap_100ns: self.longest_gap.map_or(0, LongestGap::duration_100ns),
            longest_gap: self.longest_gap, close_unmap: self.close_unmap,
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
    next_fault_sequence: u64,
}

impl<const N: usize, const TOP: usize> InstallerSyscallSpans<N, TOP> {
    pub const fn new() -> Self {
        Self { rows: [Row::EMPTY; N], activation_overflow: 0, next_fault_sequence: 0 }
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

    /// Admit at most one unresolved fault per exact thread. A full observation never
    /// replaces an uncertain interval or grants authority from a numeric Reply alone.
    pub fn fault_enter(&mut self, owner: SpanOwner, reply: u64,
        now_100ns: u64) -> Option<InstallerFaultTicket> {
        let row = self.rows.iter_mut().find(|row| row.owner == Some(owner))?;
        if reply == 0 || row.active_fault.is_some() {
            row.fault_admission_overflow = row.fault_admission_overflow.saturating_add(1);
            return None;
        }
        let Some(sequence) = self.next_fault_sequence.checked_add(1) else {
            row.fault_admission_overflow = row.fault_admission_overflow.saturating_add(1);
            return None;
        };
        self.next_fault_sequence = sequence;
        let ticket = InstallerFaultTicket { owner, reply, sequence };
        row.active_fault = Some(ActiveFault {
            ticket, entered_at_100ns: now_100ns, crossed_next_entry: false,
        });
        Some(ticket)
    }

    /// Record only an acknowledged completion of the exact admitted fault. Time remains
    /// provisional until the next table entry closes the containing between-call gap.
    pub fn fault_reply_accepted(&mut self, ticket: InstallerFaultTicket,
        now_100ns: u64) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.owner == Some(ticket.owner)) else {
            return false;
        };
        let Some(active) = row.active_fault.filter(|fault| fault.ticket == ticket) else {
            return false;
        };
        if now_100ns < active.entered_at_100ns { return false; }
        if let Some(last) = row.last_return.filter(|_| !active.crossed_next_entry) {
            let overlap_start = active.entered_at_100ns.max(last.at_100ns);
            row.completed_fault_open_gap_100ns = row.completed_fault_open_gap_100ns
                .saturating_add(now_100ns.saturating_sub(overlap_start));
        }
        row.active_fault = None;
        true
    }

    pub fn begin(&mut self, owner: SpanOwner, ssn: u32, now: u64) -> bool {
        self.begin_with_runtime(owner, ssn, now, None)
    }

    /// The runtime sample is optional: a failed observation never changes the wall/fault gap.
    pub fn begin_with_runtime(&mut self, owner: SpanOwner, ssn: u32, now: u64,
        runtime: Option<RuntimeSample>) -> bool {
        self.begin_with_pair_runtime(owner, ssn, now,
            PairedRuntimeSample { child: runtime, root: None })
    }

    pub fn begin_with_pair_runtime(&mut self, owner: SpanOwner, ssn: u32, now: u64,
        runtime: PairedRuntimeSample) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.owner == Some(owner)) else {
            return false;
        };
        if let Some(fault) = row.active_fault.as_mut() {
            fault.crossed_next_entry = true;
        }
        if row.active.is_some() || row.pending.take().is_some() {
            row.unresolved_replaced = row.unresolved_replaced.saturating_add(1);
        }
        if let Some(last) = row.last_return.take() {
            let gap = now.saturating_sub(last.at_100ns);
            let fault = row.completed_fault_open_gap_100ns.min(gap);
            let close_runtime = row.close_return_runtime.take()
                .filter(|observed| observed.at_100ns == last.at_100ns);
            if last.ssn == SSN_NT_CLOSE && ssn == SSN_NT_UNMAP_VIEW_OF_SECTION {
                row.close_unmap.observe(gap, fault,
                    close_runtime.map_or(PairedRuntimeSample::default(), |observed| observed.sample),
                    runtime);
            }
            row.total_gap_100ns = row.total_gap_100ns.saturating_add(gap);
            row.completed_fault_gap_100ns = row.completed_fault_gap_100ns
                .saturating_add(fault);
            row.completed_fault_open_gap_100ns = 0;
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
        row.close_return_runtime = None;
        row.active = Some(ActiveSpan { ssn, at_100ns: now });
        true
    }

    /// A runtime read is needed only at the next Unmap entry after an observed Close.
    pub fn needs_runtime_sample(&self, owner: SpanOwner, ssn: u32) -> bool {
        if ssn != SSN_NT_UNMAP_VIEW_OF_SECTION { return false; }
        self.rows.iter().find(|row| row.owner == Some(owner)).is_some_and(|row| {
            row.last_return.is_some_and(|last| last.ssn == SSN_NT_CLOSE
                && row.close_return_runtime.is_some_and(|observed|
                    observed.at_100ns == last.at_100ns && observed.sample.has_any()))
        })
    }

    /// Attach a read to the exact nonpending Close return that opened this gap.
    pub fn record_close_runtime(&mut self, owner: SpanOwner, at_100ns: u64,
        sample: Option<RuntimeSample>) -> bool {
        self.record_close_pair_runtime(owner, at_100ns,
            PairedRuntimeSample { child: sample, root: None })
    }

    pub fn record_close_pair_runtime(&mut self, owner: SpanOwner, at_100ns: u64,
        sample: PairedRuntimeSample) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.owner == Some(owner)) else {
            return false;
        };
        if !row.last_return.is_some_and(|last| last.ssn == SSN_NT_CLOSE
            && last.status != STATUS_PENDING && last.at_100ns == at_100ns)
            || row.close_return_runtime.is_some() { return false; }
        row.close_return_runtime = Some(CloseReturnRuntime { at_100ns, sample });
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
        row.close_return_runtime = None;
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
    fn close_unmap_runtime_requires_exact_owner_and_scheduling_context() {
        const CLOSE: u32 = 27;
        const UNMAP: u32 = 277;
        let mut ledger = InstallerSyscallSpans::<2, 2>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, CLOSE, 100));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 200));
        assert!(ledger.record_close_runtime(A, 200, Some(RuntimeSample {
            sched_context: 71, bound_us: 10, donated_us: 20,
        })));
        assert!(ledger.needs_runtime_sample(A, UNMAP));
        assert!(ledger.begin_with_runtime(A, UNMAP, 500, Some(RuntimeSample {
            sched_context: 71, bound_us: 110, donated_us: 70,
        })));
        let first = ledger.snapshot(A, 500).unwrap();
        assert_eq!(first.total_gap_100ns, 300);
        assert_eq!(first.close_unmap.wall_100ns, 300);
        assert_eq!(first.close_unmap.classified, 1);
        assert_eq!(first.close_unmap.bound_us, 100);
        assert_eq!(first.close_unmap.donated_us, 50);
        assert_eq!(first.close_unmap.unclassified_100ns, 0);

        assert!(ledger.return_from_dispatch(A, UNMAP, 0, 510));
        assert!(ledger.begin(A, CLOSE, 600));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 610));
        assert!(ledger.record_close_runtime(A, 610, Some(RuntimeSample {
            sched_context: 71, bound_us: 120, donated_us: 75,
        })));
        assert!(ledger.begin_with_runtime(A, UNMAP, 910, Some(RuntimeSample {
            sched_context: 72, bound_us: 200, donated_us: 100,
        })));
        let changed = ledger.snapshot(A, 910).unwrap();
        assert_eq!(changed.close_unmap.wall_100ns, 600);
        assert_eq!(changed.close_unmap.classified, 1);
        assert_eq!(changed.close_unmap.unclassified_100ns, 300);
        assert_eq!(changed.close_unmap.changed_context, 1);
        assert_eq!(changed.close_unmap.bound_us, 100);

        assert!(ledger.return_from_dispatch(A, UNMAP, 0, 920));
        assert!(ledger.begin(A, CLOSE, 930));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 940));
        assert!(ledger.record_close_runtime(A, 940, None));
        assert!(!ledger.needs_runtime_sample(A, UNMAP));
        assert!(ledger.begin_with_runtime(A, UNMAP, 1240, None));
        let failed = ledger.snapshot(A, 1240).unwrap();
        assert_eq!(failed.close_unmap.wall_100ns, 900);
        assert_eq!(failed.close_unmap.unclassified_100ns, 600);
        assert_eq!(failed.close_unmap.failed_read, 1);
        assert_eq!(failed.close_unmap.bound_us, 100);

        assert!(ledger.return_from_dispatch(A, UNMAP, 0, 1250));
        assert!(ledger.begin(A, CLOSE, 1260));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 1270));
        assert!(ledger.record_close_runtime(A, 1270, Some(RuntimeSample {
            sched_context: 71, bound_us: 300, donated_us: 200,
        })));
        assert!(ledger.needs_runtime_sample(A, UNMAP));
        assert!(ledger.begin_with_runtime(A, UNMAP, 1570, None));
        let failed_entry = ledger.snapshot(A, 1570).unwrap();
        assert_eq!(failed_entry.close_unmap.wall_100ns, 1200);
        assert_eq!(failed_entry.close_unmap.unclassified_100ns, 900);
        assert_eq!(failed_entry.close_unmap.failed_read, 2);
        assert_eq!(failed_entry.close_unmap.bound_us, 100);

        let next = SpanOwner { process_generation: A.process_generation + 1, ..A };
        assert!(ledger.activate(next));
        assert!(!ledger.needs_runtime_sample(next, UNMAP));
        assert_eq!(ledger.snapshot(next, 1300).unwrap().close_unmap.wall_100ns, 0);
    }

    #[test]
    fn close_unmap_root_and_child_reads_classify_independently() {
        const CLOSE: u32 = 27;
        const UNMAP: u32 = 277;
        let sample = |sc, bound_us, donated_us| RuntimeSample {
            sched_context: sc, bound_us, donated_us,
        };
        let mut ledger = InstallerSyscallSpans::<1, 1>::new();
        assert!(ledger.activate(A));

        assert!(ledger.begin(A, CLOSE, 100));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 200));
        assert!(ledger.record_close_pair_runtime(A, 200, PairedRuntimeSample {
            child: None, root: Some(sample(14, 1_000, 100)),
        }));
        assert!(ledger.needs_runtime_sample(A, UNMAP));
        assert!(ledger.begin_with_pair_runtime(A, UNMAP, 500, PairedRuntimeSample {
            child: None, root: Some(sample(14, 1_250, 130)),
        }));
        let first = ledger.snapshot(A, 500).unwrap().close_unmap;
        assert_eq!((first.classified, first.failed_read, first.unclassified_100ns), (0, 1, 300));
        assert_eq!((first.root_classified, first.root_bound_us, first.root_donated_us),
            (1, 250, 30));
        assert_eq!(first.root_unclassified_100ns, 0);

        assert!(ledger.return_from_dispatch(A, UNMAP, 0, 510));
        assert!(ledger.begin(A, CLOSE, 600));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 610));
        assert!(ledger.record_close_pair_runtime(A, 610, PairedRuntimeSample {
            child: Some(sample(71, 10, 20)), root: None,
        }));
        assert!(ledger.begin_with_pair_runtime(A, UNMAP, 910, PairedRuntimeSample {
            child: Some(sample(71, 110, 70)), root: Some(sample(14, 1_500, 140)),
        }));
        let second = ledger.snapshot(A, 910).unwrap().close_unmap;
        assert_eq!((second.classified, second.bound_us, second.donated_us), (1, 100, 50));
        assert_eq!((second.root_classified, second.root_failed_read,
            second.root_unclassified_100ns), (1, 1, 300));

        assert!(ledger.return_from_dispatch(A, UNMAP, 0, 920));
        assert!(ledger.begin(A, CLOSE, 930));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 940));
        assert!(ledger.record_close_pair_runtime(A, 940, PairedRuntimeSample {
            child: Some(sample(71, 200, 100)), root: Some(sample(14, 1_600, 200)),
        }));
        assert!(ledger.begin_with_pair_runtime(A, UNMAP, 1240, PairedRuntimeSample {
            child: Some(sample(72, 300, 150)), root: Some(sample(14, 1_590, 210)),
        }));
        let third = ledger.snapshot(A, 1240).unwrap().close_unmap;
        assert_eq!((third.pairs, third.wall_100ns, third.changed_context), (3, 900, 1));
        assert_eq!((third.root_classified, third.root_counter_regression,
            third.root_unclassified_100ns), (1, 1, 600));

        let next = SpanOwner { process_generation: A.process_generation + 1, ..A };
        assert!(ledger.activate(next));
        assert_eq!(ledger.snapshot(next, 1240).unwrap().close_unmap.pairs, 0);
    }

    #[test]
    fn pending_close_opens_no_gap_and_unacknowledged_fault_adds_no_fault_time() {
        const CLOSE: u32 = 27;
        const UNMAP: u32 = 277;
        let mut ledger = InstallerSyscallSpans::<1, 1>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, CLOSE, 100));
        assert!(ledger.return_from_dispatch(A, CLOSE, STATUS_PENDING, 200));
        assert!(!ledger.record_close_runtime(A, 200, Some(RuntimeSample {
            sched_context: 71, bound_us: 1, donated_us: 1,
        })));
        assert!(!ledger.needs_runtime_sample(A, UNMAP));
        assert!(ledger.begin_with_runtime(A, UNMAP, 500, None));
        assert_eq!(ledger.snapshot(A, 500).unwrap().close_unmap.wall_100ns, 0);

        assert!(ledger.return_from_dispatch(A, UNMAP, 0, 510));
        assert!(ledger.begin(A, CLOSE, 600));
        assert!(ledger.return_from_dispatch(A, CLOSE, 0, 610));
        assert!(ledger.record_close_runtime(A, 610, Some(RuntimeSample {
            sched_context: 71, bound_us: 10, donated_us: 10,
        })));
        let ticket = ledger.fault_enter(A, 83, 700).unwrap();
        assert!(ledger.begin_with_runtime(A, UNMAP, 900, Some(RuntimeSample {
            sched_context: 71, bound_us: 20, donated_us: 20,
        })));
        let snapshot = ledger.snapshot(A, 900).unwrap();
        assert_eq!(snapshot.close_unmap.wall_100ns, 290);
        assert_eq!(snapshot.close_unmap.fault_100ns, 0);
        assert_eq!(snapshot.unresolved_faults, 1);
        assert_eq!(snapshot.close_unmap.classified, 1);
        assert!(!ledger.fault_reply_accepted(ticket, 650));
    }

    #[test]
    fn close_unmap_runtime_does_not_replace_acknowledged_fault_or_wall_time() {
        let mut ledger = InstallerSyscallSpans::<1, 1>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, SSN_NT_CLOSE, 100));
        assert!(ledger.return_from_dispatch(A, SSN_NT_CLOSE, 0, 200));
        assert!(ledger.record_close_runtime(A, 200, Some(RuntimeSample {
            sched_context: 71, bound_us: 10, donated_us: 20,
        })));
        let ticket = ledger.fault_enter(A, 83, 250).unwrap();
        assert!(ledger.fault_reply_accepted(ticket, 300));
        assert!(ledger.begin_with_runtime(A, SSN_NT_UNMAP_VIEW_OF_SECTION, 500,
            Some(RuntimeSample { sched_context: 71, bound_us: 100, donated_us: 80 })));
        let snapshot = ledger.snapshot(A, 500).unwrap();
        assert_eq!(snapshot.total_gap_100ns, 300);
        assert_eq!(snapshot.completed_fault_gap_100ns, 50);
        assert_eq!(snapshot.residual_gap_100ns, 250);
        assert_eq!(snapshot.close_unmap.wall_100ns, 300);
        assert_eq!(snapshot.close_unmap.fault_100ns, 50);
        assert_eq!(snapshot.close_unmap.bound_us, 90);
        assert_eq!(snapshot.close_unmap.donated_us, 60);
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

    #[test]
    fn accepted_fault_time_is_intersected_with_the_exact_between_syscall_gap() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));

        assert!(ledger.begin(A, 113, 100)); // NtMapViewOfSection.
        assert!(ledger.return_from_dispatch(A, 113, 0, 200));
        let fault = ledger.fault_enter(A, 71, 250).unwrap();
        assert!(ledger.fault_reply_accepted(fault, 350));
        assert!(ledger.begin(A, 277, 500)); // NtUnmapViewOfSection.

        let snapshot = ledger.snapshot(A, 500).unwrap();
        assert_eq!(snapshot.top[0].map(|total| total.ssn), Some(113));
        assert_eq!(snapshot.top[0].map(|total| total.total_100ns), Some(100));
        assert_eq!(snapshot.total_gap_100ns, 300);
        assert_eq!(snapshot.completed_fault_gap_100ns, 100);
        assert_eq!(snapshot.residual_gap_100ns, 200);
        assert_eq!(snapshot.unresolved_faults, 0);
        // The 100 ticks of native dispatch and 300 ticks of between-call time partition
        // the 400-tick observation. The fault is a subset of the gap, not extra time.
        assert_eq!(
            snapshot.top[0].unwrap().total_100ns
                + snapshot.completed_fault_gap_100ns + snapshot.residual_gap_100ns,
            400,
        );
    }

    #[test]
    fn fault_ticket_rejects_pending_and_reused_reply_across_exact_lifetimes() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, 27, 100)); // NtClose.
        assert!(ledger.return_from_dispatch(A, 27, 0, 150));

        let first = ledger.fault_enter(A, 71, 200).unwrap();
        let pending = ledger.snapshot(A, 250).unwrap();
        assert_eq!(pending.unresolved_faults, 1);
        assert_eq!(pending.completed_fault_gap_100ns, 0);

        assert!(ledger.fault_reply_accepted(first, 260));
        let reused = ledger.fault_enter(A, 71, 300).unwrap();
        assert_ne!(first, reused); // The numeric Reply may be recycled for this same thread.
        assert!(!ledger.fault_reply_accepted(first, 350));
        assert_eq!(ledger.snapshot(A, 350).unwrap().unresolved_faults, 1);
        assert!(ledger.fault_reply_accepted(reused, 360));
        assert!(!ledger.fault_reply_accepted(reused, 370));
        assert!(ledger.begin(A, 277, 400));
        let snapshot = ledger.snapshot(A, 400).unwrap();
        assert_eq!(snapshot.total_gap_100ns, 250);
        assert_eq!(snapshot.completed_fault_gap_100ns, 120);
        assert_eq!(snapshot.residual_gap_100ns, 130);
        assert_eq!(snapshot.unresolved_faults, 0);

        assert!(ledger.return_from_dispatch(A, 277, 0, 410));
        let stale = ledger.fault_enter(A, 71, 420).unwrap();
        let newer = SpanOwner { process_generation: A.process_generation + 1, ..A };
        assert!(ledger.activate(newer));
        assert!(ledger.begin(newer, 27, 1_000));
        assert!(ledger.return_from_dispatch(newer, 27, 0, 1_050));
        let current = ledger.fault_enter(newer, 71, 1_100).unwrap();
        assert!(!ledger.fault_reply_accepted(stale, 1_150));
        assert_eq!(ledger.snapshot(newer, 1_150).unwrap().unresolved_faults, 1);
        assert!(ledger.fault_reply_accepted(current, 1_200));
        assert!(ledger.begin(newer, 277, 1_300));
        let snapshot = ledger.snapshot(newer, 1_300).unwrap();
        assert_eq!(snapshot.completed_fault_gap_100ns, 100);
        assert_eq!(snapshot.residual_gap_100ns, 150);
        assert_eq!(ledger.snapshot(A, 1_300), None);
    }

    #[test]
    fn unresolved_fault_crossing_the_next_entry_never_charges_a_later_gap() {
        let mut ledger = InstallerSyscallSpans::<1, 2>::new();
        assert!(ledger.activate(A));
        assert!(ledger.begin(A, 27, 100));
        assert!(ledger.return_from_dispatch(A, 27, 0, 150));
        let fault = ledger.fault_enter(A, 71, 200).unwrap();
        assert!(ledger.fault_enter(A, 72, 250).is_none());
        assert_eq!(ledger.snapshot(A, 250).unwrap().fault_admission_overflow, 1);

        assert!(ledger.begin(A, 277, 300)); // Original Reply is still unresolved.
        let pending = ledger.snapshot(A, 300).unwrap();
        assert_eq!(pending.total_gap_100ns, 150);
        assert_eq!(pending.completed_fault_gap_100ns, 0);
        assert_eq!(pending.residual_gap_100ns, 150);
        assert_eq!(pending.unresolved_faults, 1);

        assert!(ledger.return_from_dispatch(A, 277, 0, 320));
        assert!(ledger.fault_reply_accepted(fault, 350));
        assert!(ledger.begin(A, 113, 400));
        let closed = ledger.snapshot(A, 400).unwrap();
        assert_eq!(closed.total_gap_100ns, 230);
        assert_eq!(closed.completed_fault_gap_100ns, 0);
        assert_eq!(closed.residual_gap_100ns, 230);
        assert_eq!(closed.unresolved_faults, 0);
    }
}
