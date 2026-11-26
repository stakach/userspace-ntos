//! Value-only correlation of an installer Close gap with root-side observations.
//! The native executive owns counters and SC reads; this ledger only checks identity,
//! lifetime and monotonicity before a diagnostic can attribute their deltas.

use crate::{RuntimeSample, SpanOwner};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Row {
    owner: SpanOwner,
    return_at_100ns: u64,
    root: Option<RuntimeSample>,
    sampled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRuntimeDelta {
    Classified { bound_us: u64, donated_us: u64 },
    Unavailable,
    ChangedContext,
    CounterRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootGapObservation {
    pub slot: usize,
    pub owner: SpanOwner,
    pub return_at_100ns: u64,
    pub observed_at_100ns: u64,
    pub root: RootRuntimeDelta,
}

/// Fixed slots parallel the native installer's bounded exact-owner rows. A slot is never
/// authority to read a Reply or to wake a thread; the full owner and return timestamp match.
pub struct RootServiceGapLedger<const N: usize> {
    rows: [Option<Row>; N],
}

/// Bounds even the cheap root-wide baseline reads when short gaps never consume
/// the separate long-gap sample budget.
pub struct RootGapBaselineBudget {
    limit: u64,
    used: u64,
    refused: u64,
}

impl RootGapBaselineBudget {
    pub const fn new(limit: u64) -> Self {
        Self { limit, used: 0, refused: 0 }
    }

    pub fn admit(&mut self) -> bool {
        if self.used == self.limit {
            self.refused = self.refused.saturating_add(1);
            false
        } else {
            self.used += 1;
            true
        }
    }

    pub fn used(&self) -> u64 { self.used }
    pub fn refused(&self) -> u64 { self.refused }
}

impl<const N: usize> RootServiceGapLedger<N> {
    pub const fn new() -> Self { Self { rows: [None; N] } }

    pub fn arm(&mut self, owner: SpanOwner, return_at_100ns: u64,
        root: Option<RuntimeSample>) -> Option<usize> {
        let slot = self.rows.iter().position(|row| row.is_some_and(|row| row.owner == owner))
            .or_else(|| self.rows.iter().position(Option::is_none))?;
        self.rows[slot] = Some(Row { owner, return_at_100ns, root, sampled: false });
        Some(slot)
    }

    pub fn sample(&mut self, owner: SpanOwner, return_at_100ns: u64,
        observed_at_100ns: u64, root: Option<RuntimeSample>) -> Option<RootGapObservation> {
        let (slot, row) = self.exact(owner, return_at_100ns)?;
        if observed_at_100ns < return_at_100ns { return None; }
        self.rows[slot].as_mut()?.sampled = true;
        Some(observation(slot, row, observed_at_100ns, root))
    }

    /// The counter baseline is taken before the native SC read. Attach that independent
    /// read only if the same exact Close is still present after the debug IPC.
    pub fn attach_root_runtime(&mut self, owner: SpanOwner, return_at_100ns: u64,
        root: Option<RuntimeSample>) -> bool {
        let Some((slot, _)) = self.exact(owner, return_at_100ns) else { return false; };
        self.rows[slot].as_mut().unwrap().root = root;
        true
    }

    /// The next same-owner table entry consumes this gap. Only an actual Unmap following a
    /// sampled Close emits a completed interval; other entries discard the old baseline.
    pub fn finish(&mut self, owner: SpanOwner, return_at_100ns: u64,
        observed_at_100ns: u64, is_unmap: bool,
        root: Option<RuntimeSample>) -> Option<RootGapObservation> {
        let (slot, row) = self.exact(owner, return_at_100ns)?;
        self.rows[slot] = None;
        (is_unmap && row.sampled && observed_at_100ns >= return_at_100ns)
            .then(|| observation(slot, row, observed_at_100ns, root))
    }

    pub fn retire(&mut self, owner: SpanOwner) {
        if let Some(slot) = self.rows.iter().position(|row| row.is_some_and(|row| row.owner == owner)) {
            self.rows[slot] = None;
        }
    }

    /// Only a matching exact Close may index the native counter baseline.
    pub fn slot(&self, owner: SpanOwner, return_at_100ns: u64) -> Option<usize> {
        self.exact(owner, return_at_100ns).map(|(slot, _)| slot)
    }

    fn exact(&self, owner: SpanOwner, return_at_100ns: u64) -> Option<(usize, Row)> {
        self.rows.iter().enumerate().find_map(|(slot, row)| row
            .filter(|row| row.owner == owner && row.return_at_100ns == return_at_100ns)
            .map(|row| (slot, row)))
    }
}

impl<const N: usize> Default for RootServiceGapLedger<N> {
    fn default() -> Self { Self::new() }
}

fn observation(slot: usize, row: Row, observed_at_100ns: u64,
    end: Option<RuntimeSample>) -> RootGapObservation {
    let root = match (row.root, end) {
        (Some(start), Some(end)) if start.sched_context != end.sched_context =>
            RootRuntimeDelta::ChangedContext,
        (Some(start), Some(end)) if end.bound_us < start.bound_us
            || end.donated_us < start.donated_us => RootRuntimeDelta::CounterRegression,
        (Some(start), Some(end)) if start.sched_context != 0 =>
            RootRuntimeDelta::Classified { bound_us: end.bound_us - start.bound_us,
                donated_us: end.donated_us - start.donated_us },
        _ => RootRuntimeDelta::Unavailable,
    };
    RootGapObservation { slot, owner: row.owner, return_at_100ns: row.return_at_100ns,
        observed_at_100ns, root }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterDelta {
    pub index: usize,
    pub ticks: u64,
}

/// Rank cumulative counter changes without accepting a wrap/regression as huge work.
/// All counters must be monotonic, including those outside the returned top set.
pub fn top_counter_deltas<const TOP: usize>(before: &[u64], mut current: impl FnMut(usize) -> u64)
    -> Option<[Option<CounterDelta>; TOP]> {
    let mut top = [None; TOP];
    for (index, &start) in before.iter().enumerate() {
        let end = current(index);
        let ticks = end.checked_sub(start)?;
        if ticks == 0 { continue; }
        let entry = CounterDelta { index, ticks };
        for rank in 0..TOP {
            if top[rank].is_none_or(|old: CounterDelta| ticks > old.ticks) {
                for lower in (rank + 1..TOP).rev() { top[lower] = top[lower - 1]; }
                top[rank] = Some(entry);
                break;
            }
        }
    }
    Some(top)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: SpanOwner = SpanOwner { process_index: 14, process_generation: 19,
        thread_id: 540, thread_generation: 1 };
    const NEXT: SpanOwner = SpanOwner { process_generation: 20, ..A };
    const ROOT: RuntimeSample = RuntimeSample { sched_context: 14,
        bound_us: 100, donated_us: 2 };

    #[test]
    fn exact_owner_generation_and_return_are_required() {
        let mut ledger = RootServiceGapLedger::<2>::new();
        assert_eq!(ledger.arm(A, 100, Some(ROOT)), Some(0));
        assert_eq!(ledger.sample(NEXT, 100, 600, Some(ROOT)), None);
        assert_eq!(ledger.sample(A, 101, 600, Some(ROOT)), None);
        assert_eq!(ledger.finish(A, 100, 610, true, Some(ROOT)), None);
        assert_eq!(ledger.arm(A, 700, Some(ROOT)), Some(0));
        let sample = ledger.sample(A, 700, 5_700,
            Some(RuntimeSample { bound_us: 4_100, ..ROOT })).unwrap();
        assert_eq!(sample.root, RootRuntimeDelta::Classified {
            bound_us: 4_000, donated_us: 0 });
        assert_eq!(ledger.finish(A, 700, 6_000, true,
            Some(RuntimeSample { bound_us: 4_200, ..ROOT })).unwrap().root,
            RootRuntimeDelta::Classified { bound_us: 4_100, donated_us: 0 });
        assert_eq!(ledger.sample(A, 700, 6_100, Some(ROOT)), None);
    }

    #[test]
    fn unrelated_entry_and_stale_cap_never_inherit_a_gap() {
        let mut ledger = RootServiceGapLedger::<1>::new();
        assert_eq!(ledger.arm(A, 100, Some(ROOT)), Some(0));
        assert!(ledger.sample(A, 100, 600, Some(ROOT)).is_some());
        assert_eq!(ledger.finish(A, 100, 700, false, Some(ROOT)), None);
        assert_eq!(ledger.arm(NEXT, 800, Some(ROOT)), Some(0));
        assert_eq!(ledger.sample(A, 100, 900, Some(ROOT)), None);
        let changed = RuntimeSample { sched_context: 99, ..ROOT };
        assert_eq!(ledger.sample(NEXT, 800, 900, Some(changed)).unwrap().root,
            RootRuntimeDelta::ChangedContext);
        ledger.retire(NEXT);
        assert_eq!(ledger.finish(NEXT, 800, 1_000, true, Some(ROOT)), None);
    }

    #[test]
    fn top_deltas_reject_regression_and_keep_largest() {
        let after = [11, 5, 3, 9];
        assert_eq!(top_counter_deltas::<2>(&[1, 2, 3, 4], |index| after[index]),
            Some([Some(CounterDelta { index: 0, ticks: 10 }),
                Some(CounterDelta { index: 3, ticks: 5 })]));
        let regressed = [4, 1];
        assert_eq!(top_counter_deltas::<2>(&[1, 2], |index| regressed[index]), None);
    }

    #[test]
    fn short_gaps_cannot_spend_unbounded_baselines() {
        let mut budget = RootGapBaselineBudget::new(2);
        assert!(budget.admit());
        assert!(budget.admit());
        assert!(!budget.admit());
        assert_eq!((budget.used(), budget.refused()), (2, 1));
    }
}
