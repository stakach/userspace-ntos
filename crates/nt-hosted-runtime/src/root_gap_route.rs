//! Bounded File route evidence for one exact installer Close-to-Unmap gap.
//!
//! All calls are accounted before any sparse serial sampling. A captured route is attributed
//! only while the same process generation still owns the dispatch; missing and reused owners
//! remain explicit buckets. This ledger observes execution and never owns a File or Reply.

use crate::SpanOwner;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GapIoKind { Read, Write }

impl GapIoKind {
    const fn index(self) -> usize { match self { Self::Read => 0, Self::Write => 1 } }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GapIoDisposition { Completed, PendingAsync, PendingPark, Failed(u32) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapFileRoute { pub file_id: u64, pub device_id: u64 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapIoObservation {
    pub kind: GapIoKind,
    pub process_index: usize,
    pub captured_generation: Option<u64>,
    pub current_generation: Option<u64>,
    pub handle: u64,
    pub route: Option<GapFileRoute>,
    pub disposition: GapIoDisposition,
    pub requested_bytes: Option<u64>,
    pub completed_bytes: Option<u64>,
    pub dispatch_ticks: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapRouteKey {
    pub kind: GapIoKind,
    pub process_index: usize,
    pub process_generation: u64,
    pub handle: u64,
    pub file_id: u64,
    pub device_id: u64,
    pub disposition: GapIoDisposition,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GapRouteStats {
    pub calls: u64,
    pub dispatch_ticks: u64,
    pub requested_bytes: u64,
    pub known_requests: u64,
    pub completed_bytes: u64,
    pub known_completions: u64,
}

impl GapRouteStats {
    fn add(&mut self, observation: GapIoObservation) {
        self.calls = self.calls.saturating_add(1);
        self.dispatch_ticks = self.dispatch_ticks.saturating_add(observation.dispatch_ticks);
        if let Some(bytes) = observation.requested_bytes {
            self.requested_bytes = self.requested_bytes.saturating_add(bytes);
            self.known_requests = self.known_requests.saturating_add(1);
        }
        if observation.disposition == GapIoDisposition::Completed {
            if let Some(bytes) = observation.completed_bytes.filter(|bytes|
                observation.requested_bytes.is_some_and(|requested| *bytes <= requested)) {
                self.completed_bytes = self.completed_bytes.saturating_add(bytes);
                self.known_completions = self.known_completions.saturating_add(1);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapRouteEntry { pub key: GapRouteKey, pub stats: GapRouteStats }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapRouteSnapshot<const ROUTES: usize> {
    pub entries: [Option<GapRouteEntry>; ROUTES],
    pub total: [GapRouteStats; 2],
    pub unknown_owner: [GapRouteStats; 2],
    pub changed_generation: [GapRouteStats; 2],
    pub unknown_route: [GapRouteStats; 2],
    pub capacity_overflow: [GapRouteStats; 2],
}

impl<const ROUTES: usize> GapRouteSnapshot<ROUTES> {
    const fn empty() -> Self {
        Self { entries: [None; ROUTES], total: [GapRouteStats::new(); 2],
            unknown_owner: [GapRouteStats::new(); 2],
            changed_generation: [GapRouteStats::new(); 2],
            unknown_route: [GapRouteStats::new(); 2],
            capacity_overflow: [GapRouteStats::new(); 2] }
    }

    /// No call may vanish from the named routes plus explicit unclassified buckets.
    pub fn reconciles(&self, kind: GapIoKind) -> bool {
        let index = kind.index();
        let named = self.entries.iter().flatten().filter(|entry| entry.key.kind == kind)
            .try_fold(0u64, |count, entry| count.checked_add(entry.stats.calls));
        named.and_then(|count| count.checked_add(self.unknown_owner[index].calls))
            .and_then(|count| count.checked_add(self.changed_generation[index].calls))
            .and_then(|count| count.checked_add(self.unknown_route[index].calls))
            .and_then(|count| count.checked_add(self.capacity_overflow[index].calls))
            == Some(self.total[index].calls)
    }
}

impl GapRouteStats {
    const fn new() -> Self {
        Self { calls: 0, dispatch_ticks: 0, requested_bytes: 0, known_requests: 0,
            completed_bytes: 0, known_completions: 0 }
    }
}

#[derive(Clone, Copy)]
struct Row<const ROUTES: usize> {
    owner: SpanOwner,
    return_at_100ns: u64,
    snapshot: GapRouteSnapshot<ROUTES>,
}

/// The native executive assigns these slots only after its matching root-gap row is armed.
/// Every sample and retirement rechecks the owner and exact Close return timestamp.
pub struct RootGapRouteLedger<const ROWS: usize, const ROUTES: usize> {
    rows: [Option<Row<ROUTES>>; ROWS],
}

impl<const ROWS: usize, const ROUTES: usize> RootGapRouteLedger<ROWS, ROUTES> {
    pub const fn new() -> Self { Self { rows: [None; ROWS] } }

    pub fn arm(&mut self, slot: usize, owner: SpanOwner, return_at_100ns: u64) -> bool {
        let Some(row) = self.rows.get_mut(slot) else { return false; };
        // The root-gap ledger reuses a slot for a newer Close by the same owner.
        if row.is_some_and(|existing| existing.owner != owner) { return false; }
        *row = Some(Row { owner, return_at_100ns, snapshot: GapRouteSnapshot::empty() });
        true
    }

    pub fn active(&self) -> bool { self.rows.iter().any(Option::is_some) }

    pub fn record(&mut self, observation: GapIoObservation) {
        for row in self.rows.iter_mut().flatten() {
            row.snapshot.record(observation);
        }
    }

    pub fn sample(&self, slot: usize, owner: SpanOwner,
        return_at_100ns: u64) -> Option<GapRouteSnapshot<ROUTES>> {
        self.rows.get(slot)?.as_ref().filter(|row|
            row.owner == owner && row.return_at_100ns == return_at_100ns)
            .map(|row| row.snapshot)
    }

    pub fn retire(&mut self, slot: usize, owner: SpanOwner, return_at_100ns: u64)
        -> Option<GapRouteSnapshot<ROUTES>> {
        let snapshot = self.sample(slot, owner, return_at_100ns)?;
        self.rows[slot] = None;
        Some(snapshot)
    }

    pub fn retire_owner(&mut self, owner: SpanOwner) {
        for row in &mut self.rows {
            if row.is_some_and(|row| row.owner == owner) { *row = None; }
        }
    }
}

impl<const ROWS: usize, const ROUTES: usize> Default for RootGapRouteLedger<ROWS, ROUTES> {
    fn default() -> Self { Self::new() }
}

impl<const ROUTES: usize> GapRouteSnapshot<ROUTES> {
    fn record(&mut self, observation: GapIoObservation) {
        let index = observation.kind.index();
        self.total[index].add(observation);
        let Some(generation) = observation.captured_generation.filter(|generation| *generation != 0)
            else { self.unknown_owner[index].add(observation); return; };
        if observation.current_generation != Some(generation) {
            self.changed_generation[index].add(observation);
            return;
        }
        let Some(route) = observation.route.filter(|route| route.file_id != 0 && route.device_id != 0)
            else { self.unknown_route[index].add(observation); return; };
        let key = GapRouteKey { kind: observation.kind,
            process_index: observation.process_index, process_generation: generation,
            handle: observation.handle, file_id: route.file_id, device_id: route.device_id,
            disposition: observation.disposition };
        if let Some(entry) = self.entries.iter_mut().flatten().find(|entry| entry.key == key) {
            entry.stats.add(observation);
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) {
            *slot = Some(GapRouteEntry { key, stats: GapRouteStats::new() });
            slot.as_mut().unwrap().stats.add(observation);
        } else {
            self.capacity_overflow[index].add(observation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(process_generation: u64) -> SpanOwner {
        SpanOwner { process_index: 3, process_generation, thread_id: 7,
            thread_generation: 2 }
    }

    fn io(generation: u64, handle: u64, file: u64) -> GapIoObservation {
        GapIoObservation { kind: GapIoKind::Read, process_index: 11,
            captured_generation: Some(generation), current_generation: Some(generation),
            handle, route: Some(GapFileRoute { file_id: file, device_id: 14 }),
            disposition: GapIoDisposition::Completed, requested_bytes: Some(9),
            completed_bytes: Some(5), dispatch_ticks: 40 }
    }

    #[test]
    fn handle_reuse_and_process_reuse_do_not_merge_routes() {
        let mut ledger = RootGapRouteLedger::<1, 4>::new();
        assert!(ledger.arm(0, owner(5), 100));
        ledger.record(io(6, 0x40, 101));
        ledger.record(io(6, 0x40, 102));
        ledger.record(io(7, 0x40, 102));
        let snap = ledger.sample(0, owner(5), 100).unwrap();
        assert_eq!(snap.entries.iter().flatten().count(), 3);
        assert!(snap.reconciles(GapIoKind::Read));
        let mut changed = io(6, 0x40, 101);
        changed.current_generation = Some(7);
        ledger.record(changed);
        let snap = ledger.sample(0, owner(5), 100).unwrap();
        assert_eq!(snap.changed_generation[0].calls, 1);
        assert_eq!(snap.entries.iter().flatten().map(|entry| entry.stats.calls).sum::<u64>(), 3);
        assert!(snap.reconciles(GapIoKind::Read));
    }

    #[test]
    fn missing_routes_and_capacity_overflow_remain_accounted() {
        let mut ledger = RootGapRouteLedger::<1, 1>::new();
        ledger.arm(0, owner(5), 100);
        ledger.record(io(6, 0x40, 101));
        ledger.record(io(6, 0x44, 102));
        let mut unknown = io(6, 0x48, 103);
        unknown.route = None;
        ledger.record(unknown);
        unknown.captured_generation = None;
        ledger.record(unknown);
        let snap = ledger.sample(0, owner(5), 100).unwrap();
        assert_eq!(snap.total[0].calls, 4);
        assert_eq!(snap.capacity_overflow[0].calls, 1);
        assert_eq!(snap.unknown_route[0].calls, 1);
        assert_eq!(snap.unknown_owner[0].calls, 1);
        assert!(snap.reconciles(GapIoKind::Read));
    }

    #[test]
    fn pending_and_completed_information_are_distinct() {
        let mut ledger = RootGapRouteLedger::<1, 4>::new();
        ledger.arm(0, owner(5), 100);
        ledger.record(io(6, 0x40, 101));
        let mut pending = io(6, 0x40, 101);
        pending.disposition = GapIoDisposition::PendingPark;
        pending.completed_bytes = Some(9);
        ledger.record(pending);
        let snap = ledger.sample(0, owner(5), 100).unwrap();
        assert_eq!(snap.entries.iter().flatten().count(), 2);
        assert_eq!(snap.total[0].known_completions, 1);
        assert_eq!(snap.total[0].completed_bytes, 5);
        assert!(snap.reconciles(GapIoKind::Read));
    }

    #[test]
    fn exact_sample_and_retirement_discard_old_calls() {
        let mut ledger = RootGapRouteLedger::<1, 2>::new();
        assert!(ledger.arm(0, owner(5), 100));
        ledger.record(io(6, 0x40, 101));
        assert!(!ledger.arm(0, owner(6), 101));
        assert_eq!(ledger.sample(0, owner(5), 100).unwrap().total[0].calls, 1);
        assert!(ledger.sample(0, owner(6), 100).is_none());
        assert!(ledger.sample(0, owner(5), 101).is_none());
        assert!(ledger.retire(0, owner(5), 101).is_none());
        assert_eq!(ledger.retire(0, owner(5), 100).unwrap().total[0].calls, 1);
        ledger.record(io(6, 0x40, 101));
        assert!(ledger.sample(0, owner(5), 100).is_none());
        ledger.arm(0, owner(5), 200);
        assert_eq!(ledger.sample(0, owner(5), 200).unwrap().total[0].calls, 0);
    }

    #[test]
    fn newer_close_by_same_owner_replaces_the_old_gap() {
        let mut ledger = RootGapRouteLedger::<1, 2>::new();
        assert!(ledger.arm(0, owner(5), 100));
        ledger.record(io(6, 0x40, 101));
        assert!(ledger.arm(0, owner(5), 200));
        assert!(ledger.sample(0, owner(5), 100).is_none());
        assert_eq!(ledger.sample(0, owner(5), 200).unwrap().total[0].calls, 0);
    }

    #[test]
    fn counter_mismatch_or_overflow_refuses_reconciliation() {
        let mut ledger = RootGapRouteLedger::<1, 1>::new();
        ledger.arm(0, owner(5), 100);
        ledger.record(io(6, 0x40, 101));
        let mut snap = ledger.sample(0, owner(5), 100).unwrap();
        snap.total[0].calls = 0;
        assert!(!snap.reconciles(GapIoKind::Read));
        snap.total[0].calls = 1;
        snap.unknown_route[0].calls = u64::MAX;
        assert!(!snap.reconciles(GapIoKind::Read));
    }
}
