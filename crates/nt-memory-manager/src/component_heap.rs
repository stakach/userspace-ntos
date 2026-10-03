//! Reserved component heap geometry, exact worker admission, and mapping effect ownership.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeapReservation {
    base: u64,
    initial_frames: u64,
    reserved_frames: u64,
    writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapFaultError { OutsideReservation, Protection }

impl HeapReservation {
    pub fn new(base: u64, initial_frames: u64, reserved_frames: u64, writable: bool) -> Option<Self> {
        if base == 0 || base & 0xfff != 0 || initial_frames == 0
            || initial_frames > reserved_frames { return None; }
        base.checked_add(reserved_frames.checked_mul(0x1000)?)?;
        Some(Self { base, initial_frames, reserved_frames, writable })
    }

    pub const fn initial_frames(self) -> u64 { self.initial_frames }
    pub const fn reserved_frames(self) -> u64 { self.reserved_frames }

    pub fn fault_page(self, address: u64, fault_status: u64) -> Result<u64, HeapFaultError> {
        let offset = address.checked_sub(self.base).ok_or(HeapFaultError::OutsideReservation)?;
        let index = offset / 0x1000;
        if index >= self.reserved_frames { return Err(HeapFaultError::OutsideReservation); }
        // Only ordinary non-present data reads/writes may commit heap pages.
        if fault_status & !6 != 0 || (fault_status & 2 != 0 && !self.writable) {
            return Err(HeapFaultError::Protection);
        }
        Ok(index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapPageState { Uncommitted, Entered, Mapped, Indeterminate }

impl HeapPageState {
    /// Another admitted worker may have queued a non-present fault before this page committed.
    pub const fn acknowledge_queued_fault(self) -> bool { matches!(self, Self::Mapped) }
    pub fn begin(&mut self) -> bool {
        if *self != Self::Uncommitted { return false; }
        *self = Self::Entered;
        true
    }

    pub fn complete(&mut self, mapped: bool) {
        assert_eq!(*self, Self::Entered, "mapping completion owns an entered effect");
        *self = if mapped { Self::Mapped } else { Self::Indeterminate };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapBindingError { WrongOwner, Retired, NoCapacity }

struct HeapWorker<Worker> { identity: Worker, retired: bool }

/// The native adapter supplies full authenticated physical identities, not numeric badges.
pub struct HeapOwnerLedger<Owner, Worker> {
    owner: Owner,
    vspace: u64,
    workers: Vec<HeapWorker<Worker>>,
    retired: bool,
}

impl<Owner: Copy + Eq, Worker: Copy + Eq> HeapOwnerLedger<Owner, Worker> {
    pub const fn new(owner: Owner, vspace: u64) -> Self {
        Self { owner, vspace, workers: Vec::new(), retired: false }
    }

    pub fn bind_worker(&mut self, owner: Owner, worker: Worker, vspace: u64) -> Result<(), HeapBindingError> {
        if self.retired { return Err(HeapBindingError::Retired); }
        if owner != self.owner || vspace == 0 || vspace != self.vspace {
            return Err(HeapBindingError::WrongOwner);
        }
        if let Some(row) = self.workers.iter().find(|row| row.identity == worker) {
            return if row.retired { Err(HeapBindingError::Retired) } else { Ok(()) };
        }
        self.workers.try_reserve(1).map_err(|_| HeapBindingError::NoCapacity)?;
        self.workers.push(HeapWorker { identity: worker, retired: false });
        Ok(())
    }

    pub fn authorize(&self, owner: Owner, worker: Worker, vspace: u64) -> bool {
        !self.retired && owner == self.owner && vspace == self.vspace && vspace != 0
            && self.workers.iter().any(|row| row.identity == worker && !row.retired)
    }

    pub fn retire_worker(&mut self, owner: Owner, worker: Worker) -> bool {
        if owner != self.owner { return false; }
        let Some(row) = self.workers.iter_mut().find(|row| row.identity == worker && !row.retired) else { return false; };
        row.retired = true;
        true
    }

    pub fn has_workers(&self) -> bool { self.workers.iter().any(|row| !row.retired) }
    pub fn retire_owner(&mut self) { self.retired = true; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_heap_reserves_without_committing_and_checks_exact_fault_permissions() {
        let heap = HeapReservation::new(0x1e00_0000, 128, 16384, true).unwrap();
        assert_eq!(heap.initial_frames(), 128);
        assert_eq!(heap.reserved_frames(), 16384);
        assert_eq!(heap.fault_page(0x1e08_0001, 0), Ok(128));
        assert_eq!(heap.fault_page(0x1e08_0001, 2), Ok(128));
        assert!(heap.fault_page(0x1dff_ffff, 0).is_err());
        assert!(heap.fault_page(0x2200_0000, 0).is_err());
        assert!(heap.fault_page(0x1e08_0000, 1).is_err());
        assert!(heap.fault_page(0x1e08_0000, 16).is_err());
        let readonly = HeapReservation::new(0x1e00_0000, 128, 16384, false).unwrap();
        assert!(readonly.fault_page(0x1e08_0000, 2).is_err());
        assert_eq!(readonly.fault_page(0x1e08_0000, 0), Ok(128));
        assert!(HeapReservation::new(1, 128, 16384, true).is_none());
        assert!(HeapReservation::new(0x1e00_0000, 129, 128, true).is_none());
        assert!(HeapReservation::new(u64::MAX & !0xfff, 1, 2, true).is_none());
    }

    #[test]
    fn component_heap_mapping_effects_are_owned_before_entry_and_never_replayed() {
        let mut page = HeapPageState::Uncommitted;
        assert!(page.begin());
        assert_eq!(page, HeapPageState::Entered);
        assert!(!page.begin());
        page.complete(false);
        assert_eq!(page, HeapPageState::Indeterminate);
        assert!(!page.begin());
        let mut mapped = HeapPageState::Uncommitted;
        assert!(mapped.begin());
        mapped.complete(true);
        assert_eq!(mapped, HeapPageState::Mapped);
        assert!(!mapped.begin());
        assert!(mapped.acknowledge_queued_fault());
        assert!(!page.acknowledge_queued_fault());
        assert!(!HeapPageState::Entered.acknowledge_queued_fault());
    }

    #[test]
    fn component_heap_worker_admission_matches_owner_and_worker_incarnations() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Owner { domain: u64, generation: u64 }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Worker { executor: u64, generation: u64 }
        let owner = Owner { domain: 7, generation: 11 };
        let stale_owner = Owner { generation: 10, ..owner };
        let primary = Worker { executor: 45, generation: 11 };
        let worker = Worker { executor: 46, generation: 11 };
        let stale_worker = Worker { generation: 10, ..worker };
        let mut ledger = HeapOwnerLedger::new(owner, 0x9000);
        assert!(ledger.bind_worker(owner, primary, 0x9000).is_ok());
        assert!(ledger.bind_worker(owner, worker, 0x9000).is_ok());
        assert!(ledger.bind_worker(owner, worker, 0x9000).is_ok());
        assert!(ledger.bind_worker(stale_owner, stale_worker, 0x9000).is_err());
        assert!(ledger.bind_worker(owner, stale_worker, 0xa000).is_err());
        assert!(ledger.authorize(owner, primary, 0x9000));
        assert!(ledger.authorize(owner, worker, 0x9000));
        assert!(!ledger.authorize(stale_owner, worker, 0x9000));
        assert!(!ledger.authorize(owner, stale_worker, 0x9000));
        assert!(!ledger.authorize(owner, worker, 0xa000));
        assert!(!ledger.retire_worker(stale_owner, worker));
        assert!(ledger.retire_worker(owner, worker));
        assert!(!ledger.authorize(owner, worker, 0x9000));
        assert_eq!(ledger.bind_worker(owner, worker, 0x9000), Err(HeapBindingError::Retired));
        let fresh_worker = Worker { generation: 12, ..worker };
        assert!(ledger.bind_worker(owner, fresh_worker, 0x9000).is_ok());
        assert!(ledger.authorize(owner, fresh_worker, 0x9000));
        assert!(ledger.authorize(owner, primary, 0x9000));
        ledger.retire_owner();
        assert!(!ledger.authorize(owner, primary, 0x9000));
        assert!(ledger.bind_worker(owner, worker, 0x9000).is_err());
    }

    #[test]
    fn component_heap_wrong_owner_cannot_enter_mapping_or_reset_uncertain_effects() {
        let mut ledger = HeapOwnerLedger::new((7u64, 11u64), 0x9000);
        ledger.bind_worker((7, 11), (45u64, 11u64), 0x9000).unwrap();
        let mut page = HeapPageState::Uncommitted;
        if ledger.authorize((7, 10), (45, 11), 0x9000) { assert!(page.begin()); }
        assert_eq!(page, HeapPageState::Uncommitted);
        assert!(ledger.authorize((7, 11), (45, 11), 0x9000));
        assert!(page.begin());
        page.complete(false);
        ledger.retire_worker((7, 11), (45, 11));
        ledger.bind_worker((7, 11), (45, 12), 0x9000).unwrap();
        assert!(!ledger.authorize((7, 11), (45, 11), 0x9000));
        assert!(ledger.authorize((7, 11), (45, 12), 0x9000));
        assert!(!page.begin(), "a new worker cannot replay the old worker's uncertain map");
    }
}
