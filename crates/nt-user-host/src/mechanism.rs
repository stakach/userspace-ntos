//! Host-side mechanism slots for user processes.
//!
//! `nt-process` owns NT policy objects (EPROCESS/ETHREAD and handles). A seL4 host still needs a
//! small trusted table that maps those PIDs/TIDs to mechanism slots and fault badges. This table is
//! deliberately cap-free and allocation-free so it can be tested outside the executive.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MechanismError {
    SlotOutOfRange,
    SlotOccupied,
    DuplicatePid,
    DuplicateTid,
    DuplicateBadge,
    InvalidIdentity,
    InvalidBadge,
    StaleIdentity,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessMechanism {
    pub pi: usize,
    pub pid: u32,
    pub main_tid: u32,
    pub top_badge: u64,
    pub generation: u64,
}

impl ProcessMechanism {
    pub const fn empty() -> Self {
        Self {
            pi: 0,
            pid: 0,
            main_tid: 0,
            top_badge: 0,
            generation: 0,
        }
    }

    pub const fn is_live(self) -> bool {
        self.pid != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessMechanismTable<const N: usize> {
    slots: [ProcessMechanism; N],
}

impl<const N: usize> Default for ProcessMechanismTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThreadMechanismKind {
    Main,
    Pool { slot: usize },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThreadMechanism {
    pub pi: usize,
    pub tid: u32,
    pub kind: ThreadMechanismKind,
}

impl ThreadMechanism {
    pub const fn empty() -> Self {
        Self {
            pi: 0,
            tid: 0,
            kind: ThreadMechanismKind::Main,
        }
    }

    pub const fn is_live(self) -> bool {
        self.tid != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadMechanismTable<const P: usize, const S: usize> {
    main: [ThreadMechanism; P],
    pool: [[ThreadMechanism; S]; P],
}

impl<const P: usize, const S: usize> Default for ThreadMechanismTable<P, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const P: usize, const S: usize> ThreadMechanismTable<P, S> {
    pub const fn new() -> Self {
        Self {
            main: [ThreadMechanism::empty(); P],
            pool: [[ThreadMechanism::empty(); S]; P],
        }
    }

    pub fn clear(&mut self) {
        for slot in self.main.iter_mut() {
            *slot = ThreadMechanism::empty();
        }
        for slots in self.pool.iter_mut() {
            for slot in slots.iter_mut() {
                *slot = ThreadMechanism::empty();
            }
        }
    }

    pub fn claim_main(&mut self, pi: usize, tid: u32) -> Result<ThreadMechanism, MechanismError> {
        if pi >= P {
            return Err(MechanismError::SlotOutOfRange);
        }
        if tid == 0 {
            return Err(MechanismError::InvalidIdentity);
        }
        if self.main[pi].is_live() {
            return Err(MechanismError::SlotOccupied);
        }
        if self.get_by_tid(tid).is_some() {
            return Err(MechanismError::DuplicateTid);
        }

        let mechanism = ThreadMechanism {
            pi,
            tid,
            kind: ThreadMechanismKind::Main,
        };
        self.main[pi] = mechanism;
        Ok(mechanism)
    }

    pub fn claim_pool(
        &mut self,
        pi: usize,
        slot: usize,
        tid: u32,
    ) -> Result<ThreadMechanism, MechanismError> {
        if pi >= P || slot >= S {
            return Err(MechanismError::SlotOutOfRange);
        }
        if tid == 0 {
            return Err(MechanismError::InvalidIdentity);
        }
        if self.pool[pi][slot].is_live() {
            return Err(MechanismError::SlotOccupied);
        }
        if self.get_by_tid(tid).is_some() {
            return Err(MechanismError::DuplicateTid);
        }

        let mechanism = ThreadMechanism {
            pi,
            tid,
            kind: ThreadMechanismKind::Pool { slot },
        };
        self.pool[pi][slot] = mechanism;
        Ok(mechanism)
    }

    pub fn release_main(&mut self, pi: usize) -> Option<ThreadMechanism> {
        let slot = self.main.get_mut(pi)?;
        if !slot.is_live() {
            return None;
        }
        let previous = *slot;
        *slot = ThreadMechanism::empty();
        Some(previous)
    }

    pub fn release_pool(&mut self, pi: usize, pool_slot: usize) -> Option<ThreadMechanism> {
        let slot = self.pool.get_mut(pi)?.get_mut(pool_slot)?;
        if !slot.is_live() {
            return None;
        }
        let previous = *slot;
        *slot = ThreadMechanism::empty();
        Some(previous)
    }

    pub fn release_tid(&mut self, tid: u32) -> Option<ThreadMechanism> {
        let mechanism = self.get_by_tid(tid)?;
        match mechanism.kind {
            ThreadMechanismKind::Main => self.release_main(mechanism.pi),
            ThreadMechanismKind::Pool { slot } => self.release_pool(mechanism.pi, slot),
        }
    }

    pub fn main_for_pi(&self, pi: usize) -> Option<ThreadMechanism> {
        self.main.get(pi).copied().filter(|slot| slot.is_live())
    }

    pub fn pool_for_slot(&self, pi: usize, pool_slot: usize) -> Option<ThreadMechanism> {
        self.pool
            .get(pi)?
            .get(pool_slot)
            .copied()
            .filter(|slot| slot.is_live())
    }

    pub fn main_tid_for_pi(&self, pi: usize) -> Option<u32> {
        self.main_for_pi(pi).map(|slot| slot.tid)
    }

    pub fn pool_tid_for_slot(&self, pi: usize, pool_slot: usize) -> Option<u32> {
        self.pool_for_slot(pi, pool_slot).map(|slot| slot.tid)
    }

    pub fn get_by_tid(&self, tid: u32) -> Option<ThreadMechanism> {
        (tid != 0).then_some(())?;
        for slot in self.main.iter() {
            if slot.tid == tid {
                return Some(*slot);
            }
        }
        for process in self.pool.iter() {
            for slot in process.iter() {
                if slot.tid == tid {
                    return Some(*slot);
                }
            }
        }
        None
    }

    pub fn pi_for_tid(&self, tid: u32) -> Option<usize> {
        self.get_by_tid(tid).map(|slot| slot.pi)
    }

    pub fn pool_slot_for_tid(&self, tid: u32) -> Option<(usize, usize)> {
        let mechanism = self.get_by_tid(tid)?;
        match mechanism.kind {
            ThreadMechanismKind::Main => None,
            ThreadMechanismKind::Pool { slot } => Some((mechanism.pi, slot)),
        }
    }

    pub fn live_len(&self) -> usize {
        let main = self.main.iter().filter(|slot| slot.is_live()).count();
        let pool = self
            .pool
            .iter()
            .flat_map(|slots| slots.iter())
            .filter(|slot| slot.is_live())
            .count();
        main + pool
    }
}

impl<const N: usize> ProcessMechanismTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [ProcessMechanism::empty(); N],
        }
    }

    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = ProcessMechanism::empty();
        }
    }

    fn validate_identity(
        &self,
        pi: usize,
        pid: u32,
        main_tid: u32,
        top_badge: u64,
        generation: u64,
    ) -> Result<(), MechanismError> {
        if pi >= N {
            return Err(MechanismError::SlotOutOfRange);
        }
        if pid == 0 || main_tid == 0 || generation == 0 {
            return Err(MechanismError::InvalidIdentity);
        }
        if top_badge >= u64::BITS as u64 {
            return Err(MechanismError::InvalidBadge);
        }
        Ok(())
    }

    pub fn claim(
        &mut self,
        pi: usize,
        pid: u32,
        main_tid: u32,
        top_badge: u64,
        generation: u64,
    ) -> Result<ProcessMechanism, MechanismError> {
        self.validate_identity(pi, pid, main_tid, top_badge, generation)?;
        if self.slots[pi].is_live() {
            return Err(MechanismError::SlotOccupied);
        }
        if self.pi_for_pid(pid).is_some() {
            return Err(MechanismError::DuplicatePid);
        }
        if self.pi_for_tid(main_tid).is_some() {
            return Err(MechanismError::DuplicateTid);
        }
        if self.pi_for_badge(top_badge).is_some() {
            return Err(MechanismError::DuplicateBadge);
        }

        let mechanism = ProcessMechanism {
            pi,
            pid,
            main_tid,
            top_badge,
            generation,
        };
        self.slots[pi] = mechanism;
        Ok(mechanism)
    }

    pub fn claim_or_get(
        &mut self,
        pi: usize,
        pid: u32,
        main_tid: u32,
        top_badge: u64,
        generation: u64,
    ) -> Result<ProcessMechanism, MechanismError> {
        self.validate_identity(pi, pid, main_tid, top_badge, generation)?;
        let requested = ProcessMechanism {
            pi,
            pid,
            main_tid,
            top_badge,
            generation,
        };
        if let Some(existing) = self.get(pi) {
            return if existing == requested {
                Ok(existing)
            } else {
                Err(MechanismError::SlotOccupied)
            };
        }
        self.claim(pi, pid, main_tid, top_badge, generation)
    }

    pub fn release_pi(&mut self, pi: usize) -> Option<ProcessMechanism> {
        let slot = self.slots.get_mut(pi)?;
        if !slot.is_live() {
            return None;
        }
        let previous = *slot;
        *slot = ProcessMechanism::empty();
        Some(previous)
    }

    pub fn release_exact(
        &mut self,
        expected: ProcessMechanism,
    ) -> Result<ProcessMechanism, MechanismError> {
        let current = self
            .get(expected.pi)
            .ok_or(MechanismError::InvalidIdentity)?;
        if current != expected {
            return Err(MechanismError::StaleIdentity);
        }
        self.release_pi(expected.pi)
            .ok_or(MechanismError::InvalidIdentity)
    }

    pub fn get(&self, pi: usize) -> Option<ProcessMechanism> {
        self.slots.get(pi).copied().filter(|slot| slot.is_live())
    }

    pub fn pid_for_pi(&self, pi: usize) -> Option<u32> {
        self.get(pi).map(|slot| slot.pid)
    }

    pub fn main_tid_for_pi(&self, pi: usize) -> Option<u32> {
        self.get(pi).map(|slot| slot.main_tid)
    }

    pub fn badge_for_pi(&self, pi: usize) -> Option<u64> {
        self.get(pi).map(|slot| slot.top_badge)
    }

    pub fn pi_for_pid(&self, pid: u32) -> Option<usize> {
        (pid != 0).then_some(())?;
        self.slots
            .iter()
            .find(|slot| slot.pid == pid)
            .map(|slot| slot.pi)
    }

    pub fn pi_for_tid(&self, tid: u32) -> Option<usize> {
        (tid != 0).then_some(())?;
        self.slots
            .iter()
            .find(|slot| slot.main_tid == tid)
            .map(|slot| slot.pi)
    }

    pub fn pi_for_badge(&self, badge: u64) -> Option<usize> {
        self.slots
            .iter()
            .find(|slot| slot.is_live() && slot.top_badge == badge)
            .map(|slot| slot.pi)
    }

    pub fn live_badge_mask(&self) -> u64 {
        self.slots
            .iter()
            .filter(|slot| slot.is_live())
            .fold(0, |mask, slot| mask | (1u64 << slot.top_badge))
    }

    pub fn live_len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_live()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_indexes_by_pid_tid_and_badge() {
        let mut table = ProcessMechanismTable::<4>::new();
        let slot = table.claim(1, 12, 20, 2, 1).unwrap();
        assert_eq!(
            slot,
            ProcessMechanism {
                pi: 1,
                pid: 12,
                main_tid: 20,
                top_badge: 2,
                generation: 1,
            }
        );
        assert_eq!(table.pid_for_pi(1), Some(12));
        assert_eq!(table.main_tid_for_pi(1), Some(20));
        assert_eq!(table.badge_for_pi(1), Some(2));
        assert_eq!(table.pi_for_pid(12), Some(1));
        assert_eq!(table.pi_for_tid(20), Some(1));
        assert_eq!(table.pi_for_badge(2), Some(1));
        assert_eq!(table.live_badge_mask(), 1 << 2);
    }

    #[test]
    fn claim_rejects_collisions() {
        let mut table = ProcessMechanismTable::<4>::new();
        table.claim(1, 12, 20, 2, 1).unwrap();
        assert_eq!(
            table.claim(1, 13, 21, 4, 2),
            Err(MechanismError::SlotOccupied)
        );
        assert_eq!(
            table.claim(2, 12, 21, 4, 2),
            Err(MechanismError::DuplicatePid)
        );
        assert_eq!(
            table.claim(2, 13, 20, 4, 2),
            Err(MechanismError::DuplicateTid)
        );
        assert_eq!(
            table.claim(2, 13, 21, 2, 2),
            Err(MechanismError::DuplicateBadge)
        );
        assert_eq!(
            table.claim(4, 13, 21, 4, 2),
            Err(MechanismError::SlotOutOfRange)
        );
        assert_eq!(
            table.claim(2, 0, 21, 4, 2),
            Err(MechanismError::InvalidIdentity)
        );
        assert_eq!(
            table.claim(2, 13, 21, 64, 2),
            Err(MechanismError::InvalidBadge)
        );
        assert_eq!(
            table.claim(2, 13, 21, 4, 0),
            Err(MechanismError::InvalidIdentity)
        );
    }

    #[test]
    fn claim_or_get_is_idempotent_only_for_exact_identity() {
        let mut table = ProcessMechanismTable::<4>::new();
        let first = table.claim_or_get(1, 12, 20, 2, 1).unwrap();
        assert_eq!(table.claim_or_get(1, 12, 20, 2, 1), Ok(first));
        assert_eq!(
            table.claim_or_get(1, 12, 21, 2, 1),
            Err(MechanismError::SlotOccupied)
        );
        assert_eq!(
            table.claim_or_get(1, 13, 20, 2, 1),
            Err(MechanismError::SlotOccupied)
        );
        assert_eq!(
            table.claim_or_get(1, 12, 20, 3, 1),
            Err(MechanismError::SlotOccupied)
        );
        assert_eq!(
            table.claim_or_get(1, 12, 20, 2, 2),
            Err(MechanismError::SlotOccupied)
        );
    }

    #[test]
    fn release_frees_all_indexes() {
        let mut table = ProcessMechanismTable::<4>::new();
        let old = table.claim(1, 12, 20, 2, 1).unwrap();
        assert_eq!(table.live_len(), 1);
        assert_eq!(table.release_pi(1).unwrap().pid, 12);
        assert_eq!(table.live_len(), 0);
        assert_eq!(table.pi_for_pid(12), None);
        assert_eq!(table.pi_for_tid(20), None);
        assert_eq!(table.pi_for_badge(2), None);
        let replacement = table.claim(1, 14, 22, 2, 2).unwrap();
        assert_eq!(replacement.pid, 14);
        assert_eq!(table.release_exact(old), Err(MechanismError::StaleIdentity));
        assert_eq!(table.get(1), Some(replacement));
        assert_eq!(table.release_exact(replacement), Ok(replacement));
    }

    #[test]
    fn thread_claim_indexes_main_and_pool_slots() {
        let mut table = ThreadMechanismTable::<3, 2>::new();
        assert_eq!(
            table.claim_main(1, 10).unwrap(),
            ThreadMechanism {
                pi: 1,
                tid: 10,
                kind: ThreadMechanismKind::Main
            }
        );
        assert_eq!(
            table.claim_pool(1, 0, 11).unwrap(),
            ThreadMechanism {
                pi: 1,
                tid: 11,
                kind: ThreadMechanismKind::Pool { slot: 0 }
            }
        );
        assert_eq!(table.main_tid_for_pi(1), Some(10));
        assert_eq!(table.pool_tid_for_slot(1, 0), Some(11));
        assert_eq!(table.pi_for_tid(10), Some(1));
        assert_eq!(table.pool_slot_for_tid(11), Some((1, 0)));
        assert_eq!(table.pool_slot_for_tid(10), None);
        assert_eq!(table.live_len(), 2);
    }

    #[test]
    fn thread_claim_rejects_collisions() {
        let mut table = ThreadMechanismTable::<3, 2>::new();
        table.claim_main(1, 10).unwrap();
        table.claim_pool(1, 0, 11).unwrap();
        assert_eq!(table.claim_main(1, 12), Err(MechanismError::SlotOccupied));
        assert_eq!(table.claim_main(2, 10), Err(MechanismError::DuplicateTid));
        assert_eq!(
            table.claim_pool(1, 0, 12),
            Err(MechanismError::SlotOccupied)
        );
        assert_eq!(
            table.claim_pool(1, 1, 11),
            Err(MechanismError::DuplicateTid)
        );
        assert_eq!(
            table.claim_pool(3, 0, 12),
            Err(MechanismError::SlotOutOfRange)
        );
        assert_eq!(
            table.claim_pool(1, 2, 12),
            Err(MechanismError::SlotOutOfRange)
        );
        assert_eq!(
            table.claim_pool(1, 1, 0),
            Err(MechanismError::InvalidIdentity)
        );
    }

    #[test]
    fn thread_release_by_tid_frees_slot() {
        let mut table = ThreadMechanismTable::<3, 2>::new();
        table.claim_main(1, 10).unwrap();
        table.claim_pool(1, 0, 11).unwrap();
        assert_eq!(table.release_tid(11).unwrap().tid, 11);
        assert_eq!(table.pool_tid_for_slot(1, 0), None);
        assert_eq!(table.claim_pool(1, 0, 12).unwrap().tid, 12);
        assert_eq!(table.release_main(1).unwrap().tid, 10);
        assert_eq!(table.main_tid_for_pi(1), None);
        assert_eq!(table.claim_main(1, 13).unwrap().tid, 13);
    }
}
