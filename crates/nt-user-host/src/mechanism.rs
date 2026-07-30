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
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessMechanism {
    pub pi: usize,
    pub pid: u32,
    pub main_tid: u32,
    pub top_badge: u64,
}

impl ProcessMechanism {
    pub const fn empty() -> Self {
        Self {
            pi: 0,
            pid: 0,
            main_tid: 0,
            top_badge: 0,
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

impl<const N: usize> ProcessMechanismTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [ProcessMechanism::empty(); N],
        }
    }

    pub fn claim(
        &mut self,
        pi: usize,
        pid: u32,
        main_tid: u32,
        top_badge: u64,
    ) -> Result<ProcessMechanism, MechanismError> {
        if pi >= N {
            return Err(MechanismError::SlotOutOfRange);
        }
        if pid == 0 || main_tid == 0 {
            return Err(MechanismError::InvalidIdentity);
        }
        if top_badge >= u64::BITS as u64 {
            return Err(MechanismError::InvalidBadge);
        }
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
        };
        self.slots[pi] = mechanism;
        Ok(mechanism)
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
        let slot = table.claim(1, 12, 20, 2).unwrap();
        assert_eq!(
            slot,
            ProcessMechanism {
                pi: 1,
                pid: 12,
                main_tid: 20,
                top_badge: 2
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
        table.claim(1, 12, 20, 2).unwrap();
        assert_eq!(table.claim(1, 13, 21, 4), Err(MechanismError::SlotOccupied));
        assert_eq!(table.claim(2, 12, 21, 4), Err(MechanismError::DuplicatePid));
        assert_eq!(table.claim(2, 13, 20, 4), Err(MechanismError::DuplicateTid));
        assert_eq!(
            table.claim(2, 13, 21, 2),
            Err(MechanismError::DuplicateBadge)
        );
        assert_eq!(
            table.claim(4, 13, 21, 4),
            Err(MechanismError::SlotOutOfRange)
        );
        assert_eq!(
            table.claim(2, 0, 21, 4),
            Err(MechanismError::InvalidIdentity)
        );
        assert_eq!(
            table.claim(2, 13, 21, 64),
            Err(MechanismError::InvalidBadge)
        );
    }

    #[test]
    fn release_frees_all_indexes() {
        let mut table = ProcessMechanismTable::<4>::new();
        table.claim(1, 12, 20, 2).unwrap();
        assert_eq!(table.live_len(), 1);
        assert_eq!(table.release_pi(1).unwrap().pid, 12);
        assert_eq!(table.live_len(), 0);
        assert_eq!(table.pi_for_pid(12), None);
        assert_eq!(table.pi_for_tid(20), None);
        assert_eq!(table.pi_for_badge(2), None);
        assert_eq!(table.claim(1, 14, 22, 2).unwrap().pid, 14);
    }
}
