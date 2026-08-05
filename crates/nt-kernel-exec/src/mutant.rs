//! Mutant dispatcher object state.
//!
//! NT mutants are waitable, owner-tracked dispatcher objects. This store keeps the
//! executive-facing state keyed by the object-manager identity; callers supply the
//! current thread id when waiting or releasing.

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MutantError {
    NotFound,
    NotOwned,
}

pub fn map_mutant_access(mut access: u32) -> u32 {
    const MUTANT_QUERY_STATE: u32 = 0x0001;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const MUTANT_ALL_ACCESS: u32 = 0x001F_0001;

    if access & 0x8000_0000 != 0 {
        access |= 0x0002_0000 | MUTANT_QUERY_STATE;
    }
    if access & 0x2000_0000 != 0 {
        access |= 0x0002_0000 | SYNCHRONIZE;
    }
    if access & (0x1000_0000 | 0x0200_0000) != 0 {
        access |= MUTANT_ALL_ACCESS;
    }
    access & !(0xF000_0000 | 0x0200_0000)
}

struct Mutant {
    identity: u64,
    owner_thread: u64,
    recursion: u32,
    abandoned: bool,
}

#[derive(Default)]
pub struct MutantStore {
    mutants: Vec<Mutant>,
}

impl MutantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            mutants: Vec::with_capacity(capacity),
        }
    }

    pub fn initialize(&mut self, identity: u64, initial_owner: Option<u64>) {
        let (owner_thread, recursion) = match initial_owner.filter(|tid| *tid != 0) {
            Some(tid) => (tid, 1),
            None => (0, 0),
        };
        if let Some(mutant) = self
            .mutants
            .iter_mut()
            .find(|mutant| mutant.identity == identity)
        {
            mutant.owner_thread = owner_thread;
            mutant.recursion = recursion;
            mutant.abandoned = false;
            return;
        }
        self.mutants.push(Mutant {
            identity,
            owner_thread,
            recursion,
            abandoned: false,
        });
    }

    pub fn contains(&self, identity: u64) -> bool {
        self.mutants
            .iter()
            .any(|mutant| mutant.identity == identity)
    }

    pub fn ready_for(&self, identity: u64, thread: u64) -> bool {
        self.mutants
            .iter()
            .find(|mutant| mutant.identity == identity)
            .is_some_and(|mutant| mutant.owner_thread == 0 || mutant.owner_thread == thread)
    }

    pub fn acquire(&mut self, identity: u64, thread: u64) -> Option<bool> {
        let mutant = self
            .mutants
            .iter_mut()
            .find(|mutant| mutant.identity == identity)?;
        if mutant.owner_thread != 0 && mutant.owner_thread != thread {
            return Some(false);
        }
        mutant.owner_thread = thread;
        mutant.recursion = mutant.recursion.saturating_add(1).max(1);
        Some(true)
    }

    pub fn release(&mut self, identity: u64, thread: u64) -> Result<i32, MutantError> {
        let mutant = self
            .mutants
            .iter_mut()
            .find(|mutant| mutant.identity == identity)
            .ok_or(MutantError::NotFound)?;
        if mutant.owner_thread == 0 || mutant.owner_thread != thread {
            return Err(MutantError::NotOwned);
        }
        let previous = 0;
        mutant.recursion = mutant.recursion.saturating_sub(1);
        if mutant.recursion == 0 {
            mutant.owner_thread = 0;
        }
        Ok(previous)
    }

    pub fn abandon_thread(&mut self, thread: u64) -> usize {
        if thread == 0 {
            return 0;
        }
        let mut abandoned = 0usize;
        for mutant in &mut self.mutants {
            if mutant.owner_thread == thread {
                mutant.owner_thread = 0;
                mutant.recursion = 0;
                mutant.abandoned = true;
                abandoned += 1;
            }
        }
        abandoned
    }

    pub fn remove(&mut self, identity: u64) -> bool {
        let Some(index) = self
            .mutants
            .iter()
            .position(|mutant| mutant.identity == identity)
        else {
            return false;
        };
        self.mutants.remove(index);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unowned_mutant_is_acquired_by_waiter() {
        let mut store = MutantStore::new();
        store.initialize(7, None);
        assert!(store.ready_for(7, 10));
        assert_eq!(store.acquire(7, 10), Some(true));
        assert!(!store.ready_for(7, 11));
        assert!(store.ready_for(7, 10));
    }

    #[test]
    fn release_requires_the_owner_and_signals_object() {
        let mut store = MutantStore::new();
        store.initialize(8, Some(12));
        assert_eq!(store.release(8, 13), Err(MutantError::NotOwned));
        assert_eq!(store.release(8, 12), Ok(0));
        assert!(store.ready_for(8, 13));
    }

    #[test]
    fn recursive_owner_release_keeps_object_unsignaled_until_final_release() {
        let mut store = MutantStore::new();
        store.initialize(9, Some(21));
        assert_eq!(store.acquire(9, 21), Some(true));
        assert_eq!(store.release(9, 21), Ok(0));
        assert!(!store.ready_for(9, 22));
        assert_eq!(store.release(9, 21), Ok(0));
        assert!(store.ready_for(9, 22));
    }

    #[test]
    fn abandoning_owner_thread_signals_all_owned_mutants() {
        let mut store = MutantStore::new();
        store.initialize(10, Some(44));
        store.initialize(11, Some(44));
        store.initialize(12, Some(45));
        assert_eq!(store.abandon_thread(44), 2);
        assert!(store.ready_for(10, 46));
        assert!(store.ready_for(11, 46));
        assert!(!store.ready_for(12, 46));
        assert_eq!(store.abandon_thread(44), 0);
    }

    #[test]
    fn generic_access_maps_to_native_rights() {
        assert_eq!(map_mutant_access(0x8000_0000) & 1, 1);
        assert_eq!(map_mutant_access(0x2000_0000) & 0x0010_0000, 0x0010_0000);
        assert_eq!(map_mutant_access(0x1000_0000), 0x001F_0001);
    }
}
