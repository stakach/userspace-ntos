//! Spin locks (spec §6.2). A `KSPIN_LOCK` is opaque driver storage; the runtime
//! keeps its state in a side table keyed by the driver's lock pointer. On a
//! single-threaded host there is no real spinning — acquiring raises IRQL to
//! `DISPATCH_LEVEL` and releasing restores it. Double-acquire is detected.

use alloc::vec::Vec;

use crate::irql::{IrqlState, DISPATCH_LEVEL};

/// Why a spin-lock operation was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpinError {
    /// The lock is already held (single-threaded → a real deadlock).
    AlreadyHeld,
    /// An `AtDpcLevel` op was attempted below `DISPATCH_LEVEL`.
    NotAtDispatch,
    /// The lock is not held (release/`FromDpcLevel` without acquire).
    NotHeld,
}

struct Lock {
    ptr: u64,
    held: bool,
}

/// The Driver Host's spin-lock table.
#[derive(Default)]
pub struct SpinLockTable {
    locks: Vec<Lock>,
}

impl SpinLockTable {
    pub fn new() -> Self {
        Self { locks: Vec::new() }
    }

    fn slot(&mut self, ptr: u64) -> &mut Lock {
        if let Some(i) = self.locks.iter().position(|l| l.ptr == ptr) {
            return &mut self.locks[i];
        }
        self.locks.push(Lock { ptr, held: false });
        self.locks.last_mut().unwrap()
    }

    /// `KeInitializeSpinLock` — (re)initialise the lock to released.
    pub fn initialize(&mut self, ptr: u64) {
        self.slot(ptr).held = false;
    }

    pub fn is_held(&self, ptr: u64) -> bool {
        self.locks.iter().any(|l| l.ptr == ptr && l.held)
    }

    /// `KeAcquireSpinLock` — raise to `DISPATCH_LEVEL` + take the lock, returning
    /// the old IRQL to restore on release.
    pub fn acquire(&mut self, ptr: u64, irql: &mut IrqlState) -> Result<u8, SpinError> {
        if self.slot(ptr).held {
            return Err(SpinError::AlreadyHeld);
        }
        self.slot(ptr).held = true;
        Ok(irql.raise(DISPATCH_LEVEL))
    }

    /// `KeReleaseSpinLock` — release + restore the IRQL saved by `acquire`.
    pub fn release(
        &mut self,
        ptr: u64,
        irql: &mut IrqlState,
        old_irql: u8,
    ) -> Result<(), SpinError> {
        if !self.slot(ptr).held {
            return Err(SpinError::NotHeld);
        }
        self.slot(ptr).held = false;
        irql.lower(old_irql);
        Ok(())
    }

    /// `KeAcquireSpinLockAtDpcLevel` — already at `DISPATCH_LEVEL`; just take it.
    pub fn acquire_at_dpc(&mut self, ptr: u64, irql: &IrqlState) -> Result<(), SpinError> {
        if irql.current() < DISPATCH_LEVEL {
            return Err(SpinError::NotAtDispatch);
        }
        if self.slot(ptr).held {
            return Err(SpinError::AlreadyHeld);
        }
        self.slot(ptr).held = true;
        Ok(())
    }

    /// `KeReleaseSpinLockFromDpcLevel`.
    pub fn release_from_dpc(&mut self, ptr: u64, irql: &IrqlState) -> Result<(), SpinError> {
        if irql.current() < DISPATCH_LEVEL {
            return Err(SpinError::NotAtDispatch);
        }
        if !self.slot(ptr).held {
            return Err(SpinError::NotHeld);
        }
        self.slot(ptr).held = false;
        Ok(())
    }

    /// `KeTryToAcquireSpinLockAtDpcLevel` — returns `true` if taken.
    pub fn try_acquire_at_dpc(&mut self, ptr: u64, irql: &IrqlState) -> Result<bool, SpinError> {
        if irql.current() < DISPATCH_LEVEL {
            return Err(SpinError::NotAtDispatch);
        }
        if self.slot(ptr).held {
            return Ok(false);
        }
        self.slot(ptr).held = true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::irql::{APC_LEVEL, PASSIVE_LEVEL};

    #[test]
    fn acquire_raises_release_restores() {
        let mut irql = IrqlState::new();
        let mut spin = SpinLockTable::new();
        spin.initialize(0x1000);
        let old = spin.acquire(0x1000, &mut irql).unwrap();
        assert_eq!(old, PASSIVE_LEVEL);
        assert_eq!(irql.current(), DISPATCH_LEVEL);
        assert!(spin.is_held(0x1000));
        spin.release(0x1000, &mut irql, old).unwrap();
        assert_eq!(irql.current(), PASSIVE_LEVEL);
        assert!(!spin.is_held(0x1000));
    }

    #[test]
    fn double_acquire_detected() {
        let mut irql = IrqlState::new();
        let mut spin = SpinLockTable::new();
        spin.acquire(0x1000, &mut irql).unwrap();
        assert_eq!(spin.acquire(0x1000, &mut irql), Err(SpinError::AlreadyHeld));
    }

    #[test]
    fn at_dpc_level_requires_dispatch() {
        let mut irql = IrqlState::new();
        let mut spin = SpinLockTable::new();
        assert_eq!(
            spin.acquire_at_dpc(0x1000, &irql),
            Err(SpinError::NotAtDispatch)
        );
        irql.raise(DISPATCH_LEVEL);
        assert_eq!(spin.acquire_at_dpc(0x1000, &irql), Ok(()));
        assert_eq!(spin.try_acquire_at_dpc(0x1000, &irql), Ok(false)); // already held
        spin.release_from_dpc(0x1000, &irql).unwrap();
        assert_eq!(spin.try_acquire_at_dpc(0x1000, &irql), Ok(true));
    }

    #[test]
    fn release_without_acquire_rejected() {
        let mut irql = IrqlState::new();
        irql.raise(APC_LEVEL);
        let mut spin = SpinLockTable::new();
        assert_eq!(
            spin.release(0x2000, &mut irql, PASSIVE_LEVEL),
            Err(SpinError::NotHeld)
        );
    }
}
