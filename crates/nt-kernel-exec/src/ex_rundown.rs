//! NT `EX_RUNDOWN_REF` one-word admission and drain state.
//!
//! The low bit distinguishes an accepting reference count (increments of two) from a completed
//! rundown or an aligned pointer to a wait block. The native caller owns the wait block and must
//! keep it resident until `finish_wait` has replaced its pointer with the completed value.

use core::sync::atomic::{AtomicUsize, Ordering};

const ACTIVE: usize = 1;
const COUNT_INC: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExRundownRelease {
    Released,
    Pending,
    WakeWaiter,
}

#[repr(transparent)]
pub struct ExRundownRef {
    state: AtomicUsize,
}

#[repr(align(2))]
pub struct ExRundownWaitBlock {
    remaining: AtomicUsize,
}

impl ExRundownWaitBlock {
    pub const fn new() -> Self {
        Self { remaining: AtomicUsize::new(0) }
    }

    pub fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }
}

impl ExRundownRef {
    pub const fn new() -> Self {
        Self { state: AtomicUsize::new(0) }
    }

    /// Reset a descriptor with no outstanding holders or waiter.
    ///
    /// # Safety
    /// The caller must own the descriptor exclusively; resetting a live reference would lose
    /// its holders and possibly strand a waiter.
    pub unsafe fn initialize(&self) {
        self.state.store(0, Ordering::Release);
    }

    pub fn acquire(&self) -> bool {
        let mut value = self.state.load(Ordering::Acquire);
        loop {
            if value & ACTIVE != 0 { return false; }
            let next = value.checked_add(COUNT_INC).expect("EX_RUNDOWN_REF count overflow");
            match self.state.compare_exchange_weak(value, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(actual) => value = actual,
            }
        }
    }

    /// Release one previously acquired reference.
    ///
    /// # Safety
    /// The caller must own one reference. If a waiter was installed, its block must remain live
    /// until this release and the waiting thread's `finish_wait` have completed.
    pub unsafe fn release(&self) -> ExRundownRelease {
        let mut value = self.state.load(Ordering::Acquire);
        loop {
            if value & ACTIVE == 0 {
                assert!(value >= COUNT_INC, "EX_RUNDOWN_REF release without acquire");
                match self.state.compare_exchange_weak(value, value - COUNT_INC, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return ExRundownRelease::Released,
                    Err(actual) => value = actual,
                }
            } else {
                assert_ne!(value, ACTIVE, "EX_RUNDOWN_REF release after completion");
                let waiter = unsafe { &*((value & !ACTIVE) as *const ExRundownWaitBlock) };
                let previous = waiter.remaining.fetch_sub(1, Ordering::AcqRel);
                assert!(previous > 0, "EX_RUNDOWN_REF wait count underflow");
                return if previous == 1 { ExRundownRelease::WakeWaiter } else { ExRundownRelease::Pending };
            }
        }
    }

    /// Close admission and install a stack-resident wait block for current holders.
    /// Returns whether the caller must wait for outstanding holders.
    ///
    /// # Safety
    /// `waiter` must remain at the same address until `finish_wait` returns; only one waiter may
    /// begin rundown, and every outstanding holder must release exactly once.
    pub unsafe fn begin_wait(&self, waiter: &ExRundownWaitBlock) -> bool {
        let tagged = (waiter as *const ExRundownWaitBlock as usize) | ACTIVE;
        assert_eq!(tagged & !ACTIVE, waiter as *const ExRundownWaitBlock as usize);
        let mut value = self.state.load(Ordering::Acquire);
        loop {
            if value == ACTIVE { return false; }
            assert_eq!(value & ACTIVE, 0, "EX_RUNDOWN_REF has an active waiter");
            if value == 0 {
                match self.state.compare_exchange_weak(0, ACTIVE, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return false,
                    Err(actual) => value = actual,
                }
            } else {
                waiter.remaining.store(value / COUNT_INC, Ordering::Release);
                match self.state.compare_exchange_weak(value, tagged, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return true,
                    Err(actual) => value = actual,
                }
            }
        }
    }

    /// Retire the wait-block pointer after its last holder has released.
    ///
    /// # Safety
    /// The caller must be the one that installed `waiter` in `begin_wait`, and the block must
    /// remain alive until this method returns.
    pub unsafe fn finish_wait(&self, waiter: &ExRundownWaitBlock) {
        assert_eq!(waiter.remaining(), 0, "EX_RUNDOWN_REF wait not drained");
        let tagged = (waiter as *const ExRundownWaitBlock as usize) | ACTIVE;
        self.state.compare_exchange(tagged, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .expect("EX_RUNDOWN_REF waiter identity changed");
    }

    /// Reopen a completed rundown reference. A live waiter cannot be reinitialized.
    pub fn reinitialize(&self) -> bool {
        self.state.compare_exchange(ACTIVE, 0, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ACTIVE
    }
}

impl Default for ExRundownRef {
    fn default() -> Self { Self::new() }
}

impl Default for ExRundownWaitBlock {
    fn default() -> Self { Self::new() }
}
