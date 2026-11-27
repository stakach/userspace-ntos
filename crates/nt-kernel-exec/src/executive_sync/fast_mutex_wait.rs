//! Contended `FAST_MUTEX` acquisition as a real wait.
//!
//! The native `FAST_MUTEX` body stays the owner record (`Owner`, `Count`, `Contention`). When
//! the mutex is held by another thread, the caller queues with its own wait Event and parks
//! through the host dispatcher. Release hands ownership to the oldest waiter before the host
//! signals that waiter's Event, so the mutex is never observed free between the two threads.
//! `Count` projects NT's encoding: 1 free, 0 owned, `-n` owned with `n` threads still waiting.

use alloc::vec::Vec;

use super::{
    acquire_fast_mutex_unsafe, fast_mutex_layout, AcquireResult, ExecutiveSyncError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastMutexWaitTicket(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastMutexWaitAdmission {
    Acquired,
    Queued(FastMutexWaitTicket),
}

struct FastMutexWaiter {
    ticket: FastMutexWaitTicket,
    thread: u64,
    event: u64,
    granted: bool,
}

struct FastMutexQueue {
    address: u64,
    /// FIFO order; a granted waiter owns the mutex until it completes its wait.
    waiters: Vec<FastMutexWaiter>,
}

impl FastMutexQueue {
    fn waiting(&self) -> usize {
        self.waiters.iter().filter(|waiter| !waiter.granted).count()
    }
}

/// Wait queues for the fast mutexes that currently have contention. An uncontended mutex
/// has no entry; its native body alone records the owner.
#[derive(Default)]
pub struct FastMutexWaitStore {
    queues: Vec<FastMutexQueue>,
    next_ticket: u64,
}

unsafe fn read_count(mutex: *mut u8) -> i32 {
    core::ptr::read_unaligned(mutex.add(fast_mutex_layout::COUNT) as *const i32)
}

unsafe fn read_owner(mutex: *mut u8) -> u64 {
    core::ptr::read_unaligned(mutex.add(fast_mutex_layout::OWNER) as *const u64)
}

unsafe fn write_state(mutex: *mut u8, owner: u64, count: i32) {
    core::ptr::write_unaligned(mutex.add(fast_mutex_layout::OWNER) as *mut u64, owner);
    core::ptr::write_unaligned(mutex.add(fast_mutex_layout::COUNT) as *mut i32, count);
}

fn validate(mutex: *mut u8, thread: u64) -> Result<(), ExecutiveSyncError> {
    if mutex.is_null() || (mutex as usize & 7) != 0 {
        return Err(ExecutiveSyncError::InvalidAddress);
    }
    if thread == 0 {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    Ok(())
}

impl FastMutexWaitStore {
    pub const fn new() -> Self {
        Self { queues: Vec::new(), next_ticket: 1 }
    }

    fn index_of(&self, mutex: *mut u8) -> Option<usize> {
        self.queues.iter().position(|queue| queue.address == mutex as u64)
    }

    /// Acquire now, or queue `event` behind the current owner. The caller publishes `event`
    /// first and makes no provider call between this check and its wait. Recursive acquire,
    /// including a second wait by a thread already queued, is refused.
    ///
    /// # Safety
    /// `mutex` must contain initialized native `FAST_MUTEX` storage.
    pub unsafe fn begin_wait(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        event: u64,
    ) -> Result<FastMutexWaitAdmission, ExecutiveSyncError> {
        validate(mutex, thread)?;
        if event == 0 {
            return Err(ExecutiveSyncError::InvalidAddress);
        }
        let index = self.index_of(mutex);
        if index.is_some_and(|index| self.queues[index].waiters.iter().any(|waiter| waiter.thread == thread)) {
            return Err(ExecutiveSyncError::FastMutexRecursiveAcquire);
        }
        if acquire_fast_mutex_unsafe(mutex, thread)? == AcquireResult::Acquired {
            return Ok(FastMutexWaitAdmission::Acquired);
        }
        let waiting = index.map_or(0, |index| self.queues[index].waiting());
        let next_waiting = waiting.checked_add(1)
            .and_then(|count| i32::try_from(count).ok())
            .ok_or(ExecutiveSyncError::AllocationFailed)?;
        let ticket = FastMutexWaitTicket(self.next_ticket.max(1));
        let next_ticket = ticket.0.checked_add(1).ok_or(ExecutiveSyncError::AllocationFailed)?;
        let index = match index {
            Some(index) => {
                self.queues[index].waiters.try_reserve(1)
                    .map_err(|_| ExecutiveSyncError::AllocationFailed)?;
                index
            }
            None => {
                let mut queue = FastMutexQueue { address: mutex as u64, waiters: Vec::new() };
                queue.waiters.try_reserve(1)
                    .map_err(|_| ExecutiveSyncError::AllocationFailed)?;
                self.queues.try_reserve(1).map_err(|_| ExecutiveSyncError::AllocationFailed)?;
                self.queues.push(queue);
                self.queues.len() - 1
            }
        };
        let queue = &mut self.queues[index];
        queue.waiters.push(FastMutexWaiter { ticket, thread, event, granted: false });
        self.next_ticket = next_ticket;
        let contention_field = mutex.add(fast_mutex_layout::CONTENTION) as *mut u32;
        let contention = core::ptr::read_unaligned(contention_field).saturating_add(1);
        core::ptr::write_unaligned(contention_field, contention);
        write_state(mutex, read_owner(mutex), -next_waiting);
        Ok(FastMutexWaitAdmission::Queued(ticket))
    }

    /// Release `thread`'s ownership. With a waiter queued, ownership moves to the oldest one
    /// and its Event is returned; the caller signals it after dropping its store borrow.
    ///
    /// # Safety
    /// `mutex` must contain initialized native `FAST_MUTEX` storage.
    pub unsafe fn release(
        &mut self,
        mutex: *mut u8,
        thread: u64,
    ) -> Result<Option<u64>, ExecutiveSyncError> {
        validate(mutex, thread)?;
        let index = self.index_of(mutex);
        let waiting = index.map_or(0, |index| self.queues[index].waiting());
        let waiting = i32::try_from(waiting).map_err(|_| ExecutiveSyncError::FastMutexCorrupt)?;
        if read_owner(mutex) != thread || read_count(mutex) != -waiting {
            return Err(ExecutiveSyncError::NotOwned);
        }
        if index.is_some_and(|index| self.queues[index].waiters.iter().any(|waiter| {
            waiter.thread == thread && waiter.granted
        })) {
            return Err(ExecutiveSyncError::BlockingWaitRequired);
        }
        let Some(index) = index else {
            write_state(mutex, 0, 1);
            return Ok(None);
        };
        let queue = &mut self.queues[index];
        let Some(next) = queue.waiters.iter_mut().find(|waiter| !waiter.granted) else {
            // Only a granted waiter remains, and it is not this thread: a corrupt release.
            return Err(ExecutiveSyncError::FastMutexCorrupt);
        };
        next.granted = true;
        let (owner, event) = (next.thread, next.event);
        write_state(mutex, owner, -(waiting - 1));
        Ok(Some(event))
    }

    /// The exact waiter resumed after its grant: it owns the mutex and leaves the queue.
    ///
    /// # Safety
    /// `mutex` must contain initialized native `FAST_MUTEX` storage.
    pub unsafe fn complete_wait(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        ticket: FastMutexWaitTicket,
    ) -> Result<(), ExecutiveSyncError> {
        validate(mutex, thread)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::InvalidOwner)?;
        let queue = &mut self.queues[index];
        let position = queue.waiters.iter()
            .position(|waiter| waiter.ticket == ticket && waiter.thread == thread)
            .ok_or(ExecutiveSyncError::InvalidOwner)?;
        if !queue.waiters[position].granted || read_owner(mutex) != thread {
            return Err(ExecutiveSyncError::BlockingWaitRequired);
        }
        queue.waiters.remove(position);
        if queue.waiters.is_empty() {
            self.queues.remove(index);
        }
        Ok(())
    }

    /// Withdraw a wait whose dispatcher result was a validated failure. A granted ticket
    /// already owns the mutex, so withdrawing it releases (and may hand off) ownership.
    ///
    /// # Safety
    /// `mutex` must contain initialized native `FAST_MUTEX` storage.
    pub unsafe fn cancel_wait(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        ticket: FastMutexWaitTicket,
    ) -> Result<Option<u64>, ExecutiveSyncError> {
        validate(mutex, thread)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::InvalidOwner)?;
        let queue = &mut self.queues[index];
        let position = queue.waiters.iter()
            .position(|waiter| waiter.ticket == ticket && waiter.thread == thread)
            .ok_or(ExecutiveSyncError::InvalidOwner)?;
        let granted = queue.waiters[position].granted;
        if granted {
            let waiting = i32::try_from(queue.waiting())
                .map_err(|_| ExecutiveSyncError::FastMutexCorrupt)?;
            if read_owner(mutex) != thread || read_count(mutex) != -waiting {
                return Err(ExecutiveSyncError::NotOwned);
            }
            // Ownership is real: complete the wait, then release it like any owner.
            self.complete_wait(mutex, thread, ticket)?;
            return self.release(mutex, thread);
        }
        queue.waiters.remove(position);
        let waiting = queue.waiting() as i32;
        if queue.waiters.is_empty() {
            self.queues.remove(index);
        }
        write_state(mutex, read_owner(mutex), -waiting);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executive_sync::initialize_fast_mutex;

    #[repr(align(8))]
    struct Mutex([u8; fast_mutex_layout::SIZE_OF]);

    fn mutex() -> Mutex {
        let mut mutex = Mutex([0xaa; fast_mutex_layout::SIZE_OF]);
        unsafe { initialize_fast_mutex(mutex.0.as_mut_ptr()).unwrap() };
        mutex
    }

    fn state(mutex: &mut Mutex) -> (u64, i32) {
        unsafe { (read_owner(mutex.0.as_mut_ptr()), read_count(mutex.0.as_mut_ptr())) }
    }

    const A: u64 = 0x4080_0009_c000;
    const B: u64 = 0x4080_000a_1000;
    const C: u64 = 0x4080_000a_2000;

    // Boot 44648768192: win32k thread B acquired a fast mutex that thread A held across a
    // yield, and the executive panicked with BlockingWaitRequired. Contention is a wait.
    #[test]
    fn a_contended_acquire_waits_and_release_hands_ownership_to_the_waiter() {
        let mut m = mutex();
        let mut store = FastMutexWaitStore::new();
        let p = m.0.as_mut_ptr();
        unsafe {
            assert_eq!(store.begin_wait(p, A, 0xe1), Ok(FastMutexWaitAdmission::Acquired));
            let FastMutexWaitAdmission::Queued(ticket) = store.begin_wait(p, B, 0xe2).unwrap() else {
                panic!("B waits behind A");
            };
            assert_eq!(state(&mut m), (A, -1));
            assert_eq!(read_count(p), -1);
            assert_eq!(store.complete_wait(p, B, ticket), Err(ExecutiveSyncError::BlockingWaitRequired),
                "B does not own the mutex before A releases it");
            assert_eq!(store.release(p, A), Ok(Some(0xe2)), "A's release signals exactly B");
            assert_eq!(state(&mut m), (B, 0), "ownership moved without the mutex going free");
            assert_eq!(store.complete_wait(p, B, ticket), Ok(()));
            assert_eq!(store.release(p, B), Ok(None));
            assert_eq!(state(&mut m), (0, 1));
            assert_eq!(core::ptr::read_unaligned(p.add(fast_mutex_layout::CONTENTION) as *const u32), 1);
        }
    }

    #[test]
    fn waiters_are_granted_in_arrival_order() {
        let mut m = mutex();
        let mut store = FastMutexWaitStore::new();
        let p = m.0.as_mut_ptr();
        unsafe {
            store.begin_wait(p, A, 0xe1).unwrap();
            let FastMutexWaitAdmission::Queued(b) = store.begin_wait(p, B, 0xe2).unwrap() else { panic!() };
            let FastMutexWaitAdmission::Queued(c) = store.begin_wait(p, C, 0xe3).unwrap() else { panic!() };
            assert_eq!(state(&mut m), (A, -2));
            assert_eq!(store.release(p, A), Ok(Some(0xe2)));
            assert_eq!(state(&mut m), (B, -1));
            store.complete_wait(p, B, b).unwrap();
            assert_eq!(store.release(p, B), Ok(Some(0xe3)));
            store.complete_wait(p, C, c).unwrap();
            assert_eq!(store.release(p, C), Ok(None));
            assert_eq!(state(&mut m), (0, 1));
        }
    }

    #[test]
    fn recursion_and_foreign_release_stay_contract_violations() {
        let mut m = mutex();
        let mut store = FastMutexWaitStore::new();
        let p = m.0.as_mut_ptr();
        unsafe {
            store.begin_wait(p, A, 0xe1).unwrap();
            assert_eq!(store.begin_wait(p, A, 0xe1), Err(ExecutiveSyncError::FastMutexRecursiveAcquire));
            store.begin_wait(p, B, 0xe2).unwrap();
            assert_eq!(store.begin_wait(p, B, 0xe2), Err(ExecutiveSyncError::FastMutexRecursiveAcquire),
                "a queued thread cannot wait twice");
            assert_eq!(store.release(p, B), Err(ExecutiveSyncError::NotOwned), "a waiter is not the owner");
            assert_eq!(store.release(p, C), Err(ExecutiveSyncError::NotOwned));
            assert_eq!(state(&mut m), (A, -1), "refusals change nothing");
        }
    }

    #[test]
    fn a_cancelled_wait_leaves_the_queue_and_a_granted_one_passes_ownership_on() {
        let mut m = mutex();
        let mut store = FastMutexWaitStore::new();
        let p = m.0.as_mut_ptr();
        unsafe {
            store.begin_wait(p, A, 0xe1).unwrap();
            let FastMutexWaitAdmission::Queued(b) = store.begin_wait(p, B, 0xe2).unwrap() else { panic!() };
            let FastMutexWaitAdmission::Queued(c) = store.begin_wait(p, C, 0xe3).unwrap() else { panic!() };
            assert_eq!(store.cancel_wait(p, C, c), Ok(None));
            assert_eq!(state(&mut m), (A, -1));
            assert_eq!(store.release(p, A), Ok(Some(0xe2)));
            assert_eq!(store.cancel_wait(p, B, b), Ok(None), "granted then cancelled: released");
            assert_eq!(state(&mut m), (0, 1));
        }
    }

    #[test]
    fn failed_granted_cancel_keeps_the_exact_ticket_for_retry() {
        let mut m = mutex();
        let mut store = FastMutexWaitStore::new();
        let p = m.0.as_mut_ptr();
        unsafe {
            assert_eq!(store.begin_wait(p, A, 0xe1), Ok(FastMutexWaitAdmission::Acquired));
            let FastMutexWaitAdmission::Queued(ticket) = store.begin_wait(p, B, 0xe2).unwrap() else {
                panic!("B waits behind A");
            };
            assert_eq!(store.release(p, A), Ok(Some(0xe2)));
            assert_eq!(state(&mut m), (B, 0));

            // A native count mismatch must not consume B's granted wait ticket.
            write_state(p, B, 1);
            assert_eq!(store.cancel_wait(p, B, ticket), Err(ExecutiveSyncError::NotOwned));
            assert_eq!(store.queues.len(), 1);
            assert_eq!(store.queues[0].waiters.len(), 1);
            assert_eq!(store.queues[0].waiters[0].ticket, ticket);

            write_state(p, B, 0);
            assert_eq!(store.cancel_wait(p, B, ticket), Ok(None));
            assert!(store.queues.is_empty());
            assert_eq!(state(&mut m), (0, 1));
        }
    }

    #[test]
    fn fast_mutex_release_requires_completion_of_its_granted_ticket() {
        let mut m = mutex();
        let mut store = FastMutexWaitStore::new();
        let p = m.0.as_mut_ptr();
        unsafe {
            assert_eq!(store.begin_wait(p, A, 0xe1), Ok(FastMutexWaitAdmission::Acquired));
            let FastMutexWaitAdmission::Queued(first) = store.begin_wait(p, B, 0xe2).unwrap() else {
                panic!("expected first waiter");
            };
            let FastMutexWaitAdmission::Queued(second) = store.begin_wait(p, C, 0xe3).unwrap() else {
                panic!("expected second waiter");
            };
            assert_eq!(store.release(p, A), Ok(Some(0xe2)));
            assert_eq!(store.release(p, B), Err(ExecutiveSyncError::BlockingWaitRequired));
            assert_eq!(state(&mut m), (B, -1));
            assert_eq!(store.queues[0].waiters.len(), 2);
            assert!(store.queues[0].waiters[0].granted);
            assert!(!store.queues[0].waiters[1].granted);
            store.complete_wait(p, B, first).unwrap();
            assert_eq!(store.release(p, B), Ok(Some(0xe3)));
            store.complete_wait(p, C, second).unwrap();
            assert_eq!(store.release(p, C), Ok(None));
        }
    }
}
