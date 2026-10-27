//! Native x64 guarded-mutex state and wait ownership.
//!
//! A queued waiter keeps its guarded region entered while it is parked. Release grants the
//! gate to one exact ticket, but the mutex has no new owner until that waiter completes.
//! Native hosts provide the actual park and wake transport; this type never claims that a
//! contended wait succeeded before its continuation runs.

use alloc::vec::Vec;

use super::{enter_guarded_region, kthread_layout, leave_guarded_region, ExecutiveSyncError};

/// Released x64 `KGUARDED_MUTEX` layout (ReactOS `xdk/ketypes.h`).
pub mod guarded_mutex_layout {
    pub const COUNT: usize = 0x00;
    pub const OWNER: usize = 0x08;
    pub const CONTENTION: usize = 0x10;
    pub const GATE: usize = 0x18;
    pub const SPECIAL_APC_DISABLE: usize = 0x30;
    pub const SIZE_OF: usize = 0x38;
}

const LOCK_BIT: i32 = 1;
const WAITER_WOKEN: i32 = 2;
const WAITER_INCREMENT: i32 = 4;
const GATE_OBJECT: u8 = 7;
const GATE_SIZE_DWORDS: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardedMutexWaitTicket(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardedMutexWaitAdmission {
    Acquired,
    Queued(GuardedMutexWaitTicket),
}

struct GuardedWaiter {
    ticket: GuardedMutexWaitTicket,
    thread: u64,
    projection: u64,
    wake_cookie: u64,
    granted: bool,
}

struct GuardedMutex {
    address: u64,
    owner: u64,
    owner_projection: u64,
    saved_apc_disable: i16,
    contention_count: u32,
    waiters: Vec<GuardedWaiter>,
}

/// Exact ownership table for driver-visible guarded mutexes.
pub struct GuardedMutexStore {
    mutexes: Vec<GuardedMutex>,
    next_ticket: u64,
}

impl Default for GuardedMutexStore {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardedMutexStore {
    pub const fn new() -> Self {
        Self { mutexes: Vec::new(), next_ticket: 1 }
    }

    fn index_of(&self, mutex: *mut u8) -> Option<usize> {
        self.mutexes.iter().position(|state| state.address == mutex as u64)
    }

    /// Initialize driver-owned native storage. The caller owns its mapped lifetime.
    ///
    /// # Safety
    /// `mutex` must identify at least `SIZE_OF` writable, eight-byte-aligned bytes.
    pub unsafe fn initialize(&mut self, mutex: *mut u8) -> Result<(), ExecutiveSyncError> {
        validate_mutex(mutex)?;
        if let Some(index) = self.index_of(mutex) {
            if self.mutexes[index].owner != 0 || !self.mutexes[index].waiters.is_empty() {
                return Err(ExecutiveSyncError::ResourceBusy);
            }
            self.mutexes[index].saved_apc_disable = 0;
            self.mutexes[index].contention_count = 0;
            write_projection(mutex, &self.mutexes[index]);
            return Ok(());
        }
        self.mutexes.try_reserve(1).map_err(|_| ExecutiveSyncError::AllocationFailed)?;
        let state = GuardedMutex {
            address: mutex as u64,
            owner: 0,
            owner_projection: 0,
            saved_apc_disable: 0,
            contention_count: 0,
            waiters: Vec::new(),
        };
        self.mutexes.push(state);
        write_projection(mutex, self.mutexes.last().unwrap());
        Ok(())
    }

    /// Refuse teardown while ownership or any waiter is still live.
    ///
    /// # Safety
    /// `mutex` must remain the same mapped native storage passed to `initialize`.
    pub unsafe fn delete(&mut self, mutex: *mut u8) -> Result<(), ExecutiveSyncError> {
        validate_mutex(mutex)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::NotInitialized)?;
        if self.mutexes[index].owner != 0 || !self.mutexes[index].waiters.is_empty() {
            return Err(ExecutiveSyncError::ResourceBusy);
        }
        self.mutexes.remove(index);
        Ok(())
    }

    /// Enter a guarded region and acquire or queue. A nonzero `wake_cookie` names a real
    /// native wait continuation, retained by the host until released or cancelled.
    ///
    /// # Safety
    /// `mutex` and `thread_projection` must be writable native projections for the exact
    /// caller; `thread` must be that caller's driver-visible `KTHREAD` address.
    pub unsafe fn begin_wait(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        thread_projection: *mut u8,
        wake_cookie: u64,
    ) -> Result<GuardedMutexWaitAdmission, ExecutiveSyncError> {
        validate_mutex(mutex)?;
        validate_thread(thread, thread_projection)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::NotInitialized)?;
        let state = &self.mutexes[index];
        if state.owner == thread || state.waiters.iter().any(|waiter| waiter.thread == thread) {
            return Err(ExecutiveSyncError::GuardedMutexRecursiveAcquire);
        }
        // A granted waiter owns the next turn even before its continuation resumes.
        let busy = state.owner != 0 || !state.waiters.is_empty();
        if busy && wake_cookie == 0 {
            return Err(ExecutiveSyncError::InvalidAddress);
        }
        if busy {
            if state.waiters.len() >= (i32::MAX as usize / WAITER_INCREMENT as usize) {
                return Err(ExecutiveSyncError::AllocationFailed);
            }
            self.mutexes[index].waiters.try_reserve(1)
                .map_err(|_| ExecutiveSyncError::AllocationFailed)?;
        }
        let ticket = if busy {
            let ticket = GuardedMutexWaitTicket(self.next_ticket.max(1));
            self.next_ticket = ticket.0.checked_add(1)
                .ok_or(ExecutiveSyncError::AllocationFailed)?;
            Some(ticket)
        } else { None };
        let apc = enter_guarded_region(thread_projection)?;
        let state = &mut self.mutexes[index];
        let admission = if let Some(ticket) = ticket {
            state.contention_count = state.contention_count.saturating_add(1);
            state.waiters.push(GuardedWaiter {
                ticket, thread, projection: thread_projection as u64,
                wake_cookie, granted: false,
            });
            GuardedMutexWaitAdmission::Queued(ticket)
        } else {
            state.owner = thread;
            state.owner_projection = thread_projection as u64;
            state.saved_apc_disable = apc;
            GuardedMutexWaitAdmission::Acquired
        };
        write_projection(mutex, state);
        Ok(admission)
    }

    /// Complete a previously granted wait on the exact thread and ticket.
    ///
    /// # Safety
    /// `mutex` must remain mapped for this store's lifetime.
    pub unsafe fn complete_wait(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        ticket: GuardedMutexWaitTicket,
    ) -> Result<(), ExecutiveSyncError> {
        validate_mutex(mutex)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::NotInitialized)?;
        let state = &mut self.mutexes[index];
        let waiter_index = state.waiters.iter().position(|waiter| waiter.ticket == ticket && waiter.thread == thread)
            .ok_or(ExecutiveSyncError::InvalidOwner)?;
        if !state.waiters[waiter_index].granted || state.owner != 0 {
            return Err(ExecutiveSyncError::BlockingWaitRequired);
        }
        let waiter = state.waiters.remove(waiter_index);
        let apc = read_apc(waiter.projection as *mut u8);
        state.owner = thread;
        state.owner_projection = waiter.projection;
        state.saved_apc_disable = apc;
        write_projection(mutex, state);
        Ok(())
    }

    /// Release the exact owner and return at most one continuation to wake.
    ///
    /// # Safety
    /// The pointers must identify the original mapped mutex and current caller projection.
    pub unsafe fn release(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        thread_projection: *mut u8,
    ) -> Result<Option<u64>, ExecutiveSyncError> {
        validate_mutex(mutex)?;
        validate_thread(thread, thread_projection)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::NotInitialized)?;
        let state = &mut self.mutexes[index];
        if state.owner != thread || state.owner_projection != thread_projection as u64 {
            return Err(ExecutiveSyncError::NotOwned);
        }
        if read_apc(thread_projection) != state.saved_apc_disable {
            return Err(ExecutiveSyncError::ApcDisableUnderflow);
        }
        // The guarded-region decrement was made at acquire, before any blocking wait.
        leave_guarded_region(thread_projection)?;
        state.owner = 0;
        state.owner_projection = 0;
        state.saved_apc_disable = 0;
        let wake = grant_head(state);
        write_projection(mutex, state);
        Ok(wake)
    }

    /// Remove an exact pending waiter and balance its guarded region. A previously granted
    /// waiter passes its gate turn to the next queued waiter.
    ///
    /// # Safety
    /// `thread_projection` must be the same live projection supplied to `begin_wait`.
    pub unsafe fn cancel_wait(
        &mut self,
        mutex: *mut u8,
        thread: u64,
        thread_projection: *mut u8,
        ticket: GuardedMutexWaitTicket,
    ) -> Result<Option<u64>, ExecutiveSyncError> {
        validate_mutex(mutex)?;
        validate_thread(thread, thread_projection)?;
        let index = self.index_of(mutex).ok_or(ExecutiveSyncError::NotInitialized)?;
        let state = &mut self.mutexes[index];
        let waiter_index = state.waiters.iter().position(|waiter| {
            waiter.ticket == ticket && waiter.thread == thread && waiter.projection == thread_projection as u64
        }).ok_or(ExecutiveSyncError::InvalidOwner)?;
        let was_granted = state.waiters[waiter_index].granted;
        leave_guarded_region(thread_projection)?;
        state.waiters.remove(waiter_index);
        let wake = if was_granted { grant_head(state) } else { None };
        write_projection(mutex, state);
        Ok(wake)
    }
}

fn validate_mutex(mutex: *mut u8) -> Result<(), ExecutiveSyncError> {
    if mutex.is_null() || (mutex as usize & 7) != 0 {
        Err(ExecutiveSyncError::InvalidAddress)
    } else { Ok(()) }
}

fn validate_thread(thread: u64, projection: *mut u8) -> Result<(), ExecutiveSyncError> {
    if thread == 0 || projection.is_null() || (projection as usize & 7) != 0 {
        Err(ExecutiveSyncError::InvalidOwner)
    } else { Ok(()) }
}

unsafe fn read_apc(projection: *mut u8) -> i16 {
    core::ptr::read_unaligned(projection.add(kthread_layout::SPECIAL_APC_DISABLE) as *const i16)
}

fn grant_head(state: &mut GuardedMutex) -> Option<u64> {
    if let Some(waiter) = state.waiters.first_mut() {
        waiter.granted = true;
        Some(waiter.wake_cookie)
    } else { None }
}

unsafe fn write_projection(mutex: *mut u8, state: &GuardedMutex) {
    use guarded_mutex_layout as o;
    // Preserve ReactOS's lock/woken/waiter bit encoding. While the gate is signalled,
    // the selected waiter is reserved but has not yet installed its Owner field.
    let granted = state.waiters.first().is_some_and(|waiter| waiter.granted);
    let queued = state.waiters.len() - usize::from(granted);
    let count = (if state.owner == 0 { LOCK_BIT } else { 0 })
        + (if granted { WAITER_WOKEN } else { 0 })
        + (queued as i32) * WAITER_INCREMENT;
    core::ptr::write_unaligned(mutex.add(o::COUNT) as *mut i32, count);
    core::ptr::write_unaligned(mutex.add(o::OWNER) as *mut u64, state.owner);
    core::ptr::write_unaligned(mutex.add(o::CONTENTION) as *mut u32, state.contention_count);
    let gate = mutex.add(o::GATE);
    core::ptr::write_bytes(gate, 0, 0x18);
    core::ptr::write_unaligned(gate, GATE_OBJECT);
    core::ptr::write_unaligned(gate.add(2), GATE_SIZE_DWORDS);
    core::ptr::write_unaligned(gate.add(4) as *mut i32, i32::from(granted));
    let head = gate.add(8) as u64;
    core::ptr::write_unaligned(gate.add(8) as *mut u64, head);
    core::ptr::write_unaligned(gate.add(16) as *mut u64, head);
    core::ptr::write_unaligned(mutex.add(o::SPECIAL_APC_DISABLE) as *mut i16, state.saved_apc_disable);
}
