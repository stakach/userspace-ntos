//! Hosted kernel-driver system-thread and wait-broker state.
//!
//! The executive-side seL4 wiring owns TCBs, CNodes, reply caps, and endpoint badges. This crate
//! keeps the NT mechanism model host-testable: system-thread handles are real waitable identities,
//! and blocking dispatcher waits can be admitted, parked, woken, or cancelled without fabricating a
//! successful wait.

use alloc::vec::Vec;
use nt_time::{Deadline, TimeSnapshot};

use crate::{
    dispatcher_ready, poll_dispatchers, DispatcherObject, DispatcherWaitResult,
    DispatcherWaitTimeout, EventStore, MutantStore, SemaphoreStore,
};

pub const HOSTED_DRIVER_THREAD_HANDLE_BASE: u64 = 0x0000_0000_8000_0000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostedDriverThreadState {
    Ready,
    Running,
    Waiting,
    Terminated,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostedDriverThreadError {
    InvalidStartRoutine,
    InvalidHandle,
    AlreadyTerminated,
    ExhaustedHandleSpace,
    NoCapacity,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HostedDriverThread {
    pub handle: u64,
    pub start_routine: u64,
    pub start_context: u64,
    pub tcb: u64,
    pub state: HostedDriverThreadState,
    pub exit_status: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedDriverThreadTable {
    next_handle: u64,
    threads: Vec<HostedDriverThread>,
}

impl HostedDriverThreadTable {
    pub fn new() -> Self {
        Self::with_first_handle(HOSTED_DRIVER_THREAD_HANDLE_BASE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut table = Self::new();
        table.threads = Vec::with_capacity(capacity);
        table
    }

    pub fn with_first_handle(first_handle: u64) -> Self {
        Self {
            next_handle: first_handle.max(1),
            threads: Vec::new(),
        }
    }

    pub fn create(
        &mut self,
        start_routine: u64,
        start_context: u64,
    ) -> Result<u64, HostedDriverThreadError> {
        if start_routine == 0 {
            return Err(HostedDriverThreadError::InvalidStartRoutine);
        }
        if self.threads.len() == self.threads.capacity() {
            self.threads
                .try_reserve(4)
                .map_err(|_| HostedDriverThreadError::NoCapacity)?;
        }
        let handle = self.allocate_handle()?;
        self.threads.push(HostedDriverThread {
            handle,
            start_routine,
            start_context,
            tcb: 0,
            state: HostedDriverThreadState::Ready,
            exit_status: None,
        });
        Ok(handle)
    }

    fn allocate_handle(&mut self) -> Result<u64, HostedDriverThreadError> {
        let mut attempts = 0usize;
        while attempts <= self.threads.len() {
            let handle = self.next_handle;
            self.next_handle = self
                .next_handle
                .checked_add(1)
                .ok_or(HostedDriverThreadError::ExhaustedHandleSpace)?;
            if handle != 0 && self.get(handle).is_none() {
                return Ok(handle);
            }
            attempts += 1;
        }
        Err(HostedDriverThreadError::ExhaustedHandleSpace)
    }

    pub fn get(&self, handle: u64) -> Option<HostedDriverThread> {
        self.threads
            .iter()
            .copied()
            .find(|thread| thread.handle == handle)
    }

    fn get_mut(&mut self, handle: u64) -> Option<&mut HostedDriverThread> {
        self.threads
            .iter_mut()
            .find(|thread| thread.handle == handle)
    }

    pub fn attach_tcb(&mut self, handle: u64, tcb: u64) -> Result<(), HostedDriverThreadError> {
        if handle == 0 || tcb == 0 {
            return Err(HostedDriverThreadError::InvalidHandle);
        }
        let thread = self
            .get_mut(handle)
            .ok_or(HostedDriverThreadError::InvalidHandle)?;
        if thread.state == HostedDriverThreadState::Terminated {
            return Err(HostedDriverThreadError::AlreadyTerminated);
        }
        thread.tcb = tcb;
        thread.state = HostedDriverThreadState::Running;
        Ok(())
    }

    pub fn set_waiting(&mut self, handle: u64) -> Result<(), HostedDriverThreadError> {
        let thread = self
            .get_mut(handle)
            .ok_or(HostedDriverThreadError::InvalidHandle)?;
        if thread.state == HostedDriverThreadState::Terminated {
            return Err(HostedDriverThreadError::AlreadyTerminated);
        }
        thread.state = HostedDriverThreadState::Waiting;
        Ok(())
    }

    pub fn set_ready(&mut self, handle: u64) -> Result<(), HostedDriverThreadError> {
        let thread = self
            .get_mut(handle)
            .ok_or(HostedDriverThreadError::InvalidHandle)?;
        if thread.state == HostedDriverThreadState::Terminated {
            return Err(HostedDriverThreadError::AlreadyTerminated);
        }
        thread.state = HostedDriverThreadState::Ready;
        Ok(())
    }

    pub fn terminate(&mut self, handle: u64, status: i32) -> Result<(), HostedDriverThreadError> {
        let thread = self
            .get_mut(handle)
            .ok_or(HostedDriverThreadError::InvalidHandle)?;
        if thread.state == HostedDriverThreadState::Terminated {
            return Err(HostedDriverThreadError::AlreadyTerminated);
        }
        thread.state = HostedDriverThreadState::Terminated;
        thread.exit_status = Some(status);
        Ok(())
    }

    pub fn remove(&mut self, handle: u64) -> Option<HostedDriverThread> {
        let index = self
            .threads
            .iter()
            .position(|thread| thread.handle == handle)?;
        Some(self.threads.remove(index))
    }

    pub fn len(&self) -> usize {
        self.threads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}

impl Default for HostedDriverThreadTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedDispatcherWaiter {
    pub thread_handle: u64,
    pub reply_cap: u64,
    pub objects: Vec<DispatcherObject>,
    pub wait_all: bool,
    pub deadline: Deadline,
    sequence: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostedDispatcherCompletion {
    Satisfied(usize),
    Abandoned(usize),
    MutantLimitExceeded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HostedDispatcherWake {
    pub thread_handle: u64,
    pub reply_cap: u64,
    pub completion: HostedDispatcherCompletion,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HostedDispatcherTimeout {
    pub thread_handle: u64,
    pub reply_cap: u64,
    pub deadline: Deadline,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostedDispatcherWaitAdmission {
    Satisfied(usize),
    Abandoned(usize),
    PollTimeout,
    Parked,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostedDispatcherWaitError {
    InvalidThread,
    InvalidReply,
    InvalidObject,
    DuplicateObject,
    MutantLimitExceeded,
    AlreadyParked,
    NoCapacity,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct HostedDispatcherWaitQueue {
    waiters: Vec<HostedDispatcherWaiter>,
    next_sequence: u64,
}

impl HostedDispatcherWaitQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            waiters: Vec::with_capacity(capacity),
            next_sequence: 0,
        }
    }

    pub fn admit(
        &mut self,
        events: &mut EventStore,
        semaphores: &mut SemaphoreStore,
        mutants: &mut MutantStore,
        thread_handle: u64,
        reply_cap: u64,
        objects: &[DispatcherObject],
        wait_all: bool,
        timeout: DispatcherWaitTimeout,
    ) -> Result<HostedDispatcherWaitAdmission, HostedDispatcherWaitError> {
        self.admit_with_deadline(
            events,
            semaphores,
            mutants,
            thread_handle,
            reply_cap,
            objects,
            wait_all,
            timeout,
            Deadline::Infinite,
        )
    }

    pub fn admit_with_deadline(
        &mut self,
        events: &mut EventStore,
        semaphores: &mut SemaphoreStore,
        mutants: &mut MutantStore,
        thread_handle: u64,
        reply_cap: u64,
        objects: &[DispatcherObject],
        wait_all: bool,
        timeout: DispatcherWaitTimeout,
        deadline: Deadline,
    ) -> Result<HostedDispatcherWaitAdmission, HostedDispatcherWaitError> {
        if thread_handle == 0 {
            return Err(HostedDispatcherWaitError::InvalidThread);
        }
        if reply_cap == 0 {
            return Err(HostedDispatcherWaitError::InvalidReply);
        }
        match poll_dispatchers(events, semaphores, mutants, objects, wait_all) {
            DispatcherWaitResult::Signaled(index) => {
                return Ok(HostedDispatcherWaitAdmission::Satisfied(index));
            }
            DispatcherWaitResult::Abandoned(index) => {
                return Ok(HostedDispatcherWaitAdmission::Abandoned(index));
            }
            DispatcherWaitResult::TimedOut => {}
            DispatcherWaitResult::InvalidObject => {
                return Err(HostedDispatcherWaitError::InvalidObject);
            }
            DispatcherWaitResult::DuplicateObject => {
                return Err(HostedDispatcherWaitError::DuplicateObject);
            }
            DispatcherWaitResult::MutantLimitExceeded => {
                return Err(HostedDispatcherWaitError::MutantLimitExceeded);
            }
        }
        if timeout == DispatcherWaitTimeout::Poll {
            return Ok(HostedDispatcherWaitAdmission::PollTimeout);
        }
        if self
            .waiters
            .iter()
            .any(|waiter| waiter.thread_handle == thread_handle || waiter.reply_cap == reply_cap)
        {
            return Err(HostedDispatcherWaitError::AlreadyParked);
        }
        if self.waiters.len() == self.waiters.capacity() {
            self.waiters
                .try_reserve(4)
                .map_err(|_| HostedDispatcherWaitError::NoCapacity)?;
        }
        let mut parked_objects = Vec::new();
        parked_objects
            .try_reserve(objects.len())
            .map_err(|_| HostedDispatcherWaitError::NoCapacity)?;
        parked_objects.extend_from_slice(objects);
        self.waiters.push(HostedDispatcherWaiter {
            thread_handle,
            reply_cap,
            objects: parked_objects,
            wait_all,
            deadline: match timeout {
                DispatcherWaitTimeout::Blocking => deadline,
                DispatcherWaitTimeout::Infinite | DispatcherWaitTimeout::Poll => Deadline::Infinite,
            },
            sequence: self.next_sequence,
        });
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(HostedDispatcherWaitAdmission::Parked)
    }

    pub fn pop_ready(
        &mut self,
        events: &mut EventStore,
        semaphores: &mut SemaphoreStore,
        mutants: &mut MutantStore,
    ) -> Option<HostedDispatcherWake> {
        let index = self.waiters.iter().position(|waiter| {
            if waiter.wait_all {
                waiter
                    .objects
                    .iter()
                    .all(|object| dispatcher_ready(events, semaphores, mutants, *object))
            } else {
                waiter
                    .objects
                    .iter()
                    .any(|object| dispatcher_ready(events, semaphores, mutants, *object))
            }
        })?;
        let waiter = self.waiters.remove(index);
        let completion = match poll_dispatchers(
            events,
            semaphores,
            mutants,
            &waiter.objects,
            waiter.wait_all,
        ) {
            DispatcherWaitResult::Signaled(index) => HostedDispatcherCompletion::Satisfied(index),
            DispatcherWaitResult::Abandoned(index) => HostedDispatcherCompletion::Abandoned(index),
            DispatcherWaitResult::MutantLimitExceeded => {
                HostedDispatcherCompletion::MutantLimitExceeded
            }
            _ => return None,
        };
        Some(HostedDispatcherWake {
            thread_handle: waiter.thread_handle,
            reply_cap: waiter.reply_cap,
            completion,
        })
    }

    pub fn cancel_thread(&mut self, thread_handle: u64) -> Option<HostedDispatcherWaiter> {
        let index = self
            .waiters
            .iter()
            .position(|waiter| waiter.thread_handle == thread_handle)?;
        Some(self.waiters.remove(index))
    }

    pub fn next_deadline(&self, now: TimeSnapshot) -> Option<u64> {
        self.waiters
            .iter()
            .filter_map(|waiter| waiter.deadline.monotonic_target(now))
            .min()
    }

    pub fn pop_due(&mut self, now: TimeSnapshot) -> Option<HostedDispatcherTimeout> {
        let index = self
            .waiters
            .iter()
            .enumerate()
            .filter(|(_, waiter)| waiter.deadline.is_due(now))
            .min_by_key(|(_, waiter)| (waiter.deadline.ordering_key(now), waiter.sequence))
            .map(|(index, _)| index)?;
        let waiter = self.waiters.remove(index);
        Some(HostedDispatcherTimeout {
            thread_handle: waiter.thread_handle,
            reply_cap: waiter.reply_cap,
            deadline: waiter.deadline,
        })
    }

    pub fn len(&self) -> usize {
        self.waiters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventKind;

    fn stores() -> (EventStore, SemaphoreStore, MutantStore) {
        (EventStore::new(), SemaphoreStore::new(), MutantStore::new())
    }

    fn snapshot(monotonic_100ns: u64, system_time_100ns: u64) -> TimeSnapshot {
        TimeSnapshot {
            monotonic_100ns,
            system_time_100ns,
            clock_generation: 0,
        }
    }

    #[test]
    fn thread_handles_are_unique_waitable_identities() {
        let mut table = HostedDriverThreadTable::with_first_handle(0x9000);
        let first = table.create(0x1000, 0xAAAA).unwrap();
        let second = table.create(0x2000, 0xBBBB).unwrap();
        assert_eq!(first, 0x9000);
        assert_eq!(second, 0x9001);
        assert_eq!(
            table.get(first).unwrap(),
            HostedDriverThread {
                handle: first,
                start_routine: 0x1000,
                start_context: 0xAAAA,
                tcb: 0,
                state: HostedDriverThreadState::Ready,
                exit_status: None,
            }
        );
        table.attach_tcb(first, 0xCC).unwrap();
        assert_eq!(
            table.get(first).unwrap().state,
            HostedDriverThreadState::Running
        );
        table.terminate(first, 0x1234).unwrap();
        assert_eq!(
            table.get(first).unwrap().state,
            HostedDriverThreadState::Terminated
        );
        assert_eq!(table.get(first).unwrap().exit_status, Some(0x1234));
    }

    #[test]
    fn terminated_threads_cannot_be_resumed_through_wait_state() {
        let mut table = HostedDriverThreadTable::with_first_handle(0x9000);
        let handle = table.create(0x1000, 0xAAAA).unwrap();
        table.attach_tcb(handle, 0xCC).unwrap();
        table.terminate(handle, 0).unwrap();

        assert_eq!(
            table.set_waiting(handle),
            Err(HostedDriverThreadError::AlreadyTerminated)
        );
        assert_eq!(
            table.set_ready(handle),
            Err(HostedDriverThreadError::AlreadyTerminated)
        );
        assert_eq!(
            table.attach_tcb(handle, 0xDD),
            Err(HostedDriverThreadError::AlreadyTerminated)
        );
        assert_eq!(
            table.terminate(handle, 1),
            Err(HostedDriverThreadError::AlreadyTerminated)
        );
        assert_eq!(table.get(handle).unwrap().exit_status, Some(0));
    }

    #[test]
    fn blocking_wait_parks_and_release_wakes_fifo() {
        let (mut events, mut semaphores, mut mutants) = stores();
        semaphores.initialize(7, 0, 2).unwrap();
        let mut waits = HostedDispatcherWaitQueue::new();
        let objects = [DispatcherObject::Semaphore(7)];
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x50,
                &objects,
                false,
                DispatcherWaitTimeout::Infinite,
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert_eq!(waits.len(), 1);
        semaphores.release(7, 1).unwrap();
        assert_eq!(
            waits.pop_ready(&mut events, &mut semaphores, &mut mutants),
            Some(HostedDispatcherWake {
                thread_handle: 0x9000,
                reply_cap: 0x50,
                completion: HostedDispatcherCompletion::Satisfied(0),
            })
        );
        assert_eq!(semaphores.query(7), Some((0, 2)));
    }

    #[test]
    fn zero_timeout_poll_never_parks() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(8, EventKind::Notification, false);
        let mut waits = HostedDispatcherWaitQueue::new();
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x51,
                &[DispatcherObject::Event(8)],
                false,
                DispatcherWaitTimeout::Poll,
            ),
            Ok(HostedDispatcherWaitAdmission::PollTimeout)
        );
        assert!(waits.is_empty());
    }

    #[test]
    fn wait_all_wakes_only_after_every_member_is_ready() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Synchronization, true);
        semaphores.initialize(2, 0, 1).unwrap();
        let mut waits = HostedDispatcherWaitQueue::new();
        let objects = [DispatcherObject::Event(1), DispatcherObject::Semaphore(2)];
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x52,
                &objects,
                true,
                DispatcherWaitTimeout::Blocking,
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert!(events.read_state(1));
        assert_eq!(
            waits.pop_ready(&mut events, &mut semaphores, &mut mutants),
            None
        );
        semaphores.release(2, 1).unwrap();
        assert_eq!(
            waits.pop_ready(&mut events, &mut semaphores, &mut mutants),
            Some(HostedDispatcherWake {
                thread_handle: 0x9000,
                reply_cap: 0x52,
                completion: HostedDispatcherCompletion::Satisfied(0),
            })
        );
        assert!(!events.read_state(1));
        assert_eq!(semaphores.query(2), Some((0, 1)));
    }

    #[test]
    fn parked_mutant_wait_reports_abandonment() {
        let (mut events, mut semaphores, mut mutants) = stores();
        mutants.initialize(3, Some(40));
        let mut waits = HostedDispatcherWaitQueue::new();
        let objects = [DispatcherObject::Mutant {
            identity: 3,
            thread: 41,
        }];
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x53,
                &objects,
                false,
                DispatcherWaitTimeout::Infinite,
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert_eq!(mutants.abandon_thread(40), 1);
        assert_eq!(
            waits.pop_ready(&mut events, &mut semaphores, &mut mutants),
            Some(HostedDispatcherWake {
                thread_handle: 0x9000,
                reply_cap: 0x53,
                completion: HostedDispatcherCompletion::Abandoned(0),
            })
        );
    }

    #[test]
    fn timed_waits_report_next_deadline_and_pop_due_fifo() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, false);
        events.initialize(2, EventKind::Notification, false);
        let mut waits = HostedDispatcherWaitQueue::new();
        assert_eq!(
            waits.admit_with_deadline(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x60,
                &[DispatcherObject::Event(1)],
                false,
                DispatcherWaitTimeout::Blocking,
                Deadline::Relative {
                    monotonic_100ns: 30,
                },
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert_eq!(
            waits.admit_with_deadline(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9001,
                0x61,
                &[DispatcherObject::Event(2)],
                false,
                DispatcherWaitTimeout::Blocking,
                Deadline::Relative {
                    monotonic_100ns: 20,
                },
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert_eq!(
            waits.admit_with_deadline(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9002,
                0x62,
                &[DispatcherObject::Event(1)],
                false,
                DispatcherWaitTimeout::Blocking,
                Deadline::Relative {
                    monotonic_100ns: 20,
                },
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert_eq!(waits.next_deadline(snapshot(0, 100)), Some(20));
        assert_eq!(waits.pop_due(snapshot(19, 119)), None);
        assert_eq!(
            waits.pop_due(snapshot(20, 120)),
            Some(HostedDispatcherTimeout {
                thread_handle: 0x9001,
                reply_cap: 0x61,
                deadline: Deadline::Relative {
                    monotonic_100ns: 20,
                },
            })
        );
        assert_eq!(
            waits.pop_due(snapshot(20, 120)),
            Some(HostedDispatcherTimeout {
                thread_handle: 0x9002,
                reply_cap: 0x62,
                deadline: Deadline::Relative {
                    monotonic_100ns: 20,
                },
            })
        );
        assert_eq!(waits.next_deadline(snapshot(20, 120)), Some(30));
    }

    #[test]
    fn absolute_waits_reproject_and_keep_order_after_a_forward_clock_jump() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, false);
        let mut waits = HostedDispatcherWaitQueue::new();
        for (thread_handle, reply_cap, system_time_100ns) in
            [(0x9000, 0x60, 2_000), (0x9001, 0x61, 3_000)]
        {
            assert_eq!(
                waits.admit_with_deadline(
                    &mut events,
                    &mut semaphores,
                    &mut mutants,
                    thread_handle,
                    reply_cap,
                    &[DispatcherObject::Event(1)],
                    false,
                    DispatcherWaitTimeout::Blocking,
                    Deadline::Absolute { system_time_100ns },
                ),
                Ok(HostedDispatcherWaitAdmission::Parked)
            );
        }

        assert_eq!(waits.next_deadline(snapshot(100, 1_000)), Some(1_100));
        assert_eq!(waits.next_deadline(snapshot(200, 4_000)), Some(200));
        assert_eq!(
            waits.pop_due(snapshot(200, 4_000)).unwrap().thread_handle,
            0x9000
        );
        assert_eq!(
            waits.pop_due(snapshot(200, 4_000)).unwrap().thread_handle,
            0x9001
        );
    }

    #[test]
    fn signaled_timed_wait_wakes_normally_before_timeout() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, false);
        let mut waits = HostedDispatcherWaitQueue::new();
        assert_eq!(
            waits.admit_with_deadline(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x63,
                &[DispatcherObject::Event(1)],
                false,
                DispatcherWaitTimeout::Blocking,
                Deadline::Relative {
                    monotonic_100ns: 50,
                },
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        let _ = events.set(1);
        assert_eq!(
            waits.pop_ready(&mut events, &mut semaphores, &mut mutants),
            Some(HostedDispatcherWake {
                thread_handle: 0x9000,
                reply_cap: 0x63,
                completion: HostedDispatcherCompletion::Satisfied(0),
            })
        );
        assert_eq!(waits.pop_due(snapshot(50, 150)), None);
        assert_eq!(waits.next_deadline(snapshot(50, 150)), None);
    }

    #[test]
    fn duplicate_wait_all_is_rejected_before_parking() {
        let (mut events, mut semaphores, mut mutants) = stores();
        semaphores.initialize(3, 1, 1).unwrap();
        let mut waits = HostedDispatcherWaitQueue::new();
        let objects = [
            DispatcherObject::Semaphore(3),
            DispatcherObject::Semaphore(3),
        ];
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x53,
                &objects,
                true,
                DispatcherWaitTimeout::Infinite,
            ),
            Err(HostedDispatcherWaitError::DuplicateObject)
        );
        assert!(waits.is_empty());
        assert_eq!(semaphores.query(3), Some((1, 1)));
    }

    #[test]
    fn parked_thread_or_reply_cannot_be_reused() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, false);
        events.initialize(2, EventKind::Notification, false);
        let mut waits = HostedDispatcherWaitQueue::new();
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x54,
                &[DispatcherObject::Event(1)],
                false,
                DispatcherWaitTimeout::Infinite,
            ),
            Ok(HostedDispatcherWaitAdmission::Parked)
        );
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9000,
                0x55,
                &[DispatcherObject::Event(2)],
                false,
                DispatcherWaitTimeout::Infinite,
            ),
            Err(HostedDispatcherWaitError::AlreadyParked)
        );
        assert_eq!(
            waits.admit(
                &mut events,
                &mut semaphores,
                &mut mutants,
                0x9001,
                0x54,
                &[DispatcherObject::Event(2)],
                false,
                DispatcherWaitTimeout::Infinite,
            ),
            Err(HostedDispatcherWaitError::AlreadyParked)
        );
    }
}
