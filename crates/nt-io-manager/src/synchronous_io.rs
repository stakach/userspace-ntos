//! FIFO ownership for syscalls waiting to acquire a synchronous FILE_OBJECT.
//!
//! The File policy table owns Busy and the waiter count. This table owns the exact executive
//! continuation and the already-referenced canonical File route, so a concurrent handle close
//! cannot invalidate an operation that passed object-manager lookup before it blocked.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_io_completion::FileIoMode;

mod retry;
pub use retry::{
    SynchronousFileRetryAttempt, SynchronousFileRetryError, SynchronousFileRetryIdentity,
    SynchronousFileRetryOutcome, SynchronousFileRetryPhase, SynchronousFileRetryStats,
    SynchronousFileRetryView,
};

static LAST_TABLE: AtomicU64 = AtomicU64::new(0);

/// Canonical File identity, including the domain that owns its lifetime and Busy state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileIoWaitKey {
    Hosted(u64),
    LocalOverlay(u64),
}

/// Referenced lookup result captured before a syscall waits for File ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileIoWaitRoute {
    Hosted {
        file_id: u64,
        device_id: u64,
        fs_context: u64,
    },
    LocalOverlay {
        file_object: u64,
    },
}

impl FileIoWaitRoute {
    pub const fn key(self) -> FileIoWaitKey {
        match self {
            Self::Hosted { file_id, .. } => FileIoWaitKey::Hosted(file_id),
            Self::LocalOverlay { file_object } => FileIoWaitKey::LocalOverlay(file_object),
        }
    }

    pub const fn is_valid(self) -> bool {
        match self {
            Self::Hosted {
                file_id, device_id, ..
            } => file_id != 0 && device_id != 0,
            Self::LocalOverlay { .. } => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SynchronousFileWaitState {
    #[default]
    Waiting,
    Promoted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynchronousFileWaiter {
    pub route: FileIoWaitRoute,
    pub handle: u32,
    pub granted_access: u32,
    pub service_number: u32,
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    pub mode: FileIoMode,
    pub native_call_transport: bool,
    pub reply_cap: u64,
    /// Address of the x64 `syscall` instruction used to replay the captured native call.
    pub retry_ip: u64,
    /// Address immediately after the syscall. APC interruption returns through
    /// this continuation without replaying an operation that never dispatched.
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    /// Complete native IPC register frame. The executive snapshots it before parking so replay
    /// cannot inherit argument MRs from the unrelated caller that releases Busy.
    pub reply_mrs: [u64; 18],
    pub state: SynchronousFileWaitState,
    sequence: u64,
}

impl SynchronousFileWaiter {
    #[allow(clippy::too_many_arguments)]
    pub const fn waiting(
        route: FileIoWaitRoute,
        handle: u32,
        granted_access: u32,
        service_number: u32,
        pi: u32,
        tid: u64,
        badge: u64,
        mode: FileIoMode,
        native_call_transport: bool,
        retry_ip: u64,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
    ) -> Self {
        Self {
            route,
            handle,
            granted_access,
            service_number,
            pi,
            tid,
            badge,
            mode,
            native_call_transport,
            reply_cap: 0,
            retry_ip,
            resume_ip,
            resume_sp,
            resume_flags,
            reply_mrs: [0; 18],
            state: SynchronousFileWaitState::Waiting,
            sequence: 0,
        }
    }

    pub const fn key(&self) -> FileIoWaitKey {
        self.route.key()
    }

    pub const fn is_alertable(&self) -> bool {
        matches!(self.mode, FileIoMode::SynchronousAlertable)
    }
}

const DEFAULT_INITIAL_RESERVE: usize = 16;

/// One owner of retained File grants and reply capabilities.
///
/// ```compile_fail
/// use nt_io_manager::SynchronousFileWaitTable;
/// fn duplicate(table: SynchronousFileWaitTable) { let _copy = table.clone(); }
/// ```
#[derive(Debug)]
pub struct SynchronousFileWaitTable {
    slots: Vec<Option<WaitRecord>>,
    initial_reserve: usize,
    next_sequence: u64,
    identity: u64,
}

#[derive(Debug)]
struct WaitRecord {
    waiter: SynchronousFileWaiter,
    retry: Option<SynchronousFileRetryPhase>,
    next_attempt: u64,
}

impl WaitRecord {
    fn delivery_retained(&self) -> bool {
        self.retry
            .is_some_and(|phase| phase != SynchronousFileRetryPhase::Retired)
    }
}

impl Default for SynchronousFileWaitTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SynchronousFileWaitTable {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            initial_reserve,
            next_sequence: 1,
            identity: 0,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        if self.slots.len() == self.slots.capacity() {
            let reserve = if self.slots.capacity() == 0 {
                self.initial_reserve.max(1)
            } else {
                1
            };
            if self.slots.try_reserve(reserve).is_err() {
                return false;
            }
        }
        true
    }

    pub fn reset(&mut self) -> bool {
        if !self.is_empty() {
            return false;
        }
        self.slots.clear();
        if self.slots.capacity() < self.initial_reserve {
            let additional = self.initial_reserve - self.slots.capacity();
            if self.slots.try_reserve(additional).is_err() {
                return false;
            }
        }
        true
    }

    pub fn ensure_capacity(&mut self) -> bool {
        self.slots.iter().any(Option::is_none)
            || self.slots.len() < self.slots.capacity()
            || self.grow_reservation()
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    pub fn park(&mut self, mut waiter: SynchronousFileWaiter) -> Option<usize> {
        if !waiter.route.is_valid()
            || !waiter.mode.is_synchronous()
            || waiter.handle == 0
            || waiter.tid == 0
            || waiter.tid == u64::MAX
            || waiter.badge == 0
            || waiter.reply_cap == 0
            || (!waiter.native_call_transport && waiter.retry_ip == 0)
            || waiter.resume_sp == 0
            || waiter.state != SynchronousFileWaitState::Waiting
            || self.slots.iter().any(|slot| {
                slot.as_ref().is_some_and(|record| {
                    record.waiter.tid == waiter.tid || record.waiter.reply_cap == waiter.reply_cap
                })
            })
        {
            return None;
        }
        if self.identity == 0 {
            self.identity = LAST_TABLE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                    last.checked_add(1)
                })
                .ok()?
                + 1;
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1)?;
        waiter.sequence = sequence;
        let record = WaitRecord {
            waiter,
            retry: None,
            next_attempt: 1,
        };
        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(record);
            return Some(index);
        }
        if !self.grow_reservation() {
            return None;
        }
        self.slots.push(Some(record));
        Some(self.slots.len() - 1)
    }

    pub fn oldest_waiting_for_file(
        &self,
        key: FileIoWaitKey,
    ) -> Option<(usize, SynchronousFileWaiter)> {
        if self.has_promoted_for_file(key) {
            return None;
        }
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, record)| record.as_ref().map(|record| (slot, record.waiter)))
            .filter(|(_, waiter)| {
                waiter.key() == key && waiter.state == SynchronousFileWaitState::Waiting
            })
            .min_by_key(|(_, waiter)| waiter.sequence)
    }

    /// Resolve the exact pre-dispatch File acquisition wait that a queued user
    /// APC may interrupt. A promoted record already owns Busy, so the File-lock
    /// wake wins and it is deliberately excluded.
    pub fn alertable_waiting_for_thread(&self, tid: u64) -> Option<(usize, SynchronousFileWaiter)> {
        self.slots.iter().enumerate().find_map(|(slot, record)| {
            record
                .as_ref()
                .map(|record| record.waiter)
                .filter(|waiter| {
                    waiter.tid == tid
                        && waiter.is_alertable()
                        && waiter.state == SynchronousFileWaitState::Waiting
                })
                .map(|waiter| (slot, waiter))
        })
    }

    pub fn take_alertable_waiting_exact(
        &mut self,
        slot: usize,
        key: FileIoWaitKey,
        tid: u64,
    ) -> Option<SynchronousFileWaiter> {
        let waiter = &self.slots.get(slot)?.as_ref()?.waiter;
        if waiter.key() != key
            || waiter.tid != tid
            || !waiter.is_alertable()
            || waiter.state != SynchronousFileWaitState::Waiting
        {
            return None;
        }
        self.slots.get_mut(slot)?.take().map(|record| record.waiter)
    }

    /// Mark one exact FIFO waiter as the promoted Busy owner. Reply ownership remains on the
    /// record until the executive has made the retry visible.
    pub fn promote_exact(
        &mut self,
        slot: usize,
        key: FileIoWaitKey,
        tid: u64,
    ) -> Option<SynchronousFileWaiter> {
        if self.has_promoted_for_file(key) {
            return None;
        }
        let record = self.slots.get_mut(slot)?.as_mut()?;
        let waiter = &mut record.waiter;
        if waiter.key() != key
            || waiter.tid != tid
            || waiter.state != SynchronousFileWaitState::Waiting
            || waiter.reply_cap == 0
        {
            return None;
        }
        waiter.state = SynchronousFileWaitState::Promoted;
        record.retry = Some(SynchronousFileRetryPhase::Ready { last_error: None });
        Some(*waiter)
    }

    /// Consume the canonical route retained for the promoted syscall. A mismatched service number
    /// cannot steal another call's grant.
    pub fn take_promoted(
        &mut self,
        pi: u32,
        tid: u64,
        badge: u64,
        service_number: u32,
    ) -> Option<SynchronousFileWaiter> {
        let slot = self.slots.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|record| {
                let waiter = &record.waiter;
                waiter.pi == pi
                    && waiter.tid == tid
                    && waiter.badge == badge
                    && waiter.service_number == service_number
                    && waiter.state == SynchronousFileWaitState::Promoted
                    && waiter.reply_cap == 0
                    && record.retry == Some(SynchronousFileRetryPhase::Retired)
            })
        })?;
        slot.take().map(|record| record.waiter)
    }

    pub fn take_exact(
        &mut self,
        slot: usize,
        key: FileIoWaitKey,
        tid: u64,
    ) -> Option<SynchronousFileWaiter> {
        let record = self.slots.get(slot)?.as_ref()?;
        let waiter = &record.waiter;
        if waiter.key() != key || waiter.tid != tid || record.delivery_retained() {
            return None;
        }
        self.slots.get_mut(slot)?.take().map(|record| record.waiter)
    }

    pub fn take_thread_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(SynchronousFileWaiter),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot
                .as_ref()
                .is_some_and(|record| record.waiter.tid == tid && !record.delivery_retained())
            {
                take(slot.take().unwrap().waiter);
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod typed_routes;

#[cfg(test)]
mod tests {
    use super::*;

    fn acknowledge_retry(
        table: &mut SynchronousFileWaitTable,
        slot: usize,
        file_id: u64,
        tid: u64,
    ) {
        let identity = table
            .retry_identity(slot, FileIoWaitKey::Hosted(file_id), tid)
            .unwrap();
        let mut attempt = table.begin_retry(identity).unwrap();
        table
            .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
            .unwrap();
        assert!(table.finish_retry(identity, Ok(())).unwrap());
    }

    fn waiter(file_id: u64, tid: u64, reply_cap: u64) -> SynchronousFileWaiter {
        SynchronousFileWaiter {
            route: FileIoWaitRoute::Hosted {
                file_id,
                device_id: 7,
                fs_context: 9,
            },
            handle: 0x40,
            granted_access: 3,
            service_number: 191,
            pi: 2,
            tid,
            badge: tid + 100,
            mode: FileIoMode::SynchronousNonAlertable,
            native_call_transport: false,
            reply_cap,
            retry_ip: 0x1000,
            resume_ip: 0x1002,
            resume_sp: 0x2000,
            resume_flags: 0x202,
            reply_mrs: [0; 18],
            state: SynchronousFileWaitState::Waiting,
            sequence: 0,
        }
    }

    #[test]
    fn waiters_are_fifo_even_when_low_slots_are_reused() {
        let mut table = SynchronousFileWaitTable::with_initial_reserve(2);
        table.reset();
        let first = table.park(waiter(10, 1, 101)).unwrap();
        let second = table.park(waiter(10, 2, 102)).unwrap();
        assert_eq!(
            table
                .oldest_waiting_for_file(FileIoWaitKey::Hosted(10))
                .unwrap()
                .1
                .tid,
            1
        );
        let one = table
            .promote_exact(first, FileIoWaitKey::Hosted(10), 1)
            .unwrap();
        assert_eq!(one.reply_cap, 101);
        acknowledge_retry(&mut table, first, 10, 1);
        assert_eq!(table.take_promoted(2, 1, 101, 191).unwrap().tid, 1);
        let third = table.park(waiter(10, 3, 103)).unwrap();
        assert_eq!(third, first, "the freed low slot is deliberately reused");
        assert_eq!(
            table
                .oldest_waiting_for_file(FileIoWaitKey::Hosted(10))
                .unwrap()
                .1
                .tid,
            2
        );
        assert_eq!(
            table
                .promote_exact(second, FileIoWaitKey::Hosted(10), 2)
                .unwrap()
                .tid,
            2
        );
    }

    #[test]
    fn promotion_and_retry_are_exact() {
        let mut table = SynchronousFileWaitTable::new();
        let slot = table.park(waiter(10, 1, 101)).unwrap();
        assert!(table.take_promoted(2, 1, 101, 191).is_none());
        assert!(table
            .promote_exact(slot, FileIoWaitKey::Hosted(11), 1)
            .is_none());
        table
            .promote_exact(slot, FileIoWaitKey::Hosted(10), 1)
            .unwrap();
        assert!(table.take_promoted(2, 1, 101, 191).is_none());
        acknowledge_retry(&mut table, slot, 10, 1);
        assert!(table.take_promoted(3, 1, 101, 191).is_none());
        assert!(table.take_promoted(2, 1, 102, 191).is_none());
        assert!(table.take_promoted(2, 1, 101, 192).is_none());
        let ready = table.take_promoted(2, 1, 101, 191).unwrap();
        assert_eq!(ready.key(), FileIoWaitKey::Hosted(10));
        assert!(table.is_empty());
    }

    #[test]
    fn native_service_zero_is_valid_and_exact_records_can_be_removed() {
        let mut table = SynchronousFileWaitTable::new();
        let mut zero = waiter(10, 1, 101);
        zero.service_number = 0;
        let slot = table.park(zero).unwrap();
        table
            .promote_exact(slot, FileIoWaitKey::Hosted(10), 1)
            .unwrap();
        acknowledge_retry(&mut table, slot, 10, 1);
        let replay = table.take_promoted(2, 1, 101, 0).unwrap();
        assert_eq!(replay.service_number, 0);
        assert_eq!(replay.route, zero.route);

        let slot = table.park(waiter(20, 2, 102)).unwrap();
        assert!(table
            .take_exact(slot, FileIoWaitKey::Hosted(20), 3)
            .is_none());
        assert_eq!(
            table
                .take_exact(slot, FileIoWaitKey::Hosted(20), 2)
                .unwrap()
                .reply_cap,
            102
        );
    }

    #[test]
    fn duplicate_thread_and_reply_owners_are_rejected() {
        let mut table = SynchronousFileWaitTable::new();
        table.park(waiter(10, 1, 101)).unwrap();
        assert!(table.park(waiter(20, 1, 102)).is_none());
        assert!(table.park(waiter(20, 2, 101)).is_none());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn teardown_collects_waiting_and_promoted_owners() {
        let mut table = SynchronousFileWaitTable::new();
        table.park(waiter(10, 1, 101)).unwrap();
        let slot = table.park(waiter(20, 2, 102)).unwrap();
        table
            .promote_exact(slot, FileIoWaitKey::Hosted(20), 2)
            .unwrap();
        acknowledge_retry(&mut table, slot, 20, 2);
        let mut taken = alloc::vec::Vec::new();
        assert_eq!(table.take_thread_with(2, |waiter| taken.push(waiter)), 1);
        assert_eq!(taken[0].state, SynchronousFileWaitState::Promoted);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn user_apc_selects_only_an_alertable_waiting_owner() {
        let mut table = SynchronousFileWaitTable::new();
        let mut alertable = waiter(10, 1, 101);
        alertable.mode = FileIoMode::SynchronousAlertable;
        let alertable_slot = table.park(alertable).unwrap();
        table.park(waiter(20, 2, 102)).unwrap();
        let mut promoted = waiter(30, 3, 103);
        promoted.mode = FileIoMode::SynchronousAlertable;
        let promoted_slot = table.park(promoted).unwrap();
        table
            .promote_exact(promoted_slot, FileIoWaitKey::Hosted(30), 3)
            .unwrap();

        assert!(table.alertable_waiting_for_thread(2).is_none());
        assert!(table.alertable_waiting_for_thread(3).is_none());
        let (slot, selected) = table.alertable_waiting_for_thread(1).unwrap();
        assert_eq!(slot, alertable_slot);
        assert_eq!(selected.resume_ip, 0x1002);
        assert!(table
            .take_alertable_waiting_exact(slot, FileIoWaitKey::Hosted(11), selected.tid)
            .is_none());
        assert_eq!(
            table
                .take_alertable_waiting_exact(slot, selected.key(), selected.tid)
                .unwrap(),
            selected
        );
        assert_eq!(table.len(), 2);
        assert_eq!(
            table
                .oldest_waiting_for_file(FileIoWaitKey::Hosted(20))
                .unwrap()
                .1
                .tid,
            2
        );
        assert!(table.alertable_waiting_for_thread(3).is_none());
    }
}
