//! FIFO ownership for syscalls waiting to acquire a synchronous FILE_OBJECT.
//!
//! The File policy table owns Busy and the waiter count. This table owns the exact executive
//! continuation and the already-referenced canonical File route, so a concurrent handle close
//! cannot invalidate an operation that passed object-manager lookup before it blocked.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SynchronousFileWaitState {
    #[default]
    Waiting,
    Promoted,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SynchronousFileWaiter {
    pub file_id: u64,
    pub device_id: u64,
    pub fs_context: u64,
    pub handle: u32,
    pub granted_access: u32,
    pub service_number: u32,
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    pub alertable: bool,
    pub native_call_transport: bool,
    pub reply_cap: u64,
    /// Address of the x64 `syscall` instruction used to replay the captured native call.
    pub retry_ip: u64,
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
        file_id: u64,
        device_id: u64,
        fs_context: u64,
        handle: u32,
        granted_access: u32,
        service_number: u32,
        pi: u32,
        tid: u64,
        badge: u64,
        alertable: bool,
        native_call_transport: bool,
        retry_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
    ) -> Self {
        Self {
            file_id,
            device_id,
            fs_context,
            handle,
            granted_access,
            service_number,
            pi,
            tid,
            badge,
            alertable,
            native_call_transport,
            reply_cap: 0,
            retry_ip,
            resume_sp,
            resume_flags,
            reply_mrs: [0; 18],
            state: SynchronousFileWaitState::Waiting,
            sequence: 0,
        }
    }
}

const DEFAULT_INITIAL_RESERVE: usize = 16;

#[derive(Clone, Debug)]
pub struct SynchronousFileWaitTable {
    slots: Vec<Option<SynchronousFileWaiter>>,
    initial_reserve: usize,
    next_sequence: u64,
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
        self.slots.clear();
        self.next_sequence = 1;
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
        if waiter.file_id == 0
            || waiter.device_id == 0
            || waiter.handle == 0
            || waiter.tid == 0
            || waiter.badge == 0
            || waiter.reply_cap == 0
            || (!waiter.native_call_transport && waiter.retry_ip == 0)
            || waiter.resume_sp == 0
            || waiter.state != SynchronousFileWaitState::Waiting
            || self.slots.iter().any(|slot| {
                slot.is_some_and(|record| {
                    record.tid == waiter.tid || record.reply_cap == waiter.reply_cap
                })
            })
        {
            return None;
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1)?;
        waiter.sequence = sequence;
        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(waiter);
            return Some(index);
        }
        if !self.grow_reservation() {
            return None;
        }
        self.slots.push(Some(waiter));
        Some(self.slots.len() - 1)
    }

    pub fn oldest_waiting_for_file(&self, file_id: u64) -> Option<(usize, SynchronousFileWaiter)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, waiter)| waiter.map(|waiter| (slot, waiter)))
            .filter(|(_, waiter)| {
                waiter.file_id == file_id && waiter.state == SynchronousFileWaitState::Waiting
            })
            .min_by_key(|(_, waiter)| waiter.sequence)
    }

    /// Mark one exact FIFO waiter as the promoted Busy owner. Reply ownership remains on the
    /// record until the executive has made the retry visible.
    pub fn promote_exact(
        &mut self,
        slot: usize,
        file_id: u64,
        tid: u64,
    ) -> Option<SynchronousFileWaiter> {
        let waiter = self.slots.get_mut(slot)?.as_mut()?;
        if waiter.file_id != file_id
            || waiter.tid != tid
            || waiter.state != SynchronousFileWaitState::Waiting
            || waiter.reply_cap == 0
        {
            return None;
        }
        waiter.state = SynchronousFileWaitState::Promoted;
        Some(*waiter)
    }

    pub fn mark_retry_replied_exact(&mut self, slot: usize, file_id: u64, tid: u64) -> Option<()> {
        let waiter = self.slots.get_mut(slot)?.as_mut()?;
        if waiter.file_id != file_id
            || waiter.tid != tid
            || waiter.state != SynchronousFileWaitState::Promoted
            || waiter.reply_cap == 0
        {
            return None;
        }
        waiter.reply_cap = 0;
        Some(())
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
            slot.is_some_and(|waiter| {
                waiter.pi == pi
                    && waiter.tid == tid
                    && waiter.badge == badge
                    && waiter.service_number == service_number
                    && waiter.state == SynchronousFileWaitState::Promoted
                    && waiter.reply_cap == 0
            })
        })?;
        slot.take()
    }

    pub fn take_exact(
        &mut self,
        slot: usize,
        file_id: u64,
        tid: u64,
    ) -> Option<SynchronousFileWaiter> {
        let waiter = self.slots.get(slot)?.as_ref()?;
        if waiter.file_id != file_id || waiter.tid != tid {
            return None;
        }
        self.slots.get_mut(slot)?.take()
    }

    pub fn take_thread_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(SynchronousFileWaiter),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|waiter| waiter.tid == tid) {
                take(slot.take().unwrap());
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiter(file_id: u64, tid: u64, reply_cap: u64) -> SynchronousFileWaiter {
        SynchronousFileWaiter {
            file_id,
            device_id: 7,
            fs_context: 9,
            handle: 0x40,
            granted_access: 3,
            service_number: 191,
            pi: 2,
            tid,
            badge: tid + 100,
            alertable: false,
            native_call_transport: false,
            reply_cap,
            retry_ip: 0x1000,
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
        assert_eq!(table.oldest_waiting_for_file(10).unwrap().1.tid, 1);
        let one = table.promote_exact(first, 10, 1).unwrap();
        assert_eq!(one.reply_cap, 101);
        table.mark_retry_replied_exact(first, 10, 1).unwrap();
        assert_eq!(table.take_promoted(2, 1, 101, 191).unwrap().tid, 1);
        let third = table.park(waiter(10, 3, 103)).unwrap();
        assert_eq!(third, first, "the freed low slot is deliberately reused");
        assert_eq!(table.oldest_waiting_for_file(10).unwrap().1.tid, 2);
        assert_eq!(table.promote_exact(second, 10, 2).unwrap().tid, 2);
    }

    #[test]
    fn promotion_and_retry_are_exact() {
        let mut table = SynchronousFileWaitTable::new();
        let slot = table.park(waiter(10, 1, 101)).unwrap();
        assert!(table.take_promoted(2, 1, 101, 191).is_none());
        assert!(table.promote_exact(slot, 11, 1).is_none());
        table.promote_exact(slot, 10, 1).unwrap();
        assert!(table.take_promoted(2, 1, 101, 191).is_none());
        table.mark_retry_replied_exact(slot, 10, 1).unwrap();
        assert!(table.take_promoted(3, 1, 101, 191).is_none());
        assert!(table.take_promoted(2, 1, 102, 191).is_none());
        assert!(table.take_promoted(2, 1, 101, 192).is_none());
        let ready = table.take_promoted(2, 1, 101, 191).unwrap();
        assert_eq!(ready.file_id, 10);
        assert!(table.is_empty());
    }

    #[test]
    fn native_service_zero_is_valid_and_exact_records_can_be_removed() {
        let mut table = SynchronousFileWaitTable::new();
        let mut zero = waiter(10, 1, 101);
        zero.service_number = 0;
        let slot = table.park(zero).unwrap();
        table.promote_exact(slot, 10, 1).unwrap();
        table.mark_retry_replied_exact(slot, 10, 1).unwrap();
        let replay = table.take_promoted(2, 1, 101, 0).unwrap();
        assert_eq!(replay.service_number, 0);
        assert_eq!(replay.file_id, zero.file_id);

        let slot = table.park(waiter(20, 2, 102)).unwrap();
        assert!(table.take_exact(slot, 20, 3).is_none());
        assert_eq!(table.take_exact(slot, 20, 2).unwrap().reply_cap, 102);
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
        table.promote_exact(slot, 20, 2).unwrap();
        table.mark_retry_replied_exact(slot, 20, 2).unwrap();
        let mut taken = alloc::vec::Vec::new();
        assert_eq!(table.take_thread_with(2, |waiter| taken.push(waiter)), 1);
        assert_eq!(taken[0].state, SynchronousFileWaitState::Promoted);
        assert_eq!(table.len(), 1);
    }
}
