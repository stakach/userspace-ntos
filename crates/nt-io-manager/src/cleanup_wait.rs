//! Executive continuations waiting for the final File cleanup lifecycle.
//!
//! Busy ordering and driver IRP ownership live in `nt-io-completion` and
//! [`IoManager`](crate::IoManager). This table owns only the syscall transport
//! continuation needed to keep `NtClose` blocked while the kernel close
//! procedure waits for CLEANUP/CLOSE.

use alloc::vec::Vec;

const DEFAULT_INITIAL_RESERVE: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PendingFileCleanupWait {
    pub file_id: u64,
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    pub reply_cap: u64,
    pub native_call_transport: bool,
    pub reply_mrs: [u64; 18],
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingFileCleanupWaitReservation {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Debug)]
pub struct PendingFileCleanupWaitTable {
    slots: Vec<Option<PendingFileCleanupWait>>,
    reservations: Vec<u64>,
    next_generation: u64,
    initial_reserve: usize,
}

impl Default for PendingFileCleanupWaitTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingFileCleanupWaitTable {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            reservations: Vec::new(),
            next_generation: 1,
            initial_reserve,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        let slots = if self.slots.capacity() == 0 {
            self.initial_reserve.max(1)
        } else {
            1
        };
        if self.slots.len() == self.slots.capacity() && self.slots.try_reserve(slots).is_err() {
            return false;
        }
        let reservations = if self.reservations.capacity() == 0 {
            self.initial_reserve.max(1)
        } else {
            1
        };
        if self.reservations.len() == self.reservations.capacity()
            && self.reservations.try_reserve(reservations).is_err()
        {
            return false;
        }
        true
    }

    pub fn reset(&mut self) -> bool {
        self.slots.clear();
        self.reservations.clear();
        if self.slots.capacity() < self.initial_reserve
            && self
                .slots
                .try_reserve(self.initial_reserve - self.slots.capacity())
                .is_err()
        {
            return false;
        }
        if self.reservations.capacity() < self.initial_reserve
            && self
                .reservations
                .try_reserve(self.initial_reserve - self.reservations.capacity())
                .is_err()
        {
            return false;
        }
        true
    }

    pub fn reserve(&mut self) -> Option<PendingFileCleanupWaitReservation> {
        let slot = self
            .slots
            .iter()
            .zip(self.reservations.iter())
            .position(|(entry, generation)| entry.is_none() && *generation == 0)
            .or_else(|| {
                self.grow_reservation().then(|| {
                    self.slots.push(None);
                    self.reservations.push(0);
                    self.slots.len() - 1
                })
            })?;
        let generation = self.next_generation.max(1);
        self.next_generation = generation.wrapping_add(1).max(1);
        self.reservations[slot] = generation;
        Some(PendingFileCleanupWaitReservation { slot, generation })
    }

    pub fn cancel_reservation(&mut self, reservation: PendingFileCleanupWaitReservation) -> bool {
        let Some(generation) = self.reservations.get_mut(reservation.slot) else {
            return false;
        };
        if *generation != reservation.generation || self.slots[reservation.slot].is_some() {
            return false;
        }
        *generation = 0;
        true
    }

    pub fn park_reserved(
        &mut self,
        reservation: PendingFileCleanupWaitReservation,
        pending: PendingFileCleanupWait,
    ) -> Option<usize> {
        if self.reservations.get(reservation.slot).copied() != Some(reservation.generation)
            || self.slots.get(reservation.slot)?.is_some()
            || pending.file_id == 0
            || pending.tid == 0
            || pending.badge == 0
            || pending.reply_cap == 0
            || pending.resume_sp == 0
            || self.slots.iter().flatten().any(|current| {
                current.file_id == pending.file_id
                    || current.tid == pending.tid
                    || current.reply_cap == pending.reply_cap
            })
        {
            return None;
        }
        self.slots[reservation.slot] = Some(pending);
        self.reservations[reservation.slot] = 0;
        Some(reservation.slot)
    }

    pub fn take_file(&mut self, file_id: u64) -> Option<PendingFileCleanupWait> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|pending| pending.file_id == file_id))?;
        slot.take()
    }

    pub fn take_thread_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(PendingFileCleanupWait),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|pending| pending.tid == tid) {
                take(slot.take().unwrap());
                count += 1;
            }
        }
        count
    }

    pub fn allocation_capacity(&self) -> (usize, usize) {
        (self.slots.capacity(), self.reservations.capacity())
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(file_id: u64, tid: u64, reply_cap: u64) -> PendingFileCleanupWait {
        PendingFileCleanupWait {
            file_id,
            pi: 2,
            tid,
            badge: tid + 100,
            reply_cap,
            resume_ip: 0x1002,
            resume_sp: 0x2000,
            resume_flags: 0x202,
            ..PendingFileCleanupWait::default()
        }
    }

    #[test]
    fn reservation_is_exact_and_cleanup_completes_by_file_generation() {
        let mut table = PendingFileCleanupWaitTable::with_initial_reserve(1);
        let stale = table.reserve().unwrap();
        assert!(table.cancel_reservation(stale));
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        assert!(table.park_reserved(stale, pending(10, 20, 30)).is_none());
        assert_eq!(table.park_reserved(current, pending(10, 20, 30)), Some(0));
        assert!(table.take_file(11).is_none());
        assert_eq!(table.take_file(10).unwrap().reply_cap, 30);
    }

    #[test]
    fn duplicate_file_thread_and_reply_owners_are_rejected() {
        let mut table = PendingFileCleanupWaitTable::new();
        let first = table.reserve().unwrap();
        table.park_reserved(first, pending(10, 20, 30)).unwrap();
        for duplicate in [
            pending(10, 21, 31),
            pending(11, 20, 31),
            pending(11, 21, 30),
        ] {
            let reservation = table.reserve().unwrap();
            assert!(table.park_reserved(reservation, duplicate).is_none());
            assert!(table.cancel_reservation(reservation));
        }
    }

    #[test]
    fn thread_teardown_drops_only_the_continuation() {
        let mut table = PendingFileCleanupWaitTable::new();
        for (file, tid, cap) in [(10, 20, 30), (11, 21, 31)] {
            let reservation = table.reserve().unwrap();
            table
                .park_reserved(reservation, pending(file, tid, cap))
                .unwrap();
        }
        let mut taken = Vec::new();
        assert_eq!(table.take_thread_with(20, |wait| taken.push(wait)), 1);
        assert_eq!(table.take_thread_with(20, |_| unreachable!()), 0);
        assert_eq!(taken[0].file_id, 10);
        assert_eq!(table.take_file(11).unwrap().tid, 21);
        assert!(table.take_file(11).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn reset_preserves_capacity_and_rejects_stale_reservations() {
        let mut table = PendingFileCleanupWaitTable::with_initial_reserve(4);
        let stale = table.reserve().unwrap();
        assert!(table.reset());
        assert!(table.allocation_capacity().0 >= 4);
        assert!(table.allocation_capacity().1 >= 4);
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        assert!(!table.cancel_reservation(stale));
        assert!(table.park_reserved(stale, pending(10, 20, 30)).is_none());
        assert_eq!(table.park_reserved(current, pending(10, 20, 30)), Some(0));
    }
}
