//! Executive-owned continuations for `NtCancelIoFile` drain waits.
//!
//! Canonical IRP selection and cancellation remain in [`IoManager`](crate::IoManager). This table
//! owns only the transport state needed to resume one caller after the manager reports that its
//! exact File/thread IRP set has drained.

use alloc::vec::Vec;

pub const FILE_IRP_DRAIN_IOSB_PUBLISHED: u8 = 1 << 0;
pub const FILE_IRP_DRAIN_REPLY_CLAIMED: u8 = 1 << 1;
pub const FILE_IRP_DRAIN_REPLY_PUBLISHED: u8 = 1 << 2;

const FILE_IRP_DRAIN_REQUIRED: u8 =
    FILE_IRP_DRAIN_IOSB_PUBLISHED | FILE_IRP_DRAIN_REPLY_CLAIMED | FILE_IRP_DRAIN_REPLY_PUBLISHED;
const DEFAULT_INITIAL_RESERVE: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PendingFileIrpDrain {
    pub file_id: u64,
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    pub iosb_va: u64,
    pub reply_cap: u64,
    pub native_call_transport: bool,
    pub reply_mrs: [u64; 18],
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    pub delivery_state: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingFileIrpDrainReservation {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Debug)]
pub struct PendingFileIrpDrainTable {
    slots: Vec<Option<PendingFileIrpDrain>>,
    reservations: Vec<u64>,
    next_reservation_generation: u64,
    initial_reserve: usize,
}

impl Default for PendingFileIrpDrainTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingFileIrpDrainTable {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            reservations: Vec::new(),
            next_reservation_generation: 1,
            initial_reserve,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        let slot_reserve = if self.slots.capacity() == 0 {
            self.initial_reserve.max(1)
        } else {
            1
        };
        if self.slots.len() == self.slots.capacity()
            && self.slots.try_reserve(slot_reserve).is_err()
        {
            return false;
        }
        let generation_reserve = if self.reservations.capacity() == 0 {
            self.initial_reserve.max(1)
        } else {
            1
        };
        if self.reservations.len() == self.reservations.capacity()
            && self.reservations.try_reserve(generation_reserve).is_err()
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

    pub fn reserve(&mut self) -> Option<PendingFileIrpDrainReservation> {
        let slot = self
            .slots
            .iter()
            .zip(self.reservations.iter())
            .position(|(slot, generation)| slot.is_none() && *generation == 0)
            .or_else(|| {
                self.grow_reservation().then(|| {
                    self.slots.push(None);
                    self.reservations.push(0);
                    self.slots.len() - 1
                })
            })?;
        let generation = self.next_reservation_generation.max(1);
        self.next_reservation_generation = generation.wrapping_add(1).max(1);
        self.reservations[slot] = generation;
        Some(PendingFileIrpDrainReservation { slot, generation })
    }

    pub fn cancel_reservation(&mut self, reservation: PendingFileIrpDrainReservation) -> bool {
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
        reservation: PendingFileIrpDrainReservation,
        pending: PendingFileIrpDrain,
    ) -> Option<usize> {
        if self.reservations.get(reservation.slot).copied() != Some(reservation.generation)
            || self.slots.get(reservation.slot)?.is_some()
            || pending.file_id == 0
            || pending.tid == 0
            || pending.iosb_va == 0
            || pending.reply_cap == 0
            || pending.delivery_state != 0
            || self
                .slots
                .iter()
                .flatten()
                .any(|current| current.tid == pending.tid || current.reply_cap == pending.reply_cap)
        {
            return None;
        }
        self.slots[reservation.slot] = Some(pending);
        self.reservations[reservation.slot] = 0;
        Some(reservation.slot)
    }

    pub fn drain_all(&self) -> impl Iterator<Item = (usize, PendingFileIrpDrain)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, pending)| pending.map(|pending| (slot, pending)))
    }

    pub fn next_from(&self, start: usize) -> Option<(usize, PendingFileIrpDrain)> {
        self.slots
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(slot, pending)| pending.map(|pending| (slot, pending)))
    }

    pub fn get(&self, slot: usize) -> Option<PendingFileIrpDrain> {
        self.slots.get(slot).copied().flatten()
    }

    pub fn mark_iosb_published_exact(&mut self, slot: usize, file_id: u64, tid: u64) -> Option<u8> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.file_id != file_id || pending.tid != tid {
            return None;
        }
        pending.delivery_state |= FILE_IRP_DRAIN_IOSB_PUBLISHED;
        Some(pending.delivery_state)
    }

    /// Transfer the reply capability once. `Some(None)` means it was already claimed.
    pub fn claim_reply_cap_exact(
        &mut self,
        slot: usize,
        file_id: u64,
        tid: u64,
    ) -> Option<Option<u64>> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.file_id != file_id || pending.tid != tid {
            return None;
        }
        if pending.delivery_state & FILE_IRP_DRAIN_REPLY_CLAIMED != 0 {
            return Some(None);
        }
        let reply_cap = core::mem::replace(&mut pending.reply_cap, 0);
        pending.delivery_state |= FILE_IRP_DRAIN_REPLY_CLAIMED;
        Some(Some(reply_cap))
    }

    pub fn mark_reply_published_exact(
        &mut self,
        slot: usize,
        file_id: u64,
        tid: u64,
    ) -> Option<u8> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.file_id != file_id
            || pending.tid != tid
            || pending.delivery_state & FILE_IRP_DRAIN_REPLY_CLAIMED == 0
        {
            return None;
        }
        pending.delivery_state |= FILE_IRP_DRAIN_REPLY_PUBLISHED;
        Some(pending.delivery_state)
    }

    pub fn finish_exact(
        &mut self,
        slot: usize,
        file_id: u64,
        tid: u64,
    ) -> Option<PendingFileIrpDrain> {
        let entry = self.slots.get_mut(slot)?;
        if entry.is_some_and(|pending| {
            pending.file_id == file_id
                && pending.tid == tid
                && pending.delivery_state & FILE_IRP_DRAIN_REQUIRED == FILE_IRP_DRAIN_REQUIRED
        }) {
            entry.take()
        } else {
            None
        }
    }

    pub fn take_thread_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(PendingFileIrpDrain),
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

    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
            && self.reservations.iter().all(|generation| *generation == 0)
    }

    pub fn allocation_capacity(&self) -> (usize, usize) {
        (self.slots.capacity(), self.reservations.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(file_id: u64, tid: u64, reply_cap: u64) -> PendingFileIrpDrain {
        PendingFileIrpDrain {
            file_id,
            pi: 2,
            tid,
            badge: 4,
            iosb_va: 0x1000,
            reply_cap,
            ..PendingFileIrpDrain::default()
        }
    }

    #[test]
    fn reservation_is_generation_exact_and_reusable() {
        let mut table = PendingFileIrpDrainTable::with_initial_reserve(1);
        let stale = table.reserve().unwrap();
        assert!(table.cancel_reservation(stale));
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        assert!(table.park_reserved(stale, pending(10, 20, 30)).is_none());
        assert_eq!(table.park_reserved(current, pending(10, 20, 30)), Some(0));
    }

    #[test]
    fn duplicate_thread_or_reply_owner_is_rejected() {
        let mut table = PendingFileIrpDrainTable::new();
        let first = table.reserve().unwrap();
        assert!(table.park_reserved(first, pending(10, 20, 30)).is_some());
        let duplicate_thread = table.reserve().unwrap();
        assert!(table
            .park_reserved(duplicate_thread, pending(11, 20, 31))
            .is_none());
        assert!(table.cancel_reservation(duplicate_thread));
        let duplicate_reply = table.reserve().unwrap();
        assert!(table
            .park_reserved(duplicate_reply, pending(11, 21, 30))
            .is_none());
    }

    #[test]
    fn iosb_precedes_idempotent_reply_publication() {
        let mut table = PendingFileIrpDrainTable::new();
        let reservation = table.reserve().unwrap();
        let slot = table
            .park_reserved(reservation, pending(10, 20, 30))
            .unwrap();
        assert!(table.finish_exact(slot, 10, 20).is_none());
        assert_eq!(table.mark_iosb_published_exact(slot, 10, 20), Some(1));
        assert_eq!(table.claim_reply_cap_exact(slot, 10, 20), Some(Some(30)));
        assert_eq!(table.claim_reply_cap_exact(slot, 10, 20), Some(None));
        assert!(table.finish_exact(slot, 10, 20).is_none());
        assert!(table.mark_reply_published_exact(slot, 10, 20).is_some());
        assert_eq!(table.finish_exact(slot, 10, 20).unwrap().reply_cap, 0);
        assert!(table.is_empty());
    }

    #[test]
    fn teardown_returns_each_exact_owner_once() {
        let mut table = PendingFileIrpDrainTable::new();
        for (file_id, tid, cap) in [(10, 20, 30), (11, 21, 31), (12, 22, 32)] {
            let reservation = table.reserve().unwrap();
            table
                .park_reserved(reservation, pending(file_id, tid, cap))
                .unwrap();
        }
        let mut removed = alloc::vec::Vec::new();
        assert_eq!(table.take_thread_with(20, |entry| removed.push(entry)), 1);
        assert_eq!(
            table.take_thread_with(20, |_| panic!("owner removed twice")),
            0
        );
        assert_eq!(removed[0].reply_cap, 30);
        assert_eq!(table.len(), 2);
    }
}
