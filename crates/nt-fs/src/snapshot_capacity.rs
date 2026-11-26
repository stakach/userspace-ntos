//! Exact encoded-volume budget for a mounted snapshot slot.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{STATUS_ACCESS_DENIED, STATUS_DATA_ERROR, STATUS_DISK_FULL,
    STATUS_INSUFFICIENT_RESOURCES};

static NEXT_BUDGET_GENERATION: AtomicU64 = AtomicU64::new(1);

/// A move-only claim on snapshot capacity. Dropping it does not free its FileSystem-owned
/// charge: an uncertain native effect must retain capacity until an exact terminal outcome.
#[derive(Debug)]
pub struct SnapshotCapacityReservation {
    pub(super) generation: u64,
    pub(super) id: u64,
    pub(super) relative_path: String,
    pub(super) file_id: Option<u64>,
    pub(super) bytes_len: usize,
    pub(super) create_charge: usize,
    pub(super) append_charge: usize,
    pub(super) kind: SnapshotReservationKind,
    pub(super) replacement_base_cost: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SnapshotReservationKind { Append, Replacement }

struct ReservationCharge {
    id: u64,
    remaining: usize,
    relative_path: String,
    file_id: Option<u64>,
    kind: SnapshotReservationKind,
}

pub(super) struct SnapshotBudget {
    encoded_len: usize,
    capacity: usize,
    generation: u64,
    next_id: u64,
    reserved_total: usize,
    reservations: Vec<ReservationCharge>,
}

impl SnapshotBudget {
    pub(super) fn new(encoded_len: usize, capacity: usize) -> Result<Self, u32> {
        if encoded_len > capacity {
            return Err(STATUS_DISK_FULL);
        }
        let generation = NEXT_BUDGET_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| old.checked_add(1))
            .map_err(|_| STATUS_DATA_ERROR)?;
        Ok(Self {
            encoded_len, capacity, generation, next_id: 1, reserved_total: 0,
            reservations: Vec::new(),
        })
    }

    /// Compute the exact size after replacing one serialized contribution. The caller must
    /// publish this value only after the prepared mutation actually commits.
    pub(super) fn project(&self, old: usize, new: usize) -> Result<usize, u32> {
        let next = self.encoded_len.checked_sub(old)
            .and_then(|len| len.checked_add(new))
            .ok_or(STATUS_DATA_ERROR)?;
        if next.checked_add(self.reserved_total).is_none_or(|used| used > self.capacity) {
            return Err(STATUS_DISK_FULL);
        }
        Ok(next)
    }

    pub(super) fn reserve_append(
        &mut self, relative_path: String, file_id: Option<u64>, bytes_len: usize,
        create_charge: usize, append_charge: usize,
    ) -> Result<SnapshotCapacityReservation, u32> {
        self.reserve(relative_path, file_id, bytes_len, create_charge, append_charge,
            SnapshotReservationKind::Append, 0)
    }

    pub(super) fn reserve_replacement(
        &mut self, relative_path: String, file_id: u64, bytes_len: usize,
        base_cost: usize, charge: usize,
    ) -> Result<SnapshotCapacityReservation, u32> {
        self.reserve(relative_path, Some(file_id), bytes_len, 0, charge,
            SnapshotReservationKind::Replacement, base_cost)
    }

    fn reserve(
        &mut self, relative_path: String, file_id: Option<u64>, bytes_len: usize,
        create_charge: usize, append_charge: usize, kind: SnapshotReservationKind,
        replacement_base_cost: usize,
    ) -> Result<SnapshotCapacityReservation, u32> {
        if self.reservations.iter().any(|row| {
            row.relative_path.eq_ignore_ascii_case(&relative_path)
                || (file_id.is_some() && row.file_id == file_id)
        }) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let charge = create_charge.checked_add(append_charge).ok_or(STATUS_DATA_ERROR)?;
        let reserved = self.reserved_total.checked_add(charge).ok_or(STATUS_DATA_ERROR)?;
        if self.encoded_len.checked_add(reserved).is_none_or(|used| used > self.capacity) {
            return Err(STATUS_DISK_FULL);
        }
        let next_id = self.next_id.checked_add(1).ok_or(STATUS_DATA_ERROR)?;
        self.reservations.try_reserve_exact(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut row_path = String::new();
        row_path.try_reserve_exact(relative_path.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        row_path.push_str(&relative_path);
        let id = self.next_id;
        self.next_id = next_id;
        self.reserved_total = reserved;
        self.reservations.push(ReservationCharge {
            id, remaining: charge, relative_path: row_path, file_id, kind,
        });
        Ok(SnapshotCapacityReservation {
            generation: self.generation, id, relative_path, file_id, bytes_len,
            create_charge, append_charge, kind, replacement_base_cost,
        })
    }

    fn reservation(&self, token: &SnapshotCapacityReservation) -> Result<&ReservationCharge, u32> {
        if token.generation != self.generation { return Err(STATUS_DATA_ERROR); }
        self.reservations.iter().find(|row| row.id == token.id).ok_or(STATUS_DATA_ERROR)
    }

    pub(super) fn project_reserved(
        &self, token: &SnapshotCapacityReservation, old: usize, new: usize,
        consumed: usize,
    ) -> Result<usize, u32> {
        let row = self.reservation(token)?;
        if consumed > row.remaining { return Err(STATUS_DATA_ERROR); }
        let next = self.encoded_len.checked_sub(old)
            .and_then(|len| len.checked_add(new)).ok_or(STATUS_DATA_ERROR)?;
        let remaining = self.reserved_total.checked_sub(consumed).ok_or(STATUS_DATA_ERROR)?;
        if next.checked_add(remaining).is_none_or(|used| used > self.capacity) {
            return Err(STATUS_DISK_FULL);
        }
        Ok(next)
    }

    pub(super) fn update_replacement(
        &mut self, token: &SnapshotCapacityReservation, new_charge: usize,
    ) -> Result<(), u32> {
        if token.kind != SnapshotReservationKind::Replacement { return Err(STATUS_DATA_ERROR); }
        let row = self.reservation(token)?;
        if row.remaining != token.append_charge { return Err(STATUS_DATA_ERROR); }
        let remaining = self.reserved_total.checked_sub(row.remaining)
            .and_then(|total| total.checked_add(new_charge)).ok_or(STATUS_DATA_ERROR)?;
        if self.encoded_len.checked_add(remaining).is_none_or(|used| used > self.capacity) {
            return Err(STATUS_DISK_FULL);
        }
        let row = self.reservations.iter_mut().find(|row| row.id == token.id)
            .ok_or(STATUS_DATA_ERROR)?;
        row.remaining = new_charge;
        self.reserved_total = remaining;
        Ok(())
    }

    pub(super) fn publish_reserved(
        &mut self, token: &SnapshotCapacityReservation, next: usize, consumed: usize,
    ) {
        let row = self.reservations.iter_mut().find(|row| row.id == token.id)
            .expect("projected snapshot reservation");
        row.remaining -= consumed;
        self.reserved_total -= consumed;
        self.encoded_len = next;
    }

    pub(super) fn finish(&mut self, token: &SnapshotCapacityReservation) -> Result<(), u32> {
        let row = self.reservation(token)?;
        if row.remaining != 0 { return Err(STATUS_DATA_ERROR); }
        let index = self.reservations.iter().position(|row| row.id == token.id)
            .ok_or(STATUS_DATA_ERROR)?;
        self.reservations.remove(index);
        Ok(())
    }

    pub(super) fn cancel(&mut self, token: &SnapshotCapacityReservation) -> Result<(), u32> {
        let row = self.reservation(token)?;
        let remaining = row.remaining;
        let index = self.reservations.iter().position(|row| row.id == token.id)
            .ok_or(STATUS_DATA_ERROR)?;
        self.reservations.remove(index);
        self.reserved_total -= remaining;
        Ok(())
    }

    pub(super) fn owns(&self, token: &SnapshotCapacityReservation) -> bool {
        self.reservation(token).is_ok()
    }

    pub(super) fn replacement_targets(&self, file_id: u64) -> bool {
        self.reservations.iter().any(|row| {
            row.kind == SnapshotReservationKind::Replacement && row.file_id == Some(file_id)
        })
    }

    pub(super) fn replacement_file_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.reservations.iter().filter_map(|row| {
            (row.kind == SnapshotReservationKind::Replacement).then_some(row.file_id).flatten()
        })
    }

    pub(super) fn reserved_file(&self, file_id: u64) -> bool {
        self.reservations.iter().any(|row| row.file_id == Some(file_id))
    }

    pub(super) fn bind_created_file(&mut self, token: &SnapshotCapacityReservation,
        file_id: u64) -> Result<(), u32>
    {
        if token.kind != SnapshotReservationKind::Append || token.file_id.is_some() {
            return Err(STATUS_DATA_ERROR);
        }
        let row = self.reservations.iter_mut().find(|row| row.id == token.id)
            .ok_or(STATUS_DATA_ERROR)?;
        if row.file_id.is_some() { return Err(STATUS_DATA_ERROR); }
        row.file_id = Some(file_id);
        Ok(())
    }

    pub(super) fn reconcile_unpublished_replay(&mut self, actual: usize)
        -> Result<(), u32>
    {
        if !self.reservations.is_empty() { return Err(STATUS_DATA_ERROR); }
        if actual > self.capacity { return Err(STATUS_DISK_FULL); }
        self.encoded_len = actual;
        Ok(())
    }

    pub(super) fn publish(&mut self, encoded_len: usize) {
        self.encoded_len = encoded_len;
    }

    pub(super) fn encoded_len(&self) -> usize { self.encoded_len }

    pub(super) fn capacity(&self) -> usize { self.capacity }
}
