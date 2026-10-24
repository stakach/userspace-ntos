//! Exclusively borrowed, allocation-free publication of a prepared value edit.

use super::{Cell, CellId, Hive, HiveId, MutableHiveSet, Rc, RegistryValueType, String, ValueCell, Vec};
use crate::{try_encode_log_record, HiveLogOp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetValueError {
    KeyNotFound,
    InsufficientResources,
    RetainedPublication,
}

enum PreparedBlob {
    Existing(usize),
    New(Rc<Vec<u8>>),
}

enum PreparedCell {
    Existing(CellId),
    New {
        value: ValueCell,
        new_len: usize,
        next_id: u64,
    },
}

/// Owns all resources for one value edit while excluding any intervening hive mutation.
///
/// Dropping this object abandons the edit. Reservation may grow physical storage capacity,
/// but no cell, value link, payload-directory entry, counter or dirty state is published.
#[must_use = "the value edit is only published by commit"]
pub struct PreparedSetValue<'a> {
    hive: &'a mut Hive,
    key: CellId,
    value_type: RegistryValueType,
    sequence: u64,
    blob: PreparedBlob,
    cell: PreparedCell,
}

/// Move-only value edit retained while the provider's WAL and anchor become durable.
/// The mounted hive remains readable; its exact slot refuses mutation or replacement.
#[must_use = "the retained value requires durable publication or pre-entry release"]
pub struct OwnedPreparedSetValue {
    hive_id: HiveId,
    owner: u64,
    key: CellId,
    value_type: RegistryValueType,
    sequence: u64,
    blob: PreparedBlob,
    cell: PreparedCell,
    record: Vec<u8>,
    entered: bool,
}

impl core::fmt::Debug for OwnedPreparedSetValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedPreparedSetValue")
            .field("hive_id", &self.hive_id)
            .field("owner", &self.owner)
            .field("sequence", &self.sequence)
            .field("entered", &self.entered)
            .finish()
    }
}

impl OwnedPreparedSetValue {
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn record(&self) -> &[u8] { &self.record }
    pub fn hive_id(&self) -> HiveId { self.hive_id }
    /// # Safety
    /// The caller must own proof that this exact record entered its physical WAL route.
    /// An uncertain effect must retain this owner and must never call pre-entry release.
    pub unsafe fn mark_entered(&mut self) { self.entered = true; }
}

impl MutableHiveSet {
    /// Reserve the exact mounted hive and every publication allocation before WAL entry.
    pub fn prepare_owned_set_value(
        &mut self,
        hive_id: HiveId,
        key: CellId,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> Result<OwnedPreparedSetValue, SetValueError> {
        if self.retained_value_owners.iter().any(|(id, _)| *id == hive_id) {
            return Err(SetValueError::RetainedPublication);
        }
        let owner = self.next_value_owner;
        let next_owner = owner.checked_add(1).ok_or(SetValueError::InsufficientResources)?;
        self.retained_value_owners.try_reserve(1)
            .map_err(|_| SetValueError::InsufficientResources)?;
        let hive = self.hives.iter_mut().find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive).ok_or(SetValueError::KeyNotFound)?;
        if hive.open_key(path) != Some(key) {
            return Err(SetValueError::KeyNotFound);
        }
        let sequence = hive.sequence.checked_add(1).ok_or(SetValueError::InsufficientResources)?;
        let record = try_encode_log_record(
            &HiveLogOp::SetValue { path, name, value_type, data: &data }, sequence,
        ).map_err(|_| SetValueError::InsufficientResources)?;
        let prepared = hive.try_prepare_set_value(key, name, value_type, data)?;
        let PreparedSetValue { hive: _, key, value_type, sequence: prepared_sequence, blob, cell } = prepared;
        if prepared_sequence != sequence {
            return Err(SetValueError::InsufficientResources);
        }
        self.retained_value_owners.push((hive_id, owner));
        self.next_value_owner = next_owner;
        Ok(OwnedPreparedSetValue {
            hive_id, owner, key, value_type, sequence, blob, cell, record, entered: false,
        })
    }

    /// A pre-entry refusal can release the reservation. Entered effects remain pinned.
    pub fn release_unentered_owned_set_value(
        &mut self,
        prepared: OwnedPreparedSetValue,
    ) -> Result<(), (SetValueError, OwnedPreparedSetValue)> {
        let Some(index) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((SetValueError::RetainedPublication, prepared));
        };
        if prepared.entered {
            return Err((SetValueError::RetainedPublication, prepared));
        }
        self.retained_value_owners.remove(index);
        Ok(())
    }

    /// Publish after the exact native WAL marker and paired anchor are acknowledged.
    ///
    /// # Safety
    /// `durable_sequence` alone is not proof. The caller must consume an opaque receipt
    /// issued by the retained WAL owner after the exact marker and both header barriers
    /// completed and were acknowledged. The receipt must bind `prepared.record()` and its
    /// exact mounted hive/log identity. No replay or duplicate publication is permitted.
    /// A wrong sequence or owner returns the same move-only edit without changing the hive.
    pub unsafe fn publish_owned_set_value_unchecked(
        &mut self,
        prepared: OwnedPreparedSetValue,
        durable_sequence: u64,
    ) -> Result<CellId, (SetValueError, OwnedPreparedSetValue)> {
        let Some(reservation) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((SetValueError::RetainedPublication, prepared));
        };
        if !prepared.entered || prepared.sequence != durable_sequence {
            return Err((SetValueError::RetainedPublication, prepared));
        }
        let Some(hive) = self.hives.iter_mut().find(|(id, _)| *id == prepared.hive_id)
            .map(|(_, hive)| hive) else {
            return Err((SetValueError::RetainedPublication, prepared));
        };
        if hive.sequence.checked_add(1) != Some(prepared.sequence) {
            return Err((SetValueError::RetainedPublication, prepared));
        }
        let OwnedPreparedSetValue { key, value_type, sequence, blob, cell, .. } = prepared;
        let value = PreparedSetValue { hive, key, value_type, sequence, blob, cell }.commit();
        self.retained_value_owners.remove(reservation);
        Ok(value)
    }
}

impl Hive {
    /// Prepare a create or replacement without changing logical hive state.
    ///
    /// Name matching and payload interning retain `set_value` semantics. A replacement retains
    /// the original spelling and cell identity. All fallible storage growth and checked counters
    /// precede publication. The small `Rc` control block uses Rust's infallible allocator API,
    /// so allocator exhaustion there aborts during preparation, never during commit.
    pub fn try_prepare_set_value(
        &mut self,
        key: CellId,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> Result<PreparedSetValue<'_>, SetValueError> {
        if self.pending_value_journal.is_some() {
            return Err(SetValueError::RetainedPublication);
        }
        usize::try_from(key.0).map_err(|_| SetValueError::KeyNotFound)?;
        let parent = self.key(key).ok_or(SetValueError::KeyNotFound)?;
        let sequence = self
            .sequence
            .checked_add(u64::from(!parent.volatile))
            .ok_or(SetValueError::InsufficientResources)?;
        let existing = self.value_id_by_name(key, name);
        let existing_blob = self
            .value_blobs
            .iter()
            .position(|blob| blob.as_slice() == data.as_slice());
        let data_blob = existing_blob.unwrap_or(self.value_blobs.len());

        let cell = if let Some(id) = existing {
            PreparedCell::Existing(id)
        } else {
            let index =
                usize::try_from(self.next_id).map_err(|_| SetValueError::InsufficientResources)?;
            let new_len = index
                .checked_add(1)
                .ok_or(SetValueError::InsufficientResources)?;
            let next_id = self
                .next_id
                .checked_add(1)
                .ok_or(SetValueError::InsufficientResources)?;
            if index < self.cells.len() {
                return Err(SetValueError::InsufficientResources);
            }
            let mut owned_name = String::new();
            owned_name
                .try_reserve_exact(name.len())
                .map_err(|_| SetValueError::InsufficientResources)?;
            owned_name.push_str(name);
            self.cells
                .try_reserve(new_len - self.cells.len())
                .map_err(|_| SetValueError::InsufficientResources)?;
            self.key_mut(key)
                .expect("validated key remains exclusively borrowed")
                .values
                .try_reserve(1)
                .map_err(|_| SetValueError::InsufficientResources)?;
            PreparedCell::New {
                value: ValueCell {
                    id: CellId(self.next_id),
                    parent_key: key,
                    name: owned_name,
                    value_type,
                    data_blob,
                    last_write_sequence: sequence,
                },
                new_len,
                next_id,
            }
        };
        let blob = match existing_blob {
            Some(index) => PreparedBlob::Existing(index),
            None => {
                self.value_blobs
                    .try_reserve(1)
                    .map_err(|_| SetValueError::InsufficientResources)?;
                PreparedBlob::New(Rc::new(data))
            }
        };
        Ok(PreparedSetValue {
            hive: self,
            key,
            value_type,
            sequence,
            blob,
            cell,
        })
    }
}

impl PreparedSetValue<'_> {
    pub(crate) fn begin_journal(&mut self, sequence: u64, record: Vec<u8>) {
        assert!(self.hive.pending_value_journal.is_none());
        self.hive.pending_value_journal = Some(super::PendingHiveValueJournal {
            sequence,
            phase: super::HiveValueJournalPhase::AppendEntered,
            record,
        });
    }

    pub(crate) fn journal_record(&self) -> &[u8] {
        &self
            .hive
            .pending_value_journal
            .as_ref()
            .expect("journal owner installed")
            .record
    }

    pub(crate) fn enter_journal_flush(&mut self) {
        self.hive
            .pending_value_journal
            .as_mut()
            .expect("journal owner installed")
            .phase = super::HiveValueJournalPhase::FlushEntered;
    }

    /// Publish the already-reserved edit exactly once, without allocating or returning an error.
    pub fn commit(self) -> CellId {
        let Self {
            hive,
            key,
            value_type,
            sequence,
            blob,
            cell,
        } = self;
        let data_blob = match blob {
            PreparedBlob::Existing(index) => index,
            PreparedBlob::New(data) => {
                let index = hive.value_blobs.len();
                hive.value_blobs.push(data);
                index
            }
        };
        let created = matches!(&cell, PreparedCell::New { .. });
        let id = match cell {
            PreparedCell::Existing(id) => {
                let Some(Cell::Value(value)) = hive.cells[id.0 as usize].as_mut() else {
                    unreachable!("prepared value remains exclusively borrowed")
                };
                value.value_type = value_type;
                value.data_blob = data_blob;
                value.last_write_sequence = sequence;
                id
            }
            PreparedCell::New {
                value,
                new_len,
                next_id,
            } => {
                let id = value.id;
                hive.cells.resize_with(new_len, || None);
                hive.cells[id.0 as usize] = Some(Cell::Value(value));
                hive.key_mut(key)
                    .expect("prepared key remains exclusively borrowed")
                    .values
                    .push(id);
                hive.next_id = next_id;
                id
            }
        };
        hive.sequence = sequence;
        if created {
            hive.mark_dirty(key);
        }
        hive.mark_dirty(id);
        id
    }
}

#[cfg(test)]
#[path = "hive_set_value_tests.rs"]
mod tests;
