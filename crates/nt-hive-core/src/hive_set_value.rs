//! Exclusively borrowed, allocation-free publication of a prepared value edit.

use super::{Cell, CellId, Hive, Rc, RegistryValueType, String, ValueCell, Vec};

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
