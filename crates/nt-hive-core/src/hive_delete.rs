//! Retained durable deletion of a value or leaf key after an exact WAL anchor.

use super::{CellId, HiveId, MutableHiveSet, Vec};
use crate::{try_encode_log_record, HiveLogOp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteValueEditError {
    KeyNotFound,
    ValueNotFound,
    KeyMustBeDurable,
    InsufficientResources,
    RetainedPublication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteKeyEditError {
    NotFound,
    CannotDelete,
    KeyMustBeDurable,
    InsufficientResources,
    RetainedPublication,
}

/// Move-only value removal. No logical state changes while its WAL effect is pending.
#[must_use = "the retained deletion requires durable publication or pre-entry release"]
#[derive(Debug)]
pub struct OwnedPreparedDeleteValue {
    hive_id: HiveId,
    owner: u64,
    key: CellId,
    value: CellId,
    sequence: u64,
    record: Vec<u8>,
    entered: bool,
}

/// Move-only leaf removal, including its value cells.
#[must_use = "the retained deletion requires durable publication or pre-entry release"]
#[derive(Debug)]
pub struct OwnedPreparedDeleteKey {
    hive_id: HiveId,
    owner: u64,
    key: CellId,
    parent: CellId,
    sequence: u64,
    record: Vec<u8>,
    entered: bool,
}

impl OwnedPreparedDeleteValue {
    pub fn record(&self) -> &[u8] { &self.record }
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn hive_id(&self) -> HiveId { self.hive_id }

    /// # Safety
    /// Caller must prove this exact record entered its bound physical WAL route. An uncertain
    /// entry must retain the owner and must never be treated as a pre-entry release.
    pub unsafe fn mark_entered(&mut self) { self.entered = true; }
}

impl OwnedPreparedDeleteKey {
    pub fn record(&self) -> &[u8] { &self.record }
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn hive_id(&self) -> HiveId { self.hive_id }

    /// # Safety
    /// Caller must prove this exact record entered its bound physical WAL route. An uncertain
    /// entry must retain the owner and must never be treated as a pre-entry release.
    pub unsafe fn mark_entered(&mut self) { self.entered = true; }
}

impl MutableHiveSet {
    pub fn prepare_owned_delete_value(
        &mut self,
        hive_id: HiveId,
        key: CellId,
        path: &str,
        name: &str,
    ) -> Result<OwnedPreparedDeleteValue, DeleteValueEditError> {
        if self.has_retained_publication(hive_id) {
            return Err(DeleteValueEditError::RetainedPublication);
        }
        let hive = self.hives.iter().find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive).ok_or(DeleteValueEditError::KeyNotFound)?;
        if hive.pending_value_journal.is_some() {
            return Err(DeleteValueEditError::RetainedPublication);
        }
        if hive.open_key(path) != Some(key) {
            return Err(DeleteValueEditError::KeyNotFound);
        }
        if hive.is_volatile(key) {
            return Err(DeleteValueEditError::KeyMustBeDurable);
        }
        let value = hive.value_id_by_name(key, name)
            .ok_or(DeleteValueEditError::ValueNotFound)?;
        let sequence = hive.sequence.checked_add(1)
            .ok_or(DeleteValueEditError::InsufficientResources)?;
        let record = try_encode_log_record(&HiveLogOp::DeleteValue { path, name }, sequence)
            .map_err(|_| DeleteValueEditError::InsufficientResources)?;
        let owner = self.reserve_retained_owner()
            .ok_or(DeleteValueEditError::InsufficientResources)?;
        self.retained_value_owners.push((hive_id, owner));
        Ok(OwnedPreparedDeleteValue {
            hive_id, owner, key, value, sequence, record, entered: false,
        })
    }

    pub fn release_unentered_owned_delete_value(
        &mut self,
        prepared: OwnedPreparedDeleteValue,
    ) -> Result<(), (DeleteValueEditError, OwnedPreparedDeleteValue)> {
        let Some(index) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((DeleteValueEditError::RetainedPublication, prepared));
        };
        if prepared.entered {
            return Err((DeleteValueEditError::RetainedPublication, prepared));
        }
        self.retained_value_owners.remove(index);
        Ok(())
    }

    /// Publish after the exact WAL marker and paired anchor are durable.
    ///
    /// # Safety
    /// Caller must consume an opaque receipt binding this record and mounted hive/log identity
    /// after both anchor barriers. A sequence alone is never proof.
    pub unsafe fn publish_owned_delete_value_unchecked(
        &mut self,
        prepared: OwnedPreparedDeleteValue,
        durable_sequence: u64,
    ) -> Result<(), (DeleteValueEditError, OwnedPreparedDeleteValue)> {
        let Some(reservation) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((DeleteValueEditError::RetainedPublication, prepared));
        };
        if !prepared.entered || prepared.sequence != durable_sequence {
            return Err((DeleteValueEditError::RetainedPublication, prepared));
        }
        let Some(hive) = self.hives.iter_mut().find(|(id, _)| *id == prepared.hive_id)
            .map(|(_, hive)| hive) else {
            return Err((DeleteValueEditError::RetainedPublication, prepared));
        };
        if hive.sequence.checked_add(1) != Some(prepared.sequence)
            || hive.key(prepared.key).is_none_or(|key| !key.values.contains(&prepared.value))
            || hive.value(prepared.value).is_none_or(|value| value.parent_key != prepared.key)
        {
            return Err((DeleteValueEditError::RetainedPublication, prepared));
        }
        let OwnedPreparedDeleteValue { key, value, sequence, .. } = prepared;
        let parent = hive.key_mut(key).expect("retained key remains mounted");
        let position = parent.values.iter().position(|id| *id == value)
            .expect("retained value remains linked");
        parent.values.remove(position);
        parent.last_write_sequence = sequence;
        hive.cells[value.0 as usize] = None;
        hive.sequence = sequence;
        hive.mark_dirty(key);
        hive.mark_dirty(value);
        self.retained_value_owners.remove(reservation);
        Ok(())
    }

    pub fn prepare_owned_delete_key(
        &mut self,
        hive_id: HiveId,
        key: CellId,
        path: &str,
    ) -> Result<OwnedPreparedDeleteKey, DeleteKeyEditError> {
        if self.has_retained_publication(hive_id) {
            return Err(DeleteKeyEditError::RetainedPublication);
        }
        let hive = self.hives.iter().find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive).ok_or(DeleteKeyEditError::NotFound)?;
        if hive.pending_value_journal.is_some() {
            return Err(DeleteKeyEditError::RetainedPublication);
        }
        if key == hive.root() {
            return Err(DeleteKeyEditError::CannotDelete);
        }
        if hive.open_key(path) != Some(key) {
            return Err(DeleteKeyEditError::NotFound);
        }
        let cell = hive.key(key).ok_or(DeleteKeyEditError::NotFound)?;
        if !cell.subkeys.is_empty() || cell.parent.is_none() {
            return Err(DeleteKeyEditError::CannotDelete);
        }
        if cell.volatile {
            return Err(DeleteKeyEditError::KeyMustBeDurable);
        }
        let parent = cell.parent.unwrap();
        if hive.key(parent).is_none_or(|parent_cell| !parent_cell.subkeys.contains(&key)) {
            return Err(DeleteKeyEditError::NotFound);
        }
        let sequence = hive.sequence.checked_add(1)
            .ok_or(DeleteKeyEditError::InsufficientResources)?;
        let record = try_encode_log_record(&HiveLogOp::DeleteKey { path }, sequence)
            .map_err(|_| DeleteKeyEditError::InsufficientResources)?;
        let owner = self.reserve_retained_owner()
            .ok_or(DeleteKeyEditError::InsufficientResources)?;
        self.retained_value_owners.push((hive_id, owner));
        Ok(OwnedPreparedDeleteKey {
            hive_id, owner, key, parent, sequence, record, entered: false,
        })
    }

    pub fn release_unentered_owned_delete_key(
        &mut self,
        prepared: OwnedPreparedDeleteKey,
    ) -> Result<(), (DeleteKeyEditError, OwnedPreparedDeleteKey)> {
        let Some(index) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((DeleteKeyEditError::RetainedPublication, prepared));
        };
        if prepared.entered {
            return Err((DeleteKeyEditError::RetainedPublication, prepared));
        }
        self.retained_value_owners.remove(index);
        Ok(())
    }

    /// Publish after the exact WAL marker and paired anchor are durable.
    ///
    /// # Safety
    /// Caller must consume an opaque receipt binding this record and mounted hive/log identity
    /// after both anchor barriers. A sequence alone is never proof.
    pub unsafe fn publish_owned_delete_key_unchecked(
        &mut self,
        prepared: OwnedPreparedDeleteKey,
        durable_sequence: u64,
    ) -> Result<(), (DeleteKeyEditError, OwnedPreparedDeleteKey)> {
        let Some(reservation) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((DeleteKeyEditError::RetainedPublication, prepared));
        };
        if !prepared.entered || prepared.sequence != durable_sequence {
            return Err((DeleteKeyEditError::RetainedPublication, prepared));
        }
        let Some(hive) = self.hives.iter_mut().find(|(id, _)| *id == prepared.hive_id)
            .map(|(_, hive)| hive) else {
            return Err((DeleteKeyEditError::RetainedPublication, prepared));
        };
        if hive.sequence.checked_add(1) != Some(prepared.sequence)
            || hive.key(prepared.key).is_none_or(|key|
                key.parent != Some(prepared.parent) || !key.subkeys.is_empty() || key.volatile)
            || hive.key(prepared.parent).is_none_or(|parent|
                !parent.subkeys.contains(&prepared.key))
        {
            return Err((DeleteKeyEditError::RetainedPublication, prepared));
        }
        let OwnedPreparedDeleteKey { key, parent, sequence, .. } = prepared;
        // The key's values vector is moved out before changing any cells; publication allocates
        // nothing and consumes no fallible provider effect.
        let value_ids = core::mem::take(&mut hive.key_mut(key).expect("retained leaf remains mounted").values);
        hive.key_mut(parent).expect("retained parent remains mounted")
            .subkeys.retain(|child| *child != key);
        hive.key_mut(parent).expect("retained parent remains mounted").last_write_sequence = sequence;
        hive.sequence = sequence;
        for value in value_ids {
            hive.cells[value.0 as usize] = None;
            hive.mark_dirty(value);
        }
        hive.cells[key.0 as usize] = None;
        hive.mark_dirty(parent);
        hive.mark_dirty(key);
        self.retained_value_owners.remove(reservation);
        Ok(())
    }
}
