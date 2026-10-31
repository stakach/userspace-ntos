//! Retained, allocation-free publication of one durable key security descriptor.

use super::{CellId, HiveId, MutableHiveSet, Vec};
use crate::{try_encode_log_record, HiveLogOp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetKeySecurityError {
    KeyNotFound,
    KeyMustBeDurable,
    InsufficientResources,
    RetainedPublication,
}

/// Owns the exact descriptor and WAL record until the provider proves durable publication.
#[must_use = "the retained descriptor requires durable publication or pre-entry release"]
pub struct OwnedPreparedSetKeySecurity {
    hive_id: HiveId,
    owner: u64,
    key: CellId,
    sequence: u64,
    descriptor: Vec<u8>,
    record: Vec<u8>,
    entered: bool,
}

impl core::fmt::Debug for OwnedPreparedSetKeySecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedPreparedSetKeySecurity")
            .field("hive_id", &self.hive_id)
            .field("owner", &self.owner)
            .field("sequence", &self.sequence)
            .field("entered", &self.entered)
            .finish()
    }
}

impl OwnedPreparedSetKeySecurity {
    pub fn record(&self) -> &[u8] { &self.record }
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn hive_id(&self) -> HiveId { self.hive_id }

    /// # Safety
    /// The caller must prove that this exact record entered the bound physical WAL route.
    /// An uncertain entry retains ownership and forbids pre-entry release.
    pub unsafe fn mark_entered(&mut self) { self.entered = true; }
}

impl MutableHiveSet {
    /// Reserve an exact durable security edit while leaving the mounted hive unchanged.
    pub fn prepare_owned_set_key_security(
        &mut self,
        hive_id: HiveId,
        key: CellId,
        path: &str,
        descriptor: Vec<u8>,
    ) -> Result<OwnedPreparedSetKeySecurity, SetKeySecurityError> {
        if self.retained_value_owners.iter().any(|(id, _)| *id == hive_id) {
            return Err(SetKeySecurityError::RetainedPublication);
        }
        let hive = self.hives.iter().find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive).ok_or(SetKeySecurityError::KeyNotFound)?;
        if hive.pending_value_journal.is_some() {
            return Err(SetKeySecurityError::RetainedPublication);
        }
        if hive.open_key(path) != Some(key) {
            return Err(SetKeySecurityError::KeyNotFound);
        }
        if hive.is_volatile(key) {
            return Err(SetKeySecurityError::KeyMustBeDurable);
        }
        let sequence = hive.sequence.checked_add(1)
            .ok_or(SetKeySecurityError::InsufficientResources)?;
        let record = try_encode_log_record(
            &HiveLogOp::SetKeySecurityDescriptor { path, descriptor: &descriptor }, sequence,
        ).map_err(|_| SetKeySecurityError::InsufficientResources)?;
        let owner = self.reserve_retained_owner()
            .ok_or(SetKeySecurityError::InsufficientResources)?;
        self.retained_value_owners.push((hive_id, owner));
        Ok(OwnedPreparedSetKeySecurity {
            hive_id, owner, key, sequence, descriptor, record, entered: false,
        })
    }

    /// Release only when the provider proves no byte of the record entered its WAL route.
    pub fn release_unentered_owned_set_key_security(
        &mut self,
        prepared: OwnedPreparedSetKeySecurity,
    ) -> Result<(), (SetKeySecurityError, OwnedPreparedSetKeySecurity)> {
        let Some(index) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((SetKeySecurityError::RetainedPublication, prepared));
        };
        if prepared.entered {
            return Err((SetKeySecurityError::RetainedPublication, prepared));
        }
        self.retained_value_owners.remove(index);
        Ok(())
    }

    /// Publish only after the exact WAL marker and paired anchor are durable.
    ///
    /// # Safety
    /// The caller must consume an opaque receipt binding this record to the exact mounted
    /// hive/log identity after marker and both header barriers were acknowledged. A sequence
    /// alone is never proof. Wrong ownership or sequence returns the unchanged move-only edit.
    pub unsafe fn publish_owned_set_key_security_unchecked(
        &mut self,
        prepared: OwnedPreparedSetKeySecurity,
        durable_sequence: u64,
    ) -> Result<(), (SetKeySecurityError, OwnedPreparedSetKeySecurity)> {
        let Some(reservation) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((SetKeySecurityError::RetainedPublication, prepared));
        };
        if !prepared.entered || prepared.sequence != durable_sequence {
            return Err((SetKeySecurityError::RetainedPublication, prepared));
        }
        let Some(hive) = self.hives.iter_mut().find(|(id, _)| *id == prepared.hive_id)
            .map(|(_, hive)| hive) else {
            return Err((SetKeySecurityError::RetainedPublication, prepared));
        };
        if hive.sequence.checked_add(1) != Some(prepared.sequence)
            || hive.key(prepared.key).is_none_or(|key| key.volatile)
        {
            return Err((SetKeySecurityError::RetainedPublication, prepared));
        }
        let OwnedPreparedSetKeySecurity { key, sequence, descriptor, .. } = prepared;
        hive.key_mut(key).expect("retained key remains mounted").security_descriptor = Some(descriptor);
        hive.sequence = sequence;
        hive.mark_dirty(key);
        self.retained_value_owners.remove(reservation);
        Ok(())
    }
}
