//! Checked single-child publication for callers that already assigned and authorized security.

use super::{Cell, CellId, HiveId, HiveTransaction, KeyCell, MutableHiveSet, String, Vec};
use crate::{try_encode_log_record, HiveLogOp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateChildError {
    InvalidName,
    ParentNotFound,
    NameCollision,
    EmptySecurityDescriptor,
    InsufficientResources,
    ChildMustBeVolatile,
    RetainedPublication,
}

/// Move-only child edit retained across the exact provider WAL effect. Preparing may grow
/// capacity but leaves all logical cells, links, counters, and dirty state unchanged.
#[must_use = "the retained child requires durable publication or pre-entry release"]
pub struct OwnedPreparedCreateChild {
    hive_id: HiveId,
    owner: u64,
    parent: CellId,
    child: KeyCell,
    new_len: usize,
    next_id: u64,
    sequence: u64,
    record: Vec<u8>,
    entered: bool,
}

impl core::fmt::Debug for OwnedPreparedCreateChild {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedPreparedCreateChild")
            .field("hive_id", &self.hive_id)
            .field("owner", &self.owner)
            .field("sequence", &self.sequence)
            .field("entered", &self.entered)
            .finish()
    }
}

impl OwnedPreparedCreateChild {
    pub fn record(&self) -> &[u8] { &self.record }
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn hive_id(&self) -> HiveId { self.hive_id }

    /// # Safety
    /// The caller must own proof that this exact record entered its physical WAL route.
    /// An uncertain effect must retain this owner and must never call pre-entry release.
    pub unsafe fn mark_entered(&mut self) { self.entered = true; }
}

impl MutableHiveSet {
    /// Reserve one absent durable child and its exact log record before physical entry.
    pub fn prepare_owned_create_child(
        &mut self,
        hive_id: HiveId,
        parent: CellId,
        parent_path: &str,
        name: &str,
        class_name: Option<&str>,
        descriptor: Vec<u8>,
    ) -> Result<OwnedPreparedCreateChild, CreateChildError> {
        if self.retained_value_owners.iter().any(|(id, _)| *id == hive_id) {
            return Err(CreateChildError::RetainedPublication);
        }
        let owner = self.reserve_retained_owner().ok_or(CreateChildError::InsufficientResources)?;
        let hive = self.hives.iter_mut().find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive).ok_or(CreateChildError::ParentNotFound)?;
        if hive.pending_value_journal.is_some() {
            return Err(CreateChildError::RetainedPublication);
        }
        if name.is_empty() || name.contains(['\\', '\0']) {
            return Err(CreateChildError::InvalidName);
        }
        if hive.open_key(parent_path) != Some(parent) {
            return Err(CreateChildError::ParentNotFound);
        }
        let parent_cell = hive.key(parent).ok_or(CreateChildError::ParentNotFound)?;
        if parent_cell.volatile {
            return Err(CreateChildError::ChildMustBeVolatile);
        }
        if hive.open_subkey(parent, name).is_some() {
            return Err(CreateChildError::NameCollision);
        }
        if descriptor.is_empty() {
            return Err(CreateChildError::EmptySecurityDescriptor);
        }
        let index = usize::try_from(hive.next_id)
            .map_err(|_| CreateChildError::InsufficientResources)?;
        let new_len = index.checked_add(1).ok_or(CreateChildError::InsufficientResources)?;
        let next_id = hive.next_id.checked_add(1).ok_or(CreateChildError::InsufficientResources)?;
        let sequence = hive.sequence.checked_add(1).ok_or(CreateChildError::InsufficientResources)?;
        if index < hive.cells.len() {
            return Err(CreateChildError::InsufficientResources);
        }
        let record = try_encode_log_record(&HiveLogOp::CreateChild {
            parent: parent_path, name, class_name, descriptor: &descriptor,
        }, sequence).map_err(|_| CreateChildError::InsufficientResources)?;
        let child = KeyCell {
            kind: super::KeyKind::Ordinary,
            id: CellId(hive.next_id),
            parent: Some(parent),
            name: copy_string(name)?,
            subkeys: Vec::new(),
            values: Vec::new(),
            class_name: class_name.map(copy_string).transpose()?,
            security_descriptor: Some(descriptor),
            last_write_sequence: sequence,
            volatile: false,
        };
        hive.cells.try_reserve(new_len - hive.cells.len())
            .map_err(|_| CreateChildError::InsufficientResources)?;
        hive.key_mut(parent).expect("validated parent remains mounted").subkeys.try_reserve(1)
            .map_err(|_| CreateChildError::InsufficientResources)?;
        self.retained_value_owners.push((hive_id, owner));
        Ok(OwnedPreparedCreateChild {
            hive_id, owner, parent, child, new_len, next_id, sequence, record, entered: false,
        })
    }

    /// Release only when no byte of the exact record entered the physical WAL route.
    pub fn release_unentered_owned_create_child(
        &mut self,
        prepared: OwnedPreparedCreateChild,
    ) -> Result<(), (CreateChildError, OwnedPreparedCreateChild)> {
        let Some(index) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((CreateChildError::RetainedPublication, prepared));
        };
        if prepared.entered {
            return Err((CreateChildError::RetainedPublication, prepared));
        }
        self.retained_value_owners.remove(index);
        Ok(())
    }

    /// Publish one child after the exact marker and paired anchor are durable.
    ///
    /// # Safety
    /// The caller must consume an opaque receipt issued by the retained WAL owner after the
    /// marker and both header barriers completed. The receipt must bind the exact record and
    /// mounted hive/log identity. A sequence number by itself is never proof.
    pub unsafe fn publish_owned_create_child_unchecked(
        &mut self,
        prepared: OwnedPreparedCreateChild,
        durable_sequence: u64,
    ) -> Result<CellId, (CreateChildError, OwnedPreparedCreateChild)> {
        let Some(reservation) = self.retained_value_owners.iter().position(|(id, owner)|
            *id == prepared.hive_id && *owner == prepared.owner) else {
            return Err((CreateChildError::RetainedPublication, prepared));
        };
        if !prepared.entered || prepared.sequence != durable_sequence {
            return Err((CreateChildError::RetainedPublication, prepared));
        }
        let Some(hive) = self.hives.iter_mut().find(|(id, _)| *id == prepared.hive_id)
            .map(|(_, hive)| hive) else {
            return Err((CreateChildError::RetainedPublication, prepared));
        };
        if hive.sequence.checked_add(1) != Some(prepared.sequence) {
            return Err((CreateChildError::RetainedPublication, prepared));
        }
        let OwnedPreparedCreateChild { parent, child, new_len, next_id, sequence, .. } = prepared;
        let id = child.id;
        while hive.cells.len() < new_len {
            hive.cells.push(None);
        }
        hive.cells[id.0 as usize] = Some(Cell::Key(child));
        hive.key_mut(parent).expect("retained parent remains mounted").subkeys.push(id);
        hive.next_id = next_id;
        hive.sequence = sequence;
        hive.mark_dirty(parent);
        hive.mark_dirty(id);
        self.retained_value_owners.remove(reservation);
        Ok(id)
    }
}

fn copy_slice<T: Copy>(source: &[T]) -> Result<Vec<T>, CreateChildError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(source.len())
        .map_err(|_| CreateChildError::InsufficientResources)?;
    result.extend_from_slice(source);
    Ok(result)
}

fn copy_string(source: &str) -> Result<String, CreateChildError> {
    let mut result = String::new();
    result
        .try_reserve_exact(source.len())
        .map_err(|_| CreateChildError::InsufficientResources)?;
    result.push_str(source);
    Ok(result)
}

fn snapshot_key(key: &KeyCell) -> Result<KeyCell, CreateChildError> {
    Ok(KeyCell {
        kind: key.kind,
        id: key.id,
        parent: key.parent,
        name: copy_string(&key.name)?,
        subkeys: copy_slice(&key.subkeys)?,
        values: copy_slice(&key.values)?,
        class_name: key.class_name.as_deref().map(copy_string).transpose()?,
        security_descriptor: key
            .security_descriptor
            .as_deref()
            .map(copy_slice)
            .transpose()?,
        last_write_sequence: key.last_write_sequence,
        volatile: key.volatile,
    })
}

impl HiveTransaction<'_> {
    /// Create exactly one absent child beneath an existing parent, moving prepared metadata into
    /// the new cell before linking it. Never open an existing key or manufacture intermediates.
    /// All allocations and counter checks precede mutation; transaction drop restores the parent,
    /// cell arena and sequence. This storage primitive does not authorize access or parse security:
    /// the caller must assign the nonempty descriptor under the same exclusive hive transaction.
    /// Native counted-name limits and UTF-16 conversion belong to the native namespace adapter.
    pub fn try_create_child(
        &mut self,
        parent: CellId,
        name: String,
        class_name: Option<String>,
        security_descriptor: Vec<u8>,
    ) -> Result<CellId, CreateChildError> {
        self.try_create_child_with_options(parent, name, class_name, security_descriptor, false)
    }

    pub fn try_create_child_with_options(
        &mut self,
        parent: CellId,
        name: String,
        class_name: Option<String>,
        security_descriptor: Vec<u8>,
        volatile: bool,
    ) -> Result<CellId, CreateChildError> {
        if self.hive.pending_value_journal.is_some() {
            return Err(CreateChildError::RetainedPublication);
        }
        if name.is_empty() || name.contains(['\\', '\0']) {
            return Err(CreateChildError::InvalidName);
        }
        let parent_cell = self
            .hive
            .key(parent)
            .ok_or(CreateChildError::ParentNotFound)?;
        if self.hive.open_subkey(parent, &name).is_some() {
            return Err(CreateChildError::NameCollision);
        }
        if parent_cell.volatile && !volatile {
            return Err(CreateChildError::ChildMustBeVolatile);
        }
        if security_descriptor.is_empty() {
            return Err(CreateChildError::EmptySecurityDescriptor);
        }
        let index = usize::try_from(self.hive.next_id)
            .map_err(|_| CreateChildError::InsufficientResources)?;
        let new_len = index
            .checked_add(1)
            .ok_or(CreateChildError::InsufficientResources)?;
        let next_id = self
            .hive
            .next_id
            .checked_add(1)
            .ok_or(CreateChildError::InsufficientResources)?;
        let sequence = self
            .hive
            .sequence
            .checked_add(u64::from(!volatile))
            .ok_or(CreateChildError::InsufficientResources)?;
        if index < self.hive.cells.len() {
            return Err(CreateChildError::InsufficientResources);
        }
        let parent_index = parent.0 as usize;
        let snapshot = if parent_index < self.original_cells_len
            && !self
                .original_cells
                .iter()
                .any(|(saved, _)| *saved == parent_index)
        {
            Some(snapshot_key(parent_cell)?)
        } else {
            None
        };
        if snapshot.is_some() {
            self.original_cells
                .try_reserve(1)
                .map_err(|_| CreateChildError::InsufficientResources)?;
        }
        self.hive
            .cells
            .try_reserve(new_len - self.hive.cells.len())
            .map_err(|_| CreateChildError::InsufficientResources)?;
        self.hive
            .key_mut(parent)
            .unwrap()
            .subkeys
            .try_reserve(1)
            .map_err(|_| CreateChildError::InsufficientResources)?;

        // No fallible work follows: publish the undo owner, fully initialized child, then link.
        if let Some(snapshot) = snapshot {
            self.original_cells
                .push((parent_index, Some(Cell::Key(snapshot))));
        }
        let id = CellId(self.hive.next_id);
        self.hive.cells.resize_with(new_len, || None);
        self.hive.cells[index] = Some(Cell::Key(KeyCell {
            kind: super::KeyKind::Ordinary,
            id,
            parent: Some(parent),
            name,
            subkeys: Vec::new(),
            values: Vec::new(),
            class_name,
            security_descriptor: Some(security_descriptor),
            last_write_sequence: sequence,
            volatile,
        }));
        let parent_cell = self.hive.key_mut(parent).unwrap();
        parent_cell.subkeys.push(id);
        if !volatile {
            parent_cell.last_write_sequence = sequence;
        }
        self.hive.next_id = next_id;
        self.hive.sequence = sequence;
        Ok(id)
    }
}

#[cfg(test)]
#[path = "hive_create_child_tests.rs"]
mod tests;
