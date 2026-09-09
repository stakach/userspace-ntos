//! Checked single-child publication for callers that already assigned and authorized security.

use super::{Cell, CellId, HiveTransaction, KeyCell, String, Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateChildError {
    InvalidName,
    ParentNotFound,
    NameCollision,
    EmptySecurityDescriptor,
    InsufficientResources,
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
            .checked_add(1)
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
            id,
            parent: Some(parent),
            name,
            subkeys: Vec::new(),
            values: Vec::new(),
            class_name,
            security_descriptor: Some(security_descriptor),
            last_write_sequence: sequence,
        }));
        let parent_cell = self.hive.key_mut(parent).unwrap();
        parent_cell.subkeys.push(id);
        parent_cell.last_write_sequence = sequence;
        self.hive.next_id = next_id;
        self.hive.sequence = sequence;
        Ok(id)
    }
}

#[cfg(test)]
#[path = "hive_create_child_tests.rs"]
mod tests;
