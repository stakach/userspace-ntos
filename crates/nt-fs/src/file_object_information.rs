//! Checked observations of a live FILE_OBJECT, including an I/O-only lifetime after cleanup.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileObjectInformation {
    pub metadata: FileMetadata,
    pub current_offset: u64,
    pub mode: u32,
}

impl FileSystem {
    fn checked_file_object(&self, handle: u64) -> Result<&FileObject, u32> {
        let index = usize::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let object = self
            .handles
            .get(index)
            .and_then(Option::as_ref)
            .filter(|object| object.references != 0)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if object.handle_references > object.references {
            return Err(STATUS_DATA_ERROR);
        }
        self.volume.node(object.node_id).ok_or(STATUS_DATA_ERROR)?;
        Ok(object)
    }

    /// Observe metadata, position and mode under one filesystem borrow without allocating.
    /// A cleaned-up object remains valid while an I/O reference retains its actual node.
    pub fn query_file_object_information(&self, handle: u64) -> Result<FileObjectInformation, u32> {
        let object = self.checked_file_object(handle)?;
        let node = self.volume.node(object.node_id).ok_or(STATUS_DATA_ERROR)?;
        node.data.checked_len(&self.volume.blobs)?;
        let metadata = self
            .volume
            .metadata(object.node_id, object.delete_pending)
            .ok_or(STATUS_DATA_ERROR)?;
        Ok(FileObjectInformation {
            metadata,
            current_offset: object.current_offset,
            mode: crate::file_mode_from_create_options(object.create_options),
        })
    }

    pub(super) fn checked_object_entry(&self, object: &FileObject) -> Result<Option<(u64, usize)>, u32> {
        if object.entry_id == 0 {
            if object.node_id != 0 || !self.volume.is_dir(0) {
                return Err(STATUS_DATA_ERROR);
            }
            return Ok(None);
        }
        let Some((parent, index, node)) = self.volume.entry_location(object.entry_id) else {
            // Unlink removes the exact name before the retained FILE_OBJECT's last reference.
            // The current representation has no separate unlink receipt to distinguish tampering.
            return Ok(None);
        };
        if node != object.node_id || !self.volume.node(parent).is_some_and(|node| node.is_dir) {
            return Err(STATUS_DATA_ERROR);
        }
        Ok(Some((parent, index)))
    }

    /// Return the current namespace spelling, or the object's retained opened name after unlink.
    /// Invalid objects, corrupt live namespace, and allocation failure remain distinct errors.
    pub fn query_opened_name(&self, handle: u64) -> Result<String, u32> {
        let object = self.checked_file_object(handle)?;
        if self.checked_object_entry(object)?.is_some() || object.entry_id == 0 {
            return self.volume.try_opened_name(object.entry_id);
        }
        let mut name = String::new();
        name.try_reserve_exact(object.opened_name.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        name.push_str(&object.opened_name);
        Ok(name)
    }

    /// Return the exact live entry's alternate name. A valid root or unlinked retained object has
    /// no namespace alias and returns EMPTY, not an invalid-handle failure.
    pub fn query_short_name(&self, handle: u64) -> Result<FileShortName, u32> {
        let object = self.checked_file_object(handle)?;
        let Some((parent, index)) = self.checked_object_entry(object)? else {
            return Ok(FileShortName::EMPTY);
        };
        let entry = self
            .volume
            .node(parent)
            .and_then(|parent| parent.children.get(index))
            .ok_or(STATUS_DATA_ERROR)?;
        Ok(entry.short_name)
    }
}

impl MemFs {
    pub(super) fn try_opened_name(&self, entry_id: u64) -> Result<String, u32> {
        if entry_id == 0 {
            if !self.node(0).is_some_and(|node| node.is_dir) {
                return Err(STATUS_DATA_ERROR);
            }
            let mut root = String::new();
            root.try_reserve_exact(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            root.push('\\');
            return Ok(root);
        }
        let (mut parent, index, node) = self.entry_location(entry_id).ok_or(STATUS_DATA_ERROR)?;
        self.node(node).ok_or(STATUS_DATA_ERROR)?;
        let directory = self.node(parent).ok_or(STATUS_DATA_ERROR)?;
        if !directory.is_dir {
            return Err(STATUS_DATA_ERROR);
        }
        let mut components = Vec::new();
        components
            .try_reserve_exact(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        components.push(
            directory
                .children
                .get(index)
                .ok_or(STATUS_DATA_ERROR)?
                .created_name
                .as_str(),
        );
        let mut remaining = self.nodes.len();
        while parent != 0 {
            if remaining == 0 {
                return Err(STATUS_DATA_ERROR);
            }
            remaining -= 1;
            let grandparent = self.node(parent).ok_or(STATUS_DATA_ERROR)?.parent;
            let directory = self.node(grandparent).ok_or(STATUS_DATA_ERROR)?;
            if !directory.is_dir {
                return Err(STATUS_DATA_ERROR);
            }
            let entry = directory
                .children
                .iter()
                .find(|entry| entry.node_id == parent)
                .ok_or(STATUS_DATA_ERROR)?;
            components
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            components.push(entry.created_name.as_str());
            parent = grandparent;
        }
        let byte_len = components
            .iter()
            .try_fold(1usize, |length, component| {
                length.checked_add(component.len())
            })
            .and_then(|len| len.checked_add(components.len().saturating_sub(1)))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut name = String::new();
        name.try_reserve_exact(byte_len)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        name.push('\\');
        for (index, component) in components.iter().rev().enumerate() {
            if index != 0 {
                name.push('\\');
            }
            name.push_str(component);
        }
        Ok(name)
    }
}

#[cfg(test)]
#[path = "file_object_information/tests.rs"]
mod tests;
