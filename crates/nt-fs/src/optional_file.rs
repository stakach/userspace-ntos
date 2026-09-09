//! Checked whole-file reads for storage owners. Absence is a missing leaf, never a read failure.

use super::*;

impl FileSystem {
    fn optional_file_node(&self, path: &str) -> Result<Option<u64>, u32> {
        if path.is_empty() || path.contains('\0') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let relative = self
            .to_relative(&normalize_separators(path))
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        if let Some(id) = self.volume.lookup(&relative) {
            if self.volume.is_dir(id) {
                return Err(STATUS_FILE_IS_A_DIRECTORY);
            }
            return Ok(Some(id));
        }
        let (parent, _) =
            MemFs::parent_and_leaf_relative(&relative).ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let parent = self
            .volume
            .lookup(parent)
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        if !self.volume.is_dir(parent) {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        Ok(None)
    }

    /// Inspect an internal file without opening a FILE_OBJECT. Only a missing leaf on this mounted
    /// volume returns None. Invalid paths, directories and invalid backing extents return errors.
    pub fn try_file_len(&self, path: &str) -> Result<Option<u64>, u32> {
        let Some(id) = self.optional_file_node(path)? else {
            return Ok(None);
        };
        let node = self.volume.node(id).ok_or(STATUS_DATA_ERROR)?;
        let len = node.data.checked_len(&self.volume.blobs)?;
        Ok(Some(u64::try_from(len).map_err(|_| STATUS_DATA_ERROR)?))
    }

    /// Copy a complete internal file, including extent-backed files. A present empty file is
    /// Some(empty), so callers cannot mistake a corrupt zero-byte hive primary for a missing one.
    pub fn try_file_bytes_owned(&self, path: &str) -> Result<Option<Vec<u8>>, u32> {
        let Some(id) = self.optional_file_node(path)? else {
            return Ok(None);
        };
        let node = self.volume.node(id).ok_or(STATUS_DATA_ERROR)?;
        let len = node.data.checked_len(&self.volume.blobs)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        bytes.resize(len, 0);
        if node.data.read_into(&self.volume.blobs, 0, &mut bytes) != len {
            return Err(STATUS_DATA_ERROR);
        }
        Ok(Some(bytes))
    }
}

impl FileData {
    fn checked_len(&self, blobs: &[Vec<u8>]) -> Result<usize, u32> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.len()),
            Self::Extents(extents) => extents.iter().try_fold(0usize, |total, extent| {
                if extent.blob != ZERO_EXTENT_BLOB {
                    let blob = blobs.get(extent.blob).ok_or(STATUS_DATA_ERROR)?;
                    let end = extent
                        .offset
                        .checked_add(extent.len)
                        .ok_or(STATUS_DATA_ERROR)?;
                    if end > blob.len() {
                        return Err(STATUS_DATA_ERROR);
                    }
                }
                total.checked_add(extent.len).ok_or(STATUS_DATA_ERROR)
            }),
        }
    }
}

#[cfg(test)]
#[path = "optional_file/tests.rs"]
mod tests;
