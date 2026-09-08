//! Canonical FILE_OBJECT pointer references, independent of handles, IRPs and projection pins.
//! Dropping an owner does not release it. Checked release never invokes a backend; final release
//! merely latches close-ready work for the outer completion pump.

use crate::{FileId, FileState, IoManager};
use alloc::vec::Vec;
use nt_status::NtStatus;

/// Counted strong ownership, valid only in the issuing I/O Manager. A FileId is an identity, not
/// authorization: native callers must authenticate their pointer or handle before acquisition.
///
/// ```compile_fail
/// use nt_io_manager::FileReference;
/// fn copy(owner: FileReference) { let moved = owner; let _ = owner.count(); }
/// ```
#[derive(Debug)]
#[must_use = "explicitly release File references after their last consumer"]
pub struct FileReference {
    manager: u64,
    file: FileId,
    count: u64,
}

impl FileReference {
    pub const fn file_id(&self) -> FileId {
        self.file
    }
    pub const fn count(&self) -> u64 {
        self.count
    }
    pub const fn is_held(&self) -> bool {
        self.count != 0
    }
}

struct Count {
    file: FileId,
    count: u64,
}

#[derive(Default)]
pub(crate) struct FileReferenceStore {
    counts: Vec<Count>,
}

impl FileReferenceStore {
    pub(crate) fn remove_empty(&mut self, file: FileId) {
        if let Some(index) = self.counts.iter().position(|entry| entry.file == file) {
            assert_eq!(
                self.counts[index].count, 0,
                "removing a pointer-referenced File"
            );
            self.counts.swap_remove(index);
        }
    }
}

impl<P> IoManager<P> {
    pub fn file_reference_count(&self, file: FileId) -> u64 {
        self.file_references
            .counts
            .iter()
            .find(|entry| entry.file == file)
            .map_or(0, |entry| entry.count)
    }

    /// Acquire only while an existing canonical lifetime still permits a new pointer reference.
    /// CLOSE entry is a terminal barrier, even while its own IRP temporarily references the File.
    pub fn retain_file_reference(&mut self, file: FileId) -> Result<FileReference, NtStatus> {
        let record = self.file(file).ok_or(NtStatus::INVALID_HANDLE)?;
        if record.state == FileState::Closed
            || record.close_dispatched
            || (record.close_deferred
                && record.outstanding_irp_refs == 0
                && self.file_reference_count(file) == 0)
        {
            return Err(NtStatus::FILE_CLOSED);
        }
        let index = self
            .file_references
            .counts
            .iter()
            .position(|entry| entry.file == file);
        let count = index
            .map_or(0, |index| self.file_references.counts[index].count)
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        if index.is_none() {
            self.file_references
                .counts
                .try_reserve(1)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        }
        let manager = self.ensure_ownership_identity()?;
        if let Some(index) = index {
            self.file_references.counts[index].count = count;
        } else {
            self.file_references.counts.push(Count { file, count });
        }
        Ok(FileReference {
            manager,
            file,
            count: 1,
        })
    }

    fn file_reference_index(&self, owner: &FileReference) -> Result<usize, NtStatus> {
        if owner.count == 0
            || owner.manager == 0
            || owner.manager != self.ownership_identity()
            || self.file(owner.file).is_none()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.file_references
            .counts
            .iter()
            .position(|entry| entry.file == owner.file && entry.count >= owner.count)
            .ok_or(NtStatus::INVALID_PARAMETER)
    }

    pub fn retain_file_reference_owned(
        &mut self,
        owner: &mut FileReference,
    ) -> Result<(), NtStatus> {
        let index = self.file_reference_index(owner)?;
        let owned = owner
            .count
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let total = self.file_references.counts[index]
            .count
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        owner.count = owned;
        self.file_references.counts[index].count = total;
        Ok(())
    }

    pub fn split_file_reference_one(
        &self,
        owner: &mut FileReference,
    ) -> Result<FileReference, NtStatus> {
        self.file_reference_index(owner)?;
        owner.count -= 1;
        Ok(FileReference {
            manager: owner.manager,
            file: owner.file,
            count: 1,
        })
    }

    pub fn merge_file_references(
        &self,
        target: &mut FileReference,
        source: &mut FileReference,
    ) -> Result<(), NtStatus> {
        let index = self.file_reference_index(target)?;
        if self.file_reference_index(source)? != index {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let count = target
            .count
            .checked_add(source.count)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        if count > self.file_references.counts[index].count {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        target.count = count;
        source.count = 0;
        Ok(())
    }

    pub fn release_file_reference_one(
        &mut self,
        owner: &mut FileReference,
    ) -> Result<(), NtStatus> {
        self.release_file_reference_count(owner, 1)
    }

    pub fn release_file_reference(&mut self, owner: &mut FileReference) -> Result<(), NtStatus> {
        let count = owner.count;
        self.release_file_reference_count(owner, count)
    }

    fn release_file_reference_count(
        &mut self,
        owner: &mut FileReference,
        count: u64,
    ) -> Result<(), NtStatus> {
        let index = self.file_reference_index(owner)?;
        let owned = owner
            .count
            .checked_sub(count)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let total = self.file_references.counts[index]
            .count
            .checked_sub(count)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.file_references.counts[index].count = total;
        owner.count = owned;
        // The zero-count row remains until canonical removal, preserving its admitted capacity.
        if total == 0
            && self
                .file(owner.file)
                .is_some_and(|file| file.close_deferred)
        {
            self.queue_deferred_file_close(owner.file);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "file_reference/tests.rs"]
mod tests;
