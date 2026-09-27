//! Section writeback progress and durability boundary, independent of the storage backend.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WritebackResult {
    pub status: u32,
    pub bytes_written: u64,
    pub pages_written: u64,
}

impl WritebackResult {
    pub const fn failure(status: u32) -> Self {
        Self {
            status,
            bytes_written: 0,
            pages_written: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionWritebackPage {
    pub page_index: u64,
    pub frame: u64,
    pub file_offset: u64,
    pub length: usize,
    pub(crate) control_area: u64,
    pub(crate) file_extent: u64,
    pub(crate) dirty_epoch: u64,
}

/// A virtual alias of a section page, before filtering residency and private COW ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionPageAlias {
    pub pi: usize,
    pub page: u64,
    pub lifetime: crate::MemoryLifetime,
}

/// Read-only admission before a native alias detach or page reprotection.
pub fn admit_section_alias_rearm(
    alias: SectionPageAlias,
    current: Option<crate::ProcessIdentity>,
    view: Option<crate::MemoryLifetime>,
    frame: Option<crate::MemoryLifetime>,
) -> Result<(), u32> {
    let crate::MemoryLifetime::Process(owner) = alias.lifetime else {
        return Err(crate::STATUS_INVALID_HANDLE);
    };
    if !owner.is_valid() || current != Some(owner) {
        return Err(crate::STATUS_INVALID_HANDLE);
    }
    if view != Some(alias.lifetime) {
        return Err(crate::STATUS_NOT_MAPPED_VIEW);
    }
    if frame.is_some_and(|lifetime| lifetime != alias.lifetime) {
        return Err(crate::STATUS_INVALID_HANDLE);
    }
    Ok(())
}

#[cfg(test)]
impl SectionPageAlias {
    pub(crate) const fn for_test(pi: usize, page: u64) -> Self {
        Self {
            pi,
            page,
            lifetime: crate::MemoryLifetime::Process(crate::ProcessIdentity {
                pid: pi as u32 + 1,
                generation: crate::ProcessGeneration::Hosted(1),
            }),
        }
    }
}

pub trait SectionWritebackIo {
    /// Remove shared write access from this process and its attached kernel mappings. A failure
    /// must leave the dirty batch owned for retry. Private COW pages are not shared aliases.
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32>;
    /// Report actual accepted bytes even when the write fails.
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize);
    /// Publish through the configured backing-store checkpoint, not merely validate a file handle.
    /// Device-cache ordering and stable-storage guarantees belong to this backend boundary.
    fn persist(&mut self) -> u32;
}

/// A frozen worklist avoids retrying the same dirty page within one failed operation. The caller
/// may retire matching dirty tickets only after this returns success.
pub fn writeback_pages(
    pages: &[SectionWritebackPage],
    io: &mut impl SectionWritebackIo,
) -> WritebackResult {
    let mut result = WritebackResult::default();
    for page in pages {
        let (status, written) = io.write_page(*page);
        if written > page.length {
            result.status = 0xC000_0185; // STATUS_IO_DEVICE_ERROR: invalid backend progress
            return result;
        }
        result.bytes_written = result.bytes_written.saturating_add(written as u64);
        if status != 0 {
            result.status = status;
            return result;
        }
        if written != page.length {
            result.status = 0xC000_0001; // STATUS_UNSUCCESSFUL: short successful write
            return result;
        }
        result.pages_written += 1;
    }
    // A prior operation can have staged bytes even when this range currently has no dirty pages.
    result.status = io.persist();
    result
}

#[cfg(test)]
#[path = "writeback_tests.rs"]
mod tests;
