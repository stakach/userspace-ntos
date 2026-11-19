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

impl SectionWritebackPage {
    pub const fn control_area(self) -> u64 {
        self.control_area
    }
    /// The dirty version this ticket names; later stores carry a later epoch.
    pub const fn dirty_epoch(self) -> u64 {
        self.dirty_epoch
    }
}

/// Exclusive ownership of one dirty page's asynchronous paging write, from dispatch to its exact
/// terminal and acknowledged outcome. `via` is the section whose retained FILE_OBJECT issues the
/// IRP; neither the page's frame nor that section's backing can retire while the write is owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionPageWrite {
    pub(crate) ticket: SectionWritebackPage,
    pub(crate) via: crate::SectionIdentity,
    pub(crate) generation: u64,
}

impl SectionPageWrite {
    pub const fn ticket(self) -> SectionWritebackPage {
        self.ticket
    }
    pub const fn via(self) -> crate::SectionIdentity {
        self.via
    }
}

/// The settled result of a paging write, known only after its terminal completion and strict
/// acknowledgement (or a definite refusal before any driver entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageWriteOutcome {
    /// The driver accepted every byte of the ticket.
    Written,
    /// Definite failure, or a short write: the page stays dirty for a later writer.
    Failed(u32),
    /// The effect is unknown (lost completion or ACK). The page is never written again and its
    /// frame is never released, so an uncertain write is not replayed.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageWriteState {
    Idle,
    InFlight,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageWriteRefusal {
    /// The ticket no longer names the page's current dirty version, or `via` cannot issue it.
    Stale,
    /// Another write owns the page; wait for its outcome.
    InFlight,
    /// An earlier write's effect is unknown; the page cannot be written again.
    Uncertain,
    Exhausted,
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
