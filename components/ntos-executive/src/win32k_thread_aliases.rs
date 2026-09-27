//! Exact-attempt ownership of win32k aliases of a protected thread construction.
use super::*;
use nt_user_host::process_identity::ProcessIdentity;
use nt_user_host::thread_alias_journal::{JournalError, ThreadAliasJournal};
use nt_user_host::thread_resources::ThreadMemoryLayout;
use nt_user_host::thread_rollback::ThreadRollbackId;

#[derive(Debug)]
pub(crate) struct ThreadAliasCleanup {
    journal: ThreadAliasJournal,
}

fn status(error: JournalError) -> u32 {
    match error {
        JournalError::InsufficientResources => nt_address_space::STATUS_INSUFFICIENT_RESOURCES,
        JournalError::Backend { status, .. } => status,
        _ => nt_process::STATUS_INVALID_PARAMETER,
    }
}

unsafe fn journal_attached_pi(id: ThreadRollbackId) -> Result<u64, u32> {
    let Some(owner) = attached_owner() else {
        return Ok(u32::MAX as u64);
    };
    let identity = id.identity();
    let expected = ProcessIdentity {
        pid: identity.pid,
        generation: identity.process_generation,
    };
    if owner.pi == identity.pi && owner.process != expected {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    Ok(owner.pi as u64)
}

impl ThreadAliasCleanup {
    /// Pending access exclusions must already prevent alias admission for this geometry.
    /// Actual alias ownership stays in MAPPINGS; preparation performs no release or claim.
    pub(crate) unsafe fn prepare(
        id: ThreadRollbackId,
        layout: ThreadMemoryLayout,
    ) -> Result<Self, u32> {
        ThreadAliasJournal::prepare(
            id,
            layout,
            journal_attached_pi(id)?,
            &*core::ptr::addr_of!(MAPPINGS),
        )
        .map(|journal| Self { journal })
        .map_err(status)
    }

    /// Immutable preclaim provenance, not current ownership after retirement begins.
    pub(crate) fn capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.journal.original_capabilities()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.journal.is_complete()
    }

    /// Conservative execution-gate requirement, not current cap ownership. Preserve it through
    /// partial cleanup; original cap numbers may already have been recycled on a later retry.
    pub(crate) fn needs_quiescence(&self) -> bool {
        !self.is_complete() && self.journal.original_capabilities().next().is_some()
    }

    pub(crate) unsafe fn revalidate(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .revalidate(
                id,
                journal_attached_pi(id)?,
                &*core::ptr::addr_of!(MAPPINGS),
            )
            .map_err(status)
    }

    /// Allocation-free after private, registry and mechanism cap conflicts are excluded.
    pub(crate) unsafe fn claim(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .claim(
                id,
                journal_attached_pi(id)?,
                &mut *core::ptr::addr_of_mut!(MAPPINGS),
            )
            .map_err(status)
    }

    /// The caller must retain complete disjoint claims and pending-range exclusions, and prove
    /// every provider execution/continuation using this shared attachment is quiescent. Deleting
    /// the client TCB alone is insufficient. Keep attachment identity stable and exclude all
    /// table access/reentry through this synchronous kernel-only operation and every retry.
    pub(crate) unsafe fn retire(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .retire(
                id,
                journal_attached_pi(id)?,
                &mut *core::ptr::addr_of_mut!(MAPPINGS),
                |page| Backend { page, pml4: 0, source: 0 },
            )
            .map_err(status)
    }
}
