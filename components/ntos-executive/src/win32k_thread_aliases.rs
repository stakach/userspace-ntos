//! Exact-attempt claims over win32k aliases of a protected thread construction.
use super::*;
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
            W32_ATTACHED_PI.load(Ordering::Acquire),
            &*core::ptr::addr_of!(MAPPINGS),
        )
        .map(|journal| Self { journal })
        .map_err(status)
    }

    pub(crate) fn capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.journal.original_capabilities()
    }

    pub(crate) unsafe fn revalidate(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .revalidate(
                id,
                W32_ATTACHED_PI.load(Ordering::Acquire),
                &*core::ptr::addr_of!(MAPPINGS),
            )
            .map_err(status)
    }

    /// Allocation-free after private, registry and mechanism cap conflicts are excluded. Native
    /// retirement remains disabled until every external journal and TCB quiescence is retained.
    pub(crate) unsafe fn claim(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .claim(
                id,
                W32_ATTACHED_PI.load(Ordering::Acquire),
                &mut *core::ptr::addr_of_mut!(MAPPINGS),
            )
            .map_err(status)
    }
}
