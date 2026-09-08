//! Native retained cleanup; prefetch rows keep their actual frame and cleanup phases.
use super::*;
use nt_memory_manager::prefetch::PrefetchJournalError;
use nt_user_host::thread_prefetch_journal::ThreadPrefetchJournal;
use nt_user_host::thread_resources::ThreadMemoryLayout;
use nt_user_host::thread_rollback::ThreadRollbackId;

#[derive(Debug)]
pub(crate) struct ThreadPrefetchCleanup {
    journal: ThreadPrefetchJournal,
}

fn status(error: PrefetchJournalError) -> u32 {
    match error {
        PrefetchJournalError::InsufficientResources => {
            nt_address_space::STATUS_INSUFFICIENT_RESOURCES
        }
        PrefetchJournalError::Backend { status, .. } => status,
        _ => nt_process::STATUS_INVALID_PARAMETER,
    }
}

fn current(id: ThreadRollbackId) -> Result<Option<PrefetchProcess>, u32> {
    use nt_user_host::process_identity::ProcessGeneration;
    match id.identity().process_generation {
        ProcessGeneration::Hosted(_) => {
            process(id.identity().pi as u64).map(|(process, _)| Some(process))
        }
        ProcessGeneration::Temporary(_) => {
            if hosted_process_runtime_for_pi(id.identity().pi).is_some() {
                Err(nt_process::STATUS_INVALID_PARAMETER)
            } else {
                Ok(None)
            }
        }
    }
}

impl ThreadPrefetchCleanup {
    pub(crate) unsafe fn prepare(
        id: ThreadRollbackId,
        layout: ThreadMemoryLayout,
    ) -> Result<Self, u32> {
        ThreadPrefetchJournal::prepare(id, layout, current(id)?, &*core::ptr::addr_of!(FRAMES))
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
    pub(crate) unsafe fn revalidate(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .revalidate(id, current(id)?, &*core::ptr::addr_of!(FRAMES))
            .map_err(status)
    }
    pub(crate) unsafe fn claim(&self, id: ThreadRollbackId) -> Result<(), u32> {
        self.journal
            .claim(id, current(id)?, &mut *core::ptr::addr_of_mut!(FRAMES))
            .map_err(status)
    }

    /// The caller must retain complete disjoint claims and pending-range exclusions, drain all
    /// root copy/scratch users of these root-only aliases, and keep the exact process identity
    /// stable. No table access, component IPC or reentry is permitted during this operation.
    /// Failed cleanup retains the real frame/slot phase for an equally quiescent retry.
    pub(crate) unsafe fn retire(&self, id: ThreadRollbackId) -> Result<(), u32> {
        let current = current(id)?;
        self.journal
            .retire(id, current, &mut *core::ptr::addr_of_mut!(FRAMES), &mut Cleanup)
            .map_err(status)
    }
}
