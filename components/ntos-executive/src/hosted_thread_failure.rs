//! Failed constructors remain owned by their original runtime reservation until checked cleanup.
use super::*;
use nt_user_host::thread_binding::ThreadBinding;
use nt_user_host::thread_construction::{MemoryConstructionProgress, ThreadConstructionInventory};

#[derive(Debug)]
pub(crate) enum ThreadReconciliationError {
    OwnerChanged,
    OwnershipConflict,
    Registry(nt_user_host::thread_reconciliation::ReconciliationError),
    Aliases(u32),
}

impl ThreadReconciliationError {
    pub(crate) fn status(&self) -> u32 {
        use nt_user_host::thread_reconciliation::ReconciliationError;
        use nt_user_host::thread_registry::ThreadRegistryError;
        use nt_user_host::thread_rollback::ThreadRollbackError;
        match self {
            Self::Aliases(status) => *status,
            Self::Registry(ReconciliationError::Registry(
                ThreadRegistryError::InsufficientResources
                | ThreadRegistryError::Resources(ThreadRollbackError::InsufficientResources),
            )) => nt_process::STATUS_INSUFFICIENT_RESOURCES,
            Self::OwnerChanged | Self::OwnershipConflict | Self::Registry(_) => {
                nt_process::STATUS_INVALID_PARAMETER
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct FailedHostedThreadConstruction {
    pub(crate) binding: ThreadBinding<HostedThreadRole>,
    pub(crate) resources: HostedThreadResources,
    pub(crate) construction: ThreadConstructionInventory,
    pub(crate) memory_progress: MemoryConstructionProgress<TP_WORKER_STACK_FRAME_COUNT>,
    pub(crate) teb_alias: u64,
}

/// Unlike the general copy helper, a failed copy returns its still-owned empty slot. The
/// constructor must retain it rather than publish it to a possibly failing recycle list.
pub(crate) unsafe fn copy_thread_construction_cap(source: u64) -> (u64, u64) {
    let Some(slot) = try_alloc_slot() else {
        return (0, 4);
    };
    (slot, copy_cap_into_r(source, slot))
}
