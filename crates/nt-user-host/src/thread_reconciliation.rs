//! Read-only registry preparation retained once for an exact pending construction attempt.
use alloc::vec::Vec;
use core::cell::OnceCell;
use nt_memory_manager::ClientFrameRegistry;

use crate::thread_construction::MemoryConstructionProgress;
use crate::thread_registry::{ThreadRegistryError, ThreadRegistrySnapshot};
use crate::thread_resources::ThreadMemoryResources;
use crate::thread_rollback::ThreadRollbackId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationError {
    AttemptChanged,
    ProgressChanged,
    Registry(ThreadRegistryError),
}

#[derive(Debug)]
struct Prepared<const STACK: usize> {
    id: ThreadRollbackId,
    snapshot: ThreadRegistrySnapshot<STACK>,
    empty_slot: Option<u64>,
    protected_tail: bool,
}

/// Store inside the non-cloneable pending runtime owner. OnceCell permits attaching immutable
/// preparation without exposing mutable runtime identity or resource ownership. This type cannot
/// reset or replace a prepared snapshot, transfer registry rows, or drive backend cleanup.
#[derive(Debug)]
pub struct ThreadRegistryReconciliation<const STACK: usize> {
    prepared: OnceCell<Prepared<STACK>>,
}

impl<const STACK: usize> ThreadRegistryReconciliation<STACK> {
    pub const fn empty() -> Self {
        Self {
            prepared: OnceCell::new(),
        }
    }

    pub fn is_prepared(&self) -> bool {
        self.prepared.get().is_some()
    }

    /// The caller must first match `id` to the protected pending row. Capture failures leave
    /// preparation empty; retries after successful capture revalidate the original snapshot.
    /// Complete access exclusions must remain active throughout preparation and revalidation.
    pub fn reconcile(
        &self,
        id: ThreadRollbackId,
        resources: &ThreadMemoryResources<STACK>,
        progress: &MemoryConstructionProgress<STACK>,
        registry: &ClientFrameRegistry,
    ) -> Result<&ThreadRegistrySnapshot<STACK>, ReconciliationError> {
        if let Some(prepared) = self.prepared.get() {
            if prepared.id != id {
                return Err(ReconciliationError::AttemptChanged);
            }
            if prepared.empty_slot != progress.empty_slot()
                || prepared.protected_tail != progress.protected_tail_registered()
                || !registered_pages(resources, progress)?.eq(prepared
                    .snapshot
                    .records()
                    .iter()
                    .map(|record| record.page))
            {
                return Err(ReconciliationError::ProgressChanged);
            }
            prepared
                .snapshot
                .revalidate(resources, registry)
                .map_err(ReconciliationError::Registry)?;
            validate_empty_slot(progress, &prepared.snapshot, registry)?;
            return Ok(&prepared.snapshot);
        }
        let mut pages = Vec::new();
        pages.try_reserve(STACK.saturating_add(2)).map_err(|_| {
            ReconciliationError::Registry(ThreadRegistryError::InsufficientResources)
        })?;
        pages.extend(registered_pages(resources, progress)?);
        let snapshot = ThreadRegistrySnapshot::capture_partial(resources, registry, &pages)
            .map_err(ReconciliationError::Registry)?;
        validate_empty_slot(progress, &snapshot, registry)?;
        let prepared = Prepared {
            id,
            snapshot,
            empty_slot: progress.empty_slot(),
            protected_tail: progress.protected_tail_registered(),
        };
        // No backend calls or reentrancy occur between the empty check and publication.
        assert!(self.prepared.set(prepared).is_ok());
        Ok(&self
            .prepared
            .get()
            .expect("published registry preparation")
            .snapshot)
    }
}

fn registered_pages<'a, const STACK: usize>(
    resources: &'a ThreadMemoryResources<STACK>,
    progress: &'a MemoryConstructionProgress<STACK>,
) -> Result<impl Iterator<Item = u64> + 'a, ReconciliationError> {
    if !resources.is_live()
        || (resources.stack_frames() as usize..STACK).any(|index| progress.stack_registered(index))
    {
        return Err(ReconciliationError::Registry(
            ThreadRegistryError::InvalidCoverage,
        ));
    }
    Ok((0..resources.stack_frames() as usize)
        .filter(|&index| progress.stack_registered(index))
        .map(|index| resources.stack_base() + index as u64 * 4096)
        .chain(
            (0..2)
                .filter(|&index| progress.teb_registered(index))
                .map(|index| resources.teb_va() + index as u64 * 4096),
        ))
}

fn validate_empty_slot<const STACK: usize>(
    progress: &MemoryConstructionProgress<STACK>,
    snapshot: &ThreadRegistrySnapshot<STACK>,
    registry: &ClientFrameRegistry,
) -> Result<(), ReconciliationError> {
    let Some(slot) = progress.empty_slot() else {
        return Ok(());
    };
    if snapshot
        .rollback_resources()
        .iter()
        .any(|resource| resource.cap == slot)
        || registry
            .records()
            .iter()
            .any(|record| [record.frame, record.alias_cap, record.source_cap].contains(&slot))
    {
        return Err(ReconciliationError::Registry(
            ThreadRegistryError::SharedCapability { cap: slot },
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "thread_reconciliation_tests.rs"]
mod tests;
