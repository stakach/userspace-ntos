//! Read-only registry preparation retained once for an exact pending thread retirement.
use alloc::vec::Vec;
use core::cell::OnceCell;
use nt_memory_manager::ClientFrameRegistry;

use crate::thread_construction::MemoryConstructionCoverage;
use crate::thread_registry::{ThreadRegistryError, ThreadRegistrySnapshot};
use crate::thread_resources::ThreadMemoryResources;
use crate::thread_retirement::ThreadMechanismRetirement;
use crate::thread_rollback::ThreadRollbackId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationError {
    AttemptChanged,
    ProvenanceChanged,
    ProgressChanged,
    Registry(ThreadRegistryError),
}

#[derive(Debug)]
struct Prepared<const STACK: usize> {
    id: ThreadRollbackId,
    snapshot: ThreadRegistrySnapshot<STACK>,
    provenance: Provenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provenance {
    Construction { empty_slot: Option<u64> },
    Registered,
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

    /// Immutable provenance after ownership handoff. This does not revalidate mutable registry
    /// rows: terminal transfers and acknowledged releases intentionally change those rows.
    pub fn retained_snapshot(
        &self,
        id: ThreadRollbackId,
    ) -> Result<&ThreadRegistrySnapshot<STACK>, ReconciliationError> {
        self.prepared
            .get()
            .filter(|prepared| prepared.id == id)
            .map(|prepared| &prepared.snapshot)
            .ok_or(ReconciliationError::AttemptChanged)
    }

    /// The caller must first match `id` to the protected pending row. Capture failures leave
    /// preparation empty; retries after successful capture revalidate the original snapshot.
    /// Complete access exclusions must remain active throughout preparation and revalidation.
    pub fn reconcile(
        &self,
        id: ThreadRollbackId,
        resources: &ThreadMemoryResources<STACK>,
        progress: &MemoryConstructionCoverage<STACK>,
        retirement: &ThreadMechanismRetirement,
        registry: &ClientFrameRegistry,
    ) -> Result<&ThreadRegistrySnapshot<STACK>, ReconciliationError> {
        if retirement.id() != id {
            return Err(ReconciliationError::AttemptChanged);
        }
        if retirement.original_memory_slot() != progress.empty_slot() {
            return Err(ReconciliationError::ProgressChanged);
        }
        if let Some(prepared) = self.prepared.get() {
            if prepared.id != id {
                return Err(ReconciliationError::AttemptChanged);
            }
            let Provenance::Construction { empty_slot } = prepared.provenance else {
                return Err(ReconciliationError::ProvenanceChanged);
            };
            if empty_slot != progress.empty_slot()
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
            validate_empty_slot(progress, retirement, &prepared.snapshot, registry)?;
            return Ok(&prepared.snapshot);
        }
        let mut pages = Vec::new();
        pages.try_reserve(STACK.saturating_add(2)).map_err(|_| {
            ReconciliationError::Registry(ThreadRegistryError::InsufficientResources)
        })?;
        pages.extend(registered_pages(resources, progress)?);
        let snapshot = ThreadRegistrySnapshot::capture_partial(resources, registry, &pages)
            .map_err(ReconciliationError::Registry)?;
        validate_empty_slot(progress, retirement, &snapshot, registry)?;
        let prepared = Prepared {
            id,
            snapshot,
            provenance: Provenance::Construction {
                empty_slot: progress.empty_slot(),
            },
        };
        // No backend calls or reentrancy occur between the empty check and publication.
        assert!(self.prepared.set(prepared).is_ok());
        Ok(&self
            .prepared
            .get()
            .expect("published registry preparation")
            .snapshot)
    }

    /// Reconcile an actually completed constructor's exhaustive registration evidence. The caller
    /// retains that evidence from publication, rather than reconstructing it from PI or accepting
    /// whichever registry rows happen to remain. Every described backing page must have an owner;
    /// this entry cannot substitute for partial construction or its empty-slot retirement actor.
    ///
    /// First match `id` to the protected registered pending runtime and close all memory admission.
    /// This read-only preparation does not prove mechanism or provider execution quiescence. The
    /// normal checked handoff must establish those prerequisites before releasing any capability.
    pub fn reconcile_registered(
        &self,
        id: ThreadRollbackId,
        resources: &ThreadMemoryResources<STACK>,
        registered_pages: &[u64],
        registry: &ClientFrameRegistry,
    ) -> Result<&ThreadRegistrySnapshot<STACK>, ReconciliationError> {
        if resources.client_pi != id.identity().pi {
            return Err(ReconciliationError::AttemptChanged);
        }
        if let Some(prepared) = self.prepared.get() {
            if prepared.id != id {
                return Err(ReconciliationError::AttemptChanged);
            }
            if prepared.provenance != Provenance::Registered {
                return Err(ReconciliationError::ProvenanceChanged);
            }
            let records = prepared.snapshot.records();
            if registered_pages.len() != records.len()
                || registered_pages.iter().enumerate().any(|(index, page)| {
                    registered_pages[..index].contains(page)
                        || !records.iter().any(|record| record.page == *page)
                })
            {
                return Err(ReconciliationError::ProgressChanged);
            }
            prepared
                .snapshot
                .revalidate(resources, registry)
                .map_err(ReconciliationError::Registry)?;
            return Ok(&prepared.snapshot);
        }
        let snapshot = ThreadRegistrySnapshot::capture(resources, registry, registered_pages)
            .map_err(ReconciliationError::Registry)?;
        assert!(self
            .prepared
            .set(Prepared {
                id,
                snapshot,
                provenance: Provenance::Registered,
            })
            .is_ok());
        Ok(&self
            .prepared
            .get()
            .expect("published registered preparation")
            .snapshot)
    }
}

fn registered_pages<'a, const STACK: usize>(
    resources: &'a ThreadMemoryResources<STACK>,
    progress: &'a MemoryConstructionCoverage<STACK>,
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
    progress: &MemoryConstructionCoverage<STACK>,
    retirement: &ThreadMechanismRetirement,
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
        || (retirement.pending_memory_slot().is_some()
            && registry
                .records()
                .iter()
                .any(|record| [record.frame, record.alias_cap, record.source_cap].contains(&slot)))
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
