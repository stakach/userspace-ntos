//! Reconcile private thread backing with exact client-frame registry records.
use alloc::vec::Vec;
use nt_memory_manager::{
    ClientFrameRecord, ClientFrameRegistry, ClientFrameTransfer, ClientFrameTransferError,
};

use crate::thread_resources::{append_frame, ThreadMemoryResources};
use crate::thread_rollback::{ThreadRollbackError, ThreadRollbackResource};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadRegistryError {
    Resources(ThreadRollbackError),
    InvalidCoverage,
    MissingRecord { page: u64 },
    UnexpectedRecord { page: u64 },
    UnavailableRecord { page: u64 },
    WrongFrame { page: u64 },
    SharedCapability { cap: u64 },
    StaleResources,
    StaleRecord { page: u64 },
    InsufficientResources,
    Transfer(ClientFrameTransferError),
}

/// Read-only preparation, not a second physical owner or a cleanup journal. Runtime resources
/// supply the sole physical owner of each page. Registry source/mirror caps are copies of that
/// backing by registration provenance; their numeric values alone cannot prove seL4 derivation.
/// In particular a registry `frame` that matches the target cap remains an Alias even if the row's
/// legacy `owns_frame` flag says otherwise.
///
/// Before transfer, the adapter must retain its runtime/commitment/reservations, publish complete
/// memory exclusions, and prepare external attachment journals and the checked rollback owner.
/// This snapshot does not include those journals, TCB/mechanism ownership or process generation.
#[derive(Debug)]
pub struct ThreadRegistrySnapshot<const STACK: usize> {
    resources: ThreadMemoryResources<STACK>,
    records: Vec<ClientFrameRecord>,
    inventory: Vec<ThreadRollbackResource>,
}

impl<const STACK: usize> ThreadRegistrySnapshot<STACK> {
    /// `registered_pages` is the exhaustive expected subset of this thread's backing pages.
    /// Every other page in its geometry must be absent from the registry. An empty list explicitly
    /// requests unregistered coverage, independently of process index (including index zero).
    /// All described pages must have a physical owner; partial construction needs its own journal.
    pub fn capture(
        resources: &ThreadMemoryResources<STACK>,
        registry: &ClientFrameRegistry,
        registered_pages: &[u64],
    ) -> Result<Self, ThreadRegistryError> {
        if !resources.is_live() || resources.backing_pages().any(|(_, owner, _)| owner == 0) {
            return Err(ThreadRegistryError::Resources(
                ThreadRollbackError::InvalidIdentity,
            ));
        }
        let mut inventory = resources
            .rollback_resources()
            .map_err(ThreadRegistryError::Resources)?;
        for (index, page) in registered_pages.iter().enumerate() {
            if registered_pages[..index].contains(page)
                || !resources
                    .backing_pages()
                    .any(|(owned, _, _)| owned == *page)
            {
                return Err(ThreadRegistryError::InvalidCoverage);
            }
        }
        let extra = registered_pages
            .len()
            .checked_mul(2)
            .ok_or(ThreadRegistryError::InsufficientResources)?;
        inventory
            .try_reserve(extra)
            .map_err(|_| ThreadRegistryError::InsufficientResources)?;
        inventory.clear();
        let mut records = Vec::new();
        records
            .try_reserve(registered_pages.len())
            .map_err(|_| ThreadRegistryError::InsufficientResources)?;

        for (page, owner, aliases) in resources.backing_pages() {
            let row = registry.get(resources.client_pi as u64, page);
            let extra_aliases = if registered_pages.contains(&page) {
                let row = row.ok_or(ThreadRegistryError::MissingRecord { page })?;
                if !row.is_resident() {
                    return Err(ThreadRegistryError::UnavailableRecord { page });
                }
                if row.frame != owner && row.frame != aliases[0] {
                    return Err(ThreadRegistryError::WrongFrame { page });
                }
                records.push(row);
                [row.frame, row.alias_cap, row.source_cap]
            } else {
                if row.is_some() {
                    return Err(ThreadRegistryError::UnexpectedRecord { page });
                }
                [0; 3]
            };
            append_frame(
                &mut inventory,
                owner,
                &[
                    aliases[0],
                    aliases[1],
                    extra_aliases[0],
                    extra_aliases[1],
                    extra_aliases[2],
                ],
            )
            .map_err(ThreadRegistryError::Resources)?;
        }
        let snapshot = Self {
            resources: *resources,
            records,
            inventory,
        };
        snapshot.validate_unselected(registry)?;
        Ok(snapshot)
    }

    pub fn records(&self) -> &[ClientFrameRecord] {
        &self.records
    }

    pub fn rollback_resources(&self) -> &[ThreadRollbackResource] {
        &self.inventory
    }

    /// Allocation-free validation of both selected records and expected absence, plus cap sharing
    /// outside the selection. Selected-row equality alone cannot detect a new external alias.
    pub fn revalidate(
        &self,
        resources: &ThreadMemoryResources<STACK>,
        registry: &ClientFrameRegistry,
    ) -> Result<(), ThreadRegistryError> {
        if resources != &self.resources {
            return Err(ThreadRegistryError::StaleResources);
        }
        for record in &self.records {
            if registry.get(record.pi, record.page) != Some(*record) {
                return Err(ThreadRegistryError::StaleRecord { page: record.page });
            }
        }
        self.validate_unselected(registry)
    }

    /// Validate and acquire atomically under the same mutable registry borrow. `None` means the
    /// explicit coverage has no registry rows; the external memory exclusions are still required.
    /// Rejection leaves the snapshot, registry and runtime resources intact.
    pub fn prepare_transfer(
        &self,
        resources: &ThreadMemoryResources<STACK>,
        registry: &mut ClientFrameRegistry,
    ) -> Result<Option<ClientFrameTransfer>, ThreadRegistryError> {
        self.revalidate(resources, registry)?;
        if self.records.is_empty() {
            return Ok(None);
        }
        registry
            .prepare_transfer_exact(&self.records)
            .map(Some)
            .map_err(ThreadRegistryError::Transfer)
    }

    fn validate_unselected(
        &self,
        registry: &ClientFrameRegistry,
    ) -> Result<(), ThreadRegistryError> {
        let layout = self
            .resources
            .layout()
            .expect("capture requires live geometry");
        for record in registry.records() {
            if self
                .records
                .iter()
                .any(|selected| selected.pi == record.pi && selected.page == record.page)
            {
                continue;
            }
            if record.pi == self.resources.client_pi as u64 && layout.overlaps(record.page, 4096) {
                return Err(ThreadRegistryError::UnexpectedRecord { page: record.page });
            }
            for cap in [record.frame, record.alias_cap, record.source_cap] {
                if cap != 0 && self.inventory.iter().any(|resource| resource.cap == cap) {
                    return Err(ThreadRegistryError::SharedCapability { cap });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "thread_registry_tests.rs"]
mod tests;
