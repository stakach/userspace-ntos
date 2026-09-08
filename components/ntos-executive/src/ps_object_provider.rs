//! Exact provider VSpace retention for canonical Ps aliases.
//!
//! A source cap number is provenance, not a lease. Each prepublished record owns a copied PML4
//! capability and builds its exclusive branch through that copy. Leaf owners live in the caller.

use super::*;
use crate::ps_object_paging::{PsObjectPaging, PsObjectPagingError};
use nt_memory_manager::owned_capability_copy::{
    CapabilityCopyError, CapabilityCopyIo, OwnedCapabilityCopy,
};
use nt_memory_manager::owned_paging_structure::PagingStructureError;
use nt_provider_wait::{CatalogIdentity, ProviderDomainIdentity};

const INVALID: u32 = nt_address_space::STATUS_INVALID_PARAMETER;
const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProviderRoot {
    catalog: CatalogIdentity,
    provider: ProviderDomainIdentity,
    source_pml4: u64,
}

impl ProviderRoot {
    /// # Safety
    /// Root must authenticate that this source cap is the exact provider's assigned VSpace and
    /// retain that source identity until registration finishes or its retained attempt retires.
    /// Branch 129 must be unoccupied and exclusively reserved for this ledger. Neither a provider
    /// supplied cap number nor catalog membership alone proves the VSpace association.
    pub(crate) unsafe fn new(
        catalog: CatalogIdentity,
        provider: ProviderDomainIdentity,
        source_pml4: u64,
    ) -> Result<Self, u32> {
        let target = Self {
            catalog,
            provider,
            source_pml4,
        };
        target.validate_current()?;
        Ok(target)
    }

    pub(crate) const fn catalog(self) -> CatalogIdentity {
        self.catalog
    }
    pub(crate) const fn provider(self) -> ProviderDomainIdentity {
        self.provider
    }
    pub(crate) const fn source_pml4(self) -> u64 {
        self.source_pml4
    }

    fn validate_current(self) -> Result<(), u32> {
        let catalog = unsafe { &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS) };
        if self.source_pml4 == 0
            || catalog.identity() != Some(self.catalog)
            || !catalog.contains(self.provider)
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

struct Record {
    target: ProviderRoot,
    root: OwnedCapabilityCopy<ProviderRoot>,
    paging: Option<PsObjectPaging<ProviderRoot>>,
    retiring: bool,
}

#[must_use = "retain provider root and paging owners through all cleanup failures"]
pub(crate) struct ProviderRoots {
    records: Vec<Record>,
}

impl ProviderRoots {
    pub(crate) const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn index(&self, target: ProviderRoot) -> Result<usize, u32> {
        self.records
            .iter()
            .position(|row| row.target == target)
            .ok_or(INVALID)
    }

    /// Exact retained identity only, including cleanup rows and released tombstones. This is not
    /// permission to create a mapping or resume provider execution.
    pub(crate) fn retains(&self, target: ProviderRoot) -> bool {
        self.index(target).is_ok()
    }

    /// Permanently close mapping admission before the caller starts draining leaf owners.
    pub(crate) fn close_admission(&mut self, target: ProviderRoot) -> Result<(), u32> {
        let index = self.index(target)?;
        self.records[index].retiring = true;
        Ok(())
    }

    /// # Safety
    /// The caller durably owns this ledger before entry, serializes its mechanism operations,
    /// and preserves the constructor's exact source/branch contract. No component IPC or callback
    /// may reenter it. Cross-owner capability exclusion must include this ledger before entry.
    pub(crate) unsafe fn register(&mut self, target: ProviderRoot) -> Result<(), u32> {
        target.validate_current()?;
        let _durable = allocator::enter_durable();
        let index = if let Ok(index) = self.index(target) {
            if self.records[index].retiring {
                return Err(INVALID);
            }
            index
        } else {
            // A fully drained lifetime may release its numeric source slot for another provider.
            // Its identity tombstone still forbids resurrection or rebinding to a different slot.
            if self.records.iter().any(|row| {
                (row.target.source_pml4 == target.source_pml4 && !row.root.is_released())
                    || (row.target.catalog == target.catalog
                        && row.target.provider == target.provider)
            }) {
                return Err(INVALID);
            }
            self.records.try_reserve(1).map_err(|_| RESOURCES)?;
            let index = self.records.len();
            self.records.push(Record {
                target,
                root: OwnedCapabilityCopy::new(target),
                paging: None,
                retiring: false,
            });
            index
        };
        let row = &mut self.records[index];
        row.root.construct(&mut Io).map_err(copy_error)?;
        let held = row.root.copied_cap().ok_or(INVALID)?;
        if row.paging.is_none() {
            row.paging = Some(PsObjectPaging::new(target, held).map_err(paging_error)?);
        }
        Ok(())
    }

    /// The result is borrowed mapping authority, never permission to delete or recycle the cap.
    /// Caller keeps this ledger and its target alive until all dependent leaf owners are drained.
    pub(crate) fn mapping_root(&self, target: ProviderRoot) -> Result<u64, u32> {
        target.validate_current()?;
        let row = &self.records[self.index(target)?];
        if row.retiring || row.paging.is_none() {
            return Err(INVALID);
        }
        row.root.copied_cap().ok_or(INVALID)
    }

    /// # Safety
    /// Registration's lifetime, serialization and exclusive-branch contract must still hold.
    pub(crate) unsafe fn ensure_page(
        &mut self,
        target: ProviderRoot,
        address: u64,
    ) -> Result<(), u32> {
        let held = self.mapping_root(target)?;
        let index = self.index(target)?;
        self.records[index]
            .paging
            .as_mut()
            .ok_or(INVALID)?
            .ensure_page(target, held, address)
            .map_err(paging_error)
    }

    /// # Safety
    /// Caller permanently closes leaf/execution admission and drains every dependent alias,
    /// including failed constructions, before entry. Cleanup uses retained identity even when
    /// the catalog has retired it. The copied root is never released before all tables are gone.
    pub(crate) unsafe fn retire_descendants_drained(
        &mut self,
        target: ProviderRoot,
    ) -> Result<(), u32> {
        let index = self.index(target)?;
        let row = &mut self.records[index];
        row.retiring = true;
        if row.root.is_released() {
            return Ok(());
        }
        if let Some(paging) = row.paging.as_mut() {
            // A failed root delete/recycle can hide copied_cap, but keeps this exact slot owned.
            let held = row.root.snapshot().capability().ok_or(INVALID)?;
            paging
                .retire_descendants_drained(target, held)
                .map_err(paging_error)?;
        }
        row.root.retire(&mut Io).map_err(copy_error)
    }

    /// Includes copied PML4/table slots which are empty but still awaiting allocator recycling.
    pub(crate) fn owns_cap(&self, cap: u64) -> bool {
        self.records.iter().any(|row| {
            row.root.owns_cap(cap)
                || row
                    .paging
                    .as_ref()
                    .is_some_and(|paging| paging.owns_cap(cap))
        })
    }

    /// Source provenance remains reserved through incomplete copy and every retirement failure.
    /// Teardown must consult this before unbinding/reusing the provider's original VSpace slot.
    pub(crate) fn references_vspace(&self, source_pml4: u64) -> bool {
        source_pml4 != 0
            && self
                .records
                .iter()
                .any(|row| row.target.source_pml4 == source_pml4 && !row.root.is_released())
    }

    pub(crate) fn census(&self) -> [usize; 3] {
        let mut counts = [0; 3];
        for row in &self.records {
            if row.root.is_released() {
                counts[2] += 1;
            } else if row.retiring {
                counts[1] += 1;
            } else {
                counts[0] += 1;
            }
        }
        counts
    }
}

fn copy_error(error: CapabilityCopyError) -> u32 {
    match error {
        CapabilityCopyError::Backend(status) => status,
        _ => INVALID,
    }
}

fn paging_error(error: PsObjectPagingError) -> u32 {
    match error {
        PsObjectPagingError::InsufficientResources => RESOURCES,
        PsObjectPagingError::Mechanism(PagingStructureError::Backend(status)) => status,
        _ => INVALID,
    }
}

struct Io;
impl CapabilityCopyIo<ProviderRoot> for Io {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        try_alloc_slot().ok_or(RESOURCES)
    }

    fn copy_into(&mut self, slot: u64, target: &ProviderRoot) -> Result<(), u32> {
        target.validate_current()?;
        status(unsafe { copy_cap_into_r(target.source_pml4, slot) })
    }

    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        status(unsafe { cnode_delete_r(slot) })
    }

    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }.map_err(|_| INVALID)
    }
}

fn status(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(u32::try_from(error).unwrap_or(INVALID))
    }
}
