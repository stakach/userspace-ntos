//! Per-call MMIO request receipts above generation-owned physical page projections.
//!
//! A mapped BAR page may be shared by several identical `MmMapIoSpace` requests. Page ownership
//! alone cannot tell how many matching `MmUnmapIoSpace` calls are still owed. This table records
//! each native request before its effect and retires exactly one receipt per acknowledged unmap.

use alloc::vec::Vec;
use nt_pnp_context::ContextLeaseIdentity;

use crate::{ContiguousRamOwner, ContiguousRamPublishedMapping, GopPciBarAuthority};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioRequestOwner {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub authority: MmioRequestAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioRequestAuthority {
    Pnp {
        device_id: u64,
        /// Exact PnP registry authority, context, and token, checked before native admission.
        context_lease: ContextLeaseIdentity,
    },
    Gop {
        instance: usize,
        bar: GopPciBarAuthority,
        publication: u64,
        inventory_generation: u64,
    },
    ContiguousOwned {
        instance: usize,
        child: u64,
    },
    PoolOwned {
        instance: usize,
        pool_cap_base: u64,
        allocation_base: u64,
        allocation_generation: u64,
        allocation_capacity: u64,
    },
}

/// Root-captured, generation-bearing source of an already mapped WB pool allocation.
/// `cap_physical` must query the executive's frame cap, never a component-written table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolOwnedRamSource {
    pub instance: usize,
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub pool_va_base: u64,
    pub pool_cap_base: u64,
    pub pool_frames: u64,
    pub allocation_base: u64,
    pub allocation_capacity: u64,
    pub allocation_generation: u64,
}

impl PoolOwnedRamSource {
    pub const fn owner(self) -> MmioRequestOwner {
        MmioRequestOwner {
            domain_id: self.domain_id,
            domain_cookie: self.domain_cookie,
            authority: MmioRequestAuthority::PoolOwned {
                instance: self.instance,
                pool_cap_base: self.pool_cap_base,
                allocation_base: self.allocation_base,
                allocation_generation: self.allocation_generation,
                allocation_capacity: self.allocation_capacity,
            },
        }
    }

    pub fn project(
        self,
        physical_start: u64,
        length: u64,
        mut cap_physical: impl FnMut(u64) -> Option<u64>,
    ) -> Option<u64> {
        if self.domain_id == 0 || self.domain_cookie == 0 || self.pool_cap_base == 0
            || self.pool_frames == 0 || self.allocation_generation == 0
            || self.allocation_capacity == 0 || length == 0
        {
            return None;
        }
        let physical_end = physical_start.checked_add(length)?;
        let pool_end = self.pool_va_base.checked_add(self.pool_frames.checked_mul(0x1000)?)?;
        let allocation_end = self.allocation_base.checked_add(self.allocation_capacity)?;
        if self.allocation_base < self.pool_va_base || allocation_end > pool_end {
            return None;
        }
        let first_index = (self.allocation_base - self.pool_va_base) / 0x1000;
        let last_index = (allocation_end - 1 - self.pool_va_base) / 0x1000;
        let first_page = physical_start & !0xfff;
        let offset = physical_start & 0xfff;
        let mut found = None;
        for index in first_index..=last_index {
            let cap = self.pool_cap_base.checked_add(index)?;
            if cap_physical(cap)? != first_page {
                continue;
            }
            let va = self.pool_va_base.checked_add(index.checked_mul(0x1000)?)?
                .checked_add(offset)?;
            let va_end = va.checked_add(length)?;
            if va < self.allocation_base || va_end > allocation_end {
                continue;
            }
            let last_page = (physical_end - 1) & !0xfff;
            let spanned_pages = (last_page - first_page) / 0x1000;
            let mut matches = true;
            for page in 1..=spanned_pages {
                let next_index = index.checked_add(page)?;
                if next_index >= self.pool_frames
                    || cap_physical(self.pool_cap_base.checked_add(next_index)?)?
                        != first_page.checked_add(page.checked_mul(0x1000)?)?
                {
                    matches = false;
                    break;
                }
            }
            if matches {
                if found.is_some() {
                    return None;
                }
                found = Some(va);
            }
        }
        found
    }
}

impl MmioRequestOwner {
    const fn valid(self) -> bool {
        if self.domain_id == 0 || self.domain_cookie == 0 {
            return false;
        }
        match self.authority {
            MmioRequestAuthority::Pnp { device_id, .. } => device_id != 0,
            MmioRequestAuthority::Gop {
                publication,
                inventory_generation,
                ..
            } => publication != 0 && inventory_generation != 0,
            MmioRequestAuthority::ContiguousOwned { child, .. } => child != 0,
            MmioRequestAuthority::PoolOwned {
                pool_cap_base, allocation_base, allocation_generation, allocation_capacity, ..
            } => pool_cap_base != 0 && allocation_base != 0
                && allocation_generation != 0 && allocation_capacity != 0,
        }
    }

    pub const fn contiguous_owned(owner: ContiguousRamOwner, child: u64) -> Self {
        Self {
            domain_id: owner.domain,
            domain_cookie: owner.generation,
            authority: MmioRequestAuthority::ContiguousOwned {
                instance: owner.instance,
                child,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioRequest {
    pub owner: MmioRequestOwner,
    pub physical_start: u64,
    pub length: u64,
    pub cache: u32,
}

impl MmioRequest {
    pub fn from_pool_owned(
        source: PoolOwnedRamSource,
        owner: MmioRequestOwner,
        physical_start: u64,
        length: u64,
        requested_cache: u32,
        effective_cache: u32,
        cap_physical: impl FnMut(u64) -> Option<u64>,
    ) -> Option<(Self, u64)> {
        if owner != source.owner()
            || effective_cache != nt_hal_abi::MM_CACHED
            || !matches!(requested_cache,
                nt_hal_abi::MM_NON_CACHED | nt_hal_abi::MM_CACHED)
        {
            return None;
        }
        let va = source.project(physical_start, length, cap_physical)?;
        Some((Self { owner, physical_start, length, cache: requested_cache }, va))
    }

    /// The published source mapping proves both the returned VA and requested cache before any
    /// per-call receipt is prepared. The child comes from the selected live allocation row.
    pub fn from_contiguous_published(
        owner: ContiguousRamOwner,
        child: u64,
        mapping: ContiguousRamPublishedMapping,
        physical_start: u64,
        length: u64,
        cache: u32,
    ) -> Option<(Self, u64)> {
        if child == 0 {
            return None;
        }
        let va = mapping.virtual_address(owner, physical_start, length, cache)?;
        Some((
            Self {
                owner: MmioRequestOwner::contiguous_owned(owner, child),
                physical_start,
                length,
                cache,
            },
            va,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioRequestBacking {
    Assigned {
        resource_id: u64,
        mapping_id: u64,
    },
    Gop {
        publication: u64,
        inventory_generation: u64,
    },
    ContiguousOwned {
        child: u64,
    },
    PoolOwned {
        allocation_base: u64,
        allocation_generation: u64,
        effective_cache: u32,
    },
}

impl MmioRequestBacking {
    const fn valid(self) -> bool {
        match self {
            Self::Assigned {
                resource_id,
                mapping_id,
            } => resource_id != 0 && mapping_id != 0,
            Self::Gop {
                publication,
                inventory_generation,
            } => publication != 0 && inventory_generation != 0,
            Self::ContiguousOwned { child } => child != 0,
            Self::PoolOwned { allocation_base, allocation_generation, effective_cache } =>
                allocation_base != 0 && allocation_generation != 0
                    && effective_cache == nt_hal_abi::MM_CACHED,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioRequestReceipt(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioRequestPhase {
    Pending,
    Ready,
    MapUncertain,
    Unmapping,
    UnmapUncertain,
    /// The assigned map and its exact unmap both completed for this PnP owner. It proves
    /// StartDevice use but owns no live resource-manager mapping and cannot authorize replay.
    CompletedUse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioRequestError {
    InvalidRequest,
    InvalidReceipt,
    Unavailable,
    NotFound,
    InsufficientResources,
    IdExhausted,
}

struct Row {
    receipt: MmioRequestReceipt,
    request: MmioRequest,
    virtual_start: Option<u64>,
    backing: Option<MmioRequestBacking>,
    phase: MmioRequestPhase,
}

pub struct MmioRequestLedger {
    next_receipt: u64,
    rows: Vec<Row>,
}

impl Default for MmioRequestLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl MmioRequestLedger {
    pub const fn new() -> Self {
        Self {
            next_receipt: 1,
            rows: Vec::new(),
        }
    }

    /// Includes unresolved effects, but not acknowledged PnP uses retained only as StartDevice
    /// evidence. Completed use owns no live resource-manager mapping.
    pub fn live_count(&self) -> usize {
        self.rows.iter().filter(|row| row.phase != MmioRequestPhase::CompletedUse).count()
    }

    /// Root-only view for exact device publication and teardown. The returned backing is a
    /// resource-manager receipt; a shared bank or virtual address alone is not authority.
    pub fn owner_rows(
        &self,
        owner: MmioRequestOwner,
    ) -> impl Iterator<
        Item = (
            MmioRequest,
            Option<u64>,
            Option<MmioRequestBacking>,
            MmioRequestPhase,
        ),
    > + '_ {
        self.rows
            .iter()
            .filter(move |row| {
                row.request.owner == owner && row.phase != MmioRequestPhase::CompletedUse
            })
            .map(|row| (row.request, row.virtual_start, row.backing, row.phase))
    }

    /// An acknowledged assigned map/unmap of this exact resource is publication evidence until
    /// the PnP context retires. It is never a live map or unmap authority.
    pub fn has_completed_assigned_use(&self, owner: MmioRequestOwner, resource_id: u64) -> bool {
        matches!(owner.authority, MmioRequestAuthority::Pnp { .. })
            && self.rows.iter().any(|row| {
                row.request.owner == owner
                    && row.phase == MmioRequestPhase::CompletedUse
                    && matches!(row.backing, Some(MmioRequestBacking::Assigned {
                        resource_id: row_resource, ..
                    }) if row_resource == resource_id)
            })
    }

    /// Drop completed publication evidence only when the exact PnP context is retired. Live and
    /// uncertain requests remain owned for the caller's preflight and effect settlement.
    pub fn retire_completed_pnp_owner(&mut self, owner: MmioRequestOwner) {
        if matches!(owner.authority, MmioRequestAuthority::Pnp { .. }) {
            self.rows.retain(|row| {
                row.request.owner != owner || row.phase != MmioRequestPhase::CompletedUse
            });
        }
    }

    pub fn has_pnp_device_rows(&self, domain_id: u64, domain_cookie: u64, device_id: u64) -> bool {
        self.rows.iter().any(|row| {
            row.phase != MmioRequestPhase::CompletedUse
                && row.request.owner.domain_id == domain_id
                && row.request.owner.domain_cookie == domain_cookie
                && matches!(row.request.owner.authority,
                    MmioRequestAuthority::Pnp { device_id: row_device, .. }
                    if row_device == device_id)
        })
    }

    /// A source child cannot be retired while even an uncertain same-VA request remains.
    pub fn has_contiguous_source_rows(&self, owner: ContiguousRamOwner, child: u64) -> bool {
        self.rows
            .iter()
            .any(|row| row.request.owner == MmioRequestOwner::contiguous_owned(owner, child))
    }

    pub fn has_pool_source_rows(
        &self,
        pool_cap_base: u64,
        allocation_base: u64,
        allocation_capacity: u64,
    ) -> bool {
        let Some(end) = allocation_base.checked_add(allocation_capacity) else {
            return true;
        };
        self.rows.iter().any(|row| {
            let MmioRequestAuthority::PoolOwned {
                pool_cap_base: row_pool_cap_base,
                allocation_base: row_allocation_base,
                allocation_capacity: row_allocation_capacity,
                ..
            } = row.request.owner.authority else { return false };
            // A stale or uncertain generation still fences reuse of overlapping storage.
            let row_end = row_allocation_base.saturating_add(row_allocation_capacity);
            pool_cap_base == row_pool_cap_base
                && allocation_base < row_end && row_allocation_base < end
        })
    }

    /// A driver VSpace and its frame caps remain owned while any logical pool map can still
    /// name them, including a map or unmap whose outcome is uncertain.
    pub fn has_pool_cap_rows(&self, pool_cap_base: u64) -> bool {
        pool_cap_base != 0 && self.rows.iter().any(|row| matches!(
            row.request.owner.authority,
            MmioRequestAuthority::PoolOwned { pool_cap_base: owned, .. }
                if owned == pool_cap_base
        ))
    }

    pub fn phase(&self, receipt: MmioRequestReceipt) -> Option<MmioRequestPhase> {
        self.rows
            .iter()
            .find(|row| row.receipt == receipt)
            .map(|row| row.phase)
    }

    /// Reserve before entering resource-manager or native PageMap effects. A prior pending or
    /// uncertain equivalent request fences replay, while completed identical calls get new IDs.
    pub fn prepare(
        &mut self,
        request: MmioRequest,
    ) -> Result<MmioRequestReceipt, MmioRequestError> {
        let Some(request_end) = request.physical_start.checked_add(request.length) else {
            return Err(MmioRequestError::InvalidRequest);
        };
        if !request.owner.valid() || request.length == 0 {
            return Err(MmioRequestError::InvalidRequest);
        }
        if let MmioRequestAuthority::Gop {
            bar,
            publication,
            inventory_generation,
            ..
        } = request.owner.authority
        {
            if bar
                .project(
                    request.physical_start,
                    request.length,
                    inventory_generation,
                    request.owner.domain_id,
                    request.owner.domain_cookie,
                    publication,
                )
                .is_none()
            {
                return Err(MmioRequestError::InvalidRequest);
            }
        }
        if self.rows.iter().any(|row| {
            let row_end = row.request.physical_start + row.request.length;
            request.physical_start < row_end
                && row.request.physical_start < request_end
                && matches!(
                    row.phase,
                    MmioRequestPhase::Pending
                        | MmioRequestPhase::MapUncertain
                        | MmioRequestPhase::Unmapping
                        | MmioRequestPhase::UnmapUncertain
                )
        }) {
            return Err(MmioRequestError::Unavailable);
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| MmioRequestError::InsufficientResources)?;
        let next = self
            .next_receipt
            .checked_add(1)
            .ok_or(MmioRequestError::IdExhausted)?;
        let receipt = MmioRequestReceipt(self.next_receipt);
        self.next_receipt = next;
        self.rows.push(Row {
            receipt,
            request,
            virtual_start: None,
            backing: None,
            phase: MmioRequestPhase::Pending,
        });
        Ok(receipt)
    }

    /// Publish a successful map. The backing token is root-owned; a numeric VA is never its
    /// authority. A grant may outlive this request until its device context is retired.
    pub fn complete(
        &mut self,
        receipt: MmioRequestReceipt,
        virtual_start: u64,
        backing: MmioRequestBacking,
    ) -> Result<(), MmioRequestError> {
        let row = self.row_mut(receipt)?;
        if row.phase != MmioRequestPhase::Pending {
            return Err(MmioRequestError::Unavailable);
        }
        let same_authority = matches!(
            (row.request.owner.authority, backing),
            (
                MmioRequestAuthority::Pnp { .. },
                MmioRequestBacking::Assigned { .. }
            )
        ) || matches!((row.request.owner.authority, backing),
                (MmioRequestAuthority::Gop { publication: owner_publication,
                    inventory_generation: owner_inventory, .. },
                 MmioRequestBacking::Gop { publication, inventory_generation })
                if owner_publication == publication && owner_inventory == inventory_generation);
        let same_authority = same_authority
            || matches!(
                (row.request.owner.authority, backing),
                (MmioRequestAuthority::ContiguousOwned { child: owner_child, .. },
                 MmioRequestBacking::ContiguousOwned { child }) if owner_child == child
            );
        let same_authority = same_authority || matches!(
            (row.request.owner.authority, backing),
            (MmioRequestAuthority::PoolOwned { allocation_base: owner_base,
                allocation_generation: owner_generation, .. },
             MmioRequestBacking::PoolOwned { allocation_base, allocation_generation, .. })
                if owner_base == allocation_base && owner_generation == allocation_generation
        );
        if virtual_start == 0
            || virtual_start.checked_add(row.request.length).is_none()
            || !backing.valid()
            || !same_authority
        {
            return Err(MmioRequestError::InvalidRequest);
        }
        row.virtual_start = Some(virtual_start);
        row.backing = Some(backing);
        row.phase = MmioRequestPhase::Ready;
        Ok(())
    }

    /// Only an effect-free rejection can discard a prepared row.
    pub fn cancel_prepared(&mut self, receipt: MmioRequestReceipt) -> Result<(), MmioRequestError> {
        let index = self.index(receipt)?;
        if self.rows[index].phase != MmioRequestPhase::Pending {
            return Err(MmioRequestError::Unavailable);
        }
        self.rows.remove(index);
        Ok(())
    }

    pub fn mark_map_uncertain(
        &mut self,
        receipt: MmioRequestReceipt,
    ) -> Result<(), MmioRequestError> {
        let row = self.row_mut(receipt)?;
        if row.phase != MmioRequestPhase::Pending {
            return Err(MmioRequestError::Unavailable);
        }
        row.phase = MmioRequestPhase::MapUncertain;
        Ok(())
    }

    /// Select one exact call, newest duplicate first. An unresolved unmap for the same tuple
    /// blocks further unmaps because the caller cannot distinguish identical outstanding VAs.
    pub fn begin_unmap(
        &mut self,
        owner: MmioRequestOwner,
        virtual_start: u64,
        length: u64,
    ) -> Result<(MmioRequestReceipt, MmioRequestBacking), MmioRequestError> {
        if virtual_start == 0 || length == 0 || virtual_start.checked_add(length).is_none() {
            return Err(MmioRequestError::InvalidRequest);
        }
        if self.rows.iter().any(|row| {
            row.request.owner == owner
                && row.virtual_start == Some(virtual_start)
                && row.request.length == length
                && matches!(
                    row.phase,
                    MmioRequestPhase::Unmapping | MmioRequestPhase::UnmapUncertain
                )
        }) {
            return Err(MmioRequestError::Unavailable);
        }
        let row = self
            .rows
            .iter_mut()
            .rev()
            .find(|row| {
                row.request.owner == owner
                    && row.virtual_start == Some(virtual_start)
                    && row.request.length == length
                    && row.phase == MmioRequestPhase::Ready
            })
            .ok_or(MmioRequestError::NotFound)?;
        let backing = row.backing.ok_or(MmioRequestError::InvalidReceipt)?;
        row.phase = MmioRequestPhase::Unmapping;
        Ok((row.receipt, backing))
    }

    pub fn acknowledge_unmap(
        &mut self,
        receipt: MmioRequestReceipt,
    ) -> Result<(), MmioRequestError> {
        let index = self.index(receipt)?;
        if self.rows[index].phase != MmioRequestPhase::Unmapping {
            return Err(MmioRequestError::Unavailable);
        }
        let owner = self.rows[index].request.owner;
        if let (
            MmioRequestAuthority::Pnp { .. },
            Some(MmioRequestBacking::Assigned { resource_id, .. }),
        ) = (owner.authority, self.rows[index].backing)
        {
            // The exact call is settled; one completed receipt per owner/resource is enough
            // to prove StartDevice use. Runtime map/unmap loops must not grow history forever.
            if self.has_completed_assigned_use(owner, resource_id) {
                self.rows.remove(index);
            } else {
                self.rows[index].virtual_start = None;
                self.rows[index].phase = MmioRequestPhase::CompletedUse;
            }
        } else {
            self.rows.remove(index);
        }
        Ok(())
    }

    pub fn mark_unmap_uncertain(
        &mut self,
        receipt: MmioRequestReceipt,
    ) -> Result<(), MmioRequestError> {
        let row = self.row_mut(receipt)?;
        if row.phase != MmioRequestPhase::Unmapping {
            return Err(MmioRequestError::Unavailable);
        }
        row.phase = MmioRequestPhase::UnmapUncertain;
        Ok(())
    }

    fn index(&self, receipt: MmioRequestReceipt) -> Result<usize, MmioRequestError> {
        self.rows
            .iter()
            .position(|row| row.receipt == receipt)
            .ok_or(MmioRequestError::InvalidReceipt)
    }

    fn row_mut(&mut self, receipt: MmioRequestReceipt) -> Result<&mut Row, MmioRequestError> {
        let index = self.index(receipt)?;
        Ok(&mut self.rows[index])
    }
}
