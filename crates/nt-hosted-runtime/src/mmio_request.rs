//! Per-call MMIO request receipts above generation-owned physical page projections.
//!
//! A mapped BAR page may be shared by several identical `MmMapIoSpace` requests. Page ownership
//! alone cannot tell how many matching `MmUnmapIoSpace` calls are still owed. This table records
//! each native request before its effect and retires exactly one receipt per acknowledged unmap.

use alloc::vec::Vec;
use nt_pnp_context::ContextLeaseIdentity;

use crate::GopPciBarAuthority;

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
}

impl MmioRequestOwner {
    const fn valid(self) -> bool {
        if self.domain_id == 0 || self.domain_cookie == 0 { return false; }
        match self.authority {
            MmioRequestAuthority::Pnp { device_id, .. } => device_id != 0,
            MmioRequestAuthority::Gop { publication, inventory_generation, .. } => {
                publication != 0 && inventory_generation != 0
            }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioRequestBacking {
    Assigned { resource_id: u64, mapping_id: u64 },
    Gop { publication: u64, inventory_generation: u64 },
}

impl MmioRequestBacking {
    const fn valid(self) -> bool {
        match self {
            Self::Assigned { resource_id, mapping_id } => resource_id != 0 && mapping_id != 0,
            Self::Gop { publication, inventory_generation } => {
                publication != 0 && inventory_generation != 0
            }
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
    fn default() -> Self { Self::new() }
}

impl MmioRequestLedger {
    pub const fn new() -> Self {
        Self { next_receipt: 1, rows: Vec::new() }
    }

    /// Includes unresolved effects: these rows remain owned until their outcome is proved.
    pub fn live_count(&self) -> usize { self.rows.len() }

    /// Root-only view for exact device publication and teardown. The returned backing is a
    /// resource-manager receipt; a shared bank or virtual address alone is not authority.
    pub fn owner_rows(&self, owner: MmioRequestOwner)
        -> impl Iterator<Item = (MmioRequest, Option<u64>, Option<MmioRequestBacking>, MmioRequestPhase)> + '_
    {
        self.rows.iter().filter(move |row| row.request.owner == owner)
            .map(|row| (row.request, row.virtual_start, row.backing, row.phase))
    }

    pub fn has_pnp_device_rows(&self, domain_id: u64, domain_cookie: u64, device_id: u64) -> bool {
        self.rows.iter().any(|row| {
            row.request.owner.domain_id == domain_id
                && row.request.owner.domain_cookie == domain_cookie
                && matches!(row.request.owner.authority,
                    MmioRequestAuthority::Pnp { device_id: row_device, .. }
                    if row_device == device_id)
        })
    }

    pub fn phase(&self, receipt: MmioRequestReceipt) -> Option<MmioRequestPhase> {
        self.rows.iter().find(|row| row.receipt == receipt).map(|row| row.phase)
    }

    /// Reserve before entering resource-manager or native PageMap effects. A prior pending or
    /// uncertain equivalent request fences replay, while completed identical calls get new IDs.
    pub fn prepare(&mut self, request: MmioRequest)
        -> Result<MmioRequestReceipt, MmioRequestError>
    {
        let Some(request_end) = request.physical_start.checked_add(request.length) else {
            return Err(MmioRequestError::InvalidRequest);
        };
        if !request.owner.valid() || request.length == 0 {
            return Err(MmioRequestError::InvalidRequest);
        }
        if let MmioRequestAuthority::Gop { bar, publication, inventory_generation, .. } =
            request.owner.authority
        {
            if bar.project(request.physical_start, request.length,
                inventory_generation, request.owner.domain_id,
                request.owner.domain_cookie, publication).is_none()
            {
                return Err(MmioRequestError::InvalidRequest);
            }
        }
        if self.rows.iter().any(|row| {
            let row_end = row.request.physical_start + row.request.length;
            request.physical_start < row_end
                && row.request.physical_start < request_end
                && matches!(row.phase,
                    MmioRequestPhase::Pending | MmioRequestPhase::MapUncertain
                    | MmioRequestPhase::Unmapping | MmioRequestPhase::UnmapUncertain)
        })
        {
            return Err(MmioRequestError::Unavailable);
        }
        self.rows.try_reserve(1).map_err(|_| MmioRequestError::InsufficientResources)?;
        let next = self.next_receipt.checked_add(1).ok_or(MmioRequestError::IdExhausted)?;
        let receipt = MmioRequestReceipt(self.next_receipt);
        self.next_receipt = next;
        self.rows.push(Row {
            receipt, request, virtual_start: None, backing: None,
            phase: MmioRequestPhase::Pending,
        });
        Ok(receipt)
    }

    /// Publish a successful map. The backing token is root-owned; a numeric VA is never its
    /// authority. A grant may outlive this request until its device context is retired.
    pub fn complete(&mut self, receipt: MmioRequestReceipt, virtual_start: u64,
        backing: MmioRequestBacking) -> Result<(), MmioRequestError>
    {
        let row = self.row_mut(receipt)?;
        if row.phase != MmioRequestPhase::Pending {
            return Err(MmioRequestError::Unavailable);
        }
        let same_authority = matches!((row.request.owner.authority, backing),
            (MmioRequestAuthority::Pnp { .. }, MmioRequestBacking::Assigned { .. }))
            || matches!((row.request.owner.authority, backing),
                (MmioRequestAuthority::Gop { publication: owner_publication,
                    inventory_generation: owner_inventory, .. },
                 MmioRequestBacking::Gop { publication, inventory_generation })
                if owner_publication == publication && owner_inventory == inventory_generation);
        if virtual_start == 0 || virtual_start.checked_add(row.request.length).is_none()
            || !backing.valid() || !same_authority
        {
            return Err(MmioRequestError::InvalidRequest);
        }
        row.virtual_start = Some(virtual_start);
        row.backing = Some(backing);
        row.phase = MmioRequestPhase::Ready;
        Ok(())
    }

    /// Only an effect-free rejection can discard a prepared row.
    pub fn cancel_prepared(&mut self, receipt: MmioRequestReceipt)
        -> Result<(), MmioRequestError>
    {
        let index = self.index(receipt)?;
        if self.rows[index].phase != MmioRequestPhase::Pending {
            return Err(MmioRequestError::Unavailable);
        }
        self.rows.remove(index);
        Ok(())
    }

    pub fn mark_map_uncertain(&mut self, receipt: MmioRequestReceipt)
        -> Result<(), MmioRequestError>
    {
        let row = self.row_mut(receipt)?;
        if row.phase != MmioRequestPhase::Pending {
            return Err(MmioRequestError::Unavailable);
        }
        row.phase = MmioRequestPhase::MapUncertain;
        Ok(())
    }

    /// Select one exact call, newest duplicate first. An unresolved unmap for the same tuple
    /// blocks further unmaps because the caller cannot distinguish identical outstanding VAs.
    pub fn begin_unmap(&mut self, owner: MmioRequestOwner, virtual_start: u64, length: u64)
        -> Result<(MmioRequestReceipt, MmioRequestBacking), MmioRequestError>
    {
        if virtual_start == 0 || length == 0 || virtual_start.checked_add(length).is_none() {
            return Err(MmioRequestError::InvalidRequest);
        }
        if self.rows.iter().any(|row| row.request.owner == owner
            && row.virtual_start == Some(virtual_start) && row.request.length == length
            && matches!(row.phase,
                MmioRequestPhase::Unmapping | MmioRequestPhase::UnmapUncertain))
        {
            return Err(MmioRequestError::Unavailable);
        }
        let row = self.rows.iter_mut().rev().find(|row| row.request.owner == owner
            && row.virtual_start == Some(virtual_start) && row.request.length == length
            && row.phase == MmioRequestPhase::Ready)
            .ok_or(MmioRequestError::NotFound)?;
        let backing = row.backing.ok_or(MmioRequestError::InvalidReceipt)?;
        row.phase = MmioRequestPhase::Unmapping;
        Ok((row.receipt, backing))
    }

    pub fn acknowledge_unmap(&mut self, receipt: MmioRequestReceipt)
        -> Result<(), MmioRequestError>
    {
        let index = self.index(receipt)?;
        if self.rows[index].phase != MmioRequestPhase::Unmapping {
            return Err(MmioRequestError::Unavailable);
        }
        self.rows.remove(index);
        Ok(())
    }

    pub fn mark_unmap_uncertain(&mut self, receipt: MmioRequestReceipt)
        -> Result<(), MmioRequestError>
    {
        let row = self.row_mut(receipt)?;
        if row.phase != MmioRequestPhase::Unmapping {
            return Err(MmioRequestError::Unavailable);
        }
        row.phase = MmioRequestPhase::UnmapUncertain;
        Ok(())
    }

    fn index(&self, receipt: MmioRequestReceipt) -> Result<usize, MmioRequestError> {
        self.rows.iter().position(|row| row.receipt == receipt)
            .ok_or(MmioRequestError::InvalidReceipt)
    }

    fn row_mut(&mut self, receipt: MmioRequestReceipt)
        -> Result<&mut Row, MmioRequestError>
    {
        let index = self.index(receipt)?;
        Ok(&mut self.rows[index])
    }
}
