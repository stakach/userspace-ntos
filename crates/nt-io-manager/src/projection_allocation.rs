//! Physical pool protection for the complete canonical DEVICE_OBJECT lifetime.
//!
//! This store is independent of IoManager borrowing and does not mirror File references. Native
//! adapters authenticate the physical allocator domain and exact allocation under its pool lock
//! before staging. Logical registration domains may differ from that physical domain.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_status::NtStatus;

use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::{HostedDevicePointerRegistration, HostedDomainId, HostedDomainIdentity};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
#[must_use = "retain physical protection until checked native free acknowledgement"]
pub struct ProjectionAllocationOwner {
    nonce: u64,
    held: bool,
}

impl ProjectionAllocationOwner {
    pub fn is_held(&self) -> bool {
        self.held
    }
}

struct Row {
    nonce: u64,
    physical: HostedDomainIdentity,
    allocation: SourcePoolAllocationIdentity,
    registration: Option<HostedDevicePointerRegistration>,
    retirement_pending: bool,
}

#[derive(Default)]
/// Keep this store alive at its stable native owner for every protected row. An owner token does
/// not preserve protection if its entire ledger is discarded; unresolved rows must not be dropped.
pub struct ProjectionAllocationLedger {
    rows: Vec<Row>,
}

impl ProjectionAllocationLedger {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Allocation and nonce refusal precede publication of any protection owner.
    pub fn stage(
        &mut self,
        physical: HostedDomainIdentity,
        allocation: SourcePoolAllocationIdentity,
    ) -> Result<ProjectionAllocationOwner, NtStatus> {
        if physical.domain_id == HostedDomainId::NULL
            || physical.cookie == 0
            || allocation.component_address == 0
            || allocation.component_address & 15 != 0
            || allocation.capacity == 0
            || allocation.pool_generation == 0
            || allocation
                .component_address
                .checked_add(allocation.capacity)
                .is_none()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let end = allocation.component_address + allocation.capacity;
        if self.rows.iter().any(|row| {
            row.physical == physical
                && allocation.component_address
                    < row.allocation.component_address + row.allocation.capacity
                && row.allocation.component_address < end
        }) {
            return Err(NtStatus::DEVICE_BUSY);
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let nonce = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        self.rows.push(Row {
            nonce,
            physical,
            allocation,
            registration: None,
            retirement_pending: false,
        });
        Ok(ProjectionAllocationOwner { nonce, held: true })
    }

    /// The minted canonical registration is associated without allocating or acquiring a ref.
    pub fn attach_registration(
        &mut self,
        owner: &ProjectionAllocationOwner,
        registration: HostedDevicePointerRegistration,
    ) -> Result<(), NtStatus> {
        let row = self.row_mut(owner)?;
        if row.retirement_pending
            || row.registration.is_some()
            || registration.address() != row.allocation.component_address
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        row.registration = Some(registration);
        Ok(())
    }

    /// Generic free is denied throughout the protected payload, not by a potentially forged
    /// interior header or contradictory generation. The caller authenticates the physical pool.
    pub fn protects_address(&self, physical: HostedDomainIdentity, address: u64) -> bool {
        self.rows.iter().any(|row| {
            row.physical == physical
                && address >= row.allocation.component_address
                && address < row.allocation.component_address + row.allocation.capacity
        })
    }

    /// Enter once before native retirement effects. Refusal leaves the protection unchanged;
    /// uncertain effects retain this pending owner and do not permit re-entry/replay.
    /// `None` is valid only for exact prepublication failed-bind cleanup.
    /// For an attached registration, native callers must first establish actual canonical teardown
    /// permission and drained projection references, and retain those fences through free ACK.
    /// Registration equality here proves provenance, not permission to delete a live Device.
    pub fn begin_retirement(
        &mut self,
        owner: &ProjectionAllocationOwner,
        current_physical: HostedDomainIdentity,
        current_allocation: SourcePoolAllocationIdentity,
        expected_registration: Option<HostedDevicePointerRegistration>,
    ) -> Result<(), NtStatus> {
        let row = self.row_mut(owner)?;
        if row.retirement_pending {
            return Err(NtStatus::DEVICE_BUSY);
        }
        if row.physical != current_physical
            || row.allocation != current_allocation
            || row.registration != expected_registration
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        row.retirement_pending = true;
        Ok(())
    }

    /// Native callers invoke this only after exact physical free acknowledgement. A Reply or
    /// unregister acknowledgement alone is not a physical free acknowledgement.
    pub fn acknowledge_free(
        &mut self,
        owner: &mut ProjectionAllocationOwner,
    ) -> Result<(), NtStatus> {
        if !owner.held {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let index = self
            .rows
            .iter()
            .position(|row| row.nonce == owner.nonce)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !self.rows[index].retirement_pending {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.rows.swap_remove(index);
        owner.held = false;
        Ok(())
    }

    fn row_mut(&mut self, owner: &ProjectionAllocationOwner) -> Result<&mut Row, NtStatus> {
        if !owner.held {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.rows
            .iter_mut()
            .find(|row| row.nonce == owner.nonce)
            .ok_or(NtStatus::INVALID_PARAMETER)
    }
}

#[cfg(test)]
#[path = "projection_allocation_tests.rs"]
mod tests;
