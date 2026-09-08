//! Retained runtime ownership before fallible rollback-journal construction.
use crate::thread_binding::ThreadRuntimeReservations;
use crate::thread_construction::{FailedMemorySlot, Role, ThreadConstructionInventory};
use crate::thread_retirement::{RetirementError, ThreadConstructionRetirement, ThreadRetirementIo};
use crate::thread_rollback::{
    new_rollback_id, ThreadRollback, ThreadRollbackError, ThreadRollbackId, ThreadRollbackIdentity,
    ThreadRollbackIo, ThreadRollbackResource, ThreadRollbackStage,
};
use crate::thread_slot::RuntimeConstruction;
use alloc::vec::Vec;

/// Non-cloneable pending owner. Admission allocates no journal, and every preparation/cleanup
/// failure retains the runtime payload and exact reservation identity. Keep it in durable storage
/// until completion; dropping it is not a backend cleanup operation or reservation release.
///
/// The native adapter must keep its identity visible to ownership/collision/retirement checks,
/// while refusing runnable/control/badge dispatch and ordinary release. Those table guards and
/// memory-access exclusions are not implemented by storing this host-side object alone.
#[must_use = "retain the pending runtime and its reservations until checked cleanup completes"]
pub struct PendingThreadRuntime<R> {
    id: ThreadRollbackId,
    mechanisms: PendingMechanisms,
    runtime: R,
    reservations: ThreadRuntimeReservations,
    rollback: Option<ThreadRollback>,
    // Immutable transfer preflight, never a second per-cap release authority.
    handoff_inventory: Vec<ThreadRollbackResource>,
    memory_handed_off: bool,
}

/// Called only after journal preparation, before any memory cleanup operation. Validate every
/// expected cap and retained external transfer receipt before clearing copied cap projections.
/// Preserve geometry, process identity and reservations. Failure leaves the payload unchanged;
/// success must be allocation-free and perform no backend call or reentry.
pub trait RuntimeMemoryHandoff {
    fn clear_memory_projections(
        &mut self,
        id: ThreadRollbackId,
        inventory: &[ThreadRollbackResource],
    ) -> Result<(), u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryHandoffError {
    StaleOwner,
    NotPrepared,
    Projection(u32),
}

enum PendingMechanisms {
    Registered(u64),
    Construction(ThreadConstructionRetirement),
}

struct ProjectionRetirementIo<'a, R, T> {
    runtime: &'a mut R,
    backend: &'a mut T,
}

impl<R: RuntimeConstruction, T: ThreadRetirementIo> ThreadRetirementIo
    for ProjectionRetirementIo<'_, R, T>
{
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.backend.is_current(id)
    }
    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        self.backend.suspend_tcb(tcb)
    }
    fn delete_cap(&mut self, role: Role, cap: u64) -> Result<(), u32> {
        self.backend.delete_cap(role, cap)
    }
    fn recycle_slot(&mut self, role: Role, slot: u64) -> Result<(), u32> {
        if role == Role::Tcb {
            self.runtime.clear_retired_tcb_projection(slot)?;
        }
        self.backend.recycle_slot(role, slot)
    }
    fn recycle_failed_memory_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.backend.recycle_failed_memory_slot(slot)
    }
}

impl<R> PendingThreadRuntime<R> {
    /// Identity failure returns the original payload; no TCB/capability/commitment effect occurs.
    pub fn retain(
        identity: ThreadRollbackIdentity,
        tcb: u64,
        reservations: ThreadRuntimeReservations,
        runtime: R,
    ) -> Result<Self, (ThreadRollbackError, R)> {
        if tcb <= 1 {
            return Err((ThreadRollbackError::InvalidCapability, runtime));
        }
        let id = match new_rollback_id(identity) {
            Ok(id) => id,
            Err(error) => return Err((error, runtime)),
        };
        Ok(Self {
            id,
            mechanisms: PendingMechanisms::Registered(tcb),
            runtime,
            reservations,
            rollback: None,
            handoff_inventory: Vec::new(),
            memory_handed_off: false,
        })
    }

    /// The slot has validated and consumed this exact publication attempt. Keep the original
    /// runtime and its attached partial construction in-place before any journal allocation.
    pub(crate) fn retain_construction(
        id: ThreadRollbackId,
        inventory: ThreadConstructionInventory,
        memory_slot: Option<FailedMemorySlot>,
        reservations: ThreadRuntimeReservations,
        runtime: R,
    ) -> Self {
        Self {
            id,
            mechanisms: PendingMechanisms::Construction(ThreadConstructionRetirement::retain(
                id,
                inventory,
                memory_slot,
            )),
            runtime,
            reservations,
            rollback: None,
            handoff_inventory: Vec::new(),
            memory_handed_off: false,
        }
    }

    pub fn id(&self) -> ThreadRollbackId {
        self.id
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn reservations(&self) -> ThreadRuntimeReservations {
        self.reservations
    }

    pub fn cleanup(&self) -> Option<&ThreadRollback> {
        self.rollback.as_ref()
    }

    pub fn construction_retirement(&self) -> Option<&ThreadConstructionRetirement> {
        match &self.mechanisms {
            PendingMechanisms::Construction(owner) => Some(owner),
            PendingMechanisms::Registered(_) => None,
        }
    }

    pub(crate) fn advance_construction_retirement(
        &mut self,
        io: &mut impl ThreadRetirementIo,
    ) -> Result<(), RetirementError>
    where
        R: RuntimeConstruction,
    {
        match &mut self.mechanisms {
            PendingMechanisms::Construction(owner) => owner.advance(&mut ProjectionRetirementIo {
                runtime: &mut self.runtime,
                backend: io,
            }),
            PendingMechanisms::Registered(_) => Err(RetirementError::NotConstruction),
        }
    }

    /// Only one journal may attach to this attempt. Failed inventory validation/allocation may
    /// retry on this same pending owner, without recreating its identity or releasing any holds.
    /// Construction mechanisms and failed-memory slots must finish first. This journal then owns
    /// only memory release; disjoint external cleanup journals remain the adapter's responsibility.
    /// The resulting journal is staged, not executable: commit_memory_handoff must validate and
    /// clear copied release projections after all external transfer owners are retained.
    pub fn prepare_journal(
        &mut self,
        resources: &[ThreadRollbackResource],
    ) -> Result<(), ThreadRollbackError> {
        self.prepare_journal_with(resources, ThreadRollback::prepare_optional_tcb)
    }

    fn prepare_journal_with(
        &mut self,
        resources: &[ThreadRollbackResource],
        prepare: impl FnOnce(
            ThreadRollbackId,
            Option<u64>,
            &[ThreadRollbackResource],
        ) -> Result<ThreadRollback, ThreadRollbackError>,
    ) -> Result<(), ThreadRollbackError> {
        if self.rollback.is_some() {
            return Err(ThreadRollbackError::AlreadyPrepared);
        }
        let tcb = match &self.mechanisms {
            PendingMechanisms::Registered(tcb) => Some(*tcb),
            PendingMechanisms::Construction(owner) => {
                if !owner.is_complete() {
                    return Err(ThreadRollbackError::ConstructionPending);
                }
                if owner.conflicts(resources) {
                    return Err(ThreadRollbackError::ConflictingOwnership);
                }
                None
            }
        };
        let rollback = prepare(self.id, tcb, resources)?;
        let mut inventory = Vec::new();
        inventory
            .try_reserve_exact(resources.len())
            .map_err(|_| ThreadRollbackError::InsufficientResources)?;
        inventory.extend_from_slice(resources);
        self.handoff_inventory = inventory;
        self.rollback = Some(rollback);
        Ok(())
    }

    pub fn is_memory_handed_off(&self) -> bool {
        self.memory_handed_off
    }

    /// An exact retry after success is a no-op, even after cleanup changed the journal.
    pub fn commit_memory_handoff(
        &mut self,
        expected: ThreadRollbackId,
    ) -> Result<(), MemoryHandoffError>
    where
        R: RuntimeMemoryHandoff,
    {
        if self.id != expected {
            return Err(MemoryHandoffError::StaleOwner);
        }
        if self.rollback.is_none() {
            return Err(MemoryHandoffError::NotPrepared);
        }
        if self.memory_handed_off {
            return Ok(());
        }
        self.runtime
            .clear_memory_projections(self.id, &self.handoff_inventory)
            .map_err(MemoryHandoffError::Projection)?;
        self.memory_handed_off = true;
        Ok(())
    }

    pub fn advance(&mut self, io: &mut impl ThreadRollbackIo) -> Result<(), ThreadRollbackError> {
        if !self.memory_handed_off {
            return Err(ThreadRollbackError::NotPrepared);
        }
        self.rollback
            .as_mut()
            .ok_or(ThreadRollbackError::NotPrepared)?
            .advance(io)
    }

    /// Build a backend from read-only attribution while borrowing the private journal disjointly.
    /// The factory is never called before handoff; it exposes no mutable pending payload.
    pub fn advance_with<'a, T: ThreadRollbackIo>(
        &'a mut self,
        factory: impl FnOnce(&'a R) -> T,
    ) -> Result<(), ThreadRollbackError> {
        if !self.memory_handed_off {
            return Err(ThreadRollbackError::NotPrepared);
        }
        let rollback = self
            .rollback
            .as_mut()
            .ok_or(ThreadRollbackError::NotPrepared)?;
        let mut io = factory(&self.runtime);
        rollback.advance(&mut io)
    }

    /// Extract retirement bookkeeping only after the backend acknowledges final target commit.
    /// The original payload is not a runnable/reusable runtime: it may still describe released
    /// capabilities. The adapter must clear any mirrored references during checked release and
    /// must not republish this payload. Rejection returns the complete pending owner intact.
    pub fn try_into_retired_payload(self) -> Result<R, Self> {
        if self.rollback.as_ref().map(ThreadRollback::stage) != Some(ThreadRollbackStage::Complete)
        {
            return Err(self);
        }
        Ok(self.runtime)
    }
}

#[cfg(test)]
#[path = "thread_pending_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "thread_pending_handoff_tests.rs"]
mod handoff_tests;
