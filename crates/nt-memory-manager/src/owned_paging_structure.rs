//! Failure-retaining construction of a newly owned paging structure.
//!
//! The containing ledger must reserve and publish this owner before invoking construction.
//! Descriptors bind the native paging level, target VSpace and virtual address; this mechanism
//! neither allocates a second identity nor adopts an existing table after a mapping conflict.

/// Read-only construction and retirement progress, not capability release authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingStructurePhase {
    Vacant,
    Reserved,
    Retyped,
    Mapped,
    RetiringMapped,
    RetiringRetyped,
    RetiringDeleted,
    RetiringEmpty,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingStructureSnapshot {
    capability: Option<u64>,
    phase: PagingStructurePhase,
}

impl PagingStructureSnapshot {
    /// Includes allocated-empty and delete-acknowledged slots still awaiting recycling.
    pub const fn capability(self) -> Option<u64> {
        self.capability
    }

    pub const fn phase(self) -> PagingStructurePhase {
        self.phase
    }

    /// Successful retype accounting remains owned after capability deletion until recycling.
    pub const fn owns_retype_accounting(self) -> bool {
        matches!(
            self.phase,
            PagingStructurePhase::Retyped
                | PagingStructurePhase::Mapped
                | PagingStructurePhase::RetiringMapped
                | PagingStructurePhase::RetiringRetyped
                | PagingStructurePhase::RetiringDeleted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingStructureError {
    Backend(u32),
    InvalidCapability,
    RetiringOrReleased,
}

/// Synchronous, definitive mechanism operations. An error must leave the operation's input
/// ownership and mapping unchanged. In particular, retype failure leaves an empty slot and map
/// failure leaves an unmapped owned table. An existing table is a map error, never success.
///
/// Calls must not reenter the containing owner or ledger. They must not borrow that ledger while
/// invoking another component. The descriptor and allocated capability remain private to this
/// owner; the backend must not create untracked capability copies or child mappings.
pub trait PagingStructureIo<D> {
    /// Allocate one nonzero, exclusively owned empty slot. No allocation may be hidden by Err.
    fn reserve_slot(&mut self) -> Result<u64, u32>;
    fn retype(&mut self, slot: u64, descriptor: &D) -> Result<(), u32>;
    fn map(&mut self, slot: u64, descriptor: &D) -> Result<(), u32>;
    fn unmap(&mut self, slot: u64, descriptor: &D) -> Result<(), u32>;
    /// Acknowledge deletion only; retain allocator accounting until the separate recycle call.
    fn delete(&mut self, slot: u64) -> Result<(), u32>;
    fn recycle_retyped(&mut self, slot: u64) -> Result<(), u32>;
    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32>;
}

/// A single newly constructed table, deliberately neither `Copy` nor `Clone`.
///
/// Dropping this value does not clean up its capability. Its containing durable ledger must keep
/// the owner through every failure and may remove it only after `is_released()`. Before retirement
/// it must withdraw new child admission and retire every owned child mapping/table. Descriptors
/// may describe any native level, but their identity must remain immutable throughout ownership.
///
/// ```compile_fail
/// use nt_memory_manager::owned_paging_structure::OwnedPagingStructure;
/// let owner = OwnedPagingStructure::new((129u64, 0x4080_0000_0000u64));
/// let duplicate = owner.clone();
/// ```
#[must_use = "retain the paging owner until construction or retirement can resume"]
#[derive(Debug)]
pub struct OwnedPagingStructure<D> {
    descriptor: D,
    capability: Option<u64>,
    phase: PagingStructurePhase,
}

impl<D> OwnedPagingStructure<D> {
    pub const fn new(descriptor: D) -> Self {
        Self {
            descriptor,
            capability: None,
            phase: PagingStructurePhase::Vacant,
        }
    }

    pub const fn descriptor(&self) -> &D {
        &self.descriptor
    }

    pub const fn snapshot(&self) -> PagingStructureSnapshot {
        PagingStructureSnapshot {
            capability: self.capability,
            phase: self.phase,
        }
    }

    /// Only fully constructed, nonretiring tables can admit children.
    pub fn mapped_cap(&self) -> Option<u64> {
        (self.phase == PagingStructurePhase::Mapped)
            .then_some(self.capability)
            .flatten()
    }

    pub fn owns_cap(&self, capability: u64) -> bool {
        capability != 0 && self.capability == Some(capability)
    }

    pub const fn is_released(&self) -> bool {
        matches!(self.phase, PagingStructurePhase::Released)
    }

    /// Resume the first unacknowledged operation, without allocating metadata or repeating a
    /// successful retype/map. The slot is retained before any retype is attempted.
    pub fn construct(
        &mut self,
        io: &mut impl PagingStructureIo<D>,
    ) -> Result<(), PagingStructureError> {
        use PagingStructurePhase::*;
        if !matches!(self.phase, Vacant | Reserved | Retyped | Mapped) {
            return Err(PagingStructureError::RetiringOrReleased);
        }
        if self.phase == Vacant {
            let slot = io.reserve_slot().map_err(PagingStructureError::Backend)?;
            if slot == 0 {
                return Err(PagingStructureError::InvalidCapability);
            }
            self.capability = Some(slot);
            self.phase = Reserved;
        }
        if self.phase == Reserved {
            io.retype(self.capability.unwrap(), &self.descriptor)
                .map_err(PagingStructureError::Backend)?;
            self.phase = Retyped;
        }
        if self.phase == Retyped {
            io.map(self.capability.unwrap(), &self.descriptor)
                .map_err(PagingStructureError::Backend)?;
            self.phase = Mapped;
        }
        Ok(())
    }

    /// Irrevocably withdraw child admission and retire only acknowledged ownership. A failed
    /// unmap/delete/recycle retains its precise phase; retry never repeats an acknowledged step.
    pub fn retire(
        &mut self,
        io: &mut impl PagingStructureIo<D>,
    ) -> Result<(), PagingStructureError> {
        use PagingStructurePhase::*;
        self.phase = match self.phase {
            Vacant => Released,
            Reserved => RetiringEmpty,
            Retyped => RetiringRetyped,
            Mapped => RetiringMapped,
            phase => phase,
        };
        if self.phase == RetiringMapped {
            io.unmap(self.capability.unwrap(), &self.descriptor)
                .map_err(PagingStructureError::Backend)?;
            self.phase = RetiringRetyped;
        }
        if self.phase == RetiringRetyped {
            io.delete(self.capability.unwrap())
                .map_err(PagingStructureError::Backend)?;
            self.phase = RetiringDeleted;
        }
        if self.phase == RetiringDeleted {
            io.recycle_retyped(self.capability.unwrap())
                .map_err(PagingStructureError::Backend)?;
            self.capability = None;
            self.phase = Released;
        }
        if self.phase == RetiringEmpty {
            io.recycle_unretyped(self.capability.unwrap())
                .map_err(PagingStructureError::Backend)?;
            self.capability = None;
            self.phase = Released;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "owned_paging_structure_tests.rs"]
mod tests;
