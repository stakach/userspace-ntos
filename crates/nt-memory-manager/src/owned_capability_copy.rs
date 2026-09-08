//! Retained ownership of one copied capability, including its allocated-empty slot.
//!
//! Publish the containing owner before construction. This mechanism creates no object identity:
//! the immutable descriptor must bind the genuine source and its lifetime in the native adapter.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityCopyPhase {
    Vacant,
    Reserved,
    Copied,
    RetiringCopied,
    RetiringEmpty,
    Released,
}

/// Read-only progress, not permission to release or reuse a capability slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityCopySnapshot {
    capability: Option<u64>,
    phase: CapabilityCopyPhase,
}

impl CapabilityCopySnapshot {
    /// Includes failed-copy and delete-acknowledged slots awaiting recycling.
    pub const fn capability(self) -> Option<u64> {
        self.capability
    }
    pub const fn phase(self) -> CapabilityCopyPhase {
        self.phase
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityCopyError {
    Backend(u32),
    InvalidCapability,
    RetiringOrReleased,
}

/// Synchronous, definitive operations which must not reenter this owner or its containing ledger.
/// Errors preserve input ownership: failed copy leaves an empty slot, failed delete leaves the
/// copied capability intact, and failed recycling retains the allocated-empty slot. Ambiguous
/// transport outcomes cannot satisfy this contract. No untracked copies may escape the backend.
pub trait CapabilityCopyIo<D> {
    /// Allocate a unique nonzero empty slot. Err must not hide an acquired slot.
    fn reserve_slot(&mut self) -> Result<u64, u32>;
    /// Validate the descriptor's exact source authority before copying into the reserved slot.
    fn copy_into(&mut self, slot: u64, descriptor: &D) -> Result<(), u32>;
    fn delete(&mut self, slot: u64) -> Result<(), u32>;
    /// Copied capabilities never own retype accounting. This transfers only the empty slot.
    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32>;
}

/// Nonclone ownership with no metadata allocation inside transitions.
///
/// Keep this value in a durable ledger through every failure; Drop does not clean up mechanisms.
/// Descriptors must remain immutable, including through interior mutability. Before retirement,
/// the caller must permanently withdraw descendant admission and drain every dependent mapping,
/// paging structure and execution owner. A copied VSpace cap alone is not that rundown proof.
///
/// ```compile_fail
/// use nt_memory_manager::owned_capability_copy::OwnedCapabilityCopy;
/// let owner = OwnedCapabilityCopy::new(7u64);
/// let duplicate = owner.clone();
/// ```
#[must_use = "retain the copied capability owner until checked retirement completes"]
#[derive(Debug)]
pub struct OwnedCapabilityCopy<D> {
    descriptor: D,
    capability: Option<u64>,
    phase: CapabilityCopyPhase,
}

impl<D> OwnedCapabilityCopy<D> {
    pub const fn new(descriptor: D) -> Self {
        Self {
            descriptor,
            capability: None,
            phase: CapabilityCopyPhase::Vacant,
        }
    }

    pub const fn descriptor(&self) -> &D {
        &self.descriptor
    }

    pub const fn snapshot(&self) -> CapabilityCopySnapshot {
        CapabilityCopySnapshot {
            capability: self.capability,
            phase: self.phase,
        }
    }

    /// Only a fully copied, nonretiring capability may admit dependent owners.
    pub fn copied_cap(&self) -> Option<u64> {
        if self.phase == CapabilityCopyPhase::Copied {
            self.capability
        } else {
            None
        }
    }

    pub fn owns_cap(&self, cap: u64) -> bool {
        cap != 0 && self.capability == Some(cap)
    }

    pub const fn is_released(&self) -> bool {
        matches!(self.phase, CapabilityCopyPhase::Released)
    }

    /// Store the allocated slot before copying. Retry only the first unacknowledged operation;
    /// successfully copied capabilities are never copied again or silently replaced.
    pub fn construct(
        &mut self,
        io: &mut impl CapabilityCopyIo<D>,
    ) -> Result<(), CapabilityCopyError> {
        use CapabilityCopyPhase::*;
        if !matches!(self.phase, Vacant | Reserved | Copied) {
            return Err(CapabilityCopyError::RetiringOrReleased);
        }
        if self.phase == Vacant {
            let slot = io.reserve_slot().map_err(CapabilityCopyError::Backend)?;
            if slot == 0 {
                return Err(CapabilityCopyError::InvalidCapability);
            }
            self.capability = Some(slot);
            self.phase = Reserved;
        }
        if self.phase == Reserved {
            io.copy_into(self.capability.unwrap(), &self.descriptor)
                .map_err(CapabilityCopyError::Backend)?;
            self.phase = Copied;
        }
        Ok(())
    }

    /// Caller has drained descendants before entry. Withdrawal is irreversible even on failure;
    /// retry never repeats acknowledged deletion and never deletes a failed-copy empty slot.
    pub fn retire(&mut self, io: &mut impl CapabilityCopyIo<D>) -> Result<(), CapabilityCopyError> {
        use CapabilityCopyPhase::*;
        self.phase = match self.phase {
            Vacant => Released,
            Reserved => RetiringEmpty,
            Copied => RetiringCopied,
            phase => phase,
        };
        if self.phase == RetiringCopied {
            io.delete(self.capability.unwrap())
                .map_err(CapabilityCopyError::Backend)?;
            self.phase = RetiringEmpty;
        }
        if self.phase == RetiringEmpty {
            io.recycle_unretyped(self.capability.unwrap())
                .map_err(CapabilityCopyError::Backend)?;
            self.capability = None;
            self.phase = Released;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "owned_capability_copy_tests.rs"]
mod tests;
