//! Exact pending-owner admission for dynamic user-stack retirement, never ordinary VM access.

use crate::process_identity::ProcessIdentity;
use crate::thread_memory_access::{
    check_pending_thread_memory, PendingThreadMemory, ThreadMemoryAccessError,
};
use crate::thread_pending::PendingThreadRuntime;
use crate::thread_resources::{ThreadMemoryLayout, ThreadMemoryRange, ThreadMemoryResources};
use crate::thread_rollback::ThreadRollbackId;
use core::marker::PhantomData;

/// Read-only geometry from the retained runtime, not a caller-supplied address authorization.
pub trait RuntimeThreadMemory<const STACK: usize> {
    fn thread_memory(&self) -> &ThreadMemoryResources<STACK>;
    fn user_stack_bounds(&self) -> (u64, u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackRetirementAccessError {
    MechanismsPending,
    InvalidGeometry,
    StaleOwner,
    InvalidRange,
    OutsideStack,
    Exclusion(ThreadMemoryAccessError),
}

/// Borrowed, non-cloneable exclusion exception. The owner must remain retained, and every use
/// must revalidate it in the complete pending table. This does not authorize frame/cap release:
/// canonical registry, pagefile, scratch-alias and provider ownership checks still apply.
///
/// ```compile_fail
/// use nt_user_host::thread_memory_retirement_access::UserStackRetirementPermit;
/// fn duplicate<'a>(permit: &UserStackRetirementPermit<'a>) -> UserStackRetirementPermit<'a> {
///     permit.clone()
/// }
/// ```
pub struct UserStackRetirementPermit<'a> {
    owner: ThreadRollbackId,
    stack: ThreadMemoryRange,
    fixed: Option<ThreadMemoryLayout>,
    retained: PhantomData<&'a ()>,
}

impl<R> PendingThreadRuntime<R> {
    /// Mechanisms must be fully retired before dynamic stack backing can be released. Fixed
    /// transport pages belong to the separate memory handoff journal and are never covered here.
    pub fn user_stack_retirement_permit<const STACK: usize>(
        &self,
    ) -> Result<UserStackRetirementPermit<'_>, StackRetirementAccessError>
    where
        R: RuntimeThreadMemory<STACK>,
    {
        if !self
            .registered_mechanism_retirement()
            .or_else(|| self.construction_retirement())
            .is_some_and(|owner| owner.is_complete())
        {
            return Err(StackRetirementAccessError::MechanismsPending);
        }
        let memory = self.runtime().thread_memory();
        let (bottom, top) = self.runtime().user_stack_bounds();
        let stack = validate_geometry(self.id(), memory, bottom, top)?;
        Ok(UserStackRetirementPermit {
            owner: self.id(),
            stack,
            fixed: memory.layout(),
            retained: PhantomData,
        })
    }
}

fn validate_geometry<const STACK: usize>(
    owner: ThreadRollbackId,
    memory: &ThreadMemoryResources<STACK>,
    bottom: u64,
    top: u64,
) -> Result<ThreadMemoryRange, StackRetirementAccessError> {
    if bottom == 0
        || top <= bottom
        || bottom % 4096 != 0
        || top % 4096 != 0
        || memory.client_pi != owner.identity().pi
        || memory.has_unlocated_capabilities()
        || memory
            .layout()
            .is_some_and(|fixed| fixed.overlaps(bottom, top - bottom))
    {
        return Err(StackRetirementAccessError::InvalidGeometry);
    }
    Ok(ThreadMemoryRange {
        base: bottom,
        size: top - bottom,
    })
}

impl UserStackRetirementPermit<'_> {
    pub fn owner(&self) -> ThreadRollbackId {
        self.owner
    }

    pub fn range(&self) -> ThreadMemoryRange {
        self.stack
    }

    /// `current_process` must come from the adapter's current process authority, not this permit.
    /// Validate before every synchronous cleanup attempt. No allocation or backend call occurs.
    pub fn check<'a, const STACK: usize>(
        &self,
        pi: usize,
        current_process: ProcessIdentity,
        base: u64,
        size: u64,
        pending: impl IntoIterator<Item = PendingThreadMemory<'a, STACK>>,
    ) -> Result<(), StackRetirementAccessError> {
        let identity = self.owner.identity();
        if identity.pi != pi
            || identity.pid != current_process.pid
            || identity.process_generation != current_process.generation
        {
            return Err(StackRetirementAccessError::StaleOwner);
        }
        let end = base
            .checked_add(size)
            .filter(|_| size != 0 && base % 4096 == 0 && size % 4096 == 0)
            .ok_or(StackRetirementAccessError::InvalidRange)?;
        if base < self.stack.base || end > self.stack.base + self.stack.size {
            return Err(StackRetirementAccessError::OutsideStack);
        }
        let mut found = false;
        for entry in pending {
            if entry.owner == self.owner {
                if found
                    || validate_geometry(
                        entry.owner,
                        entry.memory,
                        entry.user_stack_allocation_base,
                        entry.user_stack_base,
                    )? != self.stack
                    || entry.memory.layout() != self.fixed
                {
                    return Err(StackRetirementAccessError::StaleOwner);
                }
                found = true;
            } else {
                check_pending_thread_memory(pi, base, size, core::iter::once(entry))
                    .map_err(StackRetirementAccessError::Exclusion)?;
            }
        }
        if !found {
            return Err(StackRetirementAccessError::StaleOwner);
        }
        Ok(())
    }
}
