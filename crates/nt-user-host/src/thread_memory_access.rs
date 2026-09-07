//! Deny-only memory exclusions retained by pending thread cleanup, independent of its journal.

use crate::thread_resources::{ThreadMemoryRange, ThreadMemoryResources};
use crate::thread_rollback::ThreadRollbackId;

/// Borrowed description, not a cleanup owner or permission to release any resource.
pub struct PendingThreadMemory<'a, const STACK: usize> {
    pub owner: ThreadRollbackId,
    pub memory: &'a ThreadMemoryResources<STACK>,
    pub user_stack_allocation_base: u64,
    pub user_stack_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadMemoryAccessError {
    InvalidRange,
    InvalidOwner(ThreadRollbackId),
    Excluded(ThreadRollbackId),
}

/// This is an exclusion check, not process authority admission. All pending generations at a PI
/// participate: a stale retained owner must not become invisible after an incorrect PI reuse.
/// Empty operations touch no memory. Invalid nonempty requests fail even without pending owners.
pub fn check_pending_thread_memory<'a, const STACK: usize>(
    pi: usize,
    base: u64,
    size: u64,
    pending: impl IntoIterator<Item = PendingThreadMemory<'a, STACK>>,
) -> Result<(), ThreadMemoryAccessError> {
    if size == 0 {
        return Ok(());
    }
    base.checked_add(size)
        .ok_or(ThreadMemoryAccessError::InvalidRange)?;
    for entry in pending {
        if entry.owner.identity().pi != pi {
            continue;
        }
        let invalid = ThreadMemoryAccessError::InvalidOwner(entry.owner);
        let layout = entry.memory.layout();
        if layout.is_some() && entry.memory.client_pi != pi
            || entry.memory.has_unlocated_capabilities()
        {
            return Err(invalid);
        }
        let stack = match (entry.user_stack_allocation_base, entry.user_stack_base) {
            (0, 0) => None,
            (bottom, top)
                if bottom != 0 && top > bottom && bottom % 4096 == 0 && top % 4096 == 0 =>
            {
                Some(ThreadMemoryRange {
                    base: bottom,
                    size: top - bottom,
                })
            }
            _ => return Err(invalid),
        };
        // Missing geometry is not proof that a pending owner has no accessible aliases.
        if layout.is_none() && stack.is_none() {
            return Err(invalid);
        }
        if layout.is_some_and(|layout| layout.overlaps(base, size))
            || stack.is_some_and(|stack| stack.overlaps(base, size))
        {
            return Err(ThreadMemoryAccessError::Excluded(entry.owner));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "thread_memory_access_tests.rs"]
mod tests;
