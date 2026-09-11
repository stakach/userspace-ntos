//! Exclusive queued APC selection across fallible user-context staging.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);

pub(super) fn allocate_identity() -> Result<u64, u32> {
    NEXT_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
}

/// Owns one exact queued APC until register installation commits or teardown releases it.
/// Dropping a live claim does not authorize another delivery attempt; the queue remains claimed.
///
/// ```compile_fail
/// use nt_process::UserApcClaim;
/// fn duplicate(claim: UserApcClaim) { let _ = claim.clone(); }
/// ```
#[derive(Debug)]
pub struct UserApcClaim {
    manager: u64,
    lifetime: ThreadLifetime,
    entry: u64,
    apc: UserApc,
    consumed: bool,
}

impl UserApcClaim {
    pub const fn apc(&self) -> UserApc {
        self.apc
    }
    pub const fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
}

impl ProcessManager {
    /// Claim the FIFO head without dequeuing it or allocating. A claimed head cannot be peeked,
    /// taken, or removed by its timer source while context staging may still refer to it.
    pub fn claim_user_apc(&mut self, tid: ThreadId) -> Result<Option<UserApcClaim>, u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.is_system_thread {
            return Err(STATUS_INVALID_HANDLE);
        }
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let Some(queued) = thread.user_apc_queue.front_mut() else {
            return Ok(None);
        };
        if queued.claimed {
            return Err(STATUS_DEVICE_BUSY);
        }
        debug_assert_ne!(self.user_apc_manager_identity, 0);
        queued.claimed = true;
        Ok(Some(UserApcClaim {
            manager: self.user_apc_manager_identity,
            lifetime: ThreadLifetime {
                thread_id: tid,
                process_id: thread.process_id,
                generation: thread.activation_generation,
            },
            entry: queued.identity,
            apc: queued.apc,
            consumed: false,
        }))
    }

    /// Validate after reentrant frame writes, immediately before checked context installation.
    /// Installation and commit must have no intervening executive reentry.
    pub fn validate_user_apc_claim(&self, claim: &UserApcClaim) -> bool {
        if claim.consumed || claim.manager == 0 || claim.manager != self.user_apc_manager_identity {
            return false;
        }
        self.threads
            .get(&claim.lifetime.thread_id)
            .is_some_and(|thread| {
                thread.process_id == claim.lifetime.process_id
                    && thread.activation_generation == claim.lifetime.generation
                    && thread.state != ThreadState::Terminated
                    && !thread.is_system_thread
                    && thread
                        .user_apc_queue
                        .front()
                        .is_some_and(|queued| queued.identity == claim.entry && queued.claimed)
            })
    }

    /// Consume only the selected APC after checked register installation succeeds.
    pub fn commit_user_apc_claim(&mut self, claim: &mut UserApcClaim) -> Result<UserApc, u32> {
        if !self.validate_user_apc_claim(claim) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let queued = self
            .threads
            .get_mut(&claim.lifetime.thread_id)
            .unwrap()
            .user_apc_queue
            .pop_front()
            .unwrap();
        claim.consumed = true;
        Ok(queued.apc)
    }

    /// A definite abandonment unclaims its exact entry, or acknowledges that queue clearing/thread
    /// teardown already invalidated it. Repeated release is harmless; another manager is an error.
    /// Never commits delivery or unclaims a newer entry with the same payload, source, or TID.
    pub fn release_user_apc_claim(&mut self, claim: &mut UserApcClaim) -> Result<(), u32> {
        if claim.manager == 0 || claim.manager != self.user_apc_manager_identity {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if claim.consumed {
            return Ok(());
        }
        if let Some(thread) = self.threads.get_mut(&claim.lifetime.thread_id) {
            if thread.process_id == claim.lifetime.process_id
                && thread.activation_generation == claim.lifetime.generation
            {
                if let Some(queued) = thread
                    .user_apc_queue
                    .iter_mut()
                    .find(|queued| queued.identity == claim.entry)
                {
                    if !queued.claimed {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    queued.claimed = false;
                }
            }
        }
        claim.consumed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
