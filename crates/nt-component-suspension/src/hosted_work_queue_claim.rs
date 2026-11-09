//! Ownership model for a hosted work item removed from a shared queue.
//!
//! The native adapter authenticates `K` against the physical queue slot, provider
//! generation, and queue head. A later callback invocation has its own route, dispatch,
//! Reply, and epoch. The queue may advance its head after this owner retains the copied
//! entry; a yielded callback still has one exact claim until its return is observed.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedWorkQueueClaimError {
    WrongInvocation,
    NoClaim,
}

#[must_use = "a dequeued provider callback needs an exact terminal observation"]
pub struct HostedWorkQueueClaim<K, E> {
    invocation: K,
    entry: Option<E>,
    entered: bool,
}

impl<K: Copy + Eq, E: Copy> HostedWorkQueueClaim<K, E> {
    pub fn dequeue(invocation: K, entry: E) -> Self {
        Self { invocation, entry: Some(entry), entered: false }
    }

    pub fn invocation(&self) -> K { self.invocation }

    pub fn retained_entry(&self, invocation: K) -> Result<&E, HostedWorkQueueClaimError> {
        if invocation != self.invocation {
            return Err(HostedWorkQueueClaimError::WrongInvocation);
        }
        self.entry.as_ref().ok_or(HostedWorkQueueClaimError::NoClaim)
    }

    /// Give the callback its copied arguments while retaining the queue claim. Reentry
    /// cannot execute the same work item again after an uncertain native effect.
    pub fn enter(&mut self, invocation: K) -> Result<E, HostedWorkQueueClaimError> {
        if invocation != self.invocation {
            return Err(HostedWorkQueueClaimError::WrongInvocation);
        }
        if self.entered {
            return Err(HostedWorkQueueClaimError::NoClaim);
        }
        let entry = *self.entry.as_ref().ok_or(HostedWorkQueueClaimError::NoClaim)?;
        self.entered = true;
        Ok(entry)
    }

    /// Retire a consumed shared slot only when no callback was entered. This is not a
    /// terminal callback acknowledgement and never advances the successful drain count.
    pub fn abort_before_enter(
        &mut self, invocation: K,
    ) -> Result<(), HostedWorkQueueClaimError> {
        if invocation != self.invocation {
            return Err(HostedWorkQueueClaimError::WrongInvocation);
        }
        if self.entered {
            return Err(HostedWorkQueueClaimError::NoClaim);
        }
        self.entry.take().ok_or(HostedWorkQueueClaimError::NoClaim)?;
        Ok(())
    }

    /// A returned callback may advance the native drain counter only once.
    pub fn acknowledge_return(
        &mut self, invocation: K,
    ) -> Result<(), HostedWorkQueueClaimError> {
        if invocation != self.invocation {
            return Err(HostedWorkQueueClaimError::WrongInvocation);
        }
        if !self.entered {
            return Err(HostedWorkQueueClaimError::NoClaim);
        }
        self.entry.take().ok_or(HostedWorkQueueClaimError::NoClaim)?;
        self.entered = false;
        Ok(())
    }
}
