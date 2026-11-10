//! Exact process and original Reply policy for a definitively failed entered spawn.
//!
//! The executive owns the physical child, Reply cap, and references. This value only decides
//! which observed completions may advance that owner; it never performs or retries an effect.

use crate::{ProcessDeletionCandidate, ProcessDeletionPhase, ProcessMechanism};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasFailure {
    Definite(u32),
    Uncertain(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortError {
    InvalidIdentity,
    InvalidStatus,
    UncertainEffect,
    StaleIdentity,
    OutOfOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortPhase {
    TerminateChild,
    RetireExecution,
    ReplyReady,
    ReplyEntered,
    ReplyAcknowledged,
    RevokeEntered,
    RevokeAcknowledged,
    RevokeReconciled,
    Complete,
}

/// One child mechanism and one original Reply. All transitions are generation exact.
pub struct EnteredSpawnAbort {
    child: ProcessMechanism,
    status: u32,
    phase: AbortPhase,
}

impl EnteredSpawnAbort {
    pub fn begin(child: ProcessMechanism, failure: AliasFailure) -> Result<Self, AbortError> {
        if child.pid == 0 || child.main_tid == 0 || child.generation == 0 || child.top_badge == 0 {
            return Err(AbortError::InvalidIdentity);
        }
        let AliasFailure::Definite(status) = failure else {
            return Err(AbortError::UncertainEffect);
        };
        if status == 0 {
            return Err(AbortError::InvalidStatus);
        }
        Ok(Self {
            child,
            status,
            phase: AbortPhase::TerminateChild,
        })
    }

    pub const fn phase(&self) -> AbortPhase {
        self.phase
    }
    pub const fn child(&self) -> ProcessMechanism {
        self.child
    }
    pub const fn blocks_child_teardown(&self) -> bool {
        matches!(self.phase, AbortPhase::TerminateChild)
    }
    pub const fn blocks_creator_teardown(&self) -> bool {
        !matches!(self.phase,
            AbortPhase::RevokeAcknowledged | AbortPhase::RevokeReconciled | AbortPhase::Complete)
    }

    fn require_child(&self, child: ProcessMechanism) -> Result<(), AbortError> {
        if self.child == child {
            Ok(())
        } else {
            Err(AbortError::StaleIdentity)
        }
    }

    pub fn record_child_terminated(&mut self, child: ProcessMechanism) -> Result<(), AbortError> {
        self.require_child(child)?;
        if self.phase != AbortPhase::TerminateChild {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::RetireExecution;
        Ok(())
    }

    pub fn record_execution_retired(
        &mut self,
        candidate: ProcessDeletionCandidate,
    ) -> Result<(), AbortError> {
        if !candidate.matches_mechanism(self.child) {
            return Err(AbortError::StaleIdentity);
        }
        if self.phase != AbortPhase::RetireExecution
            || candidate.phase < ProcessDeletionPhase::AwaitingReferences
        {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::ReplyReady;
        Ok(())
    }

    /// Record entry before the native Reply call, so an uncertain result cannot cause a replay.
    pub fn enter_reply(&mut self, child: ProcessMechanism) -> Result<u32, AbortError> {
        self.require_child(child)?;
        if self.phase != AbortPhase::ReplyReady {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::ReplyEntered;
        Ok(self.status)
    }

    /// May follow a direct Reply success or a later exact hosted Reply ACK observation.
    pub fn acknowledge_reply(&mut self, child: ProcessMechanism) -> Result<(), AbortError> {
        self.require_child(child)?;
        if self.phase != AbortPhase::ReplyEntered {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::ReplyAcknowledged;
        Ok(())
    }

    /// A confirmed cancellation permits revoking the original Reply. Record
    /// entry before the native revoke; an uncertain result must not be replayed.
    pub fn enter_revoke(
        &mut self,
        child: ProcessMechanism,
        cancelled: bool,
    ) -> Result<(), AbortError> {
        self.require_child(child)?;
        if !cancelled
            || !matches!(self.phase, AbortPhase::ReplyReady | AbortPhase::ReplyEntered)
        {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::RevokeEntered;
        Ok(())
    }

    /// Call only after the exact Reply was revoked and its slot retyped. The
    /// creator may now retire its mechanism while the child references remain.
    pub fn acknowledge_revoke(&mut self, child: ProcessMechanism) -> Result<(), AbortError> {
        self.require_child(child)?;
        if self.phase != AbortPhase::RevokeEntered {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::RevokeAcknowledged;
        Ok(())
    }

    /// Record completion of the creator's hosted runtime reconciliation.
    pub fn record_revoke_runtime_reconciled(
        &mut self,
        child: ProcessMechanism,
    ) -> Result<(), AbortError> {
        self.require_child(child)?;
        if self.phase != AbortPhase::RevokeAcknowledged {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::RevokeReconciled;
        Ok(())
    }

    pub fn release_references(&mut self, child: ProcessMechanism) -> Result<(), AbortError> {
        self.require_child(child)?;
        if !matches!(self.phase, AbortPhase::ReplyAcknowledged | AbortPhase::RevokeReconciled) {
            return Err(AbortError::OutOfOrder);
        }
        self.phase = AbortPhase::Complete;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
