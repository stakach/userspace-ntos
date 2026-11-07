//! One ordinary root event may run while a component's exact receive parent is held.
//! Physical Reply parking and parent restoration remain native-owned effects.

use crate::thread_binding::ThreadBinding;
use nt_component_suspension::{
    ExternalAdmissionKey, ExternalIngress, ExternalSettlement, LaneDispatchIdentity,
    NestedExecutionIdentity, NestedExecutionScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassError {
    WrongChild,
    WrongParent,
    AlreadyBound,
    Unbound,
    InvalidPhase,
    Unsettled,
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Bound,
    Delivered,
    /// Native may have entered the park effect. No refusal or timeout can reopen this attempt.
    ParkEnteredUnknown,
    Checkpointed,
    RestoreEntered,
}

/// Exact one-event checkpoint. It never owns the child Reply or the physical parent hold.
/// Native retains both and supplies positive observations after their corresponding effects.
#[must_use = "retain the exact parent and child until a checkpoint permits restoration"]
#[derive(Debug)]
pub struct RootIngressPass<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: Option<NestedExecutionIdentity>,
    phase: Phase,
    settlement: Option<ExternalSettlement>,
}

/// One restoration attempt. A parked child remains independently owned by its ingress row.
#[must_use = "retain this permit through the physical parent restoration attempt"]
#[derive(Debug)]
pub struct RootIngressRestorePermit<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: NestedExecutionIdentity,
    settlement: Option<ExternalSettlement>,
}

impl<R: Copy + Eq> RootIngressPass<R> {
    pub fn prepare<M>(
        call: &ExternalIngress<M>,
        child: ThreadBinding<R>,
    ) -> Result<Self, PassError> {
        if child.tcb <= 1
            || child.tid == 0
            || !child.process.is_valid()
            || call.executor() != child.tcb
            || !call.can_park()
        {
            return Err(PassError::WrongChild);
        }
        Ok(Self {
            child,
            admission: call.admission_key(),
            parent: None,
            phase: Phase::Prepared,
            settlement: None,
        })
    }

    pub fn admission_key(&self) -> ExternalAdmissionKey {
        self.admission
    }

    pub fn bind_parent(
        &mut self,
        scope: &NestedExecutionScope,
        dispatch: LaneDispatchIdentity,
    ) -> Result<(), PassError> {
        if self.phase != Phase::Prepared {
            return Err(PassError::AlreadyBound);
        }
        if scope.is_consumed() || scope.dispatch() != dispatch {
            return Err(PassError::WrongParent);
        }
        self.parent = Some(scope.identity());
        self.phase = Phase::Bound;
        Ok(())
    }

    fn exact_child<M>(
        &self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), PassError> {
        if child != self.child || call.admission_key() != self.admission {
            return Err(PassError::WrongChild);
        }
        Ok(())
    }

    /// Native calls this only after the exact retained Call has become the root delivery.
    pub fn deliver<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), PassError> {
        self.exact_child(child, call)?;
        if self.phase != Phase::Bound || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        self.phase = Phase::Delivered;
        Ok(())
    }

    /// A positive Reply acknowledgement and checked Free produce this unforgeable settlement.
    /// A rejected settlement is returned to its caller for retention.
    pub fn acknowledge_settlement(
        &mut self,
        child: ThreadBinding<R>,
        settlement: ExternalSettlement,
    ) -> Result<(), (PassError, ExternalSettlement)> {
        let error = if child != self.child || settlement.admission_key() != self.admission {
            Some(PassError::WrongChild)
        } else if !matches!(self.phase, Phase::Delivered | Phase::ParkEnteredUnknown) {
            Some(PassError::InvalidPhase)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((error, settlement));
        }
        self.settlement = Some(settlement);
        self.phase = Phase::Checkpointed;
        Ok(())
    }

    /// Record entry before native RootReplyPark::try_commit. An unknown effect leaves this phase
    /// sealed; the caller must retain the original Reply and must not replay the park operation.
    pub fn begin_park<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), PassError> {
        self.exact_child(child, call)?;
        if self.phase != Phase::Delivered || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        self.phase = Phase::ParkEnteredUnknown;
        Ok(())
    }

    /// Native supplies this observation only after its exact RootReplyPark commit succeeded.
    /// This is not a physical receipt: the native owner still holds and verifies the Reply.
    pub fn acknowledge_park<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), PassError> {
        self.exact_child(child, call)?;
        if self.phase != Phase::ParkEnteredUnknown || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        self.phase = Phase::Checkpointed;
        Ok(())
    }

    /// A checkpoint grants one restoration attempt; it does not settle a parked child.
    pub fn begin_restore(
        &mut self,
        scope: &NestedExecutionScope,
    ) -> Result<RootIngressRestorePermit<R>, PassError> {
        let parent = self.parent.ok_or(PassError::Unbound)?;
        if scope.is_consumed() || parent != scope.identity() {
            return Err(PassError::WrongParent);
        }
        if self.phase == Phase::RestoreEntered {
            return Err(PassError::Consumed);
        }
        if self.phase != Phase::Checkpointed {
            return Err(PassError::Unsettled);
        }
        self.phase = Phase::RestoreEntered;
        Ok(RootIngressRestorePermit {
            child: self.child,
            admission: self.admission,
            parent,
            settlement: self.settlement.take(),
        })
    }
}

impl<R: Copy> RootIngressRestorePermit<R> {
    pub fn child(&self) -> ThreadBinding<R> {
        self.child
    }
    pub fn admission_key(&self) -> ExternalAdmissionKey {
        self.admission
    }
    pub fn parent(&self) -> NestedExecutionIdentity {
        self.parent
    }
    pub fn settlement(&self) -> Option<&ExternalSettlement> {
        self.settlement.as_ref()
    }
}

#[cfg(test)]
#[path = "root_ingress_pass_tests.rs"]
mod tests;
