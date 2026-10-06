//! Child settlement fencing for a physically held parent receive continuation.
//! Native authenticates the child binding before preparation and retains every owner on failure.

use crate::thread_binding::ThreadBinding;
use nt_component_suspension::{
    ExternalAdmissionKey, ExternalIngress, ExternalSettlement, LaneDispatchIdentity,
    NestedExecutionIdentity, NestedExecutionScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierError {
    WrongChild,
    WrongAdmission,
    WrongParent,
    AlreadyBound,
    Unbound,
    Unsettled,
    Consumed,
    AlreadySettled,
}

#[must_use = "retain the child barrier before parking its parent"]
#[derive(Debug)]
pub struct ReceiveChildBarrier<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: Option<NestedExecutionIdentity>,
    settlement: Option<ExternalSettlement>,
    restore_entered: bool,
}

/// One restoration attempt, retained with the physical parent through rejected or uncertain effects.
/// Dropping it cannot reopen the barrier or authorize another attempt.
#[must_use = "retain the permit through parent restoration, including uncertainty"]
#[derive(Debug)]
pub struct ReceiveRestorePermit<R> {
    child: ThreadBinding<R>,
    parent: NestedExecutionIdentity,
    settlement: ExternalSettlement,
}

impl<R: Copy + Eq> ReceiveChildBarrier<R> {
    pub fn prepare<M>(
        call: &ExternalIngress<M>,
        child: ThreadBinding<R>,
    ) -> Result<Self, BarrierError> {
        if child.tcb <= 1
            || child.tid == 0
            || !child.process.is_valid()
            || call.executor() != child.tcb
            || !call.can_park()
        {
            return Err(BarrierError::WrongChild);
        }
        Ok(Self {
            child,
            admission: call.admission_key(),
            parent: None,
            settlement: None,
            restore_entered: false,
        })
    }

    pub fn child(&self) -> ThreadBinding<R> {
        self.child
    }
    pub fn admission_key(&self) -> ExternalAdmissionKey {
        self.admission
    }

    pub fn bind_parent(
        &mut self,
        scope: &NestedExecutionScope,
        dispatch: LaneDispatchIdentity,
    ) -> Result<(), BarrierError> {
        if self.parent.is_some() {
            return Err(BarrierError::AlreadyBound);
        }
        if scope.is_consumed() || scope.dispatch() != dispatch {
            return Err(BarrierError::WrongParent);
        }
        self.parent = Some(scope.identity());
        Ok(())
    }

    pub fn accept_settlement(
        &mut self,
        child: ThreadBinding<R>,
        settlement: ExternalSettlement,
    ) -> Result<(), (BarrierError, ExternalSettlement)> {
        let error = if self.restore_entered {
            Some(BarrierError::Consumed)
        } else if self.parent.is_none() {
            Some(BarrierError::Unbound)
        } else if child != self.child {
            Some(BarrierError::WrongChild)
        } else if settlement.admission_key() != self.admission {
            Some(BarrierError::WrongAdmission)
        } else if self.settlement.is_some() {
            Some(BarrierError::AlreadySettled)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((error, settlement));
        }
        self.settlement = Some(settlement);
        Ok(())
    }

    pub fn begin_restore(
        &mut self,
        scope: &NestedExecutionScope,
    ) -> Result<ReceiveRestorePermit<R>, BarrierError> {
        if self.restore_entered {
            return Err(BarrierError::Consumed);
        }
        let parent = self.parent.ok_or(BarrierError::Unbound)?;
        if scope.is_consumed() || parent != scope.identity() {
            return Err(BarrierError::WrongParent);
        }
        let settlement = self.settlement.take().ok_or(BarrierError::Unsettled)?;
        self.restore_entered = true;
        Ok(ReceiveRestorePermit {
            child: self.child,
            parent,
            settlement,
        })
    }
}

impl<R: Copy> ReceiveRestorePermit<R> {
    pub fn settlement(&self) -> &ExternalSettlement {
        &self.settlement
    }
    pub fn child(&self) -> ThreadBinding<R> {
        self.child
    }
    pub fn admission_key(&self) -> ExternalAdmissionKey {
        self.settlement.admission_key()
    }
    pub fn parent(&self) -> NestedExecutionIdentity {
        self.parent
    }
    pub fn matches_scope(&self, scope: &NestedExecutionScope) -> bool {
        self.parent == scope.identity()
    }
}

#[cfg(test)]
#[path = "receive_child_barrier_tests.rs"]
mod tests;
