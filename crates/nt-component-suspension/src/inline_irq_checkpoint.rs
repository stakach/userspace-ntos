//! Exact parent observation around one inline IRQ scheduler pass.
//!
//! A failed observation leaves the parent retained. It is never authority to
//! replay the scheduler pass, wake the caller, or retire its Reply.

use crate::{peer_registry::PeerRoute, IngressExecutionOwner, LaneDispatchIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InlineIrqCheckpointObservation {
    pub route: Option<PeerRoute>,
    pub dispatch: Option<LaneDispatchIdentity>,
    pub reply: Option<u64>,
    pub execution: Option<IngressExecutionOwner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InlineIrqCheckpointMismatch {
    Route,
    Dispatch,
    Reply,
    ExecutionOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InlineIrqCheckpointError {
    Preflight(InlineIrqCheckpointMismatch),
    PostRestore(InlineIrqCheckpointMismatch),
    Consumed,
}

/// One observation ticket for the exact retained parent; the ticket contains
/// no capability and does not authorize any scheduling or Reply effect.
#[must_use = "retain this ticket until the parent is exactly observed after the scheduler pass"]
#[derive(Debug)]
pub struct InlineIrqCheckpoint {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    complete: bool,
}

impl InlineIrqCheckpoint {
    pub fn begin(
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        reply: u64,
        before: InlineIrqCheckpointObservation,
    ) -> Result<Self, InlineIrqCheckpointError> {
        let claim = Self { route, dispatch, reply, complete: false };
        claim.check_before(before).map_err(InlineIrqCheckpointError::Preflight)?;
        Ok(claim)
    }

    pub fn verify_after(
        &mut self,
        after: InlineIrqCheckpointObservation,
    ) -> Result<(), InlineIrqCheckpointError> {
        if self.complete {
            return Err(InlineIrqCheckpointError::Consumed);
        }
        self.check_after(after).map_err(InlineIrqCheckpointError::PostRestore)?;
        self.complete = true;
        Ok(())
    }

    pub const fn is_complete(&self) -> bool { self.complete }

    fn check_before(
        &self,
        observed: InlineIrqCheckpointObservation,
    ) -> Result<(), InlineIrqCheckpointMismatch> {
        if observed.route != Some(self.route) {
            return Err(InlineIrqCheckpointMismatch::Route);
        }
        if observed.dispatch != Some(self.dispatch) {
            return Err(InlineIrqCheckpointMismatch::Dispatch);
        }
        if observed.reply != Some(self.reply) {
            return Err(InlineIrqCheckpointMismatch::Reply);
        }
        if !matches!(observed.execution, Some(IngressExecutionOwner::Dispatch(_))) {
            return Err(InlineIrqCheckpointMismatch::ExecutionOwner);
        }
        Ok(())
    }

    fn check_after(
        &self,
        observed: InlineIrqCheckpointObservation,
    ) -> Result<(), InlineIrqCheckpointMismatch> {
        self.check_before(observed)?;
        if observed.execution != Some(IngressExecutionOwner::Dispatch(self.dispatch)) {
            return Err(InlineIrqCheckpointMismatch::ExecutionOwner);
        }
        Ok(())
    }
}
