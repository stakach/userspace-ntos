//! Own the two independent effects of returning from a nested shared subcall.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinueReparkPhase {
    Ready,
    ContinueEntered,
    ContinueAcknowledged,
    Indeterminate,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinueReparkOutcome {
    Acknowledged,
    /// The native adapter certifies that the Call was not entered.
    NoEffects,
    /// The Call may have entered; neither effect may be replayed.
    Indeterminate,
}

/// A one-use receipt for the native continue operation. Dropping it never restores retry
/// authority; the owner remains `ContinueEntered` until an outcome is recorded.
#[derive(Debug)]
pub struct ContinueReparkAttempt {
    route: peer_registry::PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
}

pub struct SharedContinueRepark {
    route: peer_registry::PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    phase: ContinueReparkPhase,
}

impl SharedContinueRepark {
    pub fn new(
        route: peer_registry::PeerRoute,
        dispatch: LaneDispatchIdentity,
        reply: u64,
        token: u64,
    ) -> Result<Self, LaneError> {
        if reply == 0 || token == 0 || dispatch.epoch() == 0
            || route.identity().lane != dispatch.lane()
        {
            return Err(LaneError::InvalidIdentity);
        }
        Ok(Self { route, dispatch, reply, token, phase: ContinueReparkPhase::Ready })
    }

    pub const fn phase(&self) -> ContinueReparkPhase { self.phase }

    fn exact(
        &self,
        route: peer_registry::PeerRoute,
        dispatch: LaneDispatchIdentity,
        reply: u64,
        token: u64,
    ) -> bool {
        self.route == route && self.dispatch == dispatch
            && self.reply == reply && self.token == token
    }

    pub fn begin_continue(
        &mut self,
        route: peer_registry::PeerRoute,
        dispatch: LaneDispatchIdentity,
        reply: u64,
        token: u64,
    ) -> Result<ContinueReparkAttempt, LaneError> {
        if !self.exact(route, dispatch, reply, token) {
            return Err(LaneError::InvalidIdentity);
        }
        if self.phase != ContinueReparkPhase::Ready {
            return Err(LaneError::InvalidPhase);
        }
        self.phase = ContinueReparkPhase::ContinueEntered;
        Ok(ContinueReparkAttempt { route, dispatch, reply, token })
    }

    pub fn record_continue(
        &mut self,
        attempt: ContinueReparkAttempt,
        outcome: ContinueReparkOutcome,
    ) -> Result<(), LaneError> {
        if !self.exact(attempt.route, attempt.dispatch, attempt.reply, attempt.token) {
            return Err(LaneError::InvalidIdentity);
        }
        if self.phase != ContinueReparkPhase::ContinueEntered {
            return Err(LaneError::InvalidPhase);
        }
        self.phase = match outcome {
            ContinueReparkOutcome::Acknowledged => ContinueReparkPhase::ContinueAcknowledged,
            ContinueReparkOutcome::NoEffects => ContinueReparkPhase::Ready,
            ContinueReparkOutcome::Indeterminate => ContinueReparkPhase::Indeterminate,
        };
        Ok(())
    }

    pub fn repark_exact<C, R, T>(
        &mut self,
        route: peer_registry::PeerRoute,
        dispatch: LaneDispatchIdentity,
        reply: u64,
        token: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), LaneError> {
        if !self.exact(route, dispatch, reply, token) {
            return Err(LaneError::InvalidIdentity);
        }
        if self.phase != ContinueReparkPhase::ContinueAcknowledged {
            return Err(LaneError::InvalidPhase);
        }
        lanes.repark_external(dispatch.lane(), reply, token)?;
        self.phase = ContinueReparkPhase::Done;
        Ok(())
    }
}
