//! One retained pump attempt, from pre-entry through returned-result transfer.

use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_user_callback::{DispatchContext, SharedPageClientIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnedPumpKey {
    route: PeerRoute,
    physical_dispatch: LaneDispatchIdentity,
    win32k_dispatch: DispatchContext,
    client: SharedPageClientIdentity,
    initial_reply: u64,
    attempt: u64,
}

impl ReturnedPumpKey {
    pub fn new(
        route: PeerRoute,
        physical_dispatch: LaneDispatchIdentity,
        win32k_dispatch: DispatchContext,
        client: SharedPageClientIdentity,
        initial_reply: u64,
        attempt: u64,
    ) -> Option<Self> {
        (route.identity().lane == physical_dispatch.lane()
            && physical_dispatch.lane() == win32k_dispatch.lane
            && physical_dispatch.epoch() != 0
            && win32k_dispatch.dispatch_id != 0
            && initial_reply != 0 && attempt != 0)
            .then_some(Self { route, physical_dispatch, win32k_dispatch, client,
                initial_reply, attempt })
    }

    pub const fn route(self) -> PeerRoute { self.route }
    pub const fn physical_dispatch(self) -> LaneDispatchIdentity { self.physical_dispatch }
    pub const fn win32k_dispatch(self) -> DispatchContext { self.win32k_dispatch }
    pub const fn client(self) -> SharedPageClientIdentity { self.client }
    pub const fn initial_reply(self) -> u64 { self.initial_reply }
    pub const fn attempt(self) -> u64 { self.attempt }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReturnedPumpPhase { Active, Returned, Quarantined }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReturnedPumpError { WrongIdentity, ReplyMismatch, InvalidPhase, Quarantined }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnedPumpReplies {
    pub current: u64,
    pub returned: u64,
}

#[derive(Debug)]
enum State<P> {
    Active,
    Returned { pump: P, reply: u64 },
    Quarantined { pump: P, replies: ReturnedPumpReplies },
}

/// `C` carries the channel and the semantic continuation owner; `P` carries the returned pump.
/// Neither is copied or released by a failed classification. Store this in RetainedOwnerTable.
#[must_use = "retain the pump and Reply until exact downstream handoff"]
pub struct ReturnedPumpOwner<C, P> {
    key: ReturnedPumpKey,
    continuation: C,
    state: State<P>,
}

pub enum ReturnedPumpObservation<P> {
    Accepted,
    Quarantined(ReturnedPumpError),
    Refused(ReturnedPumpError, P),
}

impl<C, P> ReturnedPumpOwner<C, P> {
    pub fn active(key: ReturnedPumpKey, continuation: C) -> Self {
        Self { key, continuation, state: State::Active }
    }

    pub const fn key(&self) -> ReturnedPumpKey { self.key }
    pub fn phase(&self) -> ReturnedPumpPhase {
        match &self.state {
            State::Active => ReturnedPumpPhase::Active,
            State::Returned { .. } => ReturnedPumpPhase::Returned,
            State::Quarantined { .. } => ReturnedPumpPhase::Quarantined,
        }
    }
    pub const fn continuation(&self) -> &C { &self.continuation }
    pub fn pump(&self) -> Option<&P> {
        match &self.state {
            State::Active => None,
            State::Returned { pump, .. } | State::Quarantined { pump, .. } => Some(pump),
        }
    }
    /// Both observations survive an uncertain return; neither number alone proves authority.
    pub fn replies(&self) -> Option<ReturnedPumpReplies> {
        match &self.state {
            State::Active => None,
            State::Returned { reply, .. } => Some(ReturnedPumpReplies {
                current: *reply, returned: *reply,
            }),
            State::Quarantined { replies, .. } => Some(*replies),
        }
    }

    /// The native adapter must query `observed` from the physical owner and compare
    /// `current_reply` with the returned pump's own Reply. A copied key is not authority.
    /// A mismatch still moves the entire returned pump into this quarantined owner.
    pub fn record_return(
        &mut self,
        observed: ReturnedPumpKey,
        current_reply: u64,
        pump_reply: u64,
        pump: P,
    ) -> ReturnedPumpObservation<P> {
        if !matches!(self.state, State::Active) {
            return ReturnedPumpObservation::Refused(ReturnedPumpError::InvalidPhase, pump);
        }
        if observed != self.key {
            self.state = State::Quarantined { pump, replies: ReturnedPumpReplies {
                current: current_reply, returned: pump_reply,
            } };
            return ReturnedPumpObservation::Quarantined(ReturnedPumpError::WrongIdentity);
        }
        if current_reply == 0 || pump_reply == 0 || current_reply != pump_reply {
            self.state = State::Quarantined { pump, replies: ReturnedPumpReplies {
                current: current_reply, returned: pump_reply,
            } };
            return ReturnedPumpObservation::Quarantined(ReturnedPumpError::ReplyMismatch);
        }
        self.state = State::Returned { pump, reply: pump_reply };
        ReturnedPumpObservation::Accepted
    }

    pub fn quarantine_capture(&mut self) -> Result<(), ReturnedPumpError> {
        let previous = core::mem::replace(&mut self.state, State::Active);
        match previous {
            State::Returned { pump, reply } => {
                self.state = State::Quarantined { pump, replies: ReturnedPumpReplies {
                    current: reply, returned: reply,
                } };
                Ok(())
            }
            State::Quarantined { pump, replies } => {
                self.state = State::Quarantined { pump, replies };
                Err(ReturnedPumpError::Quarantined)
            }
            State::Active => Err(ReturnedPumpError::InvalidPhase),
        }
    }

    /// The caller must transfer the returned pair into an exact pending/terminal owner before
    /// acknowledging its RetainedOwnerTable checkout. A refusal returns `self` unchanged.
    pub fn into_returned(self, expected: ReturnedPumpKey)
        -> Result<(C, P, u64), (ReturnedPumpError, Self)>
    {
        if self.key != expected { return Err((ReturnedPumpError::WrongIdentity, self)); }
        match self.state {
            State::Active => Err((ReturnedPumpError::InvalidPhase, self)),
            State::Quarantined { .. } => Err((ReturnedPumpError::Quarantined, self)),
            State::Returned { .. } => {
                let Self { continuation, state, .. } = self;
                let State::Returned { pump, reply } = state else { unreachable!() };
                Ok((continuation, pump, reply))
            }
        }
    }
}
