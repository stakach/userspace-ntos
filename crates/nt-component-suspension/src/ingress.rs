//! Exact receive/reply ownership for an outer endpoint, independent of parked component Calls.

use super::*;

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    InvalidBinding,
    ReplyInUse,
    ExecutionBusy,
    ExecutionOwnerMismatch,
    NotReady,
    WrongAttempt,
    IdentityExhausted,
}

/// The adapter must establish provenance; zero badges or empty message words do not prove NoCall.
#[derive(Debug)]
pub enum IngressObservation<M> {
    NoCall,
    /// Own the complete message snapshot; do not retain a view into a reused native IPC bank.
    Call(M),
}

/// Evidence supplied by the native adapter after an owned snapshot has been captured. Neither
/// message contents nor badge/tag shape alone establish this classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressReceiveDisposition {
    Call,
    NoCall,
}

/// Authority to receive while idle or on behalf of one exact dispatch or shared-worker startup.
/// This does not authorize another lane to execute or change any scheduling ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressExecutionOwner {
    Idle,
    Dispatch(LaneDispatchIdentity),
    /// Receive on behalf of one exact staged worker's startup, without a dispatch epoch.
    Startup(peer_registry::PeerRoute),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressReplyObservation {
    Acknowledged,
    NoEffects,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Ready,
    Receiving(u64),
    Unresolved(u64),
    Held,
    Replying(u64),
}

/// Root must supply a genuinely unbound, exclusively owned Reply object, not just a free cptr.
/// This object retains payload ownership across failed or uncertain effects. It does not route
/// requests, allocate capabilities, or authorize execution of any provider lane.
#[must_use = "retain the ingress owner until its received call is acknowledged or transferred"]
pub struct ComponentIngress<M> {
    endpoint: u64,
    reply: u64,
    phase: Phase,
    message: Option<M>,
    held_receive: u64,
}

/// Dropping a receive attempt leaves Receiving or Unresolved intact, including any captured
/// payload, and cannot authorize a second receive.
///
/// ```compile_fail
/// use nt_component_suspension::IngressReceiveAttempt;
/// fn duplicate(attempt: IngressReceiveAttempt) { let _ = attempt.clone(); }
/// ```
#[must_use = "observe the exact receive; dropping this ticket does not permit retry"]
#[derive(Debug)]
pub struct IngressReceiveAttempt {
    identity: u64,
}

impl IngressReceiveAttempt {
    pub(crate) const fn identity(&self) -> u64 {
        self.identity
    }
}

/// Dropping a reply attempt retains the message and excludes replay of uncertain effects.
///
/// ```compile_fail
/// use nt_component_suspension::IngressReplyAttempt;
/// fn duplicate(attempt: IngressReplyAttempt) { let _ = attempt.clone(); }
/// ```
#[must_use = "record the exact reply effect before reusing its capability"]
#[derive(Debug)]
pub struct IngressReplyAttempt {
    identity: u64,
}

fn allocate_attempt(counter: &AtomicU64) -> Result<u64, IngressError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 {
                None
            } else {
                next.checked_add(1)
            }
        })
        .map_err(|_| IngressError::IdentityExhausted)
}

impl<M> ComponentIngress<M> {
    pub fn new(endpoint: u64, reply: u64) -> Result<Self, IngressError> {
        if endpoint == 0 || reply == 0 || endpoint == reply {
            return Err(IngressError::InvalidBinding);
        }
        Ok(Self {
            endpoint,
            reply,
            phase: Phase::Ready,
            message: None,
            held_receive: 0,
        })
    }

    pub const fn endpoint(&self) -> u64 {
        self.endpoint
    }
    pub const fn reply(&self) -> u64 {
        self.reply
    }
    pub(crate) fn is_held(&self) -> bool {
        self.phase == Phase::Held
    }
    pub(crate) fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }
    pub(crate) fn held_receive_matches(&self, identity: u64) -> bool {
        identity != 0 && self.phase == Phase::Held && self.held_receive == identity
    }
    /// Inspect retained data, including unresolved receives. Presence does not prove Call or Reply
    /// binding authority; classification requires separately established transport provenance.
    pub fn message(&self) -> Option<&M> {
        self.message.as_ref()
    }

    /// Internal transport release only after exact Stop or restart ACK and a fresh Free proof.
    /// This ends any Reply attempt; it never retries or claims acknowledgment of its effect.
    pub(crate) fn into_unbound_parts(mut self) -> (Self, Option<M>) {
        let message = self.message.take();
        self.phase = Phase::Ready;
        self.held_receive = 0;
        (self, message)
    }

    fn begin_receive(
        &mut self,
        counter: &AtomicU64,
    ) -> Result<IngressReceiveAttempt, IngressError> {
        if self.phase != Phase::Ready {
            return Err(IngressError::NotReady);
        }
        let identity = allocate_attempt(counter)?;
        self.phase = Phase::Receiving(identity);
        Ok(IngressReceiveAttempt { identity })
    }

    /// Retain a raw receive before doing anything that can reuse its source IPC buffer. Keep the
    /// exact ticket until provenance is established. Dropping it leaves this owner unresolved;
    /// it does not release the payload or permit reply, handoff or another receive.
    pub fn capture_receive(
        &mut self,
        attempt: &mut IngressReceiveAttempt,
        message: M,
    ) -> Result<(), (IngressError, M)> {
        if attempt.identity == 0 || self.phase != Phase::Receiving(attempt.identity) {
            return Err((IngressError::WrongAttempt, message));
        }
        self.message = Some(message);
        self.phase = Phase::Unresolved(attempt.identity);
        Ok(())
    }

    /// Complete classification of the exact captured receive. Call retains the payload under the
    /// existing reply contract; NoCall transfers the snapshot back for notification processing.
    /// Neither result acknowledges a reply. On refusal, both the ticket and snapshot stay intact.
    pub fn resolve_receive(
        &mut self,
        attempt: &mut IngressReceiveAttempt,
        disposition: IngressReceiveDisposition,
    ) -> Result<Option<M>, IngressError> {
        if attempt.identity == 0 || self.phase != Phase::Unresolved(attempt.identity) {
            return Err(IngressError::WrongAttempt);
        }
        let receive_identity = attempt.identity;
        attempt.identity = 0;
        match disposition {
            IngressReceiveDisposition::Call => {
                self.phase = Phase::Held;
                self.held_receive = receive_identity;
                Ok(None)
            }
            IngressReceiveDisposition::NoCall => {
                self.phase = Phase::Ready;
                self.held_receive = 0;
                Ok(self.message.take())
            }
        }
    }

    /// NoCall includes authenticated notification wakes and proven empty nonblocking receives.
    /// For an ambiguous result, use capture_receive and retain its ticket until resolve_receive
    /// can establish provenance. This combined path accepts only already-classified observations.
    pub fn observe_receive(
        &mut self,
        attempt: &mut IngressReceiveAttempt,
        observed: IngressObservation<M>,
    ) -> Result<(), (IngressError, IngressObservation<M>)> {
        if attempt.identity == 0 || self.phase != Phase::Receiving(attempt.identity) {
            return Err((IngressError::WrongAttempt, observed));
        }
        match observed {
            IngressObservation::NoCall => {
                self.phase = Phase::Ready;
                self.held_receive = 0;
            }
            IngressObservation::Call(message) => {
                self.message = Some(message);
                self.phase = Phase::Held;
                self.held_receive = attempt.identity;
            }
        }
        attempt.identity = 0;
        Ok(())
    }

    pub fn begin_reply(&mut self) -> Result<IngressReplyAttempt, IngressError> {
        self.begin_reply_with_counter(&NEXT_ATTEMPT)
    }

    fn begin_reply_with_counter(
        &mut self,
        counter: &AtomicU64,
    ) -> Result<IngressReplyAttempt, IngressError> {
        if self.phase != Phase::Held {
            return Err(IngressError::NotReady);
        }
        let identity = allocate_attempt(counter)?;
        self.phase = Phase::Replying(identity);
        Ok(IngressReplyAttempt { identity })
    }

    /// Only acknowledged reply consumption makes the same Reply unbound/reusable. An uncertain
    /// effect retains the exact ticket for later evidence, never permission to send again.
    pub fn observe_reply(
        &mut self,
        attempt: &mut IngressReplyAttempt,
        observed: IngressReplyObservation,
    ) -> Result<Option<M>, IngressError> {
        if attempt.identity == 0 || self.phase != Phase::Replying(attempt.identity) {
            return Err(IngressError::WrongAttempt);
        }
        match observed {
            IngressReplyObservation::Indeterminate => Ok(None),
            IngressReplyObservation::NoEffects => {
                self.phase = Phase::Held;
                attempt.identity = 0;
                Ok(None)
            }
            IngressReplyObservation::Acknowledged => {
                self.phase = Phase::Ready;
                self.held_receive = 0;
                attempt.identity = 0;
                Ok(self.message.take())
            }
        }
    }
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    pub(crate) fn validate_ingress_execution(
        &self,
        owner: IngressExecutionOwner,
    ) -> Result<(), IngressError> {
        match owner {
            IngressExecutionOwner::Idle if self.execution_busy() => {
                return Err(IngressError::ExecutionBusy)
            }
            IngressExecutionOwner::Idle => {}
            IngressExecutionOwner::Startup(route) => {
                if self.terminal_execution_busy() {
                    return Err(IngressError::ExecutionBusy);
                }
                let handle = route.identity().lane;
                let lane = self
                    .lane(handle)
                    .map_err(|_| IngressError::ExecutionOwnerMismatch)?;
                if self.running != Some(handle)
                    || lane.phase != LanePhase::Starting
                    || lane.dispatch.is_some()
                    || lane.shared_peer != Some(route)
                    || lane.binding.executor_id != route.identity().executor
                    || lane.binding.receive_endpoint != route.endpoint()
                {
                    return Err(IngressError::ExecutionOwnerMismatch);
                }
            }
            IngressExecutionOwner::Dispatch(dispatch) => {
                if self.terminal_execution_busy() {
                    return Err(IngressError::ExecutionBusy);
                }
                let lane = self
                    .lane(dispatch.lane)
                    .map_err(|_| IngressError::ExecutionOwnerMismatch)?;
                if self.running != Some(dispatch.lane)
                    || lane.phase != LanePhase::Running
                    || lane.dispatch != Some(dispatch)
                {
                    return Err(IngressError::ExecutionOwnerMismatch);
                }
            }
        }
        Ok(())
    }

    fn validate_ingress_reply(
        &self,
        reply: u64,
        owner: IngressExecutionOwner,
    ) -> Result<(), IngressError> {
        self.validate_ingress_execution(owner)?;
        if self.slots.iter().any(|slot| {
            slot.lane
                .as_ref()
                .is_some_and(|lane| lane.binding.reply_object == reply)
        }) {
            return Err(IngressError::ReplyInUse);
        }
        Ok(())
    }

    /// Consult canonical bindings on every receive claim, including idle and suspended lanes.
    /// Native code must also exclude replies retained by non-component owners.
    pub fn begin_ingress_receive<M>(
        &self,
        ingress: &mut ComponentIngress<M>,
    ) -> Result<IngressReceiveAttempt, IngressError> {
        self.begin_ingress_receive_for_owner(ingress, IngressExecutionOwner::Idle)
    }

    pub fn begin_ingress_receive_for_owner<M>(
        &self,
        ingress: &mut ComponentIngress<M>,
        owner: IngressExecutionOwner,
    ) -> Result<IngressReceiveAttempt, IngressError> {
        self.validate_ingress_reply(ingress.reply, owner)?;
        ingress.begin_receive(&NEXT_ATTEMPT)
    }

    /// Install a separately owned, genuinely unbound replacement for the same endpoint and move
    /// the original held call to its next owner. This is memory-only: no reply is sent and neither
    /// the payload nor the old bound Reply is released. Retain the returned owner before any IPC.
    /// Failures return the offered replacement intact and leave the original owner untouched.
    /// Root must also exclude replacement capabilities retained by non-component owners.
    pub fn handoff_ingress_call<M>(
        &self,
        ingress: &mut ComponentIngress<M>,
        replacement: ComponentIngress<M>,
    ) -> Result<ComponentIngress<M>, (IngressError, ComponentIngress<M>)> {
        self.handoff_ingress_call_for_owner(ingress, replacement, IngressExecutionOwner::Idle)
    }

    pub fn handoff_ingress_call_for_owner<M>(
        &self,
        ingress: &mut ComponentIngress<M>,
        replacement: ComponentIngress<M>,
        owner: IngressExecutionOwner,
    ) -> Result<ComponentIngress<M>, (IngressError, ComponentIngress<M>)> {
        let check = (|| {
            if ingress.phase != Phase::Held || replacement.phase != Phase::Ready {
                return Err(IngressError::NotReady);
            }
            if replacement.endpoint != ingress.endpoint || replacement.reply == ingress.reply {
                return Err(IngressError::InvalidBinding);
            }
            self.validate_ingress_reply(ingress.reply, owner)?;
            self.validate_ingress_reply(replacement.reply, owner)
        })();
        if let Err(error) = check {
            return Err((error, replacement));
        }
        Ok(core::mem::replace(ingress, replacement))
    }
}

#[cfg(test)]
#[path = "ingress_tests.rs"]
mod tests;
