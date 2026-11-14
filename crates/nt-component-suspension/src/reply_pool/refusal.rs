//! Stable names for a refused retained-Call admission.
//!
//! Admission refuses without effects: the Call stays retained, the canonical Reply stays bound
//! and no dispatch identity is issued. A native adapter that reports the refusal needs to say
//! which invariant held it back, without depending on the layered error shape.

use super::{ReplyAdmissionError, ReplyPoolError};
use crate::{LaneError, RetainedDispatchError, RetainedWorkError};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefusal {
    /// The route or receiver does not belong to this pool's endpoint.
    WrongEndpoint = 1,
    /// A reserved receive on the shared endpoint has not been settled.
    ReceiveInProgress = 2,
    /// No slot remains for the Reply this admission would displace.
    ReplacementPoolFull = 3,
    /// The displaced or incoming Reply is already owned by the receiver, pool or another lane.
    ReplyAliased = 4,
    /// The source has no unadmitted Call parked on the shared endpoint.
    NoRetainedCall = 5,
    /// The stored Call is no longer held by its retained owner.
    CallNotHeld = 6,
    /// The route no longer resolves to its published lane, domain and generation.
    PeerIdentity = 7,
    /// Another lane or an entered terminal owns the single execution token.
    ExecutionBusy = 8,
    /// The target lane already has a dispatch, suspension or external continuation.
    LaneNotIdle = 9,
    /// The lane's canonical Reply is still bound in the kernel.
    CanonicalReplyNotFree = 10,
    /// The kernel does not bind the incoming Reply to the lane's executor.
    CallNotBoundToExecutor = 11,
    /// The kernel binding query itself failed.
    BindingQueryFailed = 12,
    /// The pool or receiver ledger rejected the request for another local reason.
    LedgerState = 13,
}

impl AdmissionRefusal {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WrongEndpoint => "wrong-endpoint",
            Self::ReceiveInProgress => "receive-in-progress",
            Self::ReplacementPoolFull => "replacement-pool-full",
            Self::ReplyAliased => "reply-aliased",
            Self::NoRetainedCall => "no-retained-call",
            Self::CallNotHeld => "call-not-held",
            Self::PeerIdentity => "peer-identity",
            Self::ExecutionBusy => "execution-busy",
            Self::LaneNotIdle => "lane-not-idle",
            Self::CanonicalReplyNotFree => "canonical-reply-not-free",
            Self::CallNotBoundToExecutor => "call-not-bound-to-executor",
            Self::BindingQueryFailed => "binding-query-failed",
            Self::LedgerState => "ledger-state",
        }
    }
}

impl<E> ReplyAdmissionError<E> {
    pub fn refusal(&self) -> AdmissionRefusal {
        match self {
            Self::Pool(ReplyPoolError::WrongEndpoint)
            | Self::Store(RetainedWorkError::WrongEndpoint) => AdmissionRefusal::WrongEndpoint,
            Self::Pool(ReplyPoolError::NotReady) => AdmissionRefusal::ReceiveInProgress,
            Self::Pool(ReplyPoolError::NoCapacity) => AdmissionRefusal::ReplacementPoolFull,
            Self::Pool(ReplyPoolError::ReplyInUse)
            | Self::Store(RetainedWorkError::ReplyInUse)
            | Self::Dispatch(RetainedDispatchError::ReplyInUse) => AdmissionRefusal::ReplyAliased,
            Self::Pool(ReplyPoolError::Query(_))
            | Self::Dispatch(RetainedDispatchError::Query(_)) => {
                AdmissionRefusal::BindingQueryFailed
            }
            Self::Store(RetainedWorkError::NotFound) => AdmissionRefusal::NoRetainedCall,
            Self::Dispatch(RetainedDispatchError::NotHeld) => AdmissionRefusal::CallNotHeld,
            Self::Dispatch(RetainedDispatchError::Peer(_)) => AdmissionRefusal::PeerIdentity,
            Self::Dispatch(RetainedDispatchError::Lane(LaneError::Busy)) => {
                AdmissionRefusal::ExecutionBusy
            }
            Self::Dispatch(RetainedDispatchError::Lane(_)) => AdmissionRefusal::LaneNotIdle,
            Self::Dispatch(RetainedDispatchError::OldReplyNotFree) => {
                AdmissionRefusal::CanonicalReplyNotFree
            }
            Self::Dispatch(RetainedDispatchError::BindingMismatch) => {
                AdmissionRefusal::CallNotBoundToExecutor
            }
            Self::Pool(_) | Self::Store(_) | Self::Dispatch(_) => AdmissionRefusal::LedgerState,
        }
    }
}
