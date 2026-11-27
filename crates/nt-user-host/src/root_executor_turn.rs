//! Ownership of one root arrival while a passive executive worker runs it.
//!
//! The executor table selects a worker in memory. This owner keeps the physical arrival and its
//! original Reply beside the borrowed run token across a native root-to-worker Call. A returned
//! worker yield is not permission to release the arrival: the original Reply must be acknowledged
//! or durably parked first. A Call with an uncertain result stays sealed and cannot be replayed.

use crate::{root_handoff_readmission::HandoffKey, thread_binding::ThreadBinding};
use nt_component_suspension::{
    ExecutorError, ExecutorHandle, ExecutorResume, ExecutorRun, ExecutorTable, ExecutorWait,
    ExecutorYield, ExternalAdmissionKey, RootReplyIdentity, RunToken,
};

/// A move-only native row that owns the received Call and its exact Reply identity.
/// Implementations must derive these facts from the retained row, not from request payloads.
pub trait RootArrivalOwner<R: Copy + Eq> {
    fn caller_binding(&self) -> ThreadBinding<R>;
    fn admission_key(&self) -> ExternalAdmissionKey;
    fn reply_identity(&self) -> RootReplyIdentity;
    /// Root's routing decision must be derived from this retained arrival's canonical route
    /// and dispatch generation. An unrouted hosted Call reports `Unrouted`.
    fn resume_cause(&self) -> ExecutorResume;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootTurnError {
    WrongArrival,
    WrongObservation,
    InvalidPhase,
    CallIndeterminate(u64),
    WrongWorker,
    SettlementRequired,
    WrongSettlement,
    Executor(ExecutorError),
}

/// The result of the *separate* worker-return Reply. The native adapter must authenticate the
/// exact worker/Reply binding before reporting `Returned`; this host type is not physical proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCallResult {
    Returned {
        executor: ExecutorHandle,
        yielded: ExecutorYield,
    },
    Indeterminate(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettlementKind {
    ReplyAcknowledged,
    DurablyParked(ExecutorWait),
}

/// A native-issued receipt for the original caller Reply, distinct from the worker-return Reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootCallSettlement<R> {
    key: HandoffKey<R>,
    reply: RootReplyIdentity,
    kind: SettlementKind,
}

impl<R: Copy + Eq> RootCallSettlement<R> {
    /// # Safety
    /// Native must have authenticated the exact caller, Reply pool generation and physical
    /// binding, then received a positive acknowledgement for sending the original Reply.
    pub unsafe fn reply_acknowledged_from_native(
        key: HandoffKey<R>,
        reply: RootReplyIdentity,
    ) -> Self {
        Self {
            key,
            reply,
            kind: SettlementKind::ReplyAcknowledged,
        }
    }

    /// # Safety
    /// Native must have durably parked the exact original Reply for this caller and wait before
    /// issuing this receipt. A queued request or a worker yield alone is insufficient.
    pub unsafe fn durably_parked_from_native(
        key: HandoffKey<R>,
        reply: RootReplyIdentity,
        wait: ExecutorWait,
    ) -> Self {
        Self {
            key,
            reply,
            kind: SettlementKind::DurablyParked(wait),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Ready,
    CallEnteredUnknown,
    Returned(ExecutorYield),
    Uncertain,
}

/// Root owns this through every native Call result, including uncertain results.
#[must_use = "retain the original arrival, Reply and run until exact settlement"]
pub struct RootExecutorTurn<R: Copy + Eq, A: RootArrivalOwner<R>> {
    run: Option<ExecutorRun>,
    key: HandoffKey<R>,
    reply: RootReplyIdentity,
    payload: Option<A>,
    phase: Phase,
}

impl<R: Copy + Eq, A: RootArrivalOwner<R>> RootExecutorTurn<R, A> {
    /// A refusal returns the complete run and payload, so the selected arrival cannot disappear.
    pub fn new(
        run: ExecutorRun,
        key: HandoffKey<R>,
        reply: RootReplyIdentity,
        payload: A,
    ) -> Result<Self, (RootTurnError, ExecutorRun, A)> {
        if HandoffKey::new(payload.caller_binding(), payload.admission_key()) != Some(key)
            || payload.reply_identity() != reply
            || key.admission().reply() != reply.cap()
            || payload.resume_cause() != run.cause()
        {
            return Err((RootTurnError::WrongArrival, run, payload));
        }
        Ok(Self {
            run: Some(run),
            key,
            reply,
            payload: Some(payload),
            phase: Phase::Ready,
        })
    }

    pub fn held_payload(&self) -> &A {
        self.payload
            .as_ref()
            .expect("unsettled turn retains its arrival")
    }

    pub const fn reply_identity(&self) -> RootReplyIdentity {
        self.reply
    }

    /// Seal the attempt before native entry. Even a mismatching worker return stays uncertain:
    /// the Call may have run, so the adapter must reconcile it without replaying this request.
    pub fn try_call(
        &mut self,
        observed_key: HandoffKey<R>,
        observed_reply: RootReplyIdentity,
        observed_cause: ExecutorResume,
        invoke: impl FnOnce(ExecutorHandle, ExecutorResume, &A) -> RootCallResult,
    ) -> Result<(), RootTurnError> {
        if self.phase != Phase::Ready {
            return Err(RootTurnError::InvalidPhase);
        }
        let run = self.run.as_ref().expect("unsettled turn retains run");
        if observed_key != self.key
            || observed_reply != self.reply
            || observed_cause != run.cause()
            || HandoffKey::new(
                self.held_payload().caller_binding(),
                self.held_payload().admission_key(),
            ) != Some(self.key)
            || self.held_payload().reply_identity() != self.reply
            || self.held_payload().resume_cause() != observed_cause
        {
            return Err(RootTurnError::WrongObservation);
        }
        let executor = run.executor();
        self.phase = Phase::CallEnteredUnknown;
        match invoke(executor, observed_cause, self.held_payload()) {
            RootCallResult::Returned {
                executor: returned,
                yielded,
            } if returned == executor => {
                self.phase = Phase::Returned(yielded);
                Ok(())
            }
            RootCallResult::Returned { .. } => {
                self.phase = Phase::Uncertain;
                Err(RootTurnError::WrongWorker)
            }
            RootCallResult::Indeterminate(status) => {
                self.phase = Phase::Uncertain;
                Err(RootTurnError::CallIndeterminate(status))
            }
        }
    }

    /// Return the run token only after native has settled the original Reply for this exact
    /// arrival. An executor-table refusal retains the entire turn and its worker yield.
    pub fn finish(
        mut self,
        table: &mut ExecutorTable,
        settlement: Option<RootCallSettlement<R>>,
    ) -> Result<RootTurnCompletion<R, A>, (RootTurnError, Self)> {
        let Phase::Returned(yielded) = self.phase else {
            return Err((RootTurnError::InvalidPhase, self));
        };
        let Some(settlement) = settlement else {
            return Err((RootTurnError::SettlementRequired, self));
        };
        if settlement.key != self.key
            || settlement.reply != self.reply
            || !matches!(
                (yielded, settlement.kind),
                (
                    ExecutorYield::Idle | ExecutorYield::Done,
                    SettlementKind::ReplyAcknowledged
                ) | (ExecutorYield::Parked(_), SettlementKind::DurablyParked(_))
            )
            || matches!((yielded, settlement.kind),
                (ExecutorYield::Parked(expected), SettlementKind::DurablyParked(actual))
                    if expected != actual)
        {
            return Err((RootTurnError::WrongSettlement, self));
        }
        let run = self.run.take().expect("unsettled turn retains run");
        let token = match table.accept_yield(run, yielded) {
            Ok(token) => token,
            Err((error, run)) => {
                self.run = Some(run);
                return Err((RootTurnError::Executor(error), self));
            }
        };
        let payload = self.payload.take().expect("unsettled turn retains arrival");
        Ok(match settlement.kind {
            SettlementKind::ReplyAcknowledged => RootTurnCompletion::Replied { token, payload },
            SettlementKind::DurablyParked(_) => RootTurnCompletion::Parked {
                token,
                owner: ParkedRootArrival {
                    key: self.key,
                    reply: self.reply,
                    payload,
                },
            },
        })
    }
}

/// Root still owns a parked caller, even after recovering its run token.
#[must_use = "retain the parked original Call and Reply until exact later settlement"]
pub struct ParkedRootArrival<R: Copy + Eq, A: RootArrivalOwner<R>> {
    key: HandoffKey<R>,
    reply: RootReplyIdentity,
    payload: A,
}

impl<R: Copy + Eq, A: RootArrivalOwner<R>> ParkedRootArrival<R, A> {
    pub fn held_payload(&self) -> &A {
        &self.payload
    }
    pub const fn reply_identity(&self) -> RootReplyIdentity {
        self.reply
    }
    pub const fn key(&self) -> HandoffKey<R> {
        self.key
    }
}

#[must_use = "root must retain the recovered token and caller disposition"]
pub enum RootTurnCompletion<R: Copy + Eq, A: RootArrivalOwner<R>> {
    Replied {
        token: RunToken,
        payload: A,
    },
    Parked {
        token: RunToken,
        owner: ParkedRootArrival<R, A>,
    },
}
