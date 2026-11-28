//! Run-token executors: root lends execution to one passive executor at a time.
//!
//! Root is the only ingress receiver. An executor's blocking receive is a yield back to root, so
//! a blocked operation keeps its own stack instead of nesting a receive loop on root's. This
//! table is memory-only: it decides which executor an arrival may resume and performs no native
//! effect. Arrivals stay retained by ingress; a refusal here changes nothing and consumes nothing.

use crate::{
    executor_local::{
        FsInstallAcknowledgement, PassiveWorkerReadyProof, PhysicalTcbClaim,
        PhysicalWorkerEndpointClaim, TcbIdentity, TcbRetirementObservation,
    },
    peer_registry::PeerRoute,
    root_reply_replacement::{
        RootReplyIdentity, RootReplyReplacementError, RootReplySlotState, RootReplySlotTable,
    },
    LaneDispatchIdentity,
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TABLE: AtomicU64 = AtomicU64::new(1);

/// One occupant of one table's executor slot. A reused slot never repeats an earlier generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorHandle {
    table: u64,
    index: u32,
    generation: u64,
}

impl ExecutorHandle {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// The exact provider job an executor blocks on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorWait {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
}

impl ExecutorWait {
    /// A dispatch is one job on one lane, so it can only be awaited on that lane's own route.
    pub fn new(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Option<Self> {
        (dispatch.lane() == route.identity().lane).then_some(Self { route, dispatch })
    }

    pub const fn route(self) -> PeerRoute {
        self.route
    }

    pub const fn dispatch(self) -> LaneDispatchIdentity {
        self.dispatch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorState {
    /// Created but lacking both an acknowledged FS base and checked passive receive.
    Unready,
    /// At loop-top on its own endpoint; may take any unrouted work.
    Idle,
    Running,
    /// The worker has returned and rearmed, but root still owns its hosted caller's Reply.
    AwaitingHostedReply,
    /// A checked supervisor terminal returned root's run token. Native resources stay retained.
    Faulted,
    /// A terminal or native effect was uncertain. The outstanding run remains retained.
    Quarantined,
    /// Blocked mid-job; only its exact wait or that route's retirement may resume it.
    Parked(ExecutorWait),
    /// Its loop exited. The slot may be registered again under a new generation.
    Retired,
}

/// Why root lends the run token; the native Resume message carries it to the executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorResume {
    /// Work outside any job in progress (hosted syscall, IRQ, timer): an executor at loop-top.
    Unrouted,
    /// An arrival for the job in progress on this exact route: only its parked waiter.
    Routed(ExecutorWait),
    /// The route retired, so nothing more can arrive for the wait parked on it. The native
    /// owner sends this only after the peer registry stopped resolving the route.
    RouteRetired(PeerRoute),
}

/// What a running executor's blocking receive reports as it returns the run token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorYield {
    Parked(ExecutorWait),
    Idle,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorError {
    /// The table is full, or its storage could not be reserved.
    NoCapacity,
    /// No unused table identity remains; wrapping would alias an earlier table's token.
    IdentityExhausted,
    /// The token or run was issued by another table.
    WrongTable,
    NotFound,
    StaleGeneration,
    /// Every executor is parked or retired. Parked executors are never borrowed.
    NoIdleExecutor,
    /// No executor is parked on this route.
    NotParked,
    /// The route's waiter is parked on a different dispatch generation.
    WrongDispatch,
    /// Another executor is already parked on this route.
    RouteOccupied,
    /// Only an unready executor may be activated by both physical worker proofs.
    NotUnready,
    /// FS publication and checked passive receive refer to different physical workers.
    WorkerProofMismatch,
    /// A live or uncertain worker already owns this private endpoint or Reply cap.
    DuplicateWorkerIngress,
    /// A fault binding or retirement observation named a different physical owner.
    FaultIdentityMismatch,
    /// The current run has no fault binding, or it already has one.
    FaultBindingState,
    /// A fault terminal has no checked successful native effect.
    FaultTerminalUncertain,
    /// A fault retirement observation was already accepted.
    FaultAlreadyRetired,
    /// A bound live job may leave Running only through an exact normal or fault terminal.
    LiveJobOutstanding,
    /// The normal terminal did not match the bound job, worker, Reply, or next receive.
    LiveJobIdentityMismatch,
    /// The normal native effect or rearm could not be classified.
    LiveTerminalUncertain,
}

/// Identities retained before root calls a worker. The native owner keeps the physical claim and
/// both Reply capabilities; this record only checks their exact identities at the model boundary.
#[must_use = "bind the fault owner before calling the worker"]
#[derive(Debug)]
pub struct ExecutorFaultBinding {
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
    root_reply: RootReplyIdentity,
    supervisor_reply: RootReplyIdentity,
}

impl ExecutorFaultBinding {
    /// # Safety
    /// The caller must retain the exact physical TCB claim and both owner-issued Reply objects
    /// through the Call and any fault handling. No numeric capability alone proves ownership.
    pub unsafe fn from_native(
        executor: ExecutorHandle,
        claim: &PhysicalTcbClaim,
        root_reply: RootReplyIdentity,
        supervisor_reply: RootReplyIdentity,
    ) -> Option<Self> {
        (root_reply != supervisor_reply).then_some(Self {
            executor,
            tcb: claim.identity(),
            target_cap: claim.target_cap(),
            root_reply,
            supervisor_reply,
        })
    }

    fn matches_report(&self, report: &ExecutorFaultReport) -> bool {
        self.executor == report.executor
            && self.tcb == report.tcb
            && self.target_cap == report.target_cap
            && self.root_reply == report.root_reply
            && self.supervisor_reply == report.supervisor_reply
    }
}

/// The checked terminal of one supervised worker fault. A report can be constructed only at
/// the native observer, after the root Call has returned and its exact Reply is accounted for.
#[must_use = "settle this fault terminal against its bound worker run"]
#[derive(Debug)]
pub struct ExecutorFaultReport {
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
    root_reply: RootReplyIdentity,
    supervisor_reply: RootReplyIdentity,
    job: Option<LiveJobId>,
    acknowledged: bool,
}

impl ExecutorFaultReport {
    /// # Safety
    /// The supervisor must have suspended the exact worker and root must have received the
    /// complete checked terminal on the bound Reply before this can report an acknowledgement.
    pub unsafe fn acknowledged(
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        target_cap: u64,
        root_reply: RootReplyIdentity,
        supervisor_reply: RootReplyIdentity,
    ) -> Option<Self> {
        Self::new(
            executor,
            tcb,
            target_cap,
            root_reply,
            supervisor_reply,
            None,
            true,
        )
    }

    /// # Safety
    /// The checked native fault terminal must identify the exact table-issued job nonce as
    /// well as the physical worker and both private Replies. A delayed earlier report is not
    /// authority over a later Call on the same worker.
    pub unsafe fn acknowledged_live(
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        target_cap: u64,
        root_reply: RootReplyIdentity,
        supervisor_reply: RootReplyIdentity,
        job: LiveJobId,
    ) -> Option<Self> {
        Self::new(
            executor,
            tcb,
            target_cap,
            root_reply,
            supervisor_reply,
            Some(job),
            true,
        )
    }

    /// # Safety
    /// The native observer must retain all possibly affected objects and must not replay a
    /// terminal whose native effect or Reply state is uncertain.
    pub unsafe fn uncertain(
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        target_cap: u64,
        root_reply: RootReplyIdentity,
        supervisor_reply: RootReplyIdentity,
    ) -> Option<Self> {
        Self::new(
            executor,
            tcb,
            target_cap,
            root_reply,
            supervisor_reply,
            None,
            false,
        )
    }

    /// # Safety
    /// The native observer must retain the exact job and every possibly affected resource;
    /// an indeterminate fault effect cannot be replayed as a later job's terminal.
    pub unsafe fn uncertain_live(
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        target_cap: u64,
        root_reply: RootReplyIdentity,
        supervisor_reply: RootReplyIdentity,
        job: LiveJobId,
    ) -> Option<Self> {
        Self::new(
            executor,
            tcb,
            target_cap,
            root_reply,
            supervisor_reply,
            Some(job),
            false,
        )
    }

    fn new(
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        target_cap: u64,
        root_reply: RootReplyIdentity,
        supervisor_reply: RootReplyIdentity,
        job: Option<LiveJobId>,
        acknowledged: bool,
    ) -> Option<Self> {
        (target_cap != 0 && root_reply != supervisor_reply).then_some(Self {
            executor,
            tcb,
            target_cap,
            root_reply,
            supervisor_reply,
            job,
            acknowledged,
        })
    }
}

/// Proof from the owner table after native destruction of one exact Reply and every alias.
#[must_use = "record exact Reply retirement before reusing its worker slot"]
#[derive(Debug)]
pub struct FaultReplyRetirementObservation(RootReplyIdentity);

impl FaultReplyRetirementObservation {
    /// # Safety
    /// Native teardown of the exact Reply and all aliases must be acknowledged. The Reply must
    /// no longer be the current main selector. An attempted or uncertain delete is insufficient.
    pub unsafe fn after_native_teardown(
        owner: &mut RootReplySlotTable,
        identity: RootReplyIdentity,
    ) -> Result<Self, RootReplyReplacementError> {
        if owner.state(identity)? != RootReplySlotState::Used {
            return Err(RootReplyReplacementError::NotUsed);
        }
        owner.clear(identity, None)?;
        Ok(Self(identity))
    }
}

#[must_use = "record the observation against the exact faulted worker"]
#[derive(Debug)]
pub enum FaultRetirementObservation {
    Tcb(TcbRetirementObservation),
    Reply(FaultReplyRetirementObservation),
    HostedReply(LiveHostedReplySettlementObservation),
}

/// Root's exact observation that a live job's hosted Reply completed and became free.
/// The old owner-issued identity is retained even though the Reply table advances its generation.
#[must_use = "record this settlement before reusing the executor slot"]
#[derive(Debug)]
pub struct LiveHostedReplySettlementObservation(RootReplyIdentity);

impl LiveHostedReplySettlementObservation {
    /// # Safety
    /// Native must have acknowledged completion of the exact hosted Reply. The Reply must no
    /// longer be the main selector, and the caller must own this table through the transition.
    /// An attempted or uncertain reply is not completion and must remain retained.
    pub unsafe fn after_checked_native_completion(
        owner: &mut RootReplySlotTable,
        identity: RootReplyIdentity,
    ) -> Result<Self, RootReplyReplacementError> {
        if owner.state(identity)? != RootReplySlotState::Used {
            return Err(RootReplyReplacementError::NotUsed);
        }
        owner.mark_free(identity, None)?;
        Ok(Self(identity))
    }
}

struct FaultRecord {
    binding: ExecutorFaultBinding,
    tcb_retired: bool,
    root_reply_retired: bool,
    supervisor_reply_retired: bool,
}

/// Root's authority to resume an executor. Each table issues exactly one, and it is lent to at
/// most one executor at a time. Dropping it leaves every executor permanently unresumable.
///
/// ```compile_fail
/// use nt_component_suspension::RunToken;
/// fn duplicate(token: RunToken) { let _ = token.clone(); }
/// ```
#[must_use = "root must keep the one run token to resume any executor"]
#[derive(Debug)]
pub struct RunToken {
    table: u64,
}

/// The lent run token while one executor runs. Root holds it across the native Call and
/// trades it back for the token with that executor's yield.
///
/// ```compile_fail
/// use nt_component_suspension::ExecutorRun;
/// fn duplicate(run: ExecutorRun) { let _ = run.clone(); }
/// ```
#[must_use = "return this run with the executor's yield to recover the run token"]
#[derive(Debug)]
pub struct ExecutorRun {
    executor: ExecutorHandle,
    cause: ExecutorResume,
    token: RunToken,
}

impl ExecutorRun {
    pub const fn executor(&self) -> ExecutorHandle {
        self.executor
    }

    pub const fn cause(&self) -> ExecutorResume {
        self.cause
    }
}

/// Table-issued identity for one native worker Call. Its sequence never wraps or repeats.
/// This is a selector for checking a terminal; root retains the physical claims and Replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveJobId {
    table: u64,
    sequence: u64,
}

impl LiveJobId {
    pub const fn nonce(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerEndpointIdentity {
    tcb: TcbIdentity,
    target_cap: u64,
    endpoint_cap: u64,
    endpoint_generation: u64,
}

impl WorkerEndpointIdentity {
    fn from_claim(claim: &PhysicalWorkerEndpointClaim) -> Self {
        Self {
            tcb: claim.tcb(),
            target_cap: claim.target_cap(),
            endpoint_cap: claim.endpoint_cap(),
            endpoint_generation: claim.endpoint_generation(),
        }
    }
}

struct LiveJobRecord {
    id: LiveJobId,
    hosted_reply: RootReplyIdentity,
    endpoint: WorkerEndpointIdentity,
    hosted_reply_settled: bool,
}

/// One-use native proof that the exact worker is blocked at its next private receive with
/// the same Reply offered. The owner must query the physical TCB, Reply, and endpoint together.
#[must_use = "settle this proof with the exact live job terminal"]
#[derive(Debug)]
pub struct ExactPassiveReceiveProof {
    executor: ExecutorHandle,
    endpoint: WorkerEndpointIdentity,
    reply: RootReplyIdentity,
}

impl ExactPassiveReceiveProof {
    /// # Safety
    /// A checked, non-mutating native query must have confirmed that this exact physical TCB
    /// is blocked on `endpoint` with `reply` offered. The owner must retain all three objects.
    pub unsafe fn after_checked_query(
        executor: ExecutorHandle,
        endpoint: &PhysicalWorkerEndpointClaim,
        reply: RootReplyIdentity,
    ) -> Option<Self> {
        (reply.cap() != 0).then_some(Self {
            executor,
            endpoint: WorkerEndpointIdentity::from_claim(endpoint),
            reply,
        })
    }
}

/// The checked result of one private worker Call, or an uncertain native result. Neither form
/// owns the hosted Reply: root retains it until it answers or deliberately quarantines it.
#[must_use = "settle this terminal against the exact bound live job"]
#[derive(Debug)]
pub struct LiveNormalTerminal {
    job: LiveJobId,
    result: Option<u32>,
    private_reply: RootReplyIdentity,
    rearm: Option<ExactPassiveReceiveProof>,
}

impl LiveNormalTerminal {
    /// # Safety
    /// Root must have received the complete checked result on `private_reply`, and the supplied
    /// rearm proof must come from a checked query after that same atomic ReplyRecv.
    pub unsafe fn acknowledged(
        job: LiveJobId,
        result: u32,
        private_reply: RootReplyIdentity,
        rearm: ExactPassiveReceiveProof,
    ) -> Option<Self> {
        (private_reply.cap() != 0).then_some(Self {
            job,
            result: Some(result),
            private_reply,
            rearm: Some(rearm),
        })
    }

    /// # Safety
    /// Native effects or ReplyRecv state must be indeterminate. The caller must retain the
    /// original job, hosted Reply, worker, and private Replies without replay or reuse.
    pub unsafe fn uncertain(job: LiveJobId, private_reply: RootReplyIdentity) -> Option<Self> {
        (private_reply.cap() != 0).then_some(Self {
            job,
            result: None,
            private_reply,
            rearm: None,
        })
    }
}

struct Slot {
    generation: u64,
    state: ExecutorState,
    fault: Option<FaultRecord>,
    live: Option<LiveJobRecord>,
    private_ingress: Option<PrivateWorkerIngress>,
}

#[derive(Clone, Copy)]
struct PrivateWorkerIngress {
    tcb: TcbIdentity,
    target_cap: u64,
    endpoint_cap: u64,
    reply_cap: u64,
}

/// Owns executor identity and the single derived route-to-waiter view.
pub struct ExecutorTable {
    id: u64,
    capacity: usize,
    slots: Vec<Slot>,
    next_job_sequence: u64,
}

impl ExecutorTable {
    /// Reserve the whole bounded table and issue its one run token to root.
    pub fn try_new(capacity: usize) -> Result<(Self, RunToken), ExecutorError> {
        Self::try_new_with_counter(capacity, &NEXT_TABLE)
    }

    fn try_new_with_counter(
        capacity: usize,
        counter: &AtomicU64,
    ) -> Result<(Self, RunToken), ExecutorError> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return Err(ExecutorError::NoCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| ExecutorError::NoCapacity)?;
        // Burn the identity even if this table is dropped: a leftover token names no later table.
        let id = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| ExecutorError::IdentityExhausted)?;
        Ok((
            Self {
                id,
                capacity,
                slots,
                next_job_sequence: 1,
            },
            RunToken { table: id },
        ))
    }

    /// Register an executor whose native TCB has already completed bootstrap and is blocked at
    /// loop-top on its own endpoint. New native workers must use `register_unready` instead.
    ///
    /// # Safety
    /// The caller must own the exact physical TCB, have acknowledged its executor-local FS base,
    /// and have observed a checked bootstrap-SC unbind while it is blocked on its private
    /// receive endpoint with an offered Reply before this table may select it for ingress.
    /// A ready message or numeric TCB identity is insufficient.
    pub unsafe fn register(&mut self, root: &RunToken) -> Result<ExecutorHandle, ExecutorError> {
        self.register_with_state(root, ExecutorState::Idle)
    }

    /// Register a worker that cannot receive ingress until FS and passive receive are proven.
    pub fn register_unready(&mut self, root: &RunToken) -> Result<ExecutorHandle, ExecutorError> {
        self.register_with_state(root, ExecutorState::Unready)
    }

    fn register_with_state(
        &mut self,
        root: &RunToken,
        initial: ExecutorState,
    ) -> Result<ExecutorHandle, ExecutorError> {
        if root.table != self.id {
            return Err(ExecutorError::WrongTable);
        }
        // A retired slot that cannot take a new generation stays retired for good.
        let reusable = self
            .slots
            .iter()
            .position(|slot| slot.state == ExecutorState::Retired && slot.generation < u64::MAX);
        let index = match reusable {
            Some(index) => {
                self.slots[index].generation += 1;
                self.slots[index].state = initial;
                self.slots[index].fault = None;
                self.slots[index].live = None;
                self.slots[index].private_ingress = None;
                index
            }
            None if self.slots.len() < self.capacity => {
                self.slots.push(Slot {
                    generation: 1,
                    state: initial,
                    fault: None,
                    live: None,
                    private_ingress: None,
                });
                self.slots.len() - 1
            }
            None => return Err(ExecutorError::NoCapacity),
        };
        Ok(self.handle(index))
    }

    /// Record the exact private ingress resources before a worker becomes runnable.
    /// The native owner retains both physical capabilities; these numeric selectors only
    /// exclude accidental sharing across the table's live and quarantined workers.
    pub fn admit_private_ingress(
        &mut self,
        root: &RunToken,
        executor: ExecutorHandle,
        endpoint: &PhysicalWorkerEndpointClaim,
        reply_owner: &RootReplySlotTable,
        reply: RootReplyIdentity,
    ) -> Result<(), ExecutorError> {
        if root.table != self.id {
            return Err(ExecutorError::WrongTable);
        }
        if self.state(executor)? != ExecutorState::Unready {
            return Err(ExecutorError::NotUnready);
        }
        let index = executor.index as usize;
        if self.slots[index].private_ingress.is_some() {
            return Err(ExecutorError::DuplicateWorkerIngress);
        }
        if reply_owner.state(reply) != Ok(RootReplySlotState::Used)
            || reply.cap() == 0 || endpoint.endpoint_cap() == 0
        {
            return Err(ExecutorError::WorkerProofMismatch);
        }
        if self.slots.iter().any(|slot| {
            slot.state != ExecutorState::Retired
                && slot.private_ingress.is_some_and(|owner| {
                    owner.endpoint_cap == endpoint.endpoint_cap()
                        || owner.reply_cap == reply.cap()
                })
        }) {
            return Err(ExecutorError::DuplicateWorkerIngress);
        }
        self.slots[index].private_ingress = Some(PrivateWorkerIngress {
            tcb: endpoint.tcb(),
            target_cap: endpoint.target_cap(),
            endpoint_cap: endpoint.endpoint_cap(),
            reply_cap: reply.cap(),
        });
        Ok(())
    }

    /// Publish an unready worker only after both FS publication and checked passive unbind
    /// acknowledge the same executor incarnation and physical TCB. Refusal returns both proofs.
    pub fn activate_unready(
        &mut self,
        root: &RunToken,
        acknowledged: FsInstallAcknowledgement,
        ready: PassiveWorkerReadyProof,
    ) -> Result<
        ExecutorHandle,
        (
            ExecutorError,
            FsInstallAcknowledgement,
            PassiveWorkerReadyProof,
        ),
    > {
        if root.table != self.id {
            return Err((ExecutorError::WrongTable, acknowledged, ready));
        }
        let executor = acknowledged.executor();
        if ready.executor() != executor
            || ready.tcb() != acknowledged.tcb()
            || ready.target_cap() != acknowledged.target_cap()
        {
            return Err((ExecutorError::WorkerProofMismatch, acknowledged, ready));
        }
        if let Err(error) = self.state(executor) {
            return Err((error, acknowledged, ready));
        }
        let slot = &mut self.slots[executor.index as usize];
        if slot.state != ExecutorState::Unready {
            return Err((ExecutorError::NotUnready, acknowledged, ready));
        }
        if slot.private_ingress.is_some_and(|owner| {
            owner.tcb != ready.tcb() || owner.target_cap != ready.target_cap()
        }) {
            return Err((ExecutorError::WorkerProofMismatch, acknowledged, ready));
        }
        slot.state = ExecutorState::Idle;
        Ok(executor)
    }

    /// Reclaim a never-started worker after the registry confirms exact physical TCB teardown.
    /// Kept crate-private so a numeric executor handle cannot authorize native teardown.
    pub(crate) fn retire_unready(
        &mut self,
        root: &RunToken,
        executor: ExecutorHandle,
    ) -> Result<(), ExecutorError> {
        if root.table != self.id {
            return Err(ExecutorError::WrongTable);
        }
        if self.state(executor)? != ExecutorState::Unready {
            return Err(ExecutorError::NotUnready);
        }
        self.slots[executor.index as usize].state = ExecutorState::Retired;
        Ok(())
    }

    pub fn state(&self, executor: ExecutorHandle) -> Result<ExecutorState, ExecutorError> {
        if executor.table != self.id {
            return Err(ExecutorError::WrongTable);
        }
        let slot = self
            .slots
            .get(executor.index as usize)
            .ok_or(ExecutorError::NotFound)?;
        if slot.generation != executor.generation {
            return Err(ExecutorError::StaleGeneration);
        }
        Ok(slot.state)
    }

    /// The exact job still retained by this executor, including after a fault or quarantine.
    pub fn live_job(&self, executor: ExecutorHandle) -> Result<Option<LiveJobId>, ExecutorError> {
        self.state(executor)?;
        Ok(self.slots[executor.index as usize].live.as_ref().map(|job| job.id))
    }

    pub fn running(&self) -> Option<ExecutorHandle> {
        self.position(|state| state == ExecutorState::Running)
            .map(|index| self.handle(index))
    }

    fn handle(&self, index: usize) -> ExecutorHandle {
        ExecutorHandle {
            table: self.id,
            index: index as u32,
            generation: self.slots[index].generation,
        }
    }

    fn position(&self, matches: impl Fn(ExecutorState) -> bool) -> Option<usize> {
        self.slots.iter().position(|slot| matches(slot.state))
    }

    /// The route-to-waiter map is this view of the slots, so it cannot disagree with them.
    fn waiter(&self, route: PeerRoute) -> Option<(usize, ExecutorWait)> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot.state {
                ExecutorState::Parked(wait) if wait.route == route => Some((index, wait)),
                _ => None,
            })
    }

    fn select(&self, cause: ExecutorResume) -> Result<usize, ExecutorError> {
        match cause {
            ExecutorResume::Unrouted => self
                .position(|state| state == ExecutorState::Idle)
                .ok_or(ExecutorError::NoIdleExecutor),
            ExecutorResume::Routed(arrival) => match self.waiter(arrival.route) {
                Some((index, wait)) if wait == arrival => Ok(index),
                Some(_) => Err(ExecutorError::WrongDispatch),
                None => Err(ExecutorError::NotParked),
            },
            ExecutorResume::RouteRetired(route) => self
                .waiter(route)
                .map(|(index, _)| index)
                .ok_or(ExecutorError::NotParked),
        }
    }

    /// Lend the run token to the one executor this cause selects. A refusal returns the token
    /// with no state change, so the retained arrival can be delivered again later.
    pub fn resume(
        &mut self,
        token: RunToken,
        cause: ExecutorResume,
    ) -> Result<ExecutorRun, (ExecutorError, RunToken)> {
        if token.table != self.id {
            return Err((ExecutorError::WrongTable, token));
        }
        let index = match self.select(cause) {
            Ok(index) => index,
            Err(error) => return Err((error, token)),
        };
        self.slots[index].state = ExecutorState::Running;
        Ok(ExecutorRun {
            executor: self.handle(index),
            cause,
            token,
        })
    }

    /// Record the running executor's yield and return the run token to root. A refusal leaves
    /// the executor running and returns its run.
    pub fn accept_yield(
        &mut self,
        run: ExecutorRun,
        yielded: ExecutorYield,
    ) -> Result<RunToken, (ExecutorError, ExecutorRun)> {
        // This table's only token is inside this run, so its executor is the one running.
        if run.token.table != self.id {
            return Err((ExecutorError::WrongTable, run));
        }
        if self.state(run.executor) != Ok(ExecutorState::Running) {
            return Err((ExecutorError::FaultBindingState, run));
        }
        if self.slots[run.executor.index as usize].live.is_some() {
            return Err((ExecutorError::LiveJobOutstanding, run));
        }
        let state = match yielded {
            ExecutorYield::Idle => ExecutorState::Idle,
            ExecutorYield::Done => ExecutorState::Retired,
            ExecutorYield::Parked(wait) if self.waiter(wait.route).is_some() => {
                return Err((ExecutorError::RouteOccupied, run));
            }
            ExecutorYield::Parked(wait) => ExecutorState::Parked(wait),
        };
        self.slots[run.executor.index as usize].state = state;
        self.slots[run.executor.index as usize].fault = None;
        Ok(run.token)
    }

    /// Retain the exact worker and Reply identities before the native Call. A normal return may
    /// still yield; a fault terminal must be checked against this binding before token recovery.
    pub fn bind_fault(
        &mut self,
        run: &ExecutorRun,
        binding: ExecutorFaultBinding,
    ) -> Result<(), (ExecutorError, ExecutorFaultBinding)> {
        if run.token.table != self.id {
            return Err((ExecutorError::WrongTable, binding));
        }
        if self.state(run.executor) != Ok(ExecutorState::Running)
            || self.slots[run.executor.index as usize].fault.is_some()
        {
            return Err((ExecutorError::FaultBindingState, binding));
        }
        if binding.executor != run.executor {
            return Err((ExecutorError::FaultIdentityMismatch, binding));
        }
        self.slots[run.executor.index as usize].fault = Some(FaultRecord {
            binding,
            tcb_retired: false,
            root_reply_retired: false,
            supervisor_reply_retired: false,
        });
        Ok(())
    }

    /// Retain the hosted Reply and exact worker endpoint before native Call. The unique job
    /// identity may be sent to the worker only after this record and its fault binding exist.
    /// The native route must retain the physical hosted Reply capability and its owner table
    /// entry, the endpoint claim, and both private Replies until exact settlement or teardown.
    /// These copied owner-issued identities are selectors; the model cannot own native caps.
    pub fn bind_live_job(
        &mut self,
        run: &ExecutorRun,
        hosted_owner: &RootReplySlotTable,
        hosted_reply: RootReplyIdentity,
        endpoint: &PhysicalWorkerEndpointClaim,
    ) -> Result<LiveJobId, ExecutorError> {
        if run.token.table != self.id {
            return Err(ExecutorError::WrongTable);
        }
        if self.state(run.executor) != Ok(ExecutorState::Running) {
            return Err(ExecutorError::FaultBindingState);
        }
        let slot = &self.slots[run.executor.index as usize];
        if slot.live.is_some() {
            return Err(ExecutorError::LiveJobOutstanding);
        }
        let fault = slot.fault.as_ref().ok_or(ExecutorError::FaultBindingState)?;
        let endpoint_identity = WorkerEndpointIdentity::from_claim(endpoint);
        if endpoint_identity.tcb != fault.binding.tcb
            || endpoint_identity.target_cap != fault.binding.target_cap
            || hosted_reply == fault.binding.root_reply
            || hosted_reply == fault.binding.supervisor_reply
            || hosted_owner.state(hosted_reply) != Ok(RootReplySlotState::Used)
        {
            return Err(ExecutorError::LiveJobIdentityMismatch);
        }
        let next = self
            .next_job_sequence
            .checked_add(1)
            .ok_or(ExecutorError::IdentityExhausted)?;
        let id = LiveJobId {
            table: self.id,
            sequence: self.next_job_sequence,
        };
        self.next_job_sequence = next;
        self.slots[run.executor.index as usize].live = Some(LiveJobRecord {
            id,
            hosted_reply,
            endpoint: endpoint_identity,
            hosted_reply_settled: false,
        });
        Ok(id)
    }

    /// Accept a normal worker result only after its exact private Reply and next receive are
    /// checked. The native route must keep the hosted Reply capability and its owner entry after
    /// this terminal; a mismatch or uncertain effect quarantines the run and retains every owner.
    pub fn accept_live_terminal(
        &mut self,
        run: ExecutorRun,
        terminal: LiveNormalTerminal,
    ) -> Result<(RunToken, u32), (ExecutorError, ExecutorRun, LiveNormalTerminal)> {
        if run.token.table != self.id {
            return Err((ExecutorError::WrongTable, run, terminal));
        }
        if self.state(run.executor) != Ok(ExecutorState::Running) {
            return Err((ExecutorError::FaultBindingState, run, terminal));
        }
        let slot = &mut self.slots[run.executor.index as usize];
        let exact = slot
            .live
            .as_ref()
            .zip(slot.fault.as_ref())
            .zip(terminal.rearm.as_ref())
            .is_some_and(|((job, fault), proof)| {
                terminal.job == job.id
                    && terminal.private_reply == fault.binding.root_reply
                    && proof.reply == fault.binding.root_reply
                    && proof.executor == run.executor
                    && proof.endpoint == job.endpoint
            });
        if !exact || terminal.result.is_none() {
            slot.state = ExecutorState::Quarantined;
            let error = if terminal.result.is_none() || terminal.rearm.is_none() {
                ExecutorError::LiveTerminalUncertain
            } else {
                ExecutorError::LiveJobIdentityMismatch
            };
            return Err((error, run, terminal));
        }
        let result = terminal.result.expect("checked terminal contains a result");
        slot.state = ExecutorState::AwaitingHostedReply;
        slot.fault = None;
        Ok((run.token, result))
    }

    /// A checked normal worker terminal cannot free the hosted Reply. Only the Reply owner may
    /// complete it and issue this exact settlement; until then the worker cannot take new work.
    pub fn observe_live_hosted_reply_settlement(
        &mut self,
        root: &RunToken,
        executor: ExecutorHandle,
        job: LiveJobId,
        observation: LiveHostedReplySettlementObservation,
    ) -> Result<(), (ExecutorError, LiveHostedReplySettlementObservation)> {
        if root.table != self.id {
            return Err((ExecutorError::WrongTable, observation));
        }
        if self.state(executor) != Ok(ExecutorState::AwaitingHostedReply) {
            return Err((ExecutorError::FaultBindingState, observation));
        }
        let slot = &mut self.slots[executor.index as usize];
        if !slot
            .live
            .as_ref()
            .is_some_and(|live| live.id == job && live.hosted_reply == observation.0)
        {
            return Err((ExecutorError::LiveJobIdentityMismatch, observation));
        }
        slot.live = None;
        slot.state = ExecutorState::Idle;
        Ok(())
    }

    /// A checked supervisor terminal returns the unique run token. Any wrong or uncertain
    /// terminal quarantines the worker and leaves the run with its native owner for reconciliation.
    pub fn accept_fault_terminal(
        &mut self,
        run: ExecutorRun,
        report: ExecutorFaultReport,
    ) -> Result<RunToken, (ExecutorError, ExecutorRun, ExecutorFaultReport)> {
        if run.token.table != self.id {
            return Err((ExecutorError::WrongTable, run, report));
        }
        if self.state(run.executor) != Ok(ExecutorState::Running) {
            return Err((ExecutorError::FaultBindingState, run, report));
        }
        let slot = &mut self.slots[run.executor.index as usize];
        let exact = slot
            .fault
            .as_ref()
            .is_some_and(|fault| fault.binding.matches_report(&report))
            && slot.live.as_ref().map(|live| live.id) == report.job;
        if !exact || !report.acknowledged {
            slot.state = ExecutorState::Quarantined;
            let error = if exact {
                ExecutorError::FaultTerminalUncertain
            } else {
                ExecutorError::FaultIdentityMismatch
            };
            return Err((error, run, report));
        }
        slot.state = ExecutorState::Faulted;
        Ok(run.token)
    }

    /// Record one checked native retirement. The faulted slot becomes reusable only after the
    /// exact worker TCB and both private Replies have been retired. A bound live job also needs
    /// the exact hosted caller's Reply settlement before its slot becomes reusable.
    pub fn observe_fault_retirement(
        &mut self,
        root: &RunToken,
        executor: ExecutorHandle,
        observation: FaultRetirementObservation,
    ) -> Result<(), (ExecutorError, FaultRetirementObservation)> {
        if root.table != self.id {
            return Err((ExecutorError::WrongTable, observation));
        }
        if self.state(executor) != Ok(ExecutorState::Faulted) {
            return Err((ExecutorError::FaultBindingState, observation));
        }
        let slot = &mut self.slots[executor.index as usize];
        let Some(fault) = slot.fault.as_mut() else {
            return Err((ExecutorError::FaultBindingState, observation));
        };
        let settled = match &observation {
            FaultRetirementObservation::Tcb(retired) if retired.identity() == fault.binding.tcb => {
                &mut fault.tcb_retired
            }
            FaultRetirementObservation::Reply(retired) if retired.0 == fault.binding.root_reply => {
                &mut fault.root_reply_retired
            }
            FaultRetirementObservation::Reply(retired)
                if retired.0 == fault.binding.supervisor_reply =>
            {
                &mut fault.supervisor_reply_retired
            }
            FaultRetirementObservation::HostedReply(retired) => {
                let Some(live) = slot.live.as_mut() else {
                    return Err((ExecutorError::FaultIdentityMismatch, observation));
                };
                if retired.0 != live.hosted_reply {
                    return Err((ExecutorError::FaultIdentityMismatch, observation));
                }
                &mut live.hosted_reply_settled
            }
            _ => return Err((ExecutorError::FaultIdentityMismatch, observation)),
        };
        if *settled {
            return Err((ExecutorError::FaultAlreadyRetired, observation));
        }
        *settled = true;
        if fault.tcb_retired && fault.root_reply_retired && fault.supervisor_reply_retired
            && slot.live.as_ref().is_none_or(|live| live.hosted_reply_settled)
        {
            slot.state = ExecutorState::Retired;
            slot.fault = None;
            slot.live = None;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_table_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "executor_shape_tests.rs"]
mod shape_tests;
