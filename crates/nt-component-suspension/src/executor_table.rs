//! Run-token executors: root lends execution to one passive executor at a time.
//!
//! Root is the only ingress receiver. An executor's blocking receive is a yield back to root, so
//! a blocked operation keeps its own stack instead of nesting a receive loop on root's. This
//! table is memory-only: it decides which executor an arrival may resume and performs no native
//! effect. Arrivals stay retained by ingress; a refusal here changes nothing and consumes nothing.

use crate::{peer_registry::PeerRoute, LaneDispatchIdentity};
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

static NEXT_TABLE: AtomicU64 = AtomicU64::new(1);

/// One occupant of one executor slot. A reused slot never repeats an earlier generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorHandle {
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
        let _ = (route, dispatch);
        None
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
    /// At loop-top on its own endpoint; may take any unrouted work.
    Idle,
    Running,
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
    StaleDispatch,
    /// Another executor is already parked on this route.
    RouteOccupied,
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

struct Slot {
    generation: u64,
    state: ExecutorState,
}

/// Owns executor identity and the single derived route-to-waiter view.
pub struct ExecutorTable {
    id: u64,
    capacity: usize,
    slots: Vec<Slot>,
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
        let _ = counter;
        Ok((Self { id: 0, capacity, slots: Vec::new() }, RunToken { table: 0 }))
    }

    /// Register an executor that is blocked at loop-top on its own endpoint.
    pub fn register(&mut self, root: &RunToken) -> Result<ExecutorHandle, ExecutorError> {
        let _ = (root, self.id, self.capacity, &self.slots);
        Err(ExecutorError::NotFound)
    }

    pub fn state(&self, executor: ExecutorHandle) -> Result<ExecutorState, ExecutorError> {
        let _ = executor;
        Err(ExecutorError::NotFound)
    }

    pub fn running(&self) -> Option<ExecutorHandle> {
        None
    }

    /// Lend the run token to the one executor this cause selects. A refusal returns the token
    /// with no state change, so the retained arrival can be delivered again later.
    pub fn resume(
        &mut self,
        token: RunToken,
        cause: ExecutorResume,
    ) -> Result<ExecutorRun, (ExecutorError, RunToken)> {
        let _ = cause;
        Err((ExecutorError::NotFound, token))
    }

    /// Record the running executor's yield and return the run token to root. A refusal leaves
    /// the executor running and returns its run.
    pub fn accept_yield(
        &mut self,
        run: ExecutorRun,
        yielded: ExecutorYield,
    ) -> Result<RunToken, (ExecutorError, ExecutorRun)> {
        let _ = (yielded, run.executor, run.cause, run.token.table);
        Err((ExecutorError::NotFound, run))
    }
}

#[cfg(test)]
#[path = "executor_table_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "executor_shape_tests.rs"]
mod shape_tests;
