use super::*;
use crate::{
    peer_registry::{PeerIdentity, PeerRegistry},
    LaneHandle,
};
use alloc::vec::Vec;

/// Issues published routes, each for its own provider lane.
pub(super) struct Routes {
    registry: PeerRegistry,
    next: u64,
}

impl Routes {
    pub(super) fn new() -> Self {
        Self { registry: PeerRegistry::new(0x40, 64), next: 1 }
    }

    pub(super) fn route(&mut self) -> PeerRoute {
        let id = self.next;
        self.next += 1;
        let mut registration = self
            .registry
            .stage(PeerIdentity {
                domain: 1,
                domain_generation: 1,
                executor: id,
                lane: LaneHandle { index: id as u32, generation: 1 },
            })
            .unwrap();
        self.registry.publish(&mut registration).unwrap()
    }
}

/// The job `epoch` on the route's own lane.
pub(super) fn wait(route: PeerRoute, epoch: u64) -> ExecutorWait {
    ExecutorWait::new(route, LaneDispatchIdentity { lane: route.identity().lane, epoch }).unwrap()
}

/// Root's side of the protocol: it holds the token whenever no executor runs.
pub(super) struct Root {
    pub(super) table: ExecutorTable,
    token: Option<RunToken>,
    pub(super) executors: Vec<ExecutorHandle>,
}

impl Root {
    pub(super) fn new(capacity: usize, registered: usize) -> Self {
        let (table, token) = ExecutorTable::try_new(capacity).unwrap();
        let mut root = Self { table, token: Some(token), executors: Vec::new() };
        for _ in 0..registered {
            root.register().unwrap();
        }
        root
    }

    pub(super) fn register(&mut self) -> Result<ExecutorHandle, ExecutorError> {
        let executor = self.table.register(self.token.as_ref().unwrap())?;
        self.executors.push(executor);
        Ok(executor)
    }

    pub(super) fn states(&self) -> Vec<Result<ExecutorState, ExecutorError>> {
        self.executors.iter().map(|executor| self.table.state(*executor)).collect()
    }

    pub(super) fn state(&self, executor: ExecutorHandle) -> ExecutorState {
        self.table.state(executor).unwrap()
    }

    pub(super) fn resume(&mut self, cause: ExecutorResume) -> ExecutorRun {
        let run = self.table.resume(self.token.take().unwrap(), cause).unwrap();
        assert_eq!(run.cause(), cause);
        assert_eq!(self.table.running(), Some(run.executor()));
        assert_eq!(self.table.state(run.executor()), Ok(ExecutorState::Running));
        run
    }

    pub(super) fn yields(&mut self, run: ExecutorRun, yielded: ExecutorYield) {
        self.token = Some(self.table.accept_yield(run, yielded).unwrap());
        assert_eq!(self.table.running(), None);
    }

    /// One whole turn: the selected executor runs and yields. Returns which executor ran.
    pub(super) fn turn(&mut self, cause: ExecutorResume, yielded: ExecutorYield) -> ExecutorHandle {
        let run = self.resume(cause);
        let executor = run.executor();
        self.yields(run, yielded);
        executor
    }

    /// A refused resume returns the token and changes no executor.
    pub(super) fn refused(&mut self, cause: ExecutorResume) -> ExecutorError {
        let before = self.states();
        let (error, token) = self.table.resume(self.token.take().unwrap(), cause).unwrap_err();
        self.token = Some(token);
        assert_eq!(self.states(), before);
        assert_eq!(self.table.running(), None);
        error
    }

    /// A refused yield returns the run and leaves its executor running.
    pub(super) fn refused_yield(
        &mut self,
        run: ExecutorRun,
        yielded: ExecutorYield,
    ) -> (ExecutorError, ExecutorRun) {
        let before = self.states();
        let (error, run) = self.table.accept_yield(run, yielded).unwrap_err();
        assert_eq!(self.states(), before);
        assert_eq!(self.table.running(), Some(run.executor()));
        (error, run)
    }
}

use ExecutorResume::{RouteRetired, Routed, Unrouted};
use ExecutorYield::{Done, Idle, Parked};

#[test]
fn empty_or_unreservable_capacity_is_refused() {
    assert_eq!(ExecutorTable::try_new(0).err(), Some(ExecutorError::NoCapacity));
    assert_eq!(ExecutorTable::try_new(usize::MAX).err(), Some(ExecutorError::NoCapacity));
}

#[test]
fn exhausted_table_identity_never_wraps_to_an_earlier_table() {
    let counter = AtomicU64::new(u64::MAX);
    for _ in 0..2 {
        assert_eq!(
            ExecutorTable::try_new_with_counter(1, &counter).err(),
            Some(ExecutorError::IdentityExhausted)
        );
    }
}

#[test]
fn registered_executors_are_idle_with_distinct_identity() {
    let mut root = Root::new(2, 0);
    let first = root.register().unwrap();
    let second = root.register().unwrap();
    assert_ne!(first, second);
    assert_ne!(first.index(), second.index());
    assert_eq!(root.states(), [Ok(ExecutorState::Idle), Ok(ExecutorState::Idle)]);
    assert_eq!(root.table.running(), None);
}

#[test]
fn registration_beyond_capacity_is_exhaustion_without_growth() {
    let mut root = Root::new(2, 2);
    for _ in 0..3 {
        assert_eq!(root.register(), Err(ExecutorError::NoCapacity));
    }
    assert_eq!(root.states(), [Ok(ExecutorState::Idle), Ok(ExecutorState::Idle)]);
    assert_eq!(root.table.slots.len(), 2);
}

#[test]
fn unrouted_work_runs_one_idle_executor_and_its_yield_returns_the_token() {
    let mut root = Root::new(2, 2);
    let (first, second) = (root.executors[0], root.executors[1]);
    let run = root.resume(Unrouted);
    assert_eq!(run.executor(), first);
    assert_eq!(root.state(second), ExecutorState::Idle);
    root.yields(run, Idle);
    assert_eq!(root.states(), [Ok(ExecutorState::Idle), Ok(ExecutorState::Idle)]);
    // The returned token is the same authority: it can lend execution again.
    assert_eq!(root.turn(Unrouted, Idle), first);
}

#[test]
fn a_wait_names_a_job_on_the_routes_own_lane() {
    let mut routes = Routes::new();
    let (route, other) = (routes.route(), routes.route());
    let own = LaneDispatchIdentity { lane: route.identity().lane, epoch: 5 };
    let foreign = LaneDispatchIdentity { lane: other.identity().lane, epoch: 5 };
    let wait = ExecutorWait::new(route, own).unwrap();
    assert_eq!((wait.route(), wait.dispatch()), (route, own));
    assert_eq!(ExecutorWait::new(route, foreign), None);
}

#[test]
fn routed_arrival_resumes_exactly_the_executor_parked_on_that_wait() {
    let mut routes = Routes::new();
    let (first_wait, second_wait) = (wait(routes.route(), 5), wait(routes.route(), 6));
    let mut root = Root::new(3, 3);
    let first = root.turn(Unrouted, Parked(first_wait));
    let second = root.turn(Unrouted, Parked(second_wait));
    assert_ne!(first, second);
    assert_eq!(root.state(first), ExecutorState::Parked(first_wait));

    let run = root.resume(Routed(second_wait));
    assert_eq!(run.executor(), second);
    assert_eq!(root.state(first), ExecutorState::Parked(first_wait));
    assert_eq!(root.state(root.executors[2]), ExecutorState::Idle);
    root.yields(run, Idle);
    assert_eq!(root.turn(Routed(first_wait), Idle), first);
}

#[test]
fn mismatched_dispatch_generation_is_refused_and_the_exact_arrival_stays_deliverable() {
    let mut routes = Routes::new();
    let route = routes.route();
    let mut root = Root::new(2, 2);
    let waiter = root.turn(Unrouted, Parked(wait(route, 5)));
    for other in [4, 6] {
        assert_eq!(root.refused(Routed(wait(route, other))), ExecutorError::WrongDispatch);
    }
    assert_eq!(root.state(waiter), ExecutorState::Parked(wait(route, 5)));
    assert_eq!(root.turn(Routed(wait(route, 5)), Idle), waiter);
}

#[test]
fn routed_arrival_without_a_waiter_never_borrows_an_idle_executor() {
    let mut routes = Routes::new();
    let (parked, unparked) = (wait(routes.route(), 5), wait(routes.route(), 5));
    let mut root = Root::new(2, 2);
    let waiter = root.turn(Unrouted, Parked(parked));
    assert_eq!(root.refused(Routed(unparked)), ExecutorError::NotParked);

    // Once its waiter has resumed and finished, the same wait no longer selects anyone.
    assert_eq!(root.turn(Routed(parked), Idle), waiter);
    assert_eq!(root.refused(Routed(parked)), ExecutorError::NotParked);
    assert_eq!(root.states(), [Ok(ExecutorState::Idle), Ok(ExecutorState::Idle)]);
}

#[test]
fn unrouted_arrival_never_borrows_a_parked_executor() {
    let mut routes = Routes::new();
    let parked = wait(routes.route(), 5);
    let mut root = Root::new(1, 1);
    let waiter = root.turn(Unrouted, Parked(parked));
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
    assert_eq!(root.state(waiter), ExecutorState::Parked(parked));
}

#[test]
fn second_waiter_on_an_occupied_route_is_refused_and_keeps_running() {
    let mut routes = Routes::new();
    let (route, free) = (routes.route(), routes.route());
    let mut root = Root::new(2, 2);
    let waiter = root.turn(Unrouted, Parked(wait(route, 5)));

    let mut run = root.resume(Unrouted);
    for epoch in [5, 6] {
        let (error, returned) = root.refused_yield(run, Parked(wait(route, epoch)));
        assert_eq!(error, ExecutorError::RouteOccupied);
        run = returned;
    }
    assert_eq!(root.state(waiter), ExecutorState::Parked(wait(route, 5)));
    // The returned run is still the running executor's one yield authority.
    let second = run.executor();
    root.yields(run, Parked(wait(free, 6)));
    assert_eq!(root.state(second), ExecutorState::Parked(wait(free, 6)));
}

#[test]
fn a_resumed_waiter_may_park_again_on_its_own_route() {
    let mut routes = Routes::new();
    let route = routes.route();
    let mut root = Root::new(1, 1);
    let waiter = root.turn(Unrouted, Parked(wait(route, 5)));
    assert_eq!(root.turn(Routed(wait(route, 5)), Parked(wait(route, 5))), waiter);
    assert_eq!(root.turn(Routed(wait(route, 5)), Idle), waiter);
}

#[test]
fn done_retires_the_executor_and_a_reused_slot_gets_a_new_generation() {
    let mut root = Root::new(1, 1);
    let old = root.turn(Unrouted, Done);
    assert_eq!(root.state(old), ExecutorState::Retired);
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);

    let new = root.register().unwrap();
    assert_eq!(new.index(), old.index());
    assert_ne!(new.generation(), old.generation());
    assert_eq!(root.table.state(old), Err(ExecutorError::StaleGeneration));
    assert_eq!(root.table.state(new), Ok(ExecutorState::Idle));
    assert_eq!(root.table.slots.len(), 1);
    assert_eq!(root.turn(Unrouted, Idle), new);
}

#[test]
fn unknown_and_stale_handles_are_refused() {
    let root = Root::new(2, 1);
    let known = root.executors[0];
    let beyond = ExecutorHandle { index: 1, generation: known.generation() };
    let stale = ExecutorHandle { index: 0, generation: known.generation() + 1 };
    assert_eq!(root.table.state(beyond), Err(ExecutorError::NotFound));
    assert_eq!(root.table.state(stale), Err(ExecutorError::StaleGeneration));
}

#[test]
fn late_arrival_for_a_retired_occupant_cannot_wake_the_slots_new_occupant() {
    let mut routes = Routes::new();
    let route = routes.route();
    let mut root = Root::new(1, 1);
    let old = root.turn(Unrouted, Parked(wait(route, 5)));
    assert_eq!(root.turn(Routed(wait(route, 5)), Done), old);

    // A replacement executor in the same slot waits for a later job on the same route.
    let new = root.register().unwrap();
    assert_eq!(root.turn(Unrouted, Parked(wait(route, 6))), new);
    assert_eq!(root.refused(Routed(wait(route, 5))), ExecutorError::WrongDispatch);
    assert_eq!(root.table.state(old), Err(ExecutorError::StaleGeneration));
    assert_eq!(root.turn(Routed(wait(route, 6)), Idle), new);
}

#[test]
fn a_slot_whose_generation_is_exhausted_is_never_reused() {
    let mut root = Root::new(1, 1);
    let last = root.turn(Unrouted, Done);
    root.table.slots[0].generation = u64::MAX;
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));
    assert_eq!(root.table.slots[0].generation, u64::MAX);
    assert_eq!(root.table.state(last), Err(ExecutorError::StaleGeneration));
}

#[test]
fn route_retirement_wakes_exactly_its_waiter_once() {
    let mut routes = Routes::new();
    let (retiring, live) = (wait(routes.route(), 5), wait(routes.route(), 6));
    let mut root = Root::new(3, 3);
    let first = root.turn(Unrouted, Parked(retiring));
    let second = root.turn(Unrouted, Parked(live));

    // Retirement is not an arrival for a dispatch: it wakes the route's waiter whatever its job.
    let run = root.resume(RouteRetired(retiring.route()));
    assert_eq!(run.executor(), first);
    assert_eq!(root.state(second), ExecutorState::Parked(live));
    root.yields(run, Idle);

    assert_eq!(root.refused(RouteRetired(retiring.route())), ExecutorError::NotParked);
    assert_eq!(root.refused(Routed(retiring)), ExecutorError::NotParked);
    assert_eq!(root.turn(Routed(live), Idle), second);
}

#[test]
fn another_tables_token_is_refused_and_cannot_run_a_second_executor() {
    let mut root = Root::new(2, 2);
    let (mut other, foreign) = ExecutorTable::try_new(1).unwrap();
    let before = root.states();

    assert_eq!(root.table.register(&foreign), Err(ExecutorError::WrongTable));
    let (error, foreign) = root.table.resume(foreign, Unrouted).unwrap_err();
    assert_eq!(error, ExecutorError::WrongTable);
    assert_eq!(root.states(), before);

    // With this table's own token lent, the foreign token still cannot run a second executor.
    let run = root.resume(Unrouted);
    let (error, foreign) = root.table.resume(foreign, Unrouted).unwrap_err();
    assert_eq!(error, ExecutorError::WrongTable);
    assert_eq!(root.table.running(), Some(run.executor()));
    assert_eq!(root.state(root.executors[1]), ExecutorState::Idle);
    root.yields(run, Idle);

    // The refused token is intact for its own table.
    let only = other.register(&foreign).unwrap();
    assert_eq!(other.resume(foreign, Unrouted).unwrap().executor(), only);
}

#[test]
fn another_tables_run_cannot_yield_this_tables_running_executor() {
    let mut root = Root::new(1, 1);
    let mut other = Root::new(1, 1);
    let run = root.resume(Unrouted);
    let foreign = other.resume(Unrouted);
    // Both tables issued the same slot and generation; only the table identity differs.
    assert_eq!(foreign.executor(), run.executor());

    let (error, foreign) = root.table.accept_yield(foreign, Idle).unwrap_err();
    assert_eq!(error, ExecutorError::WrongTable);
    assert_eq!(root.table.running(), Some(run.executor()));
    root.yields(run, Idle);
    other.yields(foreign, Idle);
}

/// Deterministic pseudo-random protocol walk. Whatever root and the executors attempt, at most
/// one executor runs, it runs exactly while the token is lent, no route has two waiters, and a
/// refusal changes nothing.
#[test]
fn any_interleaving_keeps_one_runner_and_one_waiter_per_route() {
    let mut routes = Routes::new();
    let waits: Vec<ExecutorWait> = (0..4)
        .flat_map(|_| {
            let route = routes.route();
            [wait(route, 1), wait(route, 2)]
        })
        .collect();
    let mut root = Root::new(4, 1);
    let mut run: Option<ExecutorRun> = None;
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    let (mut resumed, mut refused) = (0, 0);

    for _ in 0..4000 {
        let before = root.states();
        let changed = match run.take() {
            Some(running) => {
                let yielded = match next(4) {
                    0 => Idle,
                    1 => Done,
                    _ => Parked(waits[next(waits.len())]),
                };
                match root.table.accept_yield(running, yielded) {
                    Ok(token) => {
                        root.token = Some(token);
                        true
                    }
                    Err((_, running)) => {
                        run = Some(running);
                        false
                    }
                }
            }
            None if next(8) == 0 => root.register().is_ok(),
            None => {
                let cause = match next(4) {
                    0 => Unrouted,
                    1 => RouteRetired(waits[next(waits.len())].route()),
                    _ => Routed(waits[next(waits.len())]),
                };
                match root.table.resume(root.token.take().unwrap(), cause) {
                    Ok(running) => {
                        resumed += 1;
                        run = Some(running);
                        true
                    }
                    Err((_, token)) => {
                        root.token = Some(token);
                        false
                    }
                }
            }
        };
        if !changed {
            refused += 1;
            assert_eq!(root.states(), before);
        }

        let states: Vec<ExecutorState> = root.states().into_iter().flatten().collect();
        let running = states.iter().filter(|state| **state == ExecutorState::Running).count();
        assert_eq!(running, usize::from(run.is_some()));
        assert_eq!(run.is_some(), root.token.is_none());
        assert_eq!(root.table.running(), run.as_ref().map(ExecutorRun::executor));
        let parked: Vec<PeerRoute> = states
            .iter()
            .filter_map(|state| match state {
                ExecutorState::Parked(wait) => Some(wait.route()),
                _ => None,
            })
            .collect();
        for (index, route) in parked.iter().enumerate() {
            assert!(!parked[index + 1..].contains(route), "two executors wait on one route");
        }
        assert!(root.table.slots.len() <= 4);
    }
    // The walk must exercise both successful and refused transitions to prove anything.
    assert!(resumed > 200 && refused > 200, "resumed {resumed}, refused {refused}");
}
