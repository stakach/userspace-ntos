use super::*;
use crate::{
    executor_local::{PhysicalTcbClaim, PhysicalWorkerEndpointClaim, TcbIdentity, TcbRetirementObservation},
    peer_registry::{PeerIdentity, PeerRegistry},
    LaneHandle, RootReplyIdentity, RootReplyReplacementError, RootReplySlotState, RootReplySlotTable,
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
        // This fixture models an executor already bootstrapped on its private endpoint.
        let executor = unsafe { self.table.register(self.token.as_ref().unwrap()) }?;
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
fn unready_worker_cannot_receive_unrouted_work_before_fs_publication() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let worker = table.register_unready(&root).unwrap();

    // The native SetTLSBase acknowledgement has not happened. An unrouted arrival must stay
    // with root instead of selecting this worker while its FS base is still uninitialized.
    assert_ne!(table.state(worker), Ok(ExecutorState::Idle));
    let result = table.resume(root, Unrouted);
    assert!(
        matches!(result, Err((ExecutorError::NoIdleExecutor, _))),
        "unready worker {worker:?} must not be selected before FS publication"
    );
}

#[test]
fn two_worker_ingress_owners_refuse_reused_endpoint_or_reply_caps() {
    let (mut table, root) = ExecutorTable::try_new(2).unwrap();
    let diagnostic = table.register_unready(&root).unwrap();
    let production = table.register_unready(&root).unwrap();
    let diagnostic_tcb = unsafe {
        PhysicalTcbClaim::new(TcbIdentity::new(0x120, 1), 0x220).unwrap()
    };
    let production_tcb = unsafe {
        PhysicalTcbClaim::new(TcbIdentity::new(0x121, 1), 0x221).unwrap()
    };
    let diagnostic_endpoint = unsafe {
        PhysicalWorkerEndpointClaim::from_native(&diagnostic_tcb, 0x320, 1).unwrap()
    };
    let reused_endpoint = unsafe {
        PhysicalWorkerEndpointClaim::from_native(&production_tcb, 0x320, 2).unwrap()
    };
    let distinct_endpoint = unsafe {
        PhysicalWorkerEndpointClaim::from_native(&production_tcb, 0x321, 1).unwrap()
    };
    // Distinct Reply tables can each believe the same numeric cap is free. The executor table
    // must still exclude that physical Reply from a second live worker.
    let mut first_replies = RootReplySlotTable::new(1).unwrap();
    let first_reply = first_replies.insert_free(0x420).unwrap();
    first_replies.mark_used(first_reply).unwrap();
    let mut other_replies = RootReplySlotTable::new(2).unwrap();
    let distinct_reply = other_replies.insert_free(0x421).unwrap();
    let reused_reply = other_replies.insert_free(0x420).unwrap();
    other_replies.mark_used(distinct_reply).unwrap();
    other_replies.mark_used(reused_reply).unwrap();

    table.admit_private_ingress(&root, diagnostic, &diagnostic_endpoint, &first_replies, first_reply).unwrap();
    assert_eq!(
        table.admit_private_ingress(&root, production, &reused_endpoint, &other_replies, distinct_reply),
        Err(ExecutorError::DuplicateWorkerIngress),
    );
    assert_eq!(
        table.admit_private_ingress(&root, production, &distinct_endpoint, &other_replies, reused_reply),
        Err(ExecutorError::DuplicateWorkerIngress),
    );
    table.admit_private_ingress(
        &root, production, &distinct_endpoint, &other_replies, distinct_reply,
    ).unwrap();
    assert_eq!(
        table.admit_private_ingress(
            &root, production, &distinct_endpoint, &other_replies, distinct_reply,
        ),
        Err(ExecutorError::DuplicateWorkerIngress),
    );
    assert_eq!(table.state(diagnostic), Ok(ExecutorState::Unready));
    assert_eq!(table.state(production), Ok(ExecutorState::Unready));
    assert_eq!(diagnostic_endpoint.endpoint_cap(), 0x320);
    assert_eq!(reused_endpoint.tcb(), production_tcb.identity());
    assert_eq!(reused_reply.cap(), first_reply.cap());
}

#[test]
fn unknown_and_stale_handles_are_refused() {
    let root = Root::new(2, 1);
    let known = root.executors[0];
    let beyond = ExecutorHandle { index: 1, ..known };
    let stale = ExecutorHandle { generation: known.generation() + 1, ..known };
    assert_eq!(root.table.state(beyond), Err(ExecutorError::NotFound));
    assert_eq!(root.table.state(stale), Err(ExecutorError::StaleGeneration));
}

#[test]
fn another_tables_handle_cannot_name_this_tables_executor() {
    let first = Root::new(1, 1);
    let second = Root::new(1, 1);
    let first_handle = first.executors[0];
    let second_handle = second.executors[0];

    // Both tables start with slot zero, generation one. Slot coordinates alone are not
    // authority to inspect or route to an executor owned by another table.
    assert_eq!(first_handle.index(), second_handle.index());
    assert_eq!(first_handle.generation(), second_handle.generation());
    assert_eq!(first.table.state(second_handle), Err(ExecutorError::WrongTable));
    assert_eq!(second.table.state(first_handle), Err(ExecutorError::WrongTable));
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

    // The modeled worker is already bootstrapped; authority still belongs to this table.
    assert_eq!(unsafe { root.table.register(&foreign) }, Err(ExecutorError::WrongTable));
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
    let only = unsafe { other.register(&foreign) }.unwrap();
    assert_eq!(other.resume(foreign, Unrouted).unwrap().executor(), only);
}

#[test]
fn another_tables_run_cannot_yield_this_tables_running_executor() {
    let mut root = Root::new(1, 1);
    let mut other = Root::new(1, 1);
    let run = root.resume(Unrouted);
    let foreign = other.resume(Unrouted);
    // Both tables issued the same slot and generation; only the table identity differs.
    assert_eq!(foreign.executor().index(), run.executor().index());
    assert_eq!(foreign.executor().generation(), run.executor().generation());
    assert_ne!(foreign.executor(), run.executor());

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

// Root binds the exact physical worker and both owner-issued Reply identities while its run is
// active, before calling that worker. The table remains Running: the Call may return normally.
// If the supervisor suspends the worker and replies to root, root observes the checked fault
// terminal and only then moves the executor to Faulted. Table-issued identities are selectors;
// unsafe observation constructors model the checked native effects and alias teardown.
struct FaultReplyOwners {
    root_table: RootReplySlotTable,
    supervisor_table: RootReplySlotTable,
    root: RootReplyIdentity,
    supervisor: RootReplyIdentity,
}

impl FaultReplyOwners {
    fn new() -> Self {
        // These distinct owner tables issue generation-bearing identities for the root's Call
        // Reply and the supervisor's fault Reply. The caps themselves grant no authority.
        let mut root_table = RootReplySlotTable::new(1).unwrap();
        let mut supervisor_table = RootReplySlotTable::new(1).unwrap();
        let root = root_table.insert_used(0x130).unwrap();
        let supervisor = supervisor_table.insert_used(0x140).unwrap();
        Self { root_table, supervisor_table, root, supervisor }
    }

    fn retire_root(&mut self) -> FaultReplyRetirementObservation {
        // SAFETY: this fixture models acknowledged destruction of the exact Reply and every
        // alias in the native owner's CSpace, not just release of the numeric cap.
        let observed = unsafe {
            FaultReplyRetirementObservation::after_native_teardown(&mut self.root_table, self.root)
                .unwrap()
        };
        assert_eq!(self.root_table.state(self.root), Err(RootReplyReplacementError::StaleIdentity));
        observed
    }

    fn retire_supervisor(&mut self) -> FaultReplyRetirementObservation {
        // SAFETY: the exact supervisor Reply and every alias were acknowledged retired.
        let observed = unsafe {
            FaultReplyRetirementObservation::after_native_teardown(
                &mut self.supervisor_table,
                self.supervisor,
            )
            .unwrap()
        };
        assert_eq!(
            self.supervisor_table.state(self.supervisor),
            Err(RootReplyReplacementError::StaleIdentity)
        );
        observed
    }
}

fn fault_report(
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
    root_reply: RootReplyIdentity,
    supervisor_reply: RootReplyIdentity,
) -> ExecutorFaultReport {
    unsafe {
        ExecutorFaultReport::acknowledged(
            executor,
            tcb,
            target_cap,
            root_reply,
            supervisor_reply,
        )
        .unwrap()
    }
}

fn live_fault_report(
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
    root_reply: RootReplyIdentity,
    supervisor_reply: RootReplyIdentity,
    job: LiveJobId,
) -> ExecutorFaultReport {
    unsafe {
        ExecutorFaultReport::acknowledged_live(
            executor, tcb, target_cap, root_reply, supervisor_reply, job,
        ).unwrap()
    }
}

fn bind_fault(
    root: &mut Root,
    run: &ExecutorRun,
    claim: &PhysicalTcbClaim,
    root_reply: RootReplyIdentity,
    supervisor_reply: RootReplyIdentity,
) {
    let binding = unsafe {
        ExecutorFaultBinding::from_native(run.executor(), claim, root_reply, supervisor_reply)
            .unwrap()
    };
    assert!(root.table.bind_fault(run, binding).is_ok());
    assert_eq!(root.state(run.executor()), ExecutorState::Running);
}

fn active_fault_binding() -> (
    Root,
    ExecutorRun,
    ExecutorHandle,
    TcbIdentity,
    PhysicalTcbClaim,
    FaultReplyOwners,
) {
    let mut root = Root::new(1, 1);
    let run = root.resume(Unrouted);
    let executor = run.executor();
    let tcb = TcbIdentity::new(0x20, 7);
    let claim = unsafe { PhysicalTcbClaim::new(tcb, 0x120).unwrap() };
    let replies = FaultReplyOwners::new();
    bind_fault(&mut root, &run, &claim, replies.root, replies.supervisor);
    (root, run, executor, tcb, claim, replies)
}

fn observed_fault() -> (Root, ExecutorHandle, TcbIdentity, PhysicalTcbClaim, FaultReplyOwners) {
    let (mut root, run, executor, tcb, claim, replies) = active_fault_binding();
    let report = fault_report(executor, tcb, 0x120, replies.root, replies.supervisor);
    root.token = Some(root.table.accept_fault_terminal(run, report).ok().unwrap());
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    (root, executor, tcb, claim, replies)
}

#[test]
fn normal_call_completion_keeps_the_bound_worker_eligible() {
    let (mut root, run, executor, _, claim, _replies) = active_fault_binding();
    root.yields(run, Idle);
    assert_eq!(root.state(executor), ExecutorState::Idle);
    let next_run = root.resume(Unrouted);
    assert_eq!(next_run.executor(), executor);
    let next_replies = FaultReplyOwners::new();
    bind_fault(
        &mut root,
        &next_run,
        &claim,
        next_replies.root,
        next_replies.supervisor,
    );
    root.yields(next_run, Idle);
    assert_eq!(root.state(executor), ExecutorState::Idle);
}

fn hosted_reply_owner() -> (RootReplySlotTable, RootReplyIdentity) {
    let mut owner = RootReplySlotTable::new(1).unwrap();
    let reply = owner.insert_used(0x150).unwrap();
    (owner, reply)
}

fn worker_endpoint(
    claim: &PhysicalTcbClaim,
    cap: u64,
    generation: u64,
) -> PhysicalWorkerEndpointClaim {
    // SAFETY: the fixture retains the TCB and the separately owned physical endpoint. Wrong
    // owner cases below model a different valid endpoint claim, not authority from a bare cap.
    unsafe { PhysicalWorkerEndpointClaim::from_native(claim, cap, generation).unwrap() }
}

fn exact_rearm(
    executor: ExecutorHandle,
    endpoint: &PhysicalWorkerEndpointClaim,
    reply: RootReplyIdentity,
) -> ExactPassiveReceiveProof {
    // SAFETY: these are memory-only fixtures. The successful case models a checked kernel
    // query after ReplyRecv; mismatch cases deliberately submit adversarial foreign proofs.
    // The table must compare the full binding before trusting any such observation.
    unsafe { ExactPassiveReceiveProof::after_checked_query(executor, endpoint, reply).unwrap() }
}

#[test]
fn exhausted_live_job_sequence_refuses_before_loaning_a_call() {
    let (mut root, run, executor, _, claim, _) = active_fault_binding();
    let (hosted_owner, hosted_reply) = hosted_reply_owner();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    root.table.next_job_sequence = u64::MAX;
    assert_eq!(
        root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap_err(),
        ExecutorError::IdentityExhausted
    );
    assert_eq!(root.table.live_job(executor), Ok(None));
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    root.yields(run, Idle);
    assert_eq!(root.state(executor), ExecutorState::Idle);
}

#[test]
fn live_job_refuses_generic_idle_and_mints_a_new_identity_for_each_call() {
    let (mut root, run, executor, _, claim, replies) = active_fault_binding();
    let (mut hosted_owner, hosted_reply) = hosted_reply_owner();
    let (_foreign_hosted_owner, foreign_hosted_reply) = hosted_reply_owner();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    assert!(root.table.bind_live_job(&run, &hosted_owner, foreign_hosted_reply, &endpoint).is_err());
    let first_job = root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap();

    let (error, run) = root.refused_yield(run, Idle);
    assert_eq!(error, ExecutorError::LiveJobOutstanding);
    assert_eq!(root.table.live_job(executor), Ok(Some(first_job)));
    assert!(root.token.is_none());
    let terminal = unsafe {
        LiveNormalTerminal::acknowledged(
            first_job,
            0x2a,
            replies.root,
            exact_rearm(executor, &endpoint, replies.root),
        ).unwrap()
    };
    let (token, result) = root.table.accept_live_terminal(run, terminal).unwrap();
    root.token = Some(token);
    assert_eq!(result, 0x2a);
    assert_eq!(root.state(executor), ExecutorState::AwaitingHostedReply);
    assert_eq!(root.table.live_job(executor), Ok(Some(first_job)));
    // The worker result does not consume the hosted caller's Reply; root still owns that effect.
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
    let (mut foreign_owner, foreign_reply) = hosted_reply_owner();
    let wrong_settlement = unsafe {
        LiveHostedReplySettlementObservation::after_checked_native_completion(
            &mut foreign_owner, foreign_reply,
        ).unwrap()
    };
    assert_eq!(root.table.observe_live_hosted_reply_settlement(
        root.token.as_ref().unwrap(), executor, first_job, wrong_settlement,
    ).err().unwrap().0, ExecutorError::LiveJobIdentityMismatch);
    assert_eq!(root.table.live_job(executor), Ok(Some(first_job)));
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    let settled = unsafe {
        LiveHostedReplySettlementObservation::after_checked_native_completion(
            &mut hosted_owner, hosted_reply,
        ).unwrap()
    };
    root.table.observe_live_hosted_reply_settlement(
        root.token.as_ref().unwrap(), executor, first_job, settled,
    ).unwrap();
    assert_eq!(root.state(executor), ExecutorState::Idle);
    assert_eq!(root.table.live_job(executor), Ok(None));

    let next_run = root.resume(Unrouted);
    bind_fault(&mut root, &next_run, &claim, replies.root, replies.supervisor);
    let (next_hosted_owner, next_hosted_reply) = hosted_reply_owner();
    let next_job = root.table.bind_live_job(
        &next_run, &next_hosted_owner, next_hosted_reply, &endpoint,
    ).unwrap();
    assert_ne!(first_job, next_job, "a late terminal must not match a later Call");
    let stale_terminal = unsafe {
        LiveNormalTerminal::acknowledged(
            first_job,
            0x2a,
            replies.root,
            exact_rearm(executor, &endpoint, replies.root),
        ).unwrap()
    };
    let (_, returned_run, _) = root.table.accept_live_terminal(next_run, stale_terminal).err().unwrap();
    assert_eq!(returned_run.executor(), executor);
    assert_eq!(root.state(executor), ExecutorState::Quarantined);
    assert_eq!(root.table.live_job(executor), Ok(Some(next_job)));
    assert_eq!(next_hosted_owner.state(next_hosted_reply), Ok(RootReplySlotState::Used));
    assert!(root.token.is_none());
}

#[test]
fn live_terminal_rejects_wrong_private_reply_or_rearm_identity_without_replay() {
    for wrong in 0..3 {
        let (mut root, run, executor, _, claim, replies) = active_fault_binding();
        let (hosted_owner, hosted_reply) = hosted_reply_owner();
        let endpoint = worker_endpoint(&claim, 0x180, 1);
        let wrong_endpoint = worker_endpoint(&claim, 0x181, 2);
        let job = root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap();
        let other_replies = FaultReplyOwners::new();
        let foreign_root = Root::new(1, 1);
        let foreign_claim = unsafe {
            PhysicalTcbClaim::new(TcbIdentity::new(0x21, 8), 0x121).unwrap()
        };
        let foreign_endpoint = worker_endpoint(&foreign_claim, 0x182, 1);
        let (terminal_reply, proof) = match wrong {
            0 => (other_replies.root, exact_rearm(executor, &endpoint, replies.root)),
            1 => (replies.root, exact_rearm(executor, &wrong_endpoint, replies.root)),
            _ => (replies.root, exact_rearm(foreign_root.executors[0], &foreign_endpoint, other_replies.root)),
        };
        let terminal = unsafe { LiveNormalTerminal::acknowledged(job, 0, terminal_reply, proof).unwrap() };
        let (_, returned_run, _) = root.table.accept_live_terminal(run, terminal).err().unwrap();
        assert_eq!(returned_run.executor(), executor);
        assert_eq!(root.state(executor), ExecutorState::Quarantined);
        assert_eq!(root.table.live_job(executor), Ok(Some(job)));
        assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
        assert!(root.token.is_none());
        assert!(root.table.accept_yield(returned_run, Idle).is_err());
    }
}

#[test]
fn uncertain_live_terminal_retains_the_run_job_and_hosted_reply() {
    let (mut root, run, executor, _, claim, replies) = active_fault_binding();
    let (hosted_owner, hosted_reply) = hosted_reply_owner();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    let job = root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap();
    // A partial or indeterminate native ReplyRecv is not a checked result or rearm proof.
    let terminal = unsafe { LiveNormalTerminal::uncertain(job, replies.root).unwrap() };
    let (_, returned_run, _) = root.table.accept_live_terminal(run, terminal).err().unwrap();
    assert_eq!(returned_run.executor(), executor);
    assert_eq!(root.state(executor), ExecutorState::Quarantined);
    assert_eq!(root.table.live_job(executor), Ok(Some(job)));
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    assert!(root.token.is_none());
    assert!(root.table.accept_yield(returned_run, Idle).is_err());
}

#[test]
fn checked_fault_retains_the_live_job_and_hosted_reply() {
    let (mut root, run, executor, tcb, claim, replies) = active_fault_binding();
    let (hosted_owner, hosted_reply) = hosted_reply_owner();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    let job = root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap();
    let report = live_fault_report(executor, tcb, 0x120, replies.root, replies.supervisor, job);
    root.token = Some(root.table.accept_fault_terminal(run, report).unwrap());
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.table.live_job(executor), Ok(Some(job)));
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
}

#[test]
fn stale_fault_nonce_cannot_fault_a_later_call_on_the_same_worker_and_private_reply() {
    let (mut root, first_run, executor, tcb, claim, replies) = active_fault_binding();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    let (mut first_owner, first_reply) = hosted_reply_owner();
    let first_job = root.table.bind_live_job(
        &first_run, &first_owner, first_reply, &endpoint,
    ).unwrap();
    let terminal = unsafe {
        LiveNormalTerminal::acknowledged(
            first_job, 0, replies.root, exact_rearm(executor, &endpoint, replies.root),
        ).unwrap()
    };
    let (token, _) = root.table.accept_live_terminal(first_run, terminal).unwrap();
    root.token = Some(token);
    let settled = unsafe {
        LiveHostedReplySettlementObservation::after_checked_native_completion(
            &mut first_owner, first_reply,
        ).unwrap()
    };
    root.table.observe_live_hosted_reply_settlement(
        root.token.as_ref().unwrap(), executor, first_job, settled,
    ).unwrap();

    let second_run = root.resume(Unrouted);
    bind_fault(&mut root, &second_run, &claim, replies.root, replies.supervisor);
    let (second_owner, second_reply) = hosted_reply_owner();
    let second_job = root.table.bind_live_job(
        &second_run, &second_owner, second_reply, &endpoint,
    ).unwrap();
    assert_ne!(first_job, second_job);
    let stale = live_fault_report(
        executor, tcb, 0x120, replies.root, replies.supervisor, first_job,
    );
    let (error, returned_run, _) = root.table.accept_fault_terminal(second_run, stale).unwrap_err();
    assert_eq!(error, ExecutorError::FaultIdentityMismatch);
    assert_eq!(returned_run.executor(), executor);
    assert_eq!(root.state(executor), ExecutorState::Quarantined);
    assert_eq!(root.table.live_job(executor), Ok(Some(second_job)));
    assert_eq!(second_owner.state(second_reply), Ok(RootReplySlotState::Used));
    assert!(root.token.is_none());
}

#[test]
fn faulted_live_job_waits_for_exact_hosted_reply_settlement_before_slot_reuse() {
    let (mut root, run, executor, tcb, claim, mut replies) = active_fault_binding();
    let (mut hosted_owner, hosted_reply) = hosted_reply_owner();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    let job = root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap();
    let report = live_fault_report(executor, tcb, 0x120, replies.root, replies.supervisor, job);
    root.token = Some(root.table.accept_fault_terminal(run, report).unwrap());

    let retired_tcb = unsafe { TcbRetirementObservation::new(tcb) };
    root.table.observe_fault_retirement(
        root.token.as_ref().unwrap(), executor, FaultRetirementObservation::Tcb(retired_tcb),
    ).unwrap();
    let retired_private = replies.retire_root();
    root.table.observe_fault_retirement(
        root.token.as_ref().unwrap(), executor, FaultRetirementObservation::Reply(retired_private),
    ).unwrap();
    let retired_supervisor = replies.retire_supervisor();
    root.table.observe_fault_retirement(
        root.token.as_ref().unwrap(), executor, FaultRetirementObservation::Reply(retired_supervisor),
    ).unwrap();
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.table.live_job(executor), Ok(Some(job)));
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));

    // An owner-issued observation for the same numeric cap from another Reply table is not
    // authority over this hosted caller's Reply.
    let (mut foreign_owner, foreign_reply) = hosted_reply_owner();
    let wrong = unsafe {
        LiveHostedReplySettlementObservation::after_checked_native_completion(
            &mut foreign_owner, foreign_reply,
        ).unwrap()
    };
    let (error, _) = root.table.observe_fault_retirement(
        root.token.as_ref().unwrap(), executor, FaultRetirementObservation::HostedReply(wrong),
    ).err().unwrap();
    assert_eq!(error, ExecutorError::FaultIdentityMismatch);
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));

    // SAFETY: the fixture models the root's checked native Reply completion after it answers
    // the hosted caller. The owner advances its generation before issuing this observation.
    let settled = unsafe {
        LiveHostedReplySettlementObservation::after_checked_native_completion(
            &mut hosted_owner, hosted_reply,
        ).unwrap()
    };
    assert_eq!(hosted_owner.state(hosted_reply), Err(RootReplyReplacementError::StaleIdentity));
    root.table.observe_fault_retirement(
        root.token.as_ref().unwrap(), executor, FaultRetirementObservation::HostedReply(settled),
    ).unwrap();
    assert_eq!(root.state(executor), ExecutorState::Retired);
    assert_eq!(root.table.live_job(executor), Ok(None));
    let replacement = root.register().unwrap();
    assert_eq!(replacement.index(), executor.index());
    assert_ne!(replacement.generation(), executor.generation());
    assert_eq!(root.table.state(executor), Err(ExecutorError::StaleGeneration));
}

#[test]
fn uncertain_fault_terminal_quarantines_the_live_job_and_hosted_reply() {
    let (mut root, run, executor, tcb, claim, replies) = active_fault_binding();
    let (hosted_owner, hosted_reply) = hosted_reply_owner();
    let endpoint = worker_endpoint(&claim, 0x180, 1);
    let job = root.table.bind_live_job(&run, &hosted_owner, hosted_reply, &endpoint).unwrap();
    let uncertain = unsafe {
        ExecutorFaultReport::uncertain_live(
            executor, tcb, 0x120, replies.root, replies.supervisor, job,
        )
            .unwrap()
    };
    let (_, returned_run, _) = root.table.accept_fault_terminal(run, uncertain).err().unwrap();
    assert_eq!(returned_run.executor(), executor);
    assert_eq!(root.state(executor), ExecutorState::Quarantined);
    assert_eq!(root.table.live_job(executor), Ok(Some(job)));
    assert_eq!(hosted_owner.state(hosted_reply), Ok(RootReplySlotState::Used));
    assert!(root.token.is_none());
    assert!(root.table.accept_yield(returned_run, Idle).is_err());
}

#[test]
fn exact_supervisor_terminal_faults_worker_without_reusing_its_slot() {
    let (mut root, executor, tcb, _claim, mut replies) = observed_fault();

    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));

    // Teardown of the prior physical incarnation cannot release this faulted slot.
    let stale = unsafe { TcbRetirementObservation::new(TcbIdentity::new(0x20, 6)) };
    assert!(root
        .table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Tcb(stale),
        )
        .is_err());
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));

    let retired = unsafe { TcbRetirementObservation::new(tcb) };
    root.table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Tcb(retired),
        )
        .unwrap();
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));

    let root_reply = replies.retire_root();
    root.table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Reply(root_reply),
        )
        .unwrap();
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));

    let supervisor_reply = replies.retire_supervisor();
    root.table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Reply(supervisor_reply),
        )
        .unwrap();
    let replacement = root.register().unwrap();
    assert_eq!(replacement.index(), executor.index());
    assert_ne!(replacement.generation(), executor.generation());
    assert_eq!(root.table.state(executor), Err(ExecutorError::StaleGeneration));
}

#[test]
fn tcb_and_supervisor_reply_retirement_wait_for_root_reply_and_its_aliases() {
    let (mut root, executor, tcb, _claim, mut replies) = observed_fault();
    let token = root.token.as_ref().unwrap();
    let supervisor_reply = replies.retire_supervisor();
    root.table
        .observe_fault_retirement(
            token,
            executor,
            FaultRetirementObservation::Reply(supervisor_reply),
        )
        .unwrap();
    let tcb_retired = unsafe { TcbRetirementObservation::new(tcb) };
    root.table
        .observe_fault_retirement(token, executor, FaultRetirementObservation::Tcb(tcb_retired))
        .unwrap();

    // The root's Reply identity remains Used. A live alias prevents a checked native teardown
    // observation, so neither physical TCB retirement nor the other Reply can free this slot.
    assert_eq!(replies.root_table.state(replies.root), Ok(RootReplySlotState::Used));
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));

    let root_reply = replies.retire_root();
    root.table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Reply(root_reply),
        )
        .unwrap();
    assert_eq!(root.register().unwrap().index(), executor.index());
}

#[test]
fn faulted_slot_refuses_reply_retirement_from_wrong_owner_or_stale_slot_generation() {
    let (mut root, executor, tcb, _claim, mut replies) = observed_fault();
    let tcb_retired = unsafe { TcbRetirementObservation::new(tcb) };
    root.table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Tcb(tcb_retired),
        )
        .unwrap();

    // Both wrong observations are genuine retirements issued by different owner tables,
    // even though those tables use the same numeric caps as this fault's bound Replies.
    let mut other = FaultReplyOwners::new();
    for wrong in [other.retire_root(), other.retire_supervisor()] {
        let (_, _returned) = root
            .table
            .observe_fault_retirement(
                root.token.as_ref().unwrap(),
                executor,
                FaultRetirementObservation::Reply(wrong),
            )
            .err()
            .unwrap();
        assert_eq!(root.state(executor), ExecutorState::Faulted);
        assert_eq!(root.register(), Err(ExecutorError::NoCapacity));
    }

    // Reusing the root owner's slot invalidates its old identity. Retirement of the new
    // incarnation must not settle the old fault, even when the numeric cap is identical.
    let old_root = replies.root;
    replies.root_table.clear(old_root, None).unwrap();
    assert!(unsafe {
        FaultReplyRetirementObservation::after_native_teardown(&mut replies.root_table, old_root)
    }
    .is_err());
    let replacement = replies.root_table.insert_used(old_root.cap()).unwrap();
    assert_ne!(replacement, old_root);
    let newer = unsafe {
        FaultReplyRetirementObservation::after_native_teardown(&mut replies.root_table, replacement)
            .unwrap()
    };
    let (_, _returned) = root
        .table
        .observe_fault_retirement(
            root.token.as_ref().unwrap(),
            executor,
            FaultRetirementObservation::Reply(newer),
        )
        .err()
        .unwrap();
    assert_eq!(root.state(executor), ExecutorState::Faulted);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));
}

#[test]
fn fault_terminal_refuses_stale_worker_and_either_wrong_reply_binding() {
    for wrong_field in 0..6 {
        let (mut root, run, executor, tcb, _claim, replies) = active_fault_binding();
        let other_replies = FaultReplyOwners::new();
        let report = match wrong_field {
            0 => fault_report(
                Root::new(1, 1).executors[0], tcb, 0x120, replies.root, replies.supervisor,
            ),
            1 => fault_report(
                executor, TcbIdentity::new(0x21, 7), 0x120, replies.root, replies.supervisor,
            ),
            2 => fault_report(
                executor, TcbIdentity::new(0x20, 6), 0x120, replies.root, replies.supervisor,
            ),
            3 => fault_report(executor, tcb, 0x121, replies.root, replies.supervisor),
            4 => fault_report(executor, tcb, 0x120, other_replies.root, replies.supervisor),
            _ => fault_report(executor, tcb, 0x120, replies.root, other_replies.supervisor),
        };
        let (_, returned_run, _) = root.table.accept_fault_terminal(run, report).err().unwrap();
        assert_eq!(returned_run.executor(), executor);
        assert_eq!(root.state(executor), ExecutorState::Quarantined);
        assert!(root.token.is_none(), "a mismatched terminal must not return the run token");
        assert!(root.table.accept_yield(returned_run, Idle).is_err());
    }
}

#[test]
fn uncertain_fault_terminal_retains_the_quarantine_on_duplicate_observation() {
    let (mut root, run, executor, tcb, _claim, replies) = active_fault_binding();
    let uncertain = unsafe {
        ExecutorFaultReport::uncertain(executor, tcb, 0x120, replies.root, replies.supervisor)
            .unwrap()
    };
    let (_, run, _) = root.table.accept_fault_terminal(run, uncertain).err().unwrap();
    assert_eq!(root.state(executor), ExecutorState::Quarantined);
    assert!(root.token.is_none());

    // Repeating the same indeterminate observation cannot clear its uncertain native effect.
    let duplicate = unsafe {
        ExecutorFaultReport::uncertain(executor, tcb, 0x120, replies.root, replies.supervisor)
            .unwrap()
    };
    let (_, returned_run, _) = root.table.accept_fault_terminal(run, duplicate).err().unwrap();
    assert_eq!(returned_run.executor(), executor);
    assert_eq!(root.state(executor), ExecutorState::Quarantined);
    assert!(root.token.is_none());
    assert!(root.table.accept_yield(returned_run, Idle).is_err());
}

#[test]
fn duplicate_fault_terminal_cannot_return_a_second_run_token() {
    let mut root = Root::new(2, 2);
    let first_run = root.resume(Unrouted);
    let first = first_run.executor();
    let tcb = TcbIdentity::new(0x20, 7);
    let first_claim = unsafe { PhysicalTcbClaim::new(tcb, 0x120).unwrap() };
    let first_replies = FaultReplyOwners::new();
    bind_fault(&mut root, &first_run, &first_claim, first_replies.root, first_replies.supervisor);
    let report = fault_report(first, tcb, 0x120, first_replies.root, first_replies.supervisor);
    root.token = Some(root.table.accept_fault_terminal(first_run, report).ok().unwrap());

    let second_run = root.resume(Unrouted);
    let second = second_run.executor();
    assert_ne!(second, first);
    let second_claim = unsafe { PhysicalTcbClaim::new(TcbIdentity::new(0x21, 1), 0x121).unwrap() };
    let second_replies = FaultReplyOwners::new();
    bind_fault(
        &mut root,
        &second_run,
        &second_claim,
        second_replies.root,
        second_replies.supervisor,
    );
    let duplicate = fault_report(first, tcb, 0x120, first_replies.root, first_replies.supervisor);
    let (_, returned_run, _) = root
        .table
        .accept_fault_terminal(second_run, duplicate)
        .err()
        .unwrap();
    assert_eq!(returned_run.executor(), second);
    assert_eq!(root.state(first), ExecutorState::Faulted);
    assert_eq!(root.state(second), ExecutorState::Quarantined);
    assert!(root.token.is_none(), "duplicate must not return the second worker's token");
    assert!(root.table.accept_yield(returned_run, Idle).is_err());
}
