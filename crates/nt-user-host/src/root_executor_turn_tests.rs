//! RED contract for the first root-to-executor Call. The existing root-ingress pass owns a
//! nested parent; these tests cover the independent front-end that lends one run token.

use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::root_executor_turn::{
    RootArrivalOwner, RootCallResult, RootCallSettlement, RootExecutorTurn, RootTurnCompletion,
};
use crate::root_handoff_readmission::HandoffKey;
use crate::thread_binding::ThreadBinding;
use nt_component_suspension::{
    peer_registry::PeerRegistry, ComponentIngress, ComponentSuspensionLanes, ExecutorResume,
    ExecutorTable, ExecutorWait, ExecutorYield, ExternalIngress, IngressReceiveDisposition,
    IngressReceiver, IngressReplyPool, LaneBinding, ReplyBindingObservation, RootReplyIdentity,
    RootReplySlotTable,
};

fn free(_: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn binding() -> ThreadBinding<u8> {
    ThreadBinding {
        pi: 7,
        process: ProcessIdentity {
            pid: 304,
            generation: ProcessGeneration::Hosted(2),
        },
        tid: 312,
        badge: 614,
        role: 0,
        tcb: 10,
        reservations: None,
    }
}

/// The retained receiver and Call travel in the payload; a copied badge cannot replace them.
struct Held {
    _receiver: IngressReceiver<u64>,
    call: ExternalIngress<u64>,
    binding: ThreadBinding<u8>,
    reply: RootReplyIdentity,
    cause: ExecutorResume,
}

impl Held {
    fn new(reply: RootReplyIdentity) -> Self {
        Self::with_cause(reply, ExecutorResume::Unrouted)
    }

    fn with_cause(reply: RootReplyIdentity, cause: ExecutorResume) -> Self {
        let lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
        let mut receiver = IngressReceiver::new(20, reply.cap(), 1).unwrap();
        let mut pool = IngressReplyPool::new(20, 1).unwrap();
        pool.insert(
            ComponentIngress::new(20, reply.cap() + 1).unwrap(),
            &receiver,
            &lanes,
            free,
        )
        .ok()
        .unwrap();
        receiver.begin_receive(&lanes).unwrap();
        receiver.capture(191).ok().unwrap();
        receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        let call = pool
            .retain_external(&mut receiver, &lanes, binding().tcb, free, bound)
            .unwrap();
        Self {
            _receiver: receiver,
            call,
            binding: binding(),
            reply,
            cause,
        }
    }

    fn key(&self) -> HandoffKey<u8> {
        HandoffKey::new(self.binding, self.call.admission_key()).unwrap()
    }
}

impl RootArrivalOwner<u8> for Held {
    fn caller_binding(&self) -> ThreadBinding<u8> {
        self.binding
    }
    fn admission_key(&self) -> nt_component_suspension::ExternalAdmissionKey {
        self.call.admission_key()
    }
    fn reply_identity(&self) -> RootReplyIdentity {
        self.reply
    }
    fn resume_cause(&self) -> ExecutorResume {
        self.cause
    }
}

fn one_idle_executor() -> (ExecutorTable, nt_component_suspension::ExecutorRun) {
    let (mut table, token) = ExecutorTable::try_new(1).unwrap();
    // The fixture starts after exact native bootstrap and private receive.
    unsafe { table.register(&token) }.unwrap();
    let run = table.resume(token, ExecutorResume::Unrouted).unwrap();
    (table, run)
}

fn one_parked_executor(
    wait: ExecutorWait,
) -> (ExecutorTable, nt_component_suspension::ExecutorRun) {
    let (mut table, token) = ExecutorTable::try_new(1).unwrap();
    // The fixture starts after exact native bootstrap and private receive.
    unsafe { table.register(&token) }.unwrap();
    let first = table.resume(token, ExecutorResume::Unrouted).unwrap();
    let token = table
        .accept_yield(first, ExecutorYield::Parked(wait))
        .unwrap();
    let run = table.resume(token, ExecutorResume::Routed(wait)).unwrap();
    (table, run)
}

fn wait_on_route() -> ExecutorWait {
    let mut lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
    let mut peers = PeerRegistry::new(50, 1);
    let (_, mut registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            17,
            1,
            LaneBinding {
                executor_id: 100,
                receive_endpoint: 50,
                reply_object: 200,
            },
        )
        .unwrap();
    let route = peers
        .publish_lane(&mut registration, 17, 1, &lanes)
        .unwrap();
    let dispatch = lanes
        .begin_bootstrap_dispatch(route, &peers, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .unwrap();
    assert_ne!(dispatch.epoch(), 0);
    ExecutorWait::new(route, dispatch).unwrap()
}

fn two_waits_same_route() -> (ExecutorWait, ExecutorWait) {
    let mut lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
    let mut peers = PeerRegistry::new(50, 1);
    let (_, mut registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            17,
            1,
            LaneBinding {
                executor_id: 100,
                receive_endpoint: 50,
                reply_object: 200,
            },
        )
        .unwrap();
    let route = peers
        .publish_lane(&mut registration, 17, 1, &lanes)
        .unwrap();
    let first = lanes
        .begin_bootstrap_dispatch(route, &peers, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .unwrap();
    lanes.finish_dispatch(route.identity().lane, 200).unwrap();
    lanes.begin_dispatch(route.identity().lane, 200).unwrap();
    let second = lanes
        .active_dispatch_identity(route.identity().lane)
        .unwrap()
        .unwrap();
    assert_ne!(first, second);
    (
        ExecutorWait::new(route, first).unwrap(),
        ExecutorWait::new(route, second).unwrap(),
    )
}

#[test]
fn constructor_binds_the_owned_arrival_not_just_supplied_copies() {
    let mut replies = RootReplySlotTable::new(2).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let other_reply = replies.insert_used(93).unwrap();
    let original = Held::new(reply);
    let key = original.key();
    let changed_admission = Held::new(reply);
    assert_ne!(changed_admission.key(), key);
    let (table, run) = one_idle_executor();
    let executor = run.executor();

    let (_, run, retained) = match RootExecutorTurn::new(run, key, reply, changed_admission) {
        Err(refused) => refused,
        Ok(_) => panic!("the supplied key cannot replace the owned admission identity"),
    };
    assert_ne!(retained.key(), key);
    assert_eq!(table.running(), Some(executor));

    let (_, run, retained) = match RootExecutorTurn::new(run, key, other_reply, original) {
        Err(refused) => refused,
        Ok(_) => panic!("the supplied Reply cannot replace the owner's physical pool identity"),
    };
    assert_eq!(retained.key(), key);
    assert_eq!(retained.reply_identity(), reply);
    assert_eq!(table.running(), Some(executor));

    let turn = match RootExecutorTurn::new(run, key, reply, retained) {
        Ok(turn) => turn,
        Err(_) => panic!("matching owned admission and Reply must be accepted"),
    };
    assert_eq!(turn.held_payload().key(), key);
}

#[test]
fn constructor_refuses_a_run_selected_for_another_arrivals_route() {
    let mut replies = RootReplySlotTable::new(1).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let routed = Held::with_cause(reply, ExecutorResume::Routed(wait_on_route()));
    let key = routed.key();
    let (table, run) = one_idle_executor();
    let executor = run.executor();
    let (_, run, retained) = RootExecutorTurn::new(run, key, reply, routed)
        .err()
        .expect("a route-mismatched run must return the exact arrival");
    assert_eq!(retained.key(), key);
    assert_eq!(table.running(), Some(executor));
    assert_eq!(run.cause(), ExecutorResume::Unrouted);
}

#[test]
fn stale_caller_reply_or_cause_never_enters_the_native_call() {
    let mut replies = RootReplySlotTable::new(2).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let foreign_reply = replies.insert_used(93).unwrap();
    let held = Held::new(reply);
    let key = held.key();
    let (mut table, run) = one_idle_executor();
    let executor = run.executor();
    let mut turn = match RootExecutorTurn::new(run, key, reply, held) {
        Ok(turn) => turn,
        Err(_) => panic!("valid retained root arrival"),
    };
    let mut calls = 0;

    let mut stale_caller = binding();
    stale_caller.process.generation = ProcessGeneration::Hosted(3);
    let stale_key = HandoffKey::new(stale_caller, key.admission()).unwrap();
    assert!(turn
        .try_call(stale_key, reply, ExecutorResume::Unrouted, |_, _, _| {
            calls += 1;
            RootCallResult::Returned {
                executor,
                yielded: ExecutorYield::Idle,
            }
        })
        .is_err());
    assert!(turn
        .try_call(key, foreign_reply, ExecutorResume::Unrouted, |_, _, _| {
            calls += 1;
            RootCallResult::Returned {
                executor,
                yielded: ExecutorYield::Idle,
            }
        })
        .is_err());
    assert!(turn
        .try_call(
            key,
            reply,
            ExecutorResume::RouteRetired(wait_on_route().route()),
            |_, _, _| {
                calls += 1;
                RootCallResult::Returned {
                    executor,
                    yielded: ExecutorYield::Idle,
                }
            }
        )
        .is_err());
    assert_eq!(calls, 0);
    assert_eq!(turn.held_payload().key(), key);
    assert_eq!(table.running(), Some(executor));

    turn.try_call(key, reply, ExecutorResume::Unrouted, |_, _, _| {
        calls += 1;
        RootCallResult::Returned {
            executor,
            yielded: ExecutorYield::Idle,
        }
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert!(
        turn.finish(&mut table, None).is_err(),
        "a yielded worker is not a Reply ACK"
    );
}

#[test]
fn stale_route_or_dispatch_cannot_send_a_routed_arrival() {
    let mut replies = RootReplySlotTable::new(1).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let (wait, stale_dispatch) = two_waits_same_route();
    let held = Held::with_cause(reply, ExecutorResume::Routed(wait));
    let key = held.key();
    let other_route = wait_on_route();
    let (table, run) = one_parked_executor(wait);
    let executor = run.executor();
    let mut turn = match RootExecutorTurn::new(run, key, reply, held) {
        Ok(turn) => turn,
        Err(_) => panic!("valid retained routed arrival"),
    };
    let mut calls = 0;
    for observed in [
        ExecutorResume::Routed(stale_dispatch),
        ExecutorResume::Routed(other_route),
    ] {
        assert!(turn
            .try_call(key, reply, observed, |_, _, _| {
                calls += 1;
                RootCallResult::Returned {
                    executor,
                    yielded: ExecutorYield::Idle,
                }
            })
            .is_err());
    }
    assert_eq!(calls, 0);
    assert_eq!(turn.held_payload().key(), key);
    assert_eq!(table.running(), Some(executor));
    turn.try_call(key, reply, ExecutorResume::Routed(wait), |_, _, _| {
        calls += 1;
        RootCallResult::Returned {
            executor,
            yielded: ExecutorYield::Idle,
        }
    })
    .unwrap();
    assert_eq!(calls, 1);
}

#[test]
fn uncertain_root_to_worker_call_keeps_run_arrival_and_reply_without_replay() {
    let mut replies = RootReplySlotTable::new(1).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let held = Held::new(reply);
    let key = held.key();
    let (mut table, run) = one_idle_executor();
    let executor = run.executor();
    let mut turn = match RootExecutorTurn::new(run, key, reply, held) {
        Ok(turn) => turn,
        Err(_) => panic!("valid retained root arrival"),
    };
    let mut calls = 0;
    assert!(turn
        .try_call(key, reply, ExecutorResume::Unrouted, |_, _, _| {
            calls += 1;
            RootCallResult::Indeterminate(0xdead)
        })
        .is_err());
    assert!(turn
        .try_call(key, reply, ExecutorResume::Unrouted, |_, _, _| {
            calls += 1;
            RootCallResult::Returned {
                executor,
                yielded: ExecutorYield::Idle,
            }
        })
        .is_err());
    assert_eq!(calls, 1, "uncertain physical Call cannot be retried");
    assert_eq!(turn.held_payload().key(), key);
    assert_eq!(turn.reply_identity(), reply);
    assert_eq!(table.running(), Some(executor));
    // A fabricated or later Reply ACK cannot release a run whose root-to-worker Call is unknown.
    let ack = unsafe { RootCallSettlement::reply_acknowledged_from_native(key, reply) };
    assert!(turn.finish(&mut table, Some(ack)).is_err());
}

#[test]
fn exact_reply_ack_is_required_before_idle_yield_releases_the_run() {
    let mut replies = RootReplySlotTable::new(2).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let foreign_reply = replies.insert_used(93).unwrap();
    let held = Held::new(reply);
    let key = held.key();
    let (mut table, run) = one_idle_executor();
    let executor = run.executor();
    let mut turn = match RootExecutorTurn::new(run, key, reply, held) {
        Ok(turn) => turn,
        Err(_) => panic!("valid retained root arrival"),
    };
    turn.try_call(key, reply, ExecutorResume::Unrouted, |_, _, _| {
        RootCallResult::Returned {
            executor,
            yielded: ExecutorYield::Idle,
        }
    })
    .unwrap();
    let wrong = unsafe { RootCallSettlement::reply_acknowledged_from_native(key, foreign_reply) };
    let (error, retained) = match turn.finish(&mut table, Some(wrong)) {
        Err(refused) => refused,
        Ok(_) => panic!("foreign Reply acknowledgement must be refused"),
    };
    assert_eq!(retained.held_payload().key(), key);
    assert_eq!(table.running(), Some(executor));
    let _ = error;
    let ack = unsafe { RootCallSettlement::reply_acknowledged_from_native(key, reply) };
    let completion = match retained.finish(&mut table, Some(ack)) {
        Ok(completion) => completion,
        Err(_) => panic!("matching Reply ACK must release the turn"),
    };
    let RootTurnCompletion::Replied { token, payload } = completion else {
        panic!("exact ACK must release the replied arrival")
    };
    assert_eq!(payload.key(), key);
    assert_eq!(table.running(), None);
    assert_eq!(
        table
            .resume(token, ExecutorResume::Unrouted)
            .unwrap()
            .executor(),
        executor
    );
}

#[test]
fn parked_yield_requires_exact_durable_park_for_the_same_wait() {
    let mut replies = RootReplySlotTable::new(1).unwrap();
    let reply = replies.insert_used(83).unwrap();
    let held = Held::new(reply);
    let key = held.key();
    let (wait, stale_dispatch) = two_waits_same_route();
    let (mut table, run) = one_idle_executor();
    let executor = run.executor();
    let mut turn = match RootExecutorTurn::new(run, key, reply, held) {
        Ok(turn) => turn,
        Err(_) => panic!("valid retained root arrival"),
    };
    turn.try_call(key, reply, ExecutorResume::Unrouted, |_, _, _| {
        RootCallResult::Returned {
            executor,
            yielded: ExecutorYield::Parked(wait),
        }
    })
    .unwrap();
    let wrong =
        unsafe { RootCallSettlement::durably_parked_from_native(key, reply, stale_dispatch) };
    let (_, retained) = match turn.finish(&mut table, Some(wrong)) {
        Err(refused) => refused,
        Ok(_) => panic!("foreign route or dispatch cannot park this arrival"),
    };
    assert_eq!(table.running(), Some(executor));
    assert_eq!(retained.held_payload().key(), key);
    let park = unsafe { RootCallSettlement::durably_parked_from_native(key, reply, wait) };
    let completion = match retained.finish(&mut table, Some(park)) {
        Ok(completion) => completion,
        Err(_) => panic!("matching durable Park must release the run"),
    };
    let RootTurnCompletion::Parked { token, owner } = completion else {
        panic!("matching park must keep the arrival owned")
    };
    assert_eq!(owner.held_payload().key(), key);
    assert_eq!(owner.reply_identity(), reply);
    assert_eq!(table.running(), None);
    assert_eq!(
        table.state(executor),
        Ok(nt_component_suspension::ExecutorState::Parked(wait))
    );
    let _ = token;
}
