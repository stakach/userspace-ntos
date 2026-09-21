use super::*;
use crate::{
    IngressReplyObservation as Observation, IpcBufferSnapshot, LaneBinding, LanePhase,
    ReceivedMessage,
};

type Lanes = ComponentSuspensionLanes<(), (), ()>;
const FAULT_INFO: u64 = (6 << 12) | 4;
const WORDS: [u64; 4] = [0x1000, 0x2000, 0, 7];

fn message(badge: u64, info: u64) -> ReceivedMessage {
    ReceivedMessage::new(
        badge,
        info,
        WORDS,
        IpcBufferSnapshot::capture(|i| i as u64 + 100),
    )
}

fn setup(
    info: u64,
    wrong_badge: bool,
) -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    IngressReceiver<ReceivedMessage>,
) {
    setup_capacity(info, wrong_badge, 1)
}

fn setup_capacity(
    info: u64,
    wrong_badge: bool,
    capacity: usize,
) -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    IngressReceiver<ReceivedMessage>,
) {
    let mut lanes = Lanes::new(1, 2);
    let mut peers = PeerRegistry::new(20, 1);
    let (lane, mut ticket) = lanes
        .allocate_shared_staged(
            &mut peers,
            1,
            2,
            LaneBinding {
                executor_id: 10,
                receive_endpoint: 20,
                reply_object: 30,
            },
        )
        .unwrap();
    let route = peers.publish_lane(&mut ticket, 1, 2, &lanes).unwrap();
    lanes
        .begin_startup(lane, 30, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free))
        .unwrap();
    let mut receiver = IngressReceiver::new(20, 40, capacity).unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .unwrap();
    receiver
        .capture(message(if wrong_badge { 0 } else { route.badge() }, info))
        .ok()
        .unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain(
            &lanes,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            bound,
        )
        .ok()
        .unwrap();
    (lanes, peers, route, receiver)
}

fn bound(tcb: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!(tcb, 10);
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn free(tcb: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!(tcb, 10);
    Ok(ReplyBindingObservation::Free)
}

fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("refusal must precede query")
}

fn no_invoke(_: u64, _: [u64; 4]) -> Observation {
    panic!("refusal must precede native service")
}

fn fenced(lanes: &Lanes, route: PeerRoute) {
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(route.identity().lane));
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        30
    );
    assert!(lanes
        .active_dispatch_identity(route.identity().lane)
        .is_err());
}

#[test]
fn two_faults_recycle_replies_before_genuine_ready_releases_startup() {
    let (mut lanes, mut peers, route, mut receiver) = setup(FAULT_INFO, false);
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    for reply in [40, 41] {
        assert_eq!(
            receiver.service_startup_fault(route, reply, &lanes, &peers, bound, |actual, words| {
                assert_eq!(actual, reply);
                assert_eq!(words, WORDS);
                Observation::Acknowledged
            }),
            Ok(Observation::Acknowledged)
        );
        fenced(&lanes, route);
        assert_eq!(receiver.available(), 0);
        assert_eq!(peers.state(route).unwrap().1, 1);
        let (spare, payload) = receiver
            .finish_startup_fault(route, reply, &lanes, &mut peers, free)
            .ok()
            .unwrap();
        assert_eq!(payload.info(), FAULT_INFO);
        assert_eq!(payload.word(3), Some(7));
        assert_eq!(receiver.available(), 1);
        assert_eq!(peers.state(route).unwrap().1, 0);
        pool.insert(spare, &receiver, &lanes, |_| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .ok()
        .unwrap();
        assert!(pool.excludes_reply(reply));
        fenced(&lanes, route);
        receiver
            .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
            .unwrap();
        let info = if reply == 40 {
            FAULT_INFO
        } else {
            (123 << 12) | 5
        };
        receiver.capture(message(route.badge(), info)).ok().unwrap();
        receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        pool.retain(
            &mut receiver,
            &lanes,
            &mut peers,
            route.badge(),
            |_| Ok::<_, u8>(ReplyBindingObservation::Free),
            bound,
        )
        .unwrap();
    }
    let mut publication = None;
    receiver
        .ready_from_message(
            route,
            40,
            123,
            &mut lanes,
            &peers,
            &mut publication,
            |words| {
                assert_eq!(words, [0x1000, 0x2000, 0, 7, 105]);
                Some(words)
            },
            |tcb, reply| {
                if reply == 30 {
                    free(tcb, reply)
                } else {
                    bound(tcb, reply)
                }
            },
        )
        .unwrap();
    assert!(publication.is_some());
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.running(), None);
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        30
    );
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn uncertain_mapping_or_reply_prevents_replay_and_finish() {
    let (lanes, mut peers, route, mut receiver) = setup(FAULT_INFO, false);
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, bound, |reply, words| {
            assert_eq!(reply, 40);
            assert_eq!(words, WORDS);
            Observation::Indeterminate
        }),
        Ok(Observation::Indeterminate)
    );
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, no_query, no_invoke),
        Err(StartupFaultError::NotHeld)
    );
    assert!(matches!(
        receiver.finish_startup_fault(route, 40, &lanes, &mut peers, no_query),
        Err(StartupFaultError::NotAcknowledged)
    ));
    fenced(&lanes, route);
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert_eq!(
        receiver
            .store
            .stored_reply(route, 40)
            .unwrap()
            .message()
            .word(1),
        Some(0x2000)
    );
}

#[test]
fn proven_no_effects_keeps_fault_held_for_retry() {
    let (lanes, mut peers, route, mut receiver) = setup(FAULT_INFO, false);
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, bound, |_, _| {
            Observation::NoEffects
        }),
        Ok(Observation::NoEffects)
    );
    assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
    assert!(matches!(
        receiver.finish_startup_fault(route, 40, &lanes, &mut peers, no_query),
        Err(StartupFaultError::NotAcknowledged)
    ));
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, bound, |_, _| {
            Observation::Acknowledged
        }),
        Ok(Observation::Acknowledged)
    );
    fenced(&lanes, route);
}

#[test]
fn malformed_fault_framing_and_badge_refuse_before_effects() {
    for (info, wrong_badge) in [
        (6 << 12, false),
        ((6 << 12) | 3, false),
        ((6 << 12) | 5, false),
        ((3 << 12) | 4, false),
        (FAULT_INFO | 128, false),
        (FAULT_INFO | (1 << 9), false),
        (FAULT_INFO, true),
    ] {
        let (lanes, mut peers, route, mut receiver) = setup(info, wrong_badge);
        assert_eq!(
            receiver.service_startup_fault(route, 40, &lanes, &peers, no_query, no_invoke),
            Err(StartupFaultError::InvalidMessage)
        );
        assert!(matches!(
            receiver.finish_startup_fault(route, 40, &lanes, &mut peers, no_query),
            Err(StartupFaultError::InvalidMessage)
        ));
        fenced(&lanes, route);
        assert_eq!(receiver.available(), 0);
        assert_eq!(peers.state(route).unwrap().1, 1);
    }
}

#[test]
fn canonical_reply_foreign_owner_and_completed_startup_are_rejected() {
    let (mut lanes, peers, route, mut receiver) = setup(FAULT_INFO, false);
    assert_eq!(
        receiver.service_startup_fault(route, 30, &lanes, &peers, no_query, no_invoke),
        Err(StartupFaultError::WrongOwner)
    );
    let (foreign_lanes, foreign_peers, foreign_route, _) = setup(FAULT_INFO, false);
    assert_eq!(
        receiver.service_startup_fault(route, 40, &foreign_lanes, &peers, no_query, no_invoke),
        Err(StartupFaultError::WrongOwner)
    );
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &foreign_peers, no_query, no_invoke),
        Err(StartupFaultError::WrongOwner)
    );
    assert_eq!(
        receiver.service_startup_fault(foreign_route, 40, &lanes, &peers, no_query, no_invoke),
        Err(StartupFaultError::WrongOwner)
    );
    lanes
        .complete_startup(route.identity().lane, 30, bound)
        .unwrap();
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, no_query, no_invoke),
        Err(StartupFaultError::WrongOwner)
    );
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn failed_or_nonbound_query_preserves_unserviced_fault() {
    let (lanes, peers, route, mut receiver) = setup(FAULT_INFO, false);
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, |_, _| Err(9u8), no_invoke),
        Err(StartupFaultError::Query(9))
    );
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, free, no_invoke),
        Err(StartupFaultError::BindingMismatch)
    );
    assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
    fenced(&lanes, route);
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn finish_query_failure_keeps_acknowledged_call_without_replaying_service() {
    let (lanes, mut peers, route, mut receiver) = setup(FAULT_INFO, false);
    receiver
        .service_startup_fault(route, 40, &lanes, &peers, bound, |_, _| {
            Observation::Acknowledged
        })
        .unwrap();
    assert!(matches!(
        receiver.finish_startup_fault(route, 40, &lanes, &mut peers, |_, _| Err(8u8)),
        Err(StartupFaultError::Query(8))
    ));
    assert!(matches!(
        receiver.finish_startup_fault(route, 40, &lanes, &mut peers, bound),
        Err(StartupFaultError::BindingMismatch)
    ));
    assert!(receiver
        .store
        .stored_reply(route, 40)
        .unwrap()
        .is_acknowledged());
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert_eq!(
        receiver.service_startup_fault(route, 40, &lanes, &peers, no_query, no_invoke),
        Err(StartupFaultError::NotHeld)
    );
    let (spare, payload) = receiver
        .finish_startup_fault(route, 40, &lanes, &mut peers, free)
        .ok()
        .unwrap();
    assert_eq!(spare.reply(), 40);
    assert_eq!(payload.word(0), Some(0x1000));
    assert_eq!(receiver.available(), 1);
    assert_eq!(peers.state(route).unwrap().1, 0);
    fenced(&lanes, route);
}

#[test]
fn pool_query_refusal_preserves_pending_owner_for_recovery() {
    let (lanes, mut peers, route, mut receiver) = setup(FAULT_INFO, false);
    receiver
        .service_startup_fault(route, 40, &lanes, &peers, bound, |_, _| {
            Observation::Acknowledged
        })
        .unwrap();
    let (spare, _) = receiver
        .finish_startup_fault(route, 40, &lanes, &mut peers, free)
        .ok()
        .unwrap();
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    let mut pending = Some(spare);
    assert_eq!(
        pool.insert_pending(&mut pending, &receiver, &lanes, |_| Err(6u8)),
        Err(crate::ReplyPoolError::Query(6))
    );
    assert_eq!(pending.as_ref().unwrap().reply(), 40);
    assert!(pending.as_ref().unwrap().is_ready());
    assert!(pool.is_empty());
    pool.insert_pending(&mut pending, &receiver, &lanes, |_| {
        Ok::<_, u8>(ReplyBindingObservation::Free)
    })
    .unwrap();
    assert!(pending.is_none());
    assert!(pool.excludes_reply(40));
    fenced(&lanes, route);
}

#[test]
fn ready_waits_until_acknowledged_interim_fault_is_finished() {
    let (mut lanes, mut peers, route, mut receiver) = setup_capacity(FAULT_INFO, false, 2);
    receiver
        .service_startup_fault(route, 40, &lanes, &peers, bound, |_, _| {
            Observation::Acknowledged
        })
        .unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .unwrap();
    receiver
        .capture(message(route.badge(), (123 << 12) | 5))
        .ok()
        .unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain(
            &lanes,
            ComponentIngress::new(20, 42).unwrap(),
            &mut peers,
            route.badge(),
            bound,
        )
        .ok()
        .unwrap();
    assert_eq!(peers.state(route).unwrap().1, 2);
    let mut publication: Option<[u64; 5]> = None;
    assert!(receiver
        .ready_from_message(
            route,
            41,
            123,
            &mut lanes,
            &peers,
            &mut publication,
            |_| panic!("unreleased fault must block decoding"),
            no_query
        )
        .is_err());
    assert!(publication.is_none());
    assert!(receiver
        .store
        .stored_reply(route, 40)
        .unwrap()
        .is_acknowledged());
    assert!(receiver.store.stored_reply(route, 41).unwrap().is_held());
    assert_eq!(receiver.available(), 0);
    fenced(&lanes, route);
    let (spare, _) = receiver
        .finish_startup_fault(route, 40, &lanes, &mut peers, free)
        .ok()
        .unwrap();
    let mut pending = Some(spare);
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    pool.insert_pending(&mut pending, &receiver, &lanes, |_| {
        Ok::<_, u8>(ReplyBindingObservation::Free)
    })
    .unwrap();
    assert!(pending.is_none());
    assert_eq!(peers.state(route).unwrap().1, 1);
    receiver
        .ready_from_message(
            route,
            41,
            123,
            &mut lanes,
            &peers,
            &mut publication,
            Some,
            |tcb, reply| {
                if reply == 30 {
                    free(tcb, reply)
                } else {
                    bound(tcb, reply)
                }
            },
        )
        .unwrap();
    assert_eq!(publication, Some([0x1000, 0x2000, 0, 7, 105]));
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.running(), None);
    assert!(pool.excludes_reply(40));
    assert!(receiver.store.stored_reply(route, 41).unwrap().is_held());
}
