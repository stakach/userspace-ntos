use super::*;
use crate::{IpcBufferSnapshot, LaneBinding, LanePhase, ReceivedMessage};

type Lanes = ComponentSuspensionLanes<(), (), ()>;
const LABEL: u64 = 123;
const WORDS: [u64; 5] = [11, 22, 33, 44, 55];

fn setup(
    info: u64,
    wrong_badge: bool,
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
    let mut receiver = IngressReceiver::new(20, 40, 1).unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .unwrap();
    receiver
        .capture(ReceivedMessage::new(
            if wrong_badge { 0 } else { route.badge() },
            info,
            [WORDS[0], WORDS[1], WORDS[2], WORDS[3]],
            IpcBufferSnapshot::capture(|index| if index == 5 { WORDS[4] } else { 999 }),
        ))
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
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    (lanes, peers, route, receiver)
}

fn query(tcb: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!(tcb, 10);
    Ok(match reply {
        30 => ReplyBindingObservation::Free,
        40 => ReplyBindingObservation::BoundToTarget,
        _ => panic!("unexpected Reply"),
    })
}

fn unchanged(
    lanes: &Lanes,
    peers: &PeerRegistry,
    route: PeerRoute,
    receiver: &IngressReceiver<ReceivedMessage>,
) {
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(route.identity().lane));
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        30
    );
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
}

#[test]
fn fifth_buffer_word_is_published_before_first_dispatch_swaps_reply() {
    let (mut lanes, peers, route, mut receiver) = setup((LABEL << 12) | 5, false);
    let mut publication = None;
    receiver
        .ready_from_message(
            route,
            40,
            LABEL,
            &mut lanes,
            &peers,
            &mut publication,
            |words| {
                assert_eq!(words, WORDS);
                Some(words)
            },
            query,
        )
        .unwrap();
    assert_eq!(publication, Some(WORDS));
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.running(), None);
    assert_eq!(
        lanes.active_dispatch_identity(route.identity().lane),
        Ok(None)
    );
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        30
    );
    assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    let dispatch = pool
        .admit(&mut receiver, route, &mut lanes, &peers, 1, 2, query)
        .unwrap();
    assert_eq!(
        lanes.active_dispatch_identity(route.identity().lane),
        Ok(Some(dispatch))
    );
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        40
    );
    assert!(pool.excludes_reply(30));
    assert_eq!(receiver.available(), 0);
}

#[test]
fn malformed_ready_shape_and_badge_refuse_before_decode_or_query() {
    for (info, wrong_badge, label) in [
        (LABEL << 12, false, LABEL),
        ((LABEL << 12) | 4, false, LABEL),
        ((LABEL << 12) | 6, false, LABEL),
        ((LABEL << 12) | 5 | 128, false, LABEL),
        ((LABEL << 12) | 5, true, LABEL),
        ((LABEL << 12) | 5, false, 0),
        ((LABEL << 12) | 5, false, u64::MAX),
    ] {
        let (mut lanes, peers, route, mut receiver) = setup(info, wrong_badge);
        let mut publication: Option<[u64; 5]> = None;
        assert_eq!(
            receiver.ready_from_message(
                route,
                40,
                label,
                &mut lanes,
                &peers,
                &mut publication,
                |_| panic!("invalid framing"),
                |_, _| -> Result<_, u8> { panic!("invalid framing") }
            ),
            Err(StartupReadyError::InvalidMessage)
        );
        assert_eq!(publication, None);
        unchanged(&lanes, &peers, route, &receiver);
    }
}

#[test]
fn decoder_and_binding_failures_preserve_startup_and_publication_slot() {
    let (mut lanes, peers, route, mut receiver) = setup((LABEL << 12) | 5, false);
    let mut publication: Option<[u64; 5]> = None;
    assert_eq!(
        receiver.ready_from_message(
            route,
            40,
            LABEL,
            &mut lanes,
            &peers,
            &mut publication,
            |_| None,
            |_, _| -> Result<_, u8> { panic!("decode failed") }
        ),
        Err(StartupReadyError::InvalidPublication)
    );
    for (failed_reply, result, expected) in [
        (30, Err(7u8), StartupReadyError::Query(7)),
        (40, Err(8u8), StartupReadyError::Query(8)),
        (
            30,
            Ok(ReplyBindingObservation::BoundToTarget),
            StartupReadyError::OldReplyNotFree,
        ),
        (
            40,
            Ok(ReplyBindingObservation::Free),
            StartupReadyError::ReadyReplyNotBound,
        ),
    ] {
        assert_eq!(
            receiver.ready_from_message(
                route,
                40,
                LABEL,
                &mut lanes,
                &peers,
                &mut publication,
                Some,
                |tcb, reply| if reply == failed_reply {
                    result
                } else {
                    query(tcb, reply)
                }
            ),
            Err(expected)
        );
        assert_eq!(publication, None);
        unchanged(&lanes, &peers, route, &receiver);
    }
    publication = Some([777; 5]);
    assert_eq!(
        receiver.ready_from_message(
            route,
            40,
            LABEL,
            &mut lanes,
            &peers,
            &mut publication,
            |_| panic!("already published"),
            |_, _| -> Result<_, u8> { panic!("already published") }
        ),
        Err(StartupReadyError::AlreadyPublished)
    );
    assert_eq!(publication, Some([777; 5]));
    unchanged(&lanes, &peers, route, &receiver);
}
