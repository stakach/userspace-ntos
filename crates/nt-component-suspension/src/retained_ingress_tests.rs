use super::*;
use crate::peer_registry::{PeerIdentity, PeerPhase};
use crate::{IngressObservation, IngressReceiveDisposition, LaneBinding};

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn setup() -> (Lanes, PeerRegistry, PeerRoute) {
    let mut lanes = Lanes::new(2, 2);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 10,
            receive_endpoint: 20,
            reply_object: 30,
        })
        .unwrap();
    let mut peers = PeerRegistry::new(20, 2);
    let mut registration = peers
        .stage(PeerIdentity {
            domain: 1,
            domain_generation: 1,
            executor: 10,
            lane,
        })
        .unwrap();
    let route = peers.publish(&mut registration).unwrap();
    (lanes, peers, route)
}

fn receive(lanes: &Lanes, ingress: &mut ComponentIngress<u64>, message: u64) {
    let mut attempt = lanes.begin_ingress_receive(ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut attempt, IngressObservation::Call(message))
        .is_ok());
}

fn retain(
    lanes: &Lanes,
    ingress: &mut ComponentIngress<u64>,
    reply: u64,
    peers: &mut PeerRegistry,
    route: PeerRoute,
) -> RetainedIngress<u64> {
    lanes
        .retain_peer_ingress(
            ingress,
            ComponentIngress::new(20, reply).unwrap(),
            peers,
            route.badge(),
            |executor, old_reply| {
                assert_eq!(executor, route.identity().executor);
                assert_ne!(old_reply, reply);
                Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
            },
        )
        .ok()
        .unwrap()
}

#[test]
fn two_calls_finish_out_of_order_while_peer_retires() {
    let (lanes, mut peers, route) = setup();
    let mut second_domain = Lanes::new(1, 2);
    let second_lane = second_domain
        .allocate(LaneBinding {
            executor_id: 11,
            receive_endpoint: 20,
            reply_object: 31,
        })
        .unwrap();
    let mut registration = peers.stage_lane(2, 1, &second_domain, second_lane).unwrap();
    let second_route = peers
        .publish_lane(&mut registration, 2, 1, &second_domain)
        .unwrap();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    receive(&lanes, &mut ingress, 100);
    let mut first = retain(&lanes, &mut ingress, 41, &mut peers, route);
    peers.begin_retirement(route).unwrap();
    receive(&lanes, &mut ingress, 200);
    let mut second = retain(&second_domain, &mut ingress, 42, &mut peers, second_route);
    assert_eq!(first.reply(), 40);
    assert_eq!(second.reply(), 41);
    assert_eq!(ingress.reply(), 42);
    assert_eq!(peers.state(route), Ok((PeerPhase::Retiring, 1)));
    assert_eq!(peers.state(second_route), Ok((PeerPhase::Active, 1)));
    assert_eq!(peers.finish_retirement(route), Err(PeerError::RetainedWork));
    let mut second_attempt = second.begin_reply().unwrap();
    second
        .observe_reply(&mut second_attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
    let (mut reusable, payload) = second.finish(&mut peers).ok().unwrap();
    assert_eq!(payload, 200);
    assert_eq!(peers.state(route), Ok((PeerPhase::Retiring, 1)));
    assert_eq!(peers.state(second_route), Ok((PeerPhase::Active, 0)));
    assert!(lanes.begin_ingress_receive(&mut reusable).is_ok());
    let mut first_attempt = first.begin_reply().unwrap();
    first
        .observe_reply(&mut first_attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
    assert_eq!(first.finish(&mut peers).ok().unwrap().1, 100);
    peers.finish_retirement(route).unwrap();
}

#[test]
fn late_retiring_arrival_is_retained_until_acknowledged() {
    let (lanes, mut peers, route) = setup();
    peers.begin_retirement(route).unwrap();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    receive(&lanes, &mut ingress, 100);
    let mut call = retain(&lanes, &mut ingress, 41, &mut peers, route);
    assert_eq!(peers.state(route), Ok((PeerPhase::Retiring, 1)));
    assert_eq!(peers.finish_retirement(route), Err(PeerError::RetainedWork));
    let mut attempt = call.begin_reply().unwrap();
    call.observe_reply(&mut attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
    assert_eq!(call.finish(&mut peers).ok().unwrap().1, 100);
    peers.finish_retirement(route).unwrap();
}

#[test]
fn completion_requires_ack_and_preserves_owner_on_wrong_registry() {
    let (lanes, mut peers, route) = setup();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    receive(&lanes, &mut ingress, 100);
    let call = retain(&lanes, &mut ingress, 41, &mut peers, route);
    let (error, mut call) = call.finish(&mut peers).err().unwrap();
    assert_eq!(error, RetainedIngressError::NotAcknowledged);
    let mut attempt = call.begin_reply().unwrap();
    call.observe_reply(&mut attempt, IngressReplyObservation::Indeterminate)
        .unwrap();
    assert_eq!(call.begin_reply().unwrap_err(), IngressError::NotReady);
    call.observe_reply(&mut attempt, IngressReplyObservation::NoEffects)
        .unwrap();
    assert_eq!(
        call.observe_reply(&mut attempt, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    let mut ack = call.begin_reply().unwrap();
    call.observe_reply(&mut ack, IngressReplyObservation::Acknowledged)
        .unwrap();
    assert_eq!(
        call.observe_reply(&mut ack, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    let (error, call) = call.finish(&mut PeerRegistry::new(20, 2)).err().unwrap();
    assert_eq!(error, RetainedIngressError::Peer(PeerError::WrongOwner));
    assert_eq!(*call.message(), 100);
    assert_eq!(call.route(), route);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    assert_eq!(call.finish(&mut peers).ok().unwrap().1, 100);
}

#[test]
fn foreign_reply_attempt_does_not_consume_either_call() {
    let (lanes, mut peers, route) = setup();
    let mut second_domain = Lanes::new(1, 2);
    let second_lane = second_domain
        .allocate(LaneBinding {
            executor_id: 11,
            receive_endpoint: 20,
            reply_object: 31,
        })
        .unwrap();
    let mut registration = peers.stage_lane(2, 1, &second_domain, second_lane).unwrap();
    let second_route = peers
        .publish_lane(&mut registration, 2, 1, &second_domain)
        .unwrap();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    receive(&lanes, &mut ingress, 100);
    let mut first = retain(&lanes, &mut ingress, 41, &mut peers, route);
    receive(&lanes, &mut ingress, 200);
    let mut second = retain(&second_domain, &mut ingress, 42, &mut peers, second_route);
    let mut a = first.begin_reply().unwrap();
    let mut b = second.begin_reply().unwrap();
    assert_eq!(
        second.observe_reply(&mut a, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    assert_eq!(peers.state(second_route), Ok((PeerPhase::Active, 1)));
    first
        .observe_reply(&mut a, IngressReplyObservation::Acknowledged)
        .unwrap();
    second
        .observe_reply(&mut b, IngressReplyObservation::Acknowledged)
        .unwrap();
    assert_eq!(first.finish(&mut peers).ok().unwrap().1, 100);
    assert_eq!(second.finish(&mut peers).ok().unwrap().1, 200);
}

#[test]
fn failed_queries_preserve_original_and_replacement_without_retention() {
    for observation in [
        Ok(ReplyBindingObservation::Free),
        Ok(ReplyBindingObservation::Offered),
        Ok(ReplyBindingObservation::BoundElsewhere),
        Err(7u8),
    ] {
        let (lanes, mut peers, route) = setup();
        let mut ingress = ComponentIngress::new(20, 40).unwrap();
        receive(&lanes, &mut ingress, 100);
        let (error, replacement) = lanes
            .retain_peer_ingress(
                &mut ingress,
                ComponentIngress::new(20, 41).unwrap(),
                &mut peers,
                route.badge(),
                |executor, reply| {
                    assert_eq!((executor, reply), (10, 40));
                    observation
                },
            )
            .err()
            .unwrap();
        assert_eq!(
            error,
            match observation {
                Err(e) => RetainedIngressError::Query(e),
                _ => RetainedIngressError::BindingMismatch,
            }
        );
        assert_eq!(replacement.reply(), 41);
        assert_eq!(ingress.message(), Some(&100));
        assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    }
}

#[test]
fn unresolved_or_no_call_cannot_be_retained() {
    let (lanes, mut peers, route) = setup();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    let mut attempt = lanes.begin_ingress_receive(&mut ingress).unwrap();
    ingress.capture_receive(&mut attempt, 100).unwrap();
    for unresolved in [true, false] {
        if !unresolved {
            assert_eq!(
                ingress.resolve_receive(&mut attempt, IngressReceiveDisposition::NoCall),
                Ok(Some(100))
            );
        }
        let (error, replacement) = lanes
            .retain_peer_ingress(
                &mut ingress,
                ComponentIngress::new(20, 41).unwrap(),
                &mut peers,
                route.badge(),
                |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
            )
            .err()
            .unwrap();
        assert_eq!(error, RetainedIngressError::Ingress(IngressError::NotReady));
        assert_eq!(replacement.reply(), 41);
        assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    }
}

#[test]
fn invalid_replacements_roll_back_retention() {
    for (endpoint, reply, held, expected) in [
        (20, 40, false, IngressError::InvalidBinding),
        (21, 41, false, IngressError::InvalidBinding),
        (20, 30, false, IngressError::ReplyInUse),
        (20, 41, true, IngressError::NotReady),
    ] {
        let (lanes, mut peers, route) = setup();
        let mut ingress = ComponentIngress::new(20, 40).unwrap();
        receive(&lanes, &mut ingress, 100);
        let mut replacement = ComponentIngress::new(endpoint, reply).unwrap();
        if held {
            receive(&lanes, &mut replacement, 200);
        }
        let (error, replacement) = lanes
            .retain_peer_ingress(
                &mut ingress,
                replacement,
                &mut peers,
                route.badge(),
                |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
            )
            .err()
            .unwrap();
        assert_eq!(error, RetainedIngressError::Ingress(expected));
        assert_eq!(replacement.reply(), reply);
        assert_eq!(replacement.message(), if held { Some(&200) } else { None });
        assert_eq!(ingress.message(), Some(&100));
        assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    }
}

#[test]
fn unknown_or_wrong_endpoint_never_queries() {
    let (lanes, mut peers, route) = setup();
    for (endpoint, badge, expected) in [
        (20, 0, RetainedIngressError::UnknownPeer),
        (21, route.badge(), RetainedIngressError::WrongEndpoint),
    ] {
        let mut ingress = ComponentIngress::new(endpoint, 40).unwrap();
        receive(&lanes, &mut ingress, 100);
        let (error, _) = lanes
            .retain_peer_ingress(
                &mut ingress,
                ComponentIngress::new(endpoint, 41).unwrap(),
                &mut peers,
                badge,
                |_, _| -> Result<_, u8> { panic!("must not query unknown owner") },
            )
            .err()
            .unwrap();
        assert_eq!(error, expected);
        assert_eq!(ingress.message(), Some(&100));
    }
}

#[test]
fn complete_message_survives_query_buffer_reuse_and_ack() {
    use crate::{IpcBufferSnapshot, ReceivedMessage, IPC_BUFFER_WORDS};
    let (lanes, mut peers, route) = setup();
    let mut buffer = [77; IPC_BUFFER_WORDS];
    let message = ReceivedMessage::new(
        route.badge(),
        120,
        [1, 2, 3, 4],
        IpcBufferSnapshot::capture(|index| buffer[index]),
    );
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    let mut receive = lanes.begin_ingress_receive(&mut ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut receive, IngressObservation::Call(message))
        .is_ok());
    let badge = ingress.message().unwrap().badge();
    let mut call = lanes
        .retain_peer_ingress(
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            badge,
            |executor, reply| {
                assert_eq!((executor, reply), (10, 40));
                buffer.fill(99);
                Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
            },
        )
        .ok()
        .unwrap();
    assert_eq!(call.message().word(119), Some(77));
    assert_eq!(call.retention().route(), Some(route));
    let mut ack = call.begin_reply().unwrap();
    call.observe_reply(&mut ack, IngressReplyObservation::Acknowledged)
        .unwrap();
    let (_, message) = call.finish(&mut peers).ok().unwrap();
    assert_eq!(message.word(0), Some(1));
    assert_eq!(message.word(119), Some(77));
    message.restore_buffer(|index, word| buffer[index] = word);
    assert_eq!(buffer, [77; IPC_BUFFER_WORDS]);
}

#[test]
fn staged_peer_is_not_a_received_call_route() {
    let (lanes, mut peers, route) = setup();
    let mut staged = peers
        .stage(PeerIdentity {
            domain: 2,
            domain_generation: 1,
            executor: 11,
            lane: route.identity().lane,
        })
        .unwrap();
    let staged_route = staged.route().unwrap();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    receive(&lanes, &mut ingress, 100);
    let (error, replacement) = lanes
        .retain_peer_ingress(
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            staged_route.badge(),
            |_, _| -> Result<_, u8> { panic!("unpublished peer cannot authenticate a call") },
        )
        .err()
        .unwrap();
    assert_eq!(error, RetainedIngressError::UnknownPeer);
    assert_eq!(replacement.reply(), 41);
    assert_eq!(ingress.message(), Some(&100));
    assert_eq!(peers.state(staged_route), Ok((PeerPhase::Staged, 0)));
    peers.abort(&mut staged).unwrap();
}

#[test]
fn physical_execution_refusal_rolls_back_only_new_retention() {
    let (mut lanes, mut peers, route) = setup();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    receive(&lanes, &mut ingress, 100);
    lanes.begin_dispatch(route.identity().lane, 30).unwrap();
    let (error, replacement) = lanes
        .retain_peer_ingress(
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .err()
        .unwrap();
    assert_eq!(
        error,
        RetainedIngressError::Ingress(IngressError::ExecutionBusy)
    );
    assert_eq!(replacement.reply(), 41);
    assert_eq!(ingress.message(), Some(&100));
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    assert_eq!(lanes.running(), Some(route.identity().lane));
}
