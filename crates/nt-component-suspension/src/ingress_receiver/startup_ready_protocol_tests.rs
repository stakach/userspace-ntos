use super::*;

#[test]
fn readiness_preserves_startup_owner_of_another_pending_receive() {
    for stage in 0..3 {
        let (mut lanes, mut peers, route, mut receiver) =
            setup_with_capacity((LABEL << 12) | 5, false, 2);
        receiver
            .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
            .unwrap();
        if stage >= 1 {
            receiver
                .capture(ReceivedMessage::new(
                    route.badge(),
                    6 << 12 | 4,
                    [0; 4],
                    IpcBufferSnapshot::capture(|_| 0),
                ))
                .ok()
                .unwrap();
        }
        if stage == 2 {
            receiver
                .resolve(IngressReceiveDisposition::Call)
                .ok()
                .unwrap();
        }
        let phase = receiver.phase();
        let mut publication = None::<[u64; 5]>;
        assert_eq!(
            receiver.ready_from_message(
                route,
                40,
                LABEL,
                &mut lanes,
                &peers,
                &mut publication,
                |_| panic!("pending receive must reject before decoding"),
                |_, _| -> Result<ReplyBindingObservation, u8> {
                    panic!("pending receive must reject before query")
                }
            ),
            Err(StartupReadyError::WrongOwner)
        );
        assert!(publication.is_none());
        assert_eq!(receiver.phase(), phase);
        assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Starting));
        assert_eq!(lanes.running(), Some(route.identity().lane));
        assert_eq!(peers.state(route).unwrap().1, 1);
        assert_eq!(receiver.available(), 0);
        if stage == 2 {
            receiver
                .retain(
                    &lanes,
                    ComponentIngress::new(20, 42).unwrap(),
                    &mut peers,
                    route.badge(),
                    |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
                )
                .ok()
                .unwrap();
            assert!(receiver.phase().is_none());
            assert_eq!(peers.state(route).unwrap().1, 2);
        } else {
            if stage == 0 {
                receiver
                    .capture(ReceivedMessage::new(
                        0,
                        0,
                        [0; 4],
                        IpcBufferSnapshot::capture(|_| 0),
                    ))
                    .ok()
                    .unwrap();
            }
            receiver
                .resolve(IngressReceiveDisposition::NoCall)
                .ok()
                .unwrap();
            receiver
                .ready_from_message(
                    route,
                    40,
                    LABEL,
                    &mut lanes,
                    &peers,
                    &mut publication,
                    Some,
                    query,
                )
                .unwrap();
            assert_eq!(publication, Some(WORDS));
            assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
        }
    }
}

#[test]
fn four_word_protocol_validates_independent_identity_before_publication() {
    let (mut lanes, peers, route, mut receiver) = setup((LABEL << 12) | 4, false);
    let expected = [11, 22, 33, 44];
    let mut publication = None;
    receiver
        .ready_protocol_from_message(
            route,
            40,
            LABEL,
            &mut lanes,
            &peers,
            &mut publication,
            |words: [u64; 4]| (words == expected).then_some(words),
            query,
        )
        .unwrap();
    assert_eq!(publication, Some(expected));
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
    assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
}

#[test]
fn wrong_length_cap_transfer_badge_and_identity_keep_starting_fence() {
    for (info, wrong_badge, identity) in [
        ((LABEL << 12) | 5, false, [11, 22, 33, 44]),
        ((LABEL << 12) | 4 | (1 << 7), false, [11, 22, 33, 44]),
        ((LABEL << 12) | 4, true, [11, 22, 33, 44]),
        ((LABEL << 12) | 4, false, [11, 22, 33, 99]),
    ] {
        let (mut lanes, peers, route, mut receiver) = setup(info, wrong_badge);
        let mut publication = None;
        assert!(receiver
            .ready_protocol_from_message(
                route,
                40,
                LABEL,
                &mut lanes,
                &peers,
                &mut publication,
                |words: [u64; 4]| (words == identity).then_some(words),
                |_, _| -> Result<ReplyBindingObservation, u8> {
                    panic!("invalid publication must not query")
                }
            )
            .is_err());
        assert_eq!(publication, None);
        unchanged(&lanes, &peers, route, &receiver);
    }
}
