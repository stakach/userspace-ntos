use super::*;

#[test]
fn active_receive_cannot_lose_its_execution_epoch_to_completion() {
    for held in [false, true] {
        let (mut lanes, mut peers, route, dispatch, mut receiver) =
            setup_with_capacity((7 << 12) | 4, false, 3);
        receiver
            .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
            .unwrap();
        if held {
            receiver
                .capture(message(route.badge(), 8 << 12))
                .ok()
                .unwrap();
            receiver
                .resolve(IngressReceiveDisposition::Call)
                .ok()
                .unwrap();
        }
        let phase = receiver.phase();
        assert!(matches!(
            receiver.complete_stored(
                route,
                dispatch,
                &mut lanes,
                &mut peers,
                |_, _| -> Result<ReplyBindingObservation, u8> {
                    panic!("reserved receive must reject before query")
                }
            ),
            Err(StoredCompletionError::WrongOwner)
        ));
        assert!(matches!(
            receiver.complete_protocol_from_message(
                route,
                dispatch,
                41,
                7,
                &[91; 4],
                &mut lanes,
                &mut peers,
                |_, _| -> Result<ReplyBindingObservation, u8> {
                    panic!("reserved receive must reject before query")
                }
            ),
            Err(StoredCompletionError::WrongOwner)
        ));
        assert_eq!(lanes.running(), Some(dispatch.lane()));
        assert_eq!(
            lanes.active_dispatch_identity(dispatch.lane()),
            Ok(Some(dispatch))
        );
        assert_eq!(receiver.phase(), phase);
        assert_eq!(receiver.available(), 0);
        assert_eq!(peers.state(route).unwrap().1, 2);
        if held {
            receiver
                .retain(
                    &lanes,
                    ComponentIngress::new(20, 43).unwrap(),
                    &mut peers,
                    route.badge(),
                    |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
                )
                .ok()
                .unwrap();
        } else {
            receiver.capture(message(0, 0)).ok().unwrap();
            receiver
                .resolve(IngressReceiveDisposition::NoCall)
                .ok()
                .unwrap();
        }
        assert!(receiver.phase().is_none());
    }
}

#[test]
fn exact_four_word_completion_retires_only_old_admitted_call() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup((7 << 12) | 4, false);
    receiver
        .complete_protocol_from_message(
            route,
            dispatch,
            41,
            7,
            &[91; 4],
            &mut lanes,
            &mut peers,
            |_, reply| {
                Ok::<_, u8>(if reply == 41 {
                    ReplyBindingObservation::BoundToTarget
                } else {
                    ReplyBindingObservation::Free
                })
            },
        )
        .unwrap();
    assert_eq!(lanes.phase(dispatch.lane()), Ok(crate::LanePhase::Idle));
    assert!(receiver.store.stored_reply(route, 41).unwrap().is_held());
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn stale_token_badge_length_and_cap_transfer_refuse_without_queries() {
    for (info, badge, words) in [
        ((7 << 12) | 4, false, [91, 91, 91, 92]),
        ((7 << 12) | 4, true, [91; 4]),
        ((7 << 12) | 3, false, [91; 4]),
        ((7 << 12) | 4 | (1 << 7), false, [91; 4]),
    ] {
        let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(info, badge);
        assert!(matches!(
            receiver.complete_protocol_from_message(
                route,
                dispatch,
                41,
                7,
                &words,
                &mut lanes,
                &mut peers,
                |_, _| -> Result<ReplyBindingObservation, u8> {
                    panic!("invalid completion must not query")
                }
            ),
            Err(StoredCompletionError::InvalidCompletionMessage)
        ));
        assert_eq!(lanes.running(), Some(dispatch.lane()));
        assert_eq!(peers.state(route).unwrap().1, 2);
    }
}
