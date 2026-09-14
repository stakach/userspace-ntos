//! Host composition only: mechanism outcomes are supplied explicitly, not executed through IPC.

use nt_component_suspension::{
    ComponentSuspensionLanes, LaneBinding, LaneError, LaneHandle, LanePhase, SuspensionCaller,
    SuspensionHostedClient, SuspensionKey, SuspensionOwner, SuspensionScope, TerminalStage,
    TerminalStageOutcome,
};
use nt_user_host::hosted_return_target::{
    HostedReply, HostedReturnTarget, HostedReturnTargetError, RetirementEffect, RetirementOutcome,
    RetirementPhase,
};

type Target = HostedReturnTarget<u64>;
type Lanes = ComponentSuspensionLanes<Target, i32>;
const REPLY_OBJECT: u64 = 300;
const CLIENT_CAP: u64 = 500;
const KEY: SuspensionKey = SuspensionKey::provider_wait(10);

fn owner(dispatch_id: u64) -> SuspensionOwner {
    SuspensionOwner {
        provider_domain: 7,
        provider_generation: 2,
        dispatch_id,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 3,
            client_generation: 4,
            client_tid: 8,
            client_badge: 9,
        }),
    }
}

fn fixture(context: Option<u64>) -> (Lanes, LaneHandle) {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 100,
            receive_endpoint: 200,
            reply_object: REPLY_OBJECT,
        })
        .unwrap();
    lanes.begin_dispatch(lane, REPLY_OBJECT).unwrap();
    lanes
        .admit_running(
            lane,
            REPLY_OBJECT,
            KEY,
            1,
            owner(1),
            Target::new(CLIENT_CAP, context).unwrap(),
        )
        .unwrap();
    lanes.select(KEY, 0).unwrap();
    (lanes, lane)
}

fn target(lanes: &Lanes, lane: LaneHandle) -> Target {
    lanes.frame(lane, KEY).unwrap().unwrap().continuation
}

fn target_mut(lanes: &mut Lanes, lane: LaneHandle) -> &mut Target {
    &mut lanes.frame_mut(lane, KEY).unwrap().unwrap().continuation
}

fn eligible(lanes: &Lanes) -> bool {
    lanes
        .next_resumable_if(|frame| frame.continuation.can_resume())
        .is_some()
}

fn finish_terminal(lanes: &mut Lanes, lane: LaneHandle, identity: SuspensionOwner) -> Target {
    let terminal = lanes
        .retain_terminal_running(lane, REPLY_OBJECT, KEY, identity, ())
        .unwrap();
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut attempt = lanes
            .begin_terminal_stage(terminal, REPLY_OBJECT, stage)
            .unwrap();
        lanes
            .record_terminal_stage(
                &mut attempt,
                REPLY_OBJECT,
                TerminalStageOutcome::Acknowledged,
            )
            .unwrap();
    }
    let retired = lanes
        .finish_terminal(terminal, REPLY_OBJECT, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    retired.suspension.continuation
}

#[test]
fn abandonment_retries_only_the_failed_effect_before_resuming_cancellation() {
    for context in [None, Some(42)] {
        let (mut lanes, lane) = fixture(context);
        let expected = match context {
            None => HostedReply::Syscall {
                reply_cap: CLIENT_CAP,
            },
            Some(context) => HostedReply::Callback {
                reply_cap: CLIENT_CAP,
                context,
            },
        };
        assert_eq!(target(&lanes, lane).delivery(), Some(expected));
        assert!(eligible(&lanes));
        target_mut(&mut lanes, lane).request_abandonment();
        lanes.cancel(KEY, 0xc000_0120u32 as i32).unwrap();
        assert!(!eligible(&lanes));
        assert_eq!(target(&lanes, lane).delivery(), None);
        let mut effects = Vec::new();
        for (effect, outcome) in [
            (RetirementEffect::Delete, RetirementOutcome::Acknowledged),
            (RetirementEffect::Retype, RetirementOutcome::NoEffects(12)),
            (RetirementEffect::Retype, RetirementOutcome::Acknowledged),
            (
                RetirementEffect::ReleasePool,
                RetirementOutcome::Acknowledged,
            ),
        ] {
            let current = target_mut(&mut lanes, lane);
            let mut attempt = current.begin_retirement().unwrap();
            assert_eq!(attempt.reply_cap(), CLIENT_CAP);
            assert_eq!(attempt.effect(), effect);
            effects.push(attempt.effect());
            assert!(!eligible(&lanes));
            target_mut(&mut lanes, lane)
                .record_retirement(&mut attempt, outcome)
                .unwrap();
            if effect != RetirementEffect::ReleasePool {
                let view = target(&lanes, lane).retirement().unwrap();
                assert_eq!(view.reply_cap, CLIENT_CAP);
                assert!(!eligible(&lanes));
                if outcome == RetirementOutcome::NoEffects(12) {
                    assert_eq!(
                        view.phase,
                        RetirementPhase::Ready {
                            effect: RetirementEffect::Retype,
                            last_error: Some(12)
                        }
                    );
                }
            }
        }
        assert_eq!(
            effects,
            [
                RetirementEffect::Delete,
                RetirementEffect::Retype,
                RetirementEffect::Retype,
                RetirementEffect::ReleasePool
            ]
        );
        assert!(target(&lanes, lane).is_abandoned());
        let selected = lanes
            .next_resumable_if(|frame| frame.continuation.can_resume())
            .unwrap();
        assert!(selected.suspension.cancelled);
        assert_eq!(selected.suspension.completion, 0xc000_0120u32 as i32);
        lanes.begin_resume(lane, REPLY_OBJECT, KEY).unwrap();
        let retired = finish_terminal(&mut lanes, lane, owner(1));
        assert!(retired.is_abandoned());
        assert_eq!(retired.delivery(), None);
    }
}

#[test]
fn normal_terminal_delivery_is_preserved_and_excluded_from_teardown() {
    for context in [None, Some(42)] {
        let (mut lanes, lane) = fixture(context);
        let expected = target(&lanes, lane).delivery();
        lanes.begin_resume(lane, REPLY_OBJECT, KEY).unwrap();
        let terminal = lanes
            .retain_terminal_running(lane, REPLY_OBJECT, KEY, owner(1), ())
            .unwrap();
        let scope = SuspensionScope::Provider {
            domain: 7,
            generation: 2,
        };
        for stage in [
            TerminalStage::Output,
            TerminalStage::Context,
            TerminalStage::Publication,
            TerminalStage::Reply,
        ] {
            assert_eq!(lanes.next_cancellable_in_scope(scope), None);
            assert!(matches!(
                lanes.frame_mut(lane, KEY),
                Err(LaneError::InvalidPhase)
            ));
            assert_eq!(lanes.cancel(KEY, -1), Err(LaneError::InvalidPhase));
            assert!(!eligible(&lanes));
            assert_eq!(
                lanes
                    .terminal(terminal, REPLY_OBJECT)
                    .unwrap()
                    .frame
                    .continuation
                    .delivery(),
                expected
            );
            let mut attempt = lanes
                .begin_terminal_stage(terminal, REPLY_OBJECT, stage)
                .unwrap();
            lanes
                .record_terminal_stage(
                    &mut attempt,
                    REPLY_OBJECT,
                    TerminalStageOutcome::Acknowledged,
                )
                .unwrap();
        }
        let retired = lanes
            .finish_terminal(terminal, REPLY_OBJECT, Ok(()))
            .unwrap()
            .unwrap();
        assert!(!retired.suspension.cancelled);
        assert_eq!(retired.suspension.continuation.delivery(), expected);
        assert_eq!(lanes.total_suspensions(), 0);
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    }
}

#[test]
fn indeterminate_effect_or_dropped_ticket_keeps_the_frame_owned_and_ineligible() {
    for indeterminate in [false, true] {
        let (mut lanes, lane) = fixture(Some(42));
        target_mut(&mut lanes, lane).request_abandonment();
        lanes.cancel(KEY, -1).unwrap();
        let mut attempt = target_mut(&mut lanes, lane).begin_retirement().unwrap();
        if indeterminate {
            target_mut(&mut lanes, lane)
                .record_retirement(&mut attempt, RetirementOutcome::Indeterminate(55))
                .unwrap();
        }
        drop(attempt);
        target_mut(&mut lanes, lane).request_abandonment();
        assert!(matches!(
            target_mut(&mut lanes, lane).begin_retirement(),
            Err(HostedReturnTargetError::NotReady)
        ));
        let view = target(&lanes, lane).retirement().unwrap();
        assert_eq!(view.reply_cap, CLIENT_CAP);
        if indeterminate {
            assert_eq!(
                view.phase,
                RetirementPhase::Indeterminate {
                    effect: RetirementEffect::Delete,
                    status: 55
                }
            );
        } else {
            assert!(matches!(
                view.phase,
                RetirementPhase::Invoking {
                    effect: RetirementEffect::Delete,
                    ..
                }
            ));
        }
        assert_eq!(lanes.total_suspensions(), 1);
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
        assert!(!eligible(&lanes));
        assert!(!target(&lanes, lane).is_abandoned());
        assert_eq!(target(&lanes, lane).delivery(), None);
    }
}

#[test]
fn stale_ticket_cannot_mutate_a_new_frame_with_the_same_reply_cap() {
    let (mut lanes, lane) = fixture(None);
    target_mut(&mut lanes, lane).request_abandonment();
    lanes.cancel(KEY, -1).unwrap();
    let mut old = target_mut(&mut lanes, lane).begin_retirement().unwrap();
    target_mut(&mut lanes, lane)
        .record_retirement(&mut old, RetirementOutcome::Acknowledged)
        .unwrap();
    for expected in [RetirementEffect::Retype, RetirementEffect::ReleasePool] {
        let mut attempt = target_mut(&mut lanes, lane).begin_retirement().unwrap();
        assert_eq!(attempt.effect(), expected);
        target_mut(&mut lanes, lane)
            .record_retirement(&mut attempt, RetirementOutcome::Acknowledged)
            .unwrap();
    }
    lanes.begin_resume(lane, REPLY_OBJECT, KEY).unwrap();
    assert!(finish_terminal(&mut lanes, lane, owner(1)).is_abandoned());
    lanes.begin_dispatch(lane, REPLY_OBJECT).unwrap();
    lanes
        .admit_running(
            lane,
            REPLY_OBJECT,
            KEY,
            2,
            owner(2),
            Target::new(CLIENT_CAP, Some(99)).unwrap(),
        )
        .unwrap();
    lanes.select(KEY, 0).unwrap();
    target_mut(&mut lanes, lane).request_abandonment();
    lanes.cancel(KEY, -2).unwrap();
    let mut fresh = target_mut(&mut lanes, lane).begin_retirement().unwrap();
    let before = target(&lanes, lane).retirement();
    assert_eq!(
        target_mut(&mut lanes, lane).record_retirement(&mut old, RetirementOutcome::Acknowledged),
        Err(HostedReturnTargetError::WrongAttempt)
    );
    assert_eq!(target(&lanes, lane).retirement(), before);
    assert!(!eligible(&lanes));
    target_mut(&mut lanes, lane)
        .record_retirement(&mut fresh, RetirementOutcome::Acknowledged)
        .unwrap();
    for expected in [RetirementEffect::Retype, RetirementEffect::ReleasePool] {
        let mut attempt = target_mut(&mut lanes, lane).begin_retirement().unwrap();
        assert_eq!(attempt.effect(), expected);
        target_mut(&mut lanes, lane)
            .record_retirement(&mut attempt, RetirementOutcome::Acknowledged)
            .unwrap();
    }
    assert!(eligible(&lanes));
    lanes.begin_resume(lane, REPLY_OBJECT, KEY).unwrap();
    assert!(finish_terminal(&mut lanes, lane, owner(2)).is_abandoned());
}
