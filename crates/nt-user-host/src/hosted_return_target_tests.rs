use super::*;

fn target(context: Option<u32>) -> HostedReturnTarget<u32> {
    HostedReturnTarget::new(17, context).unwrap()
}

fn acknowledge(target: &mut HostedReturnTarget<u32>, expected: RetirementEffect) {
    let mut attempt = target.begin_retirement().unwrap();
    assert_eq!(attempt.reply_cap(), 17);
    assert_eq!(attempt.effect(), expected);
    target
        .record_retirement(&mut attempt, RetirementOutcome::Acknowledged)
        .unwrap();
}

#[test]
fn live_delivery_is_explicit_and_zero_cap_is_rejected() {
    assert_eq!(
        HostedReturnTarget::<u32>::new(0, None),
        Err(HostedReturnTargetError::InvalidReplyCap)
    );
    assert_eq!(
        HostedReturnTarget::new(0, Some(7u32)),
        Err(HostedReturnTargetError::InvalidReplyCap)
    );
    assert_eq!(
        target(None).delivery(),
        Some(HostedReply::Syscall { reply_cap: 17 })
    );
    assert_eq!(
        target(Some(4)).delivery(),
        Some(HostedReply::Callback {
            reply_cap: 17,
            context: 4
        })
    );
    for mut target in [target(None), target(Some(4))] {
        assert!(target.can_resume());
        assert!(!target.is_abandoned());
        assert!(target.retirement().is_none());
        assert!(matches!(
            target.begin_retirement(),
            Err(HostedReturnTargetError::NotRetiring)
        ));
        assert!(target.delivery().is_some());
    }
}

#[test]
fn abandonment_retains_capability_until_all_three_effects_are_acknowledged() {
    for context in [None, Some(4)] {
        let mut target = target(context);
        target.request_abandonment();
        for effect in [
            RetirementEffect::Delete,
            RetirementEffect::Retype,
            RetirementEffect::ReleasePool,
        ] {
            let before = target;
            target.request_abandonment();
            assert_eq!(target, before);
            assert_eq!(target.delivery(), None);
            assert!(!target.can_resume());
            assert!(!target.is_abandoned());
            assert_eq!(
                target.retirement(),
                Some(RetirementView {
                    reply_cap: 17,
                    phase: RetirementPhase::Ready {
                        effect,
                        last_error: None
                    }
                })
            );
            acknowledge(&mut target, effect);
        }
        assert_eq!(target.delivery(), None);
        assert!(target.can_resume());
        assert!(target.is_abandoned());
        assert_eq!(target.retirement(), None);
        target.request_abandonment();
        assert!(target.is_abandoned());
        assert!(matches!(
            target.begin_retirement(),
            Err(HostedReturnTargetError::NotRetiring)
        ));
    }
}

#[test]
fn no_effects_retries_only_the_same_stage_with_a_new_single_use_attempt() {
    let mut target = target(Some(4));
    target.request_abandonment();
    for effect in [
        RetirementEffect::Delete,
        RetirementEffect::Retype,
        RetirementEffect::ReleasePool,
    ] {
        let mut failed = target.begin_retirement().unwrap();
        let invoking = target;
        target.request_abandonment();
        assert_eq!(target, invoking);
        assert!(matches!(
            target.begin_retirement(),
            Err(HostedReturnTargetError::NotReady)
        ));
        target
            .record_retirement(&mut failed, RetirementOutcome::NoEffects(91))
            .unwrap();
        assert_eq!(
            target.retirement(),
            Some(RetirementView {
                reply_cap: 17,
                phase: RetirementPhase::Ready {
                    effect,
                    last_error: Some(91)
                }
            })
        );
        let mut retry = target.begin_retirement().unwrap();
        assert_ne!(retry.nonce, failed.nonce);
        let before = target;
        assert_eq!(
            target.record_retirement(&mut failed, RetirementOutcome::Acknowledged),
            Err(HostedReturnTargetError::WrongAttempt)
        );
        assert_eq!(target, before);
        target
            .record_retirement(&mut retry, RetirementOutcome::Acknowledged)
            .unwrap();
        let after = target;
        assert_eq!(
            target.record_retirement(&mut retry, RetirementOutcome::Acknowledged),
            Err(HostedReturnTargetError::WrongAttempt)
        );
        assert_eq!(target, after);
    }
    assert!(target.is_abandoned());
}

#[test]
fn indeterminate_effects_preserve_capability_and_forbid_reentry() {
    for indeterminate in [
        RetirementEffect::Delete,
        RetirementEffect::Retype,
        RetirementEffect::ReleasePool,
    ] {
        let mut target = target(None);
        target.request_abandonment();
        for effect in [
            RetirementEffect::Delete,
            RetirementEffect::Retype,
            RetirementEffect::ReleasePool,
        ] {
            if effect == indeterminate {
                break;
            }
            acknowledge(&mut target, effect);
        }
        let mut attempt = target.begin_retirement().unwrap();
        target
            .record_retirement(&mut attempt, RetirementOutcome::Indeterminate(92))
            .unwrap();
        assert_eq!(
            target.retirement(),
            Some(RetirementView {
                reply_cap: 17,
                phase: RetirementPhase::Indeterminate {
                    effect: indeterminate,
                    status: 92
                }
            })
        );
        let before = target;
        target.request_abandonment();
        assert_eq!(target, before);
        assert!(!target.can_resume());
        assert!(!target.is_abandoned());
        assert_eq!(target.delivery(), None);
        assert!(matches!(
            target.begin_retirement(),
            Err(HostedReturnTargetError::NotReady)
        ));
        assert_eq!(
            target.record_retirement(&mut attempt, RetirementOutcome::Acknowledged),
            Err(HostedReturnTargetError::WrongAttempt)
        );
        assert_eq!(target, before);
    }
}

#[test]
fn dropped_ticket_keeps_invoking_and_cross_instance_tickets_cannot_commit() {
    let mut first = target(None);
    let mut second = target(None);
    first.request_abandonment();
    second.request_abandonment();
    let mut first_attempt = first.begin_retirement().unwrap();
    let mut second_attempt = second.begin_retirement().unwrap();
    assert_ne!(first_attempt.nonce, second_attempt.nonce);
    let before = second;
    assert_eq!(
        second.record_retirement(&mut first_attempt, RetirementOutcome::Acknowledged),
        Err(HostedReturnTargetError::WrongAttempt)
    );
    assert_eq!(second, before);
    first
        .record_retirement(&mut first_attempt, RetirementOutcome::Acknowledged)
        .unwrap();
    second
        .record_retirement(&mut second_attempt, RetirementOutcome::Acknowledged)
        .unwrap();
    let attempt = first.begin_retirement().unwrap();
    let invoking = first;
    drop(attempt);
    assert_eq!(first, invoking);
    assert!(matches!(
        first.begin_retirement(),
        Err(HostedReturnTargetError::NotReady)
    ));
    first.request_abandonment();
    assert_eq!(first, invoking);
}

#[test]
fn exhausted_nonce_counter_never_wraps_or_changes_ready_state() {
    for value in [0, u64::MAX] {
        let counter = AtomicU64::new(value);
        let mut target = target(None);
        target.request_abandonment();
        let before = target;
        assert!(matches!(
            target.begin_retirement_with_counter(&counter),
            Err(HostedReturnTargetError::IdentityExhausted)
        ));
        assert_eq!(target, before);
        assert_eq!(counter.load(Ordering::Relaxed), value);
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    let mut target = target(None);
    target.request_abandonment();
    let mut attempt = target.begin_retirement_with_counter(&counter).unwrap();
    assert_eq!(attempt.nonce, u64::MAX - 1);
    target
        .record_retirement(&mut attempt, RetirementOutcome::NoEffects(7))
        .unwrap();
    let before = target;
    assert!(matches!(
        target.begin_retirement_with_counter(&counter),
        Err(HostedReturnTargetError::IdentityExhausted)
    ));
    assert_eq!(target, before);
}
