use super::*;
use ObjectWaitApcDisposition as Disposition;
use ObjectWaitApcEffect as Effect;
use ObjectWaitApcOutcome as Outcome;
use ObjectWaitApcPhase as Phase;

const ERROR: u32 = 0xc000_009a;

fn claimed(count: usize) -> (ObjectWaiterTable<u64>, ObjectWaiterIdentity) {
    let mut table = ObjectWaiterTable::new();
    let id = table.insert(50).unwrap();
    table.claim_apc(id, count).unwrap();
    (table, id)
}

fn complete(table: &mut ObjectWaiterTable<u64>, id: ObjectWaiterIdentity, effect: Effect) {
    let mut attempt = table.begin_apc_step(id).unwrap();
    assert_eq!(attempt.effect(), effect);
    table
        .record_apc_step(&mut attempt, Outcome::Completed(effect))
        .unwrap();
}

#[test]
fn claim_retains_payload_and_disables_all_ordinary_mutation_or_extraction() {
    let (mut table, id) = claimed(2);
    assert!(table.is_claimed(id));
    assert_eq!(table.get_exact(id), Some(&50));
    assert_eq!(table.iter().count(), 1);
    assert_eq!(
        table.claim_apc(id, 2),
        Err(ObjectWaitApcError::InvalidPhase)
    );
    assert!(!table.update_exact(id, |_| panic!("claimed payload mutated")));
    assert_eq!(table.take(id), None);
    assert!(!table.reset(0));
    assert!(!table.reserve(10));
    assert_eq!(table.finish_apc(id), None);
    assert!(table.has_runtime_dependency_matching(|value| *value == 50));
    assert!(!table.has_runtime_dependency_matching(|value| *value == 51));
    let peer = table.insert(51).unwrap();
    assert!(table.update_exact(peer, |value| *value = 52));
    assert_eq!(table.take(peer), Some(52));
}

#[test]
fn references_release_in_reverse_order_and_followup_is_not_a_second_decrement() {
    let (mut table, id) = claimed(3);
    for index in (0..3).rev() {
        let mut release = table.begin_apc_step(id).unwrap();
        assert_eq!(release.effect(), Effect::ReleaseReference { index });
        table
            .record_apc_step(&mut release, Outcome::NotEntered(ERROR))
            .unwrap();
        assert_eq!(table.apc(id).unwrap().remaining_references, index + 1);
        complete(&mut table, id, Effect::ReleaseReference { index });
        assert_eq!(table.apc(id).unwrap().remaining_references, index);
        let mut followup = table.begin_apc_step(id).unwrap();
        assert_eq!(followup.effect(), Effect::ReferenceFollowup { index });
        table
            .record_apc_step(&mut followup, Outcome::NotEntered(ERROR))
            .unwrap();
        assert_eq!(table.apc(id).unwrap().remaining_references, index);
        complete(&mut table, id, Effect::ReferenceFollowup { index });
    }
    assert_eq!(
        table.apc(id).unwrap().phase,
        Phase::Ready {
            effect: Effect::Stage,
            last_error: None
        }
    );
}

#[test]
fn stage_send_and_sent_reply_retirement_are_once_only_receipts() {
    let (mut table, id) = claimed(0);
    let mut stage = table.begin_apc_step(id).unwrap();
    assert_eq!(stage.identity(), id);
    assert_eq!(stage.disposition(), Disposition::UserApc);
    assert!(!stage.teardown_requested());
    assert_eq!(
        table.record_apc_step(&mut stage, Outcome::Completed(Effect::Send)),
        Err(ObjectWaitApcError::WrongEffect)
    );
    table
        .record_apc_step(&mut stage, Outcome::Completed(Effect::Stage))
        .unwrap();
    assert!(table
        .record_apc_step(&mut stage, Outcome::Completed(Effect::Stage))
        .is_err());
    let mut send = table.begin_apc_step(id).unwrap();
    table
        .record_apc_step(&mut send, Outcome::NotEntered(ERROR))
        .unwrap();
    complete(&mut table, id, Effect::Send);
    let mut retire = table.begin_apc_step(id).unwrap();
    assert_eq!(retire.effect(), Effect::RetireSentReply);
    table
        .record_apc_step(&mut retire, Outcome::NotEntered(ERROR))
        .unwrap();
    complete(&mut table, id, Effect::RetireSentReply);
    assert_eq!(table.apc(id).unwrap().phase, Phase::Complete);
    assert!(table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.take(id), None);
    assert_eq!(table.finish_apc(id), Some(50));
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.finish_apc(id), None);
}

#[test]
fn wrong_reference_index_keeps_exact_entered_effect_owned() {
    let (mut table, id) = claimed(2);
    let mut attempt = table.begin_apc_step(id).unwrap();
    assert_eq!(
        table.record_apc_step(
            &mut attempt,
            Outcome::Completed(Effect::ReleaseReference { index: 0 })
        ),
        Err(ObjectWaitApcError::WrongEffect)
    );
    assert_eq!(table.apc(id).unwrap().remaining_references, 2);
    assert!(table.begin_apc_step(id).is_err());
    table
        .record_apc_step(
            &mut attempt,
            Outcome::Completed(Effect::ReleaseReference { index: 1 }),
        )
        .unwrap();
    assert_eq!(table.apc(id).unwrap().remaining_references, 1);
}

#[test]
fn teardown_during_reference_effect_preserves_release_and_followup_cursor() {
    let (mut table, id) = claimed(2);
    let mut release = table.begin_apc_step(id).unwrap();
    table.request_teardown(id).unwrap();
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert!(table.is_claimed(id));
    table
        .record_apc_step(
            &mut release,
            Outcome::Completed(Effect::ReleaseReference { index: 1 }),
        )
        .unwrap();
    complete(&mut table, id, Effect::ReferenceFollowup { index: 1 });
    complete(&mut table, id, Effect::ReleaseReference { index: 0 });
    let mut followup = table.begin_apc_step(id).unwrap();
    table.request_teardown(id).unwrap();
    table
        .record_apc_step(&mut followup, Outcome::NotEntered(ERROR))
        .unwrap();
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert!(table.is_claimed(id));
    complete(&mut table, id, Effect::ReferenceFollowup { index: 0 });
    assert_eq!(table.apc(id).unwrap().disposition, Disposition::Teardown);
    complete(&mut table, id, Effect::RevokeReply);
    let mut retype = table.begin_apc_step(id).unwrap();
    table
        .record_apc_step(&mut retype, Outcome::NotEntered(ERROR))
        .unwrap();
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert!(table.is_claimed(id));
    complete(&mut table, id, Effect::RetypeReply);
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.finish_apc(id), Some(50));
}

#[test]
fn ready_stage_and_send_can_convert_to_teardown_without_repeating_completed_effects() {
    for staged in [false, true] {
        let (mut table, id) = claimed(0);
        if staged {
            complete(&mut table, id, Effect::Stage);
        }
        table.request_teardown(id).unwrap();
        table.request_teardown(id).unwrap();
        assert_eq!(
            table.apc(id).unwrap().phase,
            Phase::Ready {
                effect: Effect::RevokeReply,
                last_error: None
            }
        );
        complete(&mut table, id, Effect::RevokeReply);
        complete(&mut table, id, Effect::RetypeReply);
        assert_eq!(table.finish_apc(id), Some(50));
    }
}

#[test]
fn entered_user_effect_teardown_waits_for_outcome_and_never_deletes_an_accepted_reply() {
    for send in [false, true] {
        for success in [false, true] {
            let (mut table, id) = claimed(0);
            if send {
                complete(&mut table, id, Effect::Stage);
            }
            let mut attempt = table.begin_apc_step(id).unwrap();
            let effect = attempt.effect();
            table.request_teardown(id).unwrap();
            assert_eq!(table.apc(id).unwrap().disposition, Disposition::UserApc);
            assert!(table.begin_apc_step(id).is_err());
            table
                .record_apc_step(
                    &mut attempt,
                    if success {
                        Outcome::Completed(effect)
                    } else {
                        Outcome::NotEntered(ERROR)
                    },
                )
                .unwrap();
            let next = if send && success {
                Effect::RetireSentReply
            } else {
                Effect::RevokeReply
            };
            assert!(!table.has_runtime_dependency_matching(|_| true));
            assert!(table.is_claimed(id));
            assert_eq!(table.begin_apc_step(id).unwrap().effect(), next);
        }
    }
}

#[test]
fn acknowledged_send_retires_without_resend_even_when_teardown_arrives_later() {
    let (mut table, id) = claimed(0);
    complete(&mut table, id, Effect::Stage);
    complete(&mut table, id, Effect::Send);
    table.request_teardown(id).unwrap();
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert!(table.is_claimed(id));
    let mut retire = table.begin_apc_step(id).unwrap();
    assert_eq!(retire.effect(), Effect::RetireSentReply);
    table
        .record_apc_step(&mut retire, Outcome::NotEntered(ERROR))
        .unwrap();
    table.request_teardown(id).unwrap();
    assert!(!table.has_runtime_dependency_matching(|_| true));
    complete(&mut table, id, Effect::RetireSentReply);
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.finish_apc(id), Some(50));
}

#[test]
fn dropped_or_uncertain_each_effect_is_never_automatically_reoffered() {
    let effects = [
        Effect::ReleaseReference { index: 0 },
        Effect::ReferenceFollowup { index: 0 },
        Effect::Stage,
        Effect::Send,
        Effect::RetireSentReply,
        Effect::RevokeReply,
        Effect::RetypeReply,
    ];
    for effect in effects {
        for uncertain in [false, true] {
            let (mut table, id) = claimed(1);
            for prerequisite in [
                Effect::ReleaseReference { index: 0 },
                Effect::ReferenceFollowup { index: 0 },
                Effect::Stage,
                Effect::Send,
            ] {
                if table.apc(id).unwrap().phase
                    == (Phase::Ready {
                        effect,
                        last_error: None,
                    })
                {
                    break;
                }
                if matches!(effect, Effect::RevokeReply | Effect::RetypeReply)
                    && prerequisite == Effect::Stage
                {
                    table.request_teardown(id).unwrap();
                    if effect == Effect::RetypeReply {
                        complete(&mut table, id, Effect::RevokeReply);
                    }
                    break;
                }
                complete(&mut table, id, prerequisite);
            }
            let mut attempt = table.begin_apc_step(id).unwrap();
            assert_eq!(attempt.effect(), effect);
            if uncertain {
                table
                    .record_apc_step(&mut attempt, Outcome::Indeterminate(ERROR))
                    .unwrap();
            }
            drop(attempt);
            table.request_teardown(id).unwrap();
            assert!(table.next_apc_after(None).is_none());
            assert!(table.begin_apc_step(id).is_err());
            assert_eq!(
                table.has_runtime_dependency_matching(|_| true),
                matches!(effect, Effect::Stage | Effect::Send)
            );
            assert!(table.is_claimed(id));
            assert_eq!(table.take(id), None);
            assert_eq!(table.finish_apc(id), None);
            assert!(!table.reset(0));
        }
    }
}

#[test]
fn attempt_identity_is_exact_across_tables_and_reused_slots() {
    let (mut table, id) = claimed(0);
    let (mut other, other_id) = claimed(0);
    let mut stage = table.begin_apc_step(id).unwrap();
    assert_eq!(
        other.record_apc_step(&mut stage, Outcome::Completed(Effect::Stage)),
        Err(ObjectWaitApcError::WrongIdentity)
    );
    assert_eq!(
        other.claim_apc(id, 0),
        Err(ObjectWaitApcError::WrongIdentity)
    );
    assert_eq!(
        other.request_teardown(id),
        Err(ObjectWaitApcError::WrongIdentity)
    );
    assert!(!other.is_claimed(id));
    assert!(other.is_claimed(other_id));
    table
        .record_apc_step(&mut stage, Outcome::Completed(Effect::Stage))
        .unwrap();
    complete(&mut table, id, Effect::Send);
    complete(&mut table, id, Effect::RetireSentReply);
    table.finish_apc(id).unwrap();
    let new = table.insert(50).unwrap();
    table.claim_apc(new, 0).unwrap();
    assert_eq!(new.slot(), id.slot());
    assert_eq!(
        table.record_apc_step(&mut stage, Outcome::Completed(Effect::Stage)),
        Err(ObjectWaitApcError::WrongIdentity)
    );
    assert_eq!(
        table.request_teardown(id),
        Err(ObjectWaitApcError::WrongIdentity)
    );
}

#[test]
fn attempt_exhaustion_keeps_ready_owner_and_all_storage_operations_are_allocation_free() {
    let (mut table, id) = claimed(0);
    let pointer = table.entries.as_ptr();
    let capacity = table.capacity();
    table.entries[id.slot]
        .as_mut()
        .unwrap()
        .apc
        .as_mut()
        .unwrap()
        .next_attempt = u64::MAX;
    assert_eq!(
        table.begin_apc_step(id).unwrap_err(),
        ObjectWaitApcError::Exhausted
    );
    assert_eq!(
        table.apc(id).unwrap().phase,
        Phase::Ready {
            effect: Effect::Stage,
            last_error: None
        }
    );
    assert_eq!(table.next_apc_after(None), Some(id));
    assert_eq!(table.next_apc_after(Some(id.slot())), None);
    assert_eq!(table.entries.as_ptr(), pointer);
    assert_eq!(table.capacity(), capacity);
}
