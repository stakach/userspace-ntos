use super::*;
use ObjectWaitReplyDisposition as Disposition;
use ObjectWaitReplyEffect as Effect;
use ObjectWaitReplyError as Error;
use ObjectWaitReplyOutcome as Outcome;
use ObjectWaitReplyPhase as Phase;

const STATUS: u64 = 0x1234_5678_0000_0102;
const ERROR: u32 = 0xc000_009a;

fn claimed(count: usize) -> (ObjectWaiterTable<u64>, ObjectWaiterIdentity) {
    let mut table = ObjectWaiterTable::new();
    let id = table.insert(50).unwrap();
    table.claim_reply(id, count, STATUS).unwrap();
    (table, id)
}

fn complete(table: &mut ObjectWaiterTable<u64>, id: ObjectWaiterIdentity, effect: Effect) {
    let mut ticket = table.begin_reply_step(id).unwrap();
    assert_eq!(ticket.effect(), effect);
    assert_eq!(ticket.status(), table.reply(id).unwrap().status);
    table
        .record_reply_step(&mut ticket, Outcome::Completed(effect))
        .unwrap();
}

fn at_effect(effect: Effect) -> (ObjectWaiterTable<u64>, ObjectWaiterIdentity) {
    let (mut table, id) = claimed(1);
    if effect == (Effect::ReleaseReference { index: 0 }) {
        return (table, id);
    }
    complete(&mut table, id, Effect::ReleaseReference { index: 0 });
    if effect == (Effect::ReferenceFollowup { index: 0 }) {
        return (table, id);
    }
    complete(&mut table, id, Effect::ReferenceFollowup { index: 0 });
    match effect {
        Effect::Send => {}
        Effect::RetireSentReply => complete(&mut table, id, Effect::Send),
        Effect::RevokeReply => table.request_reply_teardown(id).unwrap(),
        Effect::RetypeReply => {
            table.request_reply_teardown(id).unwrap();
            complete(&mut table, id, Effect::RevokeReply);
        }
        _ => unreachable!(),
    }
    (table, id)
}

const EFFECTS: [Effect; 6] = [
    Effect::ReleaseReference { index: 0 },
    Effect::ReferenceFollowup { index: 0 },
    Effect::Send,
    Effect::RetireSentReply,
    Effect::RevokeReply,
    Effect::RetypeReply,
];

#[test]
fn claim_is_allocation_free_and_retains_selected_status_and_owner() {
    let mut table = ObjectWaiterTable::new();
    let id = table.insert(50).unwrap();
    let before = table.stats();
    table.claim_reply(id, 2, STATUS).unwrap();
    assert_eq!(table.stats(), before);
    assert!(table.is_claimed(id));
    assert_eq!(table.reply(id).unwrap().status, STATUS);
    assert_eq!(table.reply(id).unwrap().remaining_references, 2);
    assert_eq!(table.get_exact(id), Some(&50));
    assert_eq!(table.claim_reply(id, 9, 0), Err(Error::InvalidPhase));
    assert_eq!(table.claim_reply_teardown(id, 9), Err(Error::InvalidPhase));
    assert!(!table.update_exact(id, |_| panic!("claimed payload changed")));
    assert_eq!(table.take(id), None);
    assert_eq!(table.finish_reply(id), None);
    assert!(!table.reset(0));
    assert!(!table.reserve(10));
    assert!(table.has_reply_runtime_dependency_matching(|value| *value == 50));
    assert!(!table.has_reply_runtime_dependency_matching(|value| *value == 51));
    let peer = table.insert(51).unwrap();
    assert!(table.update_exact(peer, |value| *value = 52));
    assert_eq!(table.take(peer), Some(52));
}

#[test]
fn ordinary_and_apc_claims_are_mutually_exclusive() {
    let (mut table, reply) = claimed(0);
    assert_eq!(
        table.claim_apc(reply, 0),
        Err(ObjectWaitApcError::InvalidPhase)
    );
    assert!(table.apc(reply).is_err());
    assert_eq!(table.next_apc_after(None), None);
    assert!(!table.has_runtime_dependency_matching(|_| true));
    let apc = table.insert(60).unwrap();
    table.claim_apc(apc, 0).unwrap();
    assert!(table.is_claimed(apc));
    assert_eq!(table.claim_reply(apc, 0, STATUS), Err(Error::InvalidPhase));
    assert_eq!(table.claim_reply_teardown(apc, 0), Err(Error::InvalidPhase));
    assert!(table.reply(apc).is_err());
    assert_eq!(table.next_reply_after(None), Some(reply));
    assert_eq!(table.next_reply_after(Some(reply.slot())), None);
    assert_eq!(table.next_apc_after(None), Some(apc));
    assert!(!table.has_reply_runtime_dependency_matching(|value| *value == 60));
}

#[test]
fn references_release_in_reverse_order_and_followup_never_repeats_decrement() {
    let (mut table, id) = claimed(3);
    for index in (0..3).rev() {
        let mut release = table.begin_reply_step(id).unwrap();
        assert_eq!(release.effect(), Effect::ReleaseReference { index });
        assert_eq!(
            table.record_reply_step(
                &mut release,
                Outcome::Completed(Effect::ReleaseReference { index: index + 1 })
            ),
            Err(Error::WrongEffect)
        );
        assert_eq!(table.reply(id).unwrap().remaining_references, index + 1);
        table
            .record_reply_step(&mut release, Outcome::NotEntered(ERROR))
            .unwrap();
        complete(&mut table, id, Effect::ReleaseReference { index });
        assert_eq!(table.reply(id).unwrap().remaining_references, index);
        let mut followup = table.begin_reply_step(id).unwrap();
        table
            .record_reply_step(&mut followup, Outcome::NotEntered(ERROR))
            .unwrap();
        assert_eq!(table.reply(id).unwrap().remaining_references, index);
        complete(&mut table, id, Effect::ReferenceFollowup { index });
        assert_eq!(table.reply(id).unwrap().status, STATUS);
    }
    complete(&mut table, id, Effect::Send);
    complete(&mut table, id, Effect::RetireSentReply);
    assert_eq!(table.reply(id).unwrap().phase, Phase::Complete);
    assert_eq!(table.finish_reply(id), Some(50));
    assert_eq!(table.finish_reply(id), None);
}

#[test]
fn every_definite_refusal_retries_only_its_exact_effect() {
    for effect in EFFECTS {
        let (mut table, id) = at_effect(effect);
        let references = table.reply(id).unwrap().remaining_references;
        let mut ticket = table.begin_reply_step(id).unwrap();
        assert_eq!(ticket.identity(), id);
        assert_eq!(ticket.status(), STATUS);
        let disposition = ticket.disposition();
        assert_eq!(
            ticket.teardown_requested(),
            disposition == Disposition::Teardown
        );
        table
            .record_reply_step(&mut ticket, Outcome::NotEntered(ERROR))
            .unwrap();
        assert_eq!(
            table.reply(id).unwrap().phase,
            Phase::Ready {
                effect,
                last_error: Some(ERROR)
            }
        );
        assert_eq!(table.reply(id).unwrap().remaining_references, references);
        assert_eq!(table.reply(id).unwrap().disposition, disposition);
        assert_eq!(
            table.record_reply_step(&mut ticket, Outcome::Completed(effect)),
            Err(Error::InvalidPhase)
        );
        complete(&mut table, id, effect);
    }
}

#[test]
fn every_dropped_or_uncertain_effect_stays_owned_without_replay() {
    for effect in EFFECTS {
        for uncertain in [false, true] {
            let (mut table, id) = at_effect(effect);
            let mut ticket = table.begin_reply_step(id).unwrap();
            if uncertain {
                table
                    .record_reply_step(&mut ticket, Outcome::Indeterminate(ERROR))
                    .unwrap();
            }
            drop(ticket);
            table.request_reply_teardown(id).unwrap();
            table.request_reply_teardown(id).unwrap();
            assert!(table.begin_reply_step(id).is_err());
            assert_eq!(table.next_reply_after(None), None);
            assert!(table.is_claimed(id));
            assert_eq!(table.take(id), None);
            assert_eq!(table.finish_reply(id), None);
            assert!(!table.reset(0));
            assert_eq!(
                table.has_reply_runtime_dependency_matching(|_| true),
                effect == Effect::Send
            );
            assert_eq!(table.reply(id).unwrap().status, STATUS);
        }
    }
}

#[test]
fn teardown_during_each_reference_phase_preserves_exact_cursor() {
    for effect in [
        Effect::ReleaseReference { index: 0 },
        Effect::ReferenceFollowup { index: 0 },
    ] {
        let (mut table, id) = at_effect(effect);
        let mut ticket = table.begin_reply_step(id).unwrap();
        table.request_reply_teardown(id).unwrap();
        assert!(!table.has_reply_runtime_dependency_matching(|_| true));
        assert!(table.is_claimed(id));
        table
            .record_reply_step(&mut ticket, Outcome::Completed(effect))
            .unwrap();
        if effect == (Effect::ReleaseReference { index: 0 }) {
            complete(&mut table, id, Effect::ReferenceFollowup { index: 0 });
        }
        complete(&mut table, id, Effect::RevokeReply);
        complete(&mut table, id, Effect::RetypeReply);
        assert_eq!(table.reply(id).unwrap().status, STATUS);
        assert_eq!(table.finish_reply(id), Some(50));
    }
}

#[test]
fn direct_teardown_releases_references_before_revoke_and_never_sends() {
    for count in [0, 2] {
        let mut table = ObjectWaiterTable::new();
        let id = table.insert(50).unwrap();
        let before = table.stats();
        table.claim_reply_teardown(id, count).unwrap();
        assert_eq!(table.stats(), before);
        assert_eq!(table.reply(id).unwrap().status, 0);
        assert_eq!(table.reply(id).unwrap().disposition, Disposition::Teardown);
        assert!(!table.has_reply_runtime_dependency_matching(|_| true));
        for index in (0..count).rev() {
            complete(&mut table, id, Effect::ReleaseReference { index });
            complete(&mut table, id, Effect::ReferenceFollowup { index });
        }
        complete(&mut table, id, Effect::RevokeReply);
        complete(&mut table, id, Effect::RetypeReply);
        assert_eq!(table.finish_reply(id), Some(50));
    }
}

#[test]
fn ready_send_converts_but_entered_send_pins_until_definite_receipt() {
    let (mut table, id) = claimed(0);
    table.request_reply_teardown(id).unwrap();
    assert!(!table.has_reply_runtime_dependency_matching(|_| true));
    complete(&mut table, id, Effect::RevokeReply);
    complete(&mut table, id, Effect::RetypeReply);
    assert_eq!(table.finish_reply(id), Some(50));
    for accepted in [false, true] {
        let (mut table, id) = claimed(0);
        let mut ticket = table.begin_reply_step(id).unwrap();
        table.request_reply_teardown(id).unwrap();
        assert_eq!(table.reply(id).unwrap().disposition, Disposition::Reply);
        assert!(table.has_reply_runtime_dependency_matching(|_| true));
        table
            .record_reply_step(
                &mut ticket,
                if accepted {
                    Outcome::Completed(Effect::Send)
                } else {
                    Outcome::NotEntered(ERROR)
                },
            )
            .unwrap();
        assert!(!table.has_reply_runtime_dependency_matching(|_| true));
        if accepted {
            complete(&mut table, id, Effect::RetireSentReply);
        } else {
            complete(&mut table, id, Effect::RevokeReply);
            complete(&mut table, id, Effect::RetypeReply);
        }
        assert_eq!(table.finish_reply(id), Some(50));
    }
}

#[test]
fn accepted_send_is_never_replayed_or_revoked_by_late_teardown() {
    for entered_retire in [false, true] {
        let (mut table, id) = claimed(0);
        complete(&mut table, id, Effect::Send);
        let mut ticket = entered_retire.then(|| table.begin_reply_step(id).unwrap());
        table.request_reply_teardown(id).unwrap();
        assert!(!table.has_reply_runtime_dependency_matching(|_| true));
        if let Some(ticket) = ticket.as_mut() {
            table
                .record_reply_step(ticket, Outcome::NotEntered(ERROR))
                .unwrap();
        }
        complete(&mut table, id, Effect::RetireSentReply);
        table.request_reply_teardown(id).unwrap();
        assert_eq!(table.reply(id).unwrap().phase, Phase::Complete);
        assert_eq!(table.finish_reply(id), Some(50));
    }
}

#[test]
fn exact_attempts_and_payload_receipts_reject_foreign_consumed_and_reused_owners() {
    let (mut table, id) = claimed(0);
    let (mut other, other_id) = claimed(0);
    let mut ticket = table.begin_reply_step(id).unwrap();
    assert_eq!(
        other.update_reply_payload(&ticket, |_| panic!("foreign mutation")),
        Err(Error::WrongIdentity)
    );
    assert_eq!(
        other.record_reply_step(&mut ticket, Outcome::Completed(Effect::Send)),
        Err(Error::WrongIdentity)
    );
    assert_eq!(other.claim_reply(id, 0, STATUS), Err(Error::WrongIdentity));
    assert_eq!(other.claim_reply_teardown(id, 0), Err(Error::WrongIdentity));
    assert_eq!(other.request_reply_teardown(id), Err(Error::WrongIdentity));
    table
        .update_reply_payload(&ticket, |value| *value = 51)
        .unwrap();
    assert_eq!(table.get_exact(id), Some(&51));
    assert_eq!(table.reply(id).unwrap().status, STATUS);
    table
        .record_reply_step(&mut ticket, Outcome::Completed(Effect::Send))
        .unwrap();
    assert_eq!(
        table.update_reply_payload(&ticket, |_| panic!("consumed mutation")),
        Err(Error::InvalidPhase)
    );
    complete(&mut table, id, Effect::RetireSentReply);
    assert_eq!(table.finish_reply(id), Some(51));
    let replacement = table.insert(50).unwrap();
    table.claim_reply(replacement, 0, STATUS).unwrap();
    assert_eq!(replacement.slot(), id.slot());
    assert_ne!(replacement, id);
    assert_eq!(
        table.update_reply_payload(&ticket, |_| panic!("stale mutation")),
        Err(Error::WrongIdentity)
    );
    assert_eq!(
        table.record_reply_step(&mut ticket, Outcome::Completed(Effect::Send)),
        Err(Error::WrongIdentity)
    );
    assert_eq!(table.request_reply_teardown(id), Err(Error::WrongIdentity));
    assert!(table.is_claimed(replacement));
    assert!(other.is_claimed(other_id));
}

#[test]
fn live_move_and_empty_reset_preserve_exact_generations() {
    let (mut table, id) = claimed(0);
    let mut ticket = table.begin_reply_step(id).unwrap();
    let mut moved = core::mem::take(&mut table);
    assert_eq!(
        table.record_reply_step(&mut ticket, Outcome::Completed(Effect::Send)),
        Err(Error::WrongIdentity)
    );
    moved
        .record_reply_step(&mut ticket, Outcome::Completed(Effect::Send))
        .unwrap();
    complete(&mut moved, id, Effect::RetireSentReply);
    assert_eq!(moved.finish_reply(id), Some(50));
    assert!(moved.reset(0));
    let new = moved.insert(50).unwrap();
    moved.claim_reply(new, 0, STATUS).unwrap();
    assert_eq!(new.slot(), id.slot());
    assert_ne!(new, id);
    assert_eq!(
        moved.record_reply_step(&mut ticket, Outcome::Completed(Effect::Send)),
        Err(Error::WrongIdentity)
    );
}

#[test]
fn attempt_exhaustion_preserves_ready_owner_without_wraparound() {
    let (mut table, id) = claimed(0);
    table.entries[id.slot]
        .as_mut()
        .unwrap()
        .reply
        .as_mut()
        .unwrap()
        .next_attempt = u64::MAX;
    assert!(matches!(table.begin_reply_step(id), Err(Error::Exhausted)));
    assert_eq!(
        table.reply(id).unwrap().phase,
        Phase::Ready {
            effect: Effect::Send,
            last_error: None
        }
    );
    assert!(table.is_claimed(id));
    assert_eq!(table.take(id), None);
    table.request_reply_teardown(id).unwrap();
    assert!(matches!(table.begin_reply_step(id), Err(Error::Exhausted)));
}
