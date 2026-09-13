use super::*;

const CAP: u64 = 40;
const ERROR: u32 = 0xc000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Payload {
    caller_generation: u64,
    return_status: u32,
    native_call: bool,
    resume_ip: u64,
    resume_sp: u64,
    resume_flags: u64,
}

const PAYLOAD: Payload = Payload {
    caller_generation: 10,
    return_status: 0xc0,
    native_call: false,
    resume_ip: 0x1000,
    resume_sp: 0x2000,
    resume_flags: 0x202,
};

fn published() -> (CurrentApcTable<Payload>, CurrentApcIdentity) {
    let mut table = CurrentApcTable::new();
    let reservation = table.reserve().unwrap();
    let identity = table.publish(reservation, PAYLOAD, CAP).unwrap();
    (table, identity)
}

fn complete(
    table: &mut CurrentApcTable<Payload>,
    id: CurrentApcIdentity,
    effect: CurrentApcEffect,
) {
    let mut ticket = table.begin_step(id).unwrap();
    assert_eq!(ticket.effect(), effect);
    table
        .record_step(&mut ticket, CurrentApcOutcome::Completed(effect))
        .unwrap();
}

fn at(effect: CurrentApcEffect) -> (CurrentApcTable<Payload>, CurrentApcIdentity) {
    use CurrentApcEffect as E;
    let (mut table, id) = published();
    if matches!(effect, E::RevokeReply | E::RetypeReply) {
        table.request_teardown(id).unwrap();
        table.release_tail(id).unwrap();
        if effect == E::RetypeReply {
            complete(&mut table, id, E::RevokeReply);
        }
    } else {
        table.release_tail(id).unwrap();
        if effect != E::Stage {
            complete(&mut table, id, E::Stage);
        }
        if matches!(effect, E::RetireSentReply | E::ReleaseClaim) {
            complete(&mut table, id, E::Send);
        }
        if effect == E::ReleaseClaim {
            complete(&mut table, id, E::RetireSentReply);
        }
    }
    (table, id)
}

#[test]
fn reserve_before_transfer_and_publish_without_allocating_or_minting_identity() {
    let mut table = CurrentApcTable::new();
    let reservation = table.reserve().unwrap();
    let id = reservation.identity();
    let capacity = table.capacity();
    let address = table.rows.get_exact(id.0).unwrap() as *const Slot<Payload>;
    assert_eq!(
        table.publish(reservation, PAYLOAD, 0),
        Err(CurrentApcError::InvalidReply)
    );
    assert!(matches!(table.get(id), Err(CurrentApcError::InvalidPhase)));
    assert!(!table.reset());
    assert_eq!(table.publish(reservation, PAYLOAD, CAP), Ok(id));
    assert_eq!(table.capacity(), capacity);
    assert_eq!(
        table.rows.get_exact(id.0).unwrap() as *const Slot<Payload>,
        address
    );
    assert_eq!(table.get(id).unwrap().payload, PAYLOAD);
    assert_eq!(table.get(id).unwrap().reply_cap, CAP);
    assert_eq!(
        table.publish(reservation, PAYLOAD, CAP + 1),
        Err(CurrentApcError::InvalidPhase)
    );
    assert_eq!(
        table.cancel_reserved(reservation),
        Err(CurrentApcError::InvalidPhase)
    );
    let second = table.reserve().unwrap();
    assert_eq!(
        table.publish(second, PAYLOAD, CAP),
        Err(CurrentApcError::InvalidReply)
    );
    table.cancel_reserved(second).unwrap();
}

#[test]
fn await_tail_excludes_effects_and_teardown_retains_active_syscall_context() {
    let (mut table, id) = published();
    assert_eq!(table.get(id).unwrap().phase, CurrentApcPhase::AwaitTail);
    assert_eq!(table.next_ready_after(None), None);
    assert!(matches!(
        table.begin_step(id),
        Err(CurrentApcError::InvalidPhase)
    ));
    assert!(table.finish(id).is_none());
    table.request_teardown(id).unwrap();
    assert_eq!(table.get(id).unwrap().phase, CurrentApcPhase::AwaitTail);
    assert!(table.has_runtime_dependency_matching(|_| true));
    assert!(table.has_owned_matching(|_| true));
    assert_eq!(table.next_ready_after(None), None);
    table.release_tail(id).unwrap();
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.next_ready_after(None), Some(id));
    assert!(matches!(
        table.get(id).unwrap().phase,
        CurrentApcPhase::Ready {
            effect: CurrentApcEffect::RevokeReply,
            ..
        }
    ));
    assert_eq!(table.release_tail(id), Err(CurrentApcError::InvalidPhase));
}

#[test]
fn stage_send_cap_retirement_and_claim_cleanup_are_separate_receipts() {
    let (mut table, id) = at(CurrentApcEffect::Stage);
    complete(&mut table, id, CurrentApcEffect::Stage);
    complete(&mut table, id, CurrentApcEffect::Send);
    assert_eq!(table.get(id).unwrap().reply_cap, CAP);
    assert!(table.finish(id).is_none());
    complete(&mut table, id, CurrentApcEffect::RetireSentReply);
    assert_eq!(table.get(id).unwrap().reply_cap, 0);
    assert!(table.finish(id).is_none());
    complete(&mut table, id, CurrentApcEffect::ReleaseClaim);
    assert!(table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.finish(id), Some(PAYLOAD));
    assert!(table.is_empty());
    assert!(!table.has_runtime_dependency_matching(|_| true));
}

#[test]
fn definite_refusals_retry_only_current_effect_and_wrong_receipts_do_not_consume_ticket() {
    for effect in [
        CurrentApcEffect::Stage,
        CurrentApcEffect::Send,
        CurrentApcEffect::RetireSentReply,
        CurrentApcEffect::RevokeReply,
        CurrentApcEffect::RetypeReply,
        CurrentApcEffect::ReleaseClaim,
    ] {
        let (mut table, id) = at(effect);
        let original_cap = table.get(id).unwrap().reply_cap;
        let mut first = table.begin_step(id).unwrap();
        let wrong = if effect == CurrentApcEffect::Stage {
            CurrentApcEffect::Send
        } else {
            CurrentApcEffect::Stage
        };
        assert_eq!(
            table.record_step(&mut first, CurrentApcOutcome::Completed(wrong)),
            Err(CurrentApcError::WrongEffect)
        );
        table
            .record_step(&mut first, CurrentApcOutcome::NotEntered(ERROR))
            .unwrap();
        assert_eq!(
            table.get(id).unwrap().phase,
            CurrentApcPhase::Ready {
                effect,
                last_error: Some(ERROR)
            }
        );
        assert_eq!(table.get(id).unwrap().reply_cap, original_cap);
        let mut retry = table.begin_step(id).unwrap();
        assert_eq!(retry.effect(), effect);
        assert_ne!(retry.attempt, first.attempt);
        assert_eq!(
            table.record_step(&mut first, CurrentApcOutcome::Completed(effect)),
            Err(CurrentApcError::InvalidPhase)
        );
        table
            .record_step(&mut retry, CurrentApcOutcome::Completed(effect))
            .unwrap();
    }
}

#[test]
fn dropped_and_indeterminate_attempts_retain_ownership_and_context_dependencies() {
    for effect in [
        CurrentApcEffect::Stage,
        CurrentApcEffect::Send,
        CurrentApcEffect::RetireSentReply,
        CurrentApcEffect::RevokeReply,
        CurrentApcEffect::RetypeReply,
        CurrentApcEffect::ReleaseClaim,
    ] {
        for uncertain in [false, true] {
            let (mut table, id) = at(effect);
            let mut ticket = table.begin_step(id).unwrap();
            table.request_teardown(id).unwrap();
            if uncertain {
                table
                    .record_step(&mut ticket, CurrentApcOutcome::Indeterminate(ERROR))
                    .unwrap();
            }
            drop(ticket);
            assert!(table.begin_step(id).is_err());
            assert!(table.finish(id).is_none());
            assert_eq!(table.next_ready_after(None), None);
            assert!(table.has_owned_matching(|_| true));
            assert_eq!(
                table.has_runtime_dependency_matching(|_| true),
                matches!(effect, CurrentApcEffect::Stage | CurrentApcEffect::Send)
            );
            assert!(!table.reset());
        }
    }
}

#[test]
fn teardown_after_entered_stage_or_send_uses_the_actual_effect_receipt() {
    for effect in [CurrentApcEffect::Stage, CurrentApcEffect::Send] {
        for accepted in [false, true] {
            let (mut table, id) = at(effect);
            let mut ticket = table.begin_step(id).unwrap();
            table.request_teardown(id).unwrap();
            assert!(table.has_runtime_dependency_matching(|_| true));
            table
                .record_step(
                    &mut ticket,
                    if accepted {
                        CurrentApcOutcome::Completed(effect)
                    } else {
                        CurrentApcOutcome::NotEntered(ERROR)
                    },
                )
                .unwrap();
            let next = if accepted && effect == CurrentApcEffect::Send {
                CurrentApcEffect::RetireSentReply
            } else {
                CurrentApcEffect::RevokeReply
            };
            assert_eq!(table.get(id).unwrap().reply_cap, CAP);
            assert!(!table.has_runtime_dependency_matching(|_| true));
            assert_eq!(table.begin_step(id).unwrap().effect(), next);
        }
    }
}

#[test]
fn teardown_never_clears_reply_until_retype_and_never_deletes_an_accepted_send() {
    let (mut table, id) = at(CurrentApcEffect::RevokeReply);
    complete(&mut table, id, CurrentApcEffect::RevokeReply);
    assert_eq!(table.get(id).unwrap().reply_cap, CAP);
    complete(&mut table, id, CurrentApcEffect::RetypeReply);
    assert_eq!(table.get(id).unwrap().reply_cap, 0);
    complete(&mut table, id, CurrentApcEffect::ReleaseClaim);
    assert!(!table.has_runtime_dependency_matching(|_| true));
    assert_eq!(table.finish(id), Some(PAYLOAD));

    let (mut table, id) = at(CurrentApcEffect::RetireSentReply);
    table.request_teardown(id).unwrap();
    assert_eq!(
        table.begin_step(id).unwrap().effect(),
        CurrentApcEffect::RetireSentReply
    );
}

#[test]
fn stale_and_foreign_reservations_identities_and_tickets_cannot_mutate_new_owner() {
    let mut first = CurrentApcTable::new();
    let mut second = CurrentApcTable::new();
    let a = first.reserve().unwrap();
    let b = second.reserve().unwrap();
    assert_eq!(a.identity().slot(), b.identity().slot());
    assert_ne!(a.identity(), b.identity());
    assert_eq!(
        second.publish(a, PAYLOAD, CAP),
        Err(CurrentApcError::WrongIdentity)
    );
    assert_eq!(
        second.cancel_reserved(a),
        Err(CurrentApcError::WrongIdentity)
    );
    let old = first.publish(a, PAYLOAD, CAP).unwrap();
    let peer = second.publish(b, PAYLOAD, CAP).unwrap();
    first.release_tail(old).unwrap();
    let mut old_ticket = first.begin_step(old).unwrap();
    assert_eq!(
        second.record_step(
            &mut old_ticket,
            CurrentApcOutcome::Completed(CurrentApcEffect::Stage)
        ),
        Err(CurrentApcError::WrongIdentity)
    );
    assert_eq!(second.get(peer).unwrap().phase, CurrentApcPhase::AwaitTail);
    first
        .record_step(
            &mut old_ticket,
            CurrentApcOutcome::Completed(CurrentApcEffect::Stage),
        )
        .unwrap();
    complete(&mut first, old, CurrentApcEffect::Send);
    complete(&mut first, old, CurrentApcEffect::RetireSentReply);
    complete(&mut first, old, CurrentApcEffect::ReleaseClaim);
    first.finish(old).unwrap();
    let next = first.reserve().unwrap();
    let new = first.publish(next, PAYLOAD, CAP).unwrap();
    assert_eq!(old.slot(), new.slot());
    assert_ne!(old, new);
    assert_eq!(
        first.record_step(
            &mut old_ticket,
            CurrentApcOutcome::Completed(CurrentApcEffect::Stage)
        ),
        Err(CurrentApcError::WrongIdentity)
    );
    assert!(first.request_teardown(old).is_err());
    assert_eq!(first.get(new).unwrap().phase, CurrentApcPhase::AwaitTail);
}

#[test]
fn moves_and_empty_reset_preserve_exact_storage_and_attempt_budget() {
    let (table, old) = published();
    let mut moved = alloc::boxed::Box::new(table);
    assert_eq!(moved.get(old).unwrap().payload, PAYLOAD);
    assert!(!moved.reset());
    moved.request_teardown(old).unwrap();
    moved.release_tail(old).unwrap();
    complete(&mut moved, old, CurrentApcEffect::RevokeReply);
    complete(&mut moved, old, CurrentApcEffect::RetypeReply);
    complete(&mut moved, old, CurrentApcEffect::ReleaseClaim);
    moved.finish(old).unwrap();
    let next_attempt = moved.next_attempt;
    let capacity = moved.capacity();
    assert!(moved.reset());
    assert_eq!(moved.next_attempt, next_attempt);
    assert_eq!(moved.capacity(), capacity);
    let reservation = moved.reserve().unwrap();
    let current = moved.publish(reservation, PAYLOAD, CAP).unwrap();
    assert_ne!(old, current);
    assert!(moved.get(old).is_err());
}

#[test]
fn attempt_budget_exhaustion_refuses_before_entering_effect_and_keeps_owner() {
    let (mut table, id) = at(CurrentApcEffect::Stage);
    table.next_attempt = u64::MAX;
    let mut last = table.begin_step(id).unwrap();
    table
        .record_step(&mut last, CurrentApcOutcome::NotEntered(ERROR))
        .unwrap();
    assert!(matches!(
        table.begin_step(id),
        Err(CurrentApcError::Exhausted)
    ));
    assert_eq!(
        table.get(id).unwrap().phase,
        CurrentApcPhase::Ready {
            effect: CurrentApcEffect::Stage,
            last_error: Some(ERROR)
        }
    );
    assert_eq!(table.get(id).unwrap().reply_cap, CAP);
    assert!(table.has_owned_matching(|_| true));
}
