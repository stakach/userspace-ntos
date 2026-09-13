use super::*;
use nt_io_completion::FileIoMode;

use InlineFileRetirementEffect as Effect;
use InlineFileRetirementError as Error;
use InlineFileRetirementOutcome as Outcome;
use InlineFileRetirementPhase as Phase;

fn owner() -> FileIoBusyOwner {
    FileIoBusyOwner {
        key: FileIoWaitKey::Hosted(17),
        tid: 24,
        mode: FileIoMode::SynchronousAlertable,
    }
}

fn release() -> FileReferenceRelease {
    FileReferenceRelease {
        cleanup_required: false,
        close_required: true,
        device_id: 31,
        port_id: Some(3),
    }
}

fn ready(table: &mut InlineFileRetirementTable) -> InlineFileRetirementIdentity {
    let reservation = table.reserve(owner()).unwrap();
    let id = table.activate(reservation).unwrap();
    table.retire_active(id).unwrap();
    id
}

fn receipt(effect: Effect) -> Outcome {
    match effect {
        Effect::ReleasePolicy => Outcome::PolicyReleased { waiters: 2 },
        Effect::Wake => Outcome::Completed(Effect::Wake),
        Effect::ReleaseReference => Outcome::ReferenceReleased(release()),
        Effect::ReferenceFollowup => Outcome::Completed(Effect::ReferenceFollowup),
    }
}

fn step(table: &mut InlineFileRetirementTable, id: InlineFileRetirementIdentity) {
    let mut attempt = table.begin_step(id).unwrap();
    let outcome = receipt(attempt.effect());
    table.record_step(&mut attempt, outcome).unwrap();
}

#[test]
fn preeffect_reservation_activation_and_pending_transfer_do_not_retire() {
    let mut table = InlineFileRetirementTable::new();
    let reservation = table.reserve(owner()).unwrap();
    let id = reservation.identity();
    let capacity = table.rows.capacity();
    assert_eq!(table.get(id).unwrap().phase, Phase::Reserved);
    assert_eq!(table.active_owner(id), Err(Error::InvalidPhase));
    assert_eq!(table.begin_step(id).unwrap_err(), Error::InvalidPhase);
    assert_eq!(table.transfer_active(id), Err(Error::InvalidPhase));
    assert_eq!(table.finish(id), None);
    assert!(!table.reset());
    assert_eq!(table.next_ready_after(None), None);
    assert_eq!(table.activate(reservation), Ok(id));
    assert_eq!(table.rows.capacity(), capacity);
    assert_eq!(table.active_owner(id), Ok(owner()));
    assert_eq!(table.cancel_reserved(reservation), Err(Error::InvalidPhase));
    assert_eq!(table.activate(reservation), Err(Error::InvalidPhase));
    assert!(!table.reset());
    assert_eq!(table.transfer_active(id), Ok(owner()));
    assert_eq!(table.rows.capacity(), capacity);
    assert_eq!(table.transfer_active(id), Err(Error::WrongIdentity));
    assert!(table.is_empty());
    assert!(table.reset());
}

#[test]
fn cancelled_reservation_cannot_activate_reused_slot() {
    let mut table = InlineFileRetirementTable::new();
    let old = table.reserve(owner()).unwrap();
    assert_eq!(table.cancel_reserved(old), Ok(()));
    let replacement = table.reserve(owner()).unwrap();
    assert_eq!(old.identity().slot(), replacement.identity().slot());
    assert_ne!(old.identity(), replacement.identity());
    assert_eq!(table.cancel_reserved(old), Err(Error::WrongIdentity));
    assert_eq!(table.activate(old), Err(Error::WrongIdentity));
    assert_eq!(
        table.get(replacement.identity()).unwrap().phase,
        Phase::Reserved
    );
    table.cancel_reserved(replacement).unwrap();
}

#[test]
fn exact_receipts_retain_original_owner_and_reference_followup() {
    let mut table = InlineFileRetirementTable::new();
    let id = ready(&mut table);
    assert_eq!(table.transfer_active(id), Err(Error::InvalidPhase));
    assert_eq!(table.retire_active(id), Err(Error::InvalidPhase));
    assert_eq!(table.next_ready_after(None), Some(id));
    let mut policy = table.begin_step(id).unwrap();
    assert_eq!(policy.identity(), id);
    assert_eq!(policy.owner(), owner());
    assert_eq!(policy.policy_waiters(), None);
    assert_eq!(policy.reference_release(), None);
    table
        .record_step(&mut policy, receipt(Effect::ReleasePolicy))
        .unwrap();
    let mut wake = table.begin_step(id).unwrap();
    assert_eq!(wake.policy_waiters(), Some(2));
    table.record_step(&mut wake, receipt(Effect::Wake)).unwrap();
    step(&mut table, id);
    let mut followup = table.begin_step(id).unwrap();
    assert_eq!(followup.reference_release(), Some(release()));
    assert_eq!(followup.owner(), owner());
    table
        .record_step(&mut followup, Outcome::NotEntered(5))
        .unwrap();
    assert_eq!(table.get(id).unwrap().reference_release, Some(release()));
    assert_eq!(table.finish(id), None);
    step(&mut table, id);
    assert_eq!(table.get(id).unwrap().reference_release, Some(release()));
    assert_eq!(table.get(id).unwrap().phase, Phase::Complete);
    assert_eq!(table.next_ready_after(None), Some(id));
    assert_eq!(table.finish(id), Some(owner()));
    assert_eq!(table.finish(id), None);
}

#[test]
fn definite_refusal_retries_only_that_effect_with_single_use_authority() {
    let mut table = InlineFileRetirementTable::new();
    let id = ready(&mut table);
    for effect in [
        Effect::ReleasePolicy,
        Effect::Wake,
        Effect::ReleaseReference,
        Effect::ReferenceFollowup,
    ] {
        let before = table.get(id).unwrap();
        let mut rejected = table.begin_step(id).unwrap();
        assert_eq!(rejected.effect(), effect);
        assert_eq!(table.next_ready_after(None), None);
        assert_eq!(table.begin_step(id).unwrap_err(), Error::InvalidPhase);
        assert_eq!(
            table.record_step(&mut rejected, Outcome::NotEntered(7)),
            Ok(Phase::Ready {
                effect,
                last_error: Some(7),
            })
        );
        let after = table.get(id).unwrap();
        assert_eq!(before.owner, after.owner);
        assert_eq!(before.policy_waiters, after.policy_waiters);
        assert_eq!(before.reference_release, after.reference_release);
        let mut retry = table.begin_step(id).unwrap();
        assert_eq!(retry.effect(), effect);
        assert_ne!(rejected.attempt, retry.attempt);
        assert_eq!(
            table.record_step(&mut rejected, receipt(effect)),
            Err(Error::InvalidPhase)
        );
        table.record_step(&mut retry, receipt(effect)).unwrap();
        assert_eq!(
            table.record_step(&mut retry, receipt(effect)),
            Err(Error::InvalidPhase)
        );
    }
    assert_eq!(table.finish(id), Some(owner()));
}

#[test]
fn uncertain_or_dropped_effect_never_replays_or_disappears() {
    for target in [
        Effect::ReleasePolicy,
        Effect::Wake,
        Effect::ReleaseReference,
        Effect::ReferenceFollowup,
    ] {
        for uncertain in [false, true] {
            let mut table = InlineFileRetirementTable::new();
            let id = ready(&mut table);
            while table.get(id).unwrap().phase != InlineFileRetirementTable::ready(target) {
                step(&mut table, id);
            }
            let mut attempt = table.begin_step(id).unwrap();
            if uncertain {
                table
                    .record_step(&mut attempt, Outcome::Indeterminate(9))
                    .unwrap();
                assert_eq!(
                    table.record_step(&mut attempt, receipt(target)),
                    Err(Error::InvalidPhase)
                );
                assert_eq!(
                    table.get(id).unwrap().phase,
                    Phase::Indeterminate {
                        effect: target,
                        status: 9
                    }
                );
            } else {
                drop(attempt);
                assert!(
                    matches!(table.get(id).unwrap().phase, Phase::Invoking { effect, .. } if effect == target)
                );
            }
            assert_eq!(table.begin_step(id).unwrap_err(), Error::InvalidPhase);
            assert_eq!(table.transfer_active(id), Err(Error::InvalidPhase));
            assert_eq!(table.finish(id), None);
            assert_eq!(table.next_ready_after(None), None);
            assert!(!table.reset());
            assert!(!table.is_empty());
            assert_eq!(table.get(id).unwrap().owner, owner());
            if target == Effect::ReferenceFollowup {
                assert_eq!(table.get(id).unwrap().reference_release, Some(release()));
            }
        }
    }
}

#[test]
fn wrong_receipt_cannot_advance_or_consume_entered_ticket() {
    let mut table = InlineFileRetirementTable::new();
    let id = ready(&mut table);
    for effect in [
        Effect::ReleasePolicy,
        Effect::Wake,
        Effect::ReleaseReference,
        Effect::ReferenceFollowup,
    ] {
        let mut attempt = table.begin_step(id).unwrap();
        let entered = table.get(id).unwrap();
        for wrong in [
            Outcome::Completed(Effect::ReleasePolicy),
            Outcome::Completed(Effect::ReleaseReference),
            receipt(Effect::ReleasePolicy),
            receipt(Effect::Wake),
            receipt(Effect::ReleaseReference),
            receipt(Effect::ReferenceFollowup),
        ] {
            if wrong == receipt(effect) {
                continue;
            }
            assert_eq!(
                table.record_step(&mut attempt, wrong),
                Err(Error::WrongReceipt)
            );
            assert_eq!(table.get(id).unwrap(), entered);
        }
        table.record_step(&mut attempt, receipt(effect)).unwrap();
    }
}

#[test]
fn reference_receipt_is_retained_even_if_followup_must_refuse_it() {
    let mut table = InlineFileRetirementTable::new();
    let id = ready(&mut table);
    step(&mut table, id);
    step(&mut table, id);
    let released = FileReferenceRelease {
        cleanup_required: true,
        close_required: true,
        device_id: 0,
        port_id: Some(u32::MAX),
    };
    let mut attempt = table.begin_step(id).unwrap();
    table
        .record_step(&mut attempt, Outcome::ReferenceReleased(released))
        .unwrap();
    let mut followup = table.begin_step(id).unwrap();
    assert_eq!(followup.reference_release(), Some(released));
    table
        .record_step(&mut followup, Outcome::NotEntered(0xc000000d))
        .unwrap();
    assert_eq!(table.get(id).unwrap().reference_release, Some(released));
    assert_eq!(
        table.get(id).unwrap().phase,
        Phase::Ready {
            effect: Effect::ReferenceFollowup,
            last_error: Some(0xc000000d),
        }
    );
}

#[test]
fn foreign_stale_and_reused_owner_identity_cannot_authorize_effects() {
    let mut original = InlineFileRetirementTable::new();
    let old_id = ready(&mut original);
    let mut ticket = original.begin_step(old_id).unwrap();
    let mut foreign = InlineFileRetirementTable::new();
    let foreign_id = ready(&mut foreign);
    assert_eq!(old_id.slot(), foreign_id.slot());
    assert_ne!(old_id, foreign_id);
    assert_eq!(
        foreign.record_step(&mut ticket, receipt(Effect::ReleasePolicy)),
        Err(Error::WrongIdentity)
    );
    let mut moved = original;
    moved
        .record_step(&mut ticket, receipt(Effect::ReleasePolicy))
        .unwrap();
    step(&mut moved, old_id);
    step(&mut moved, old_id);
    step(&mut moved, old_id);
    moved.finish(old_id).unwrap();
    assert!(moved.reset());
    let replacement = ready(&mut moved);
    assert_eq!(replacement.slot(), old_id.slot());
    assert_ne!(replacement, old_id);
    assert_eq!(
        moved.record_step(&mut ticket, receipt(Effect::ReleasePolicy)),
        Err(Error::WrongIdentity)
    );
    assert_eq!(moved.get(replacement).unwrap().owner, owner());
    assert_eq!(
        moved.get(replacement).unwrap().phase,
        InlineFileRetirementTable::ready(Effect::ReleasePolicy)
    );
}

#[test]
fn invalid_owners_and_exhaustion_do_not_mutate_live_rows() {
    let mut table = InlineFileRetirementTable::new();
    for invalid in [
        FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(0),
            ..owner()
        },
        FileIoBusyOwner {
            key: FileIoWaitKey::LocalOverlay(17),
            ..owner()
        },
        FileIoBusyOwner { tid: 0, ..owner() },
        FileIoBusyOwner {
            tid: u64::MAX,
            ..owner()
        },
        FileIoBusyOwner {
            mode: FileIoMode::Asynchronous,
            ..owner()
        },
    ] {
        assert_eq!(table.reserve(invalid), Err(Error::InvalidOwner));
        assert_eq!(table.slot_len(), 0);
        assert_eq!(table.identity, 0);
        assert_eq!(table.next_generation, 1);
    }
    table.next_generation = u64::MAX;
    let id = ready(&mut table);
    let before = table.get(id).unwrap();
    assert_eq!(table.reserve(owner()), Err(Error::Exhausted));
    assert_eq!(table.get(id).unwrap(), before);
    table.next_attempt = u64::MAX;
    let mut attempt = table.begin_step(id).unwrap();
    table
        .record_step(&mut attempt, Outcome::NotEntered(8))
        .unwrap();
    let refused = table.get(id).unwrap();
    assert_eq!(table.begin_step(id).unwrap_err(), Error::Exhausted);
    assert_eq!(table.get(id).unwrap(), refused);
    assert!(!table.reset());
}

#[test]
fn bounded_cursor_excludes_entered_active_and_reserved_rows() {
    let mut table = InlineFileRetirementTable::new();
    let reserved = table.reserve(owner()).unwrap();
    let active = table.reserve(owner()).unwrap();
    table.activate(active).unwrap();
    let first = ready(&mut table);
    let second = ready(&mut table);
    let _entered = table.begin_step(second).unwrap();
    let third = ready(&mut table);
    for _ in 0..4 {
        step(&mut table, third);
    }
    assert_eq!(table.slot_len(), 5);
    assert_eq!(table.next_ready_after(None), Some(first));
    assert_eq!(table.next_ready_after(Some(first.slot())), Some(third));
    assert_eq!(table.next_ready_after(Some(third.slot())), None);
    assert_eq!(
        table.get(reserved.identity()).unwrap().phase,
        Phase::Reserved
    );
    assert_eq!(table.active_owner(active.identity()), Ok(owner()));
}
