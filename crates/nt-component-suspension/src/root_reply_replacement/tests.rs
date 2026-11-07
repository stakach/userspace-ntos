use super::*;

fn two_replies() -> (RootReplySlotTable, RootReplyIdentity, RootReplyIdentity) {
    let mut table = RootReplySlotTable::new(2).unwrap();
    let active = table.insert_used(10).unwrap();
    let spare = table.insert_free(20).unwrap();
    (table, active, spare)
}

#[test]
fn simultaneous_pumps_cannot_reserve_one_replacement() {
    let (mut table, active, spare) = two_replies();
    let first = table.reserve_first(active, |_| true).unwrap();
    assert_eq!(first.replacement(), spare);
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Reserved));
    assert_eq!(
        table.reserve_first(active, |_| true),
        Err(RootReplyReplacementError::NoFreeReply)
    );
    assert_eq!(table.state(active), Ok(RootReplySlotState::Used));
}

#[test]
fn ordinary_completion_releases_only_its_exact_no_effect_lease() {
    let (mut table, active, spare) = two_replies();
    let first = table.reserve(active, spare).unwrap();
    assert_eq!(table.cancel_no_effects(first), Ok(spare));
    let second = table.reserve(active, spare).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        table.cancel_no_effects(first),
        Err(RootReplyReplacementError::StaleLease)
    );
    assert_eq!(
        table.commit(first),
        Err(RootReplyReplacementError::StaleLease)
    );
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Reserved));
    assert_eq!(table.commit(second), Ok(spare));
}

#[test]
fn committed_replacement_keeps_original_reply_used_until_its_ack() {
    let (mut table, active, spare) = two_replies();
    let lease = table.reserve(active, spare).unwrap();
    assert_eq!(table.commit(lease), Ok(spare));
    assert_eq!(table.state(active), Ok(RootReplySlotState::Used));
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Used));
    assert_eq!(
        table.cancel_no_effects(lease),
        Err(RootReplyReplacementError::StaleLease)
    );
    // Native has now published spare as its main selector. Neither main nor the original may be
    // released on the strength of a copied numeric cap alone.
    assert_eq!(
        table.retire_used(spare, Some(spare)),
        Err(RootReplyReplacementError::ActiveReply)
    );
    let recycled = table.retire_used(active, Some(spare)).unwrap();
    assert_eq!(recycled.cap(), active.cap());
    assert_ne!(recycled, active);
    assert_eq!(
        table.state(active),
        Err(RootReplyReplacementError::StaleIdentity)
    );
    assert_eq!(
        table.reserve(spare, active),
        Err(RootReplyReplacementError::StaleIdentity)
    );
    assert_eq!(
        table.reserve(spare, recycled).unwrap().replacement(),
        recycled
    );
}

#[test]
fn main_slot_zero_does_not_release_a_hosted_reply_or_a_reservation() {
    let (mut table, hosted, spare) = two_replies();
    let lease = table.reserve(hosted, spare).unwrap();
    // The native hosted owner has parked the Call and set REPLY_MAIN_SLOT=0. The table has no
    // duplicate main selector, and both Replies remain owned until an exact acknowledgement.
    let current_main = None;
    assert_eq!(table.state(hosted), Ok(RootReplySlotState::Used));
    assert_eq!(
        table.clear(spare, current_main),
        Err(RootReplyReplacementError::ReservedReply)
    );
    assert_eq!(table.cancel_no_effects(lease), Ok(spare));
    assert_eq!(table.state(hosted), Ok(RootReplySlotState::Used));
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Free));
}

#[test]
fn vacant_slot_reuse_changes_incarnation_and_rejects_stale_identity() {
    let (mut table, active, spare) = two_replies();
    let initial_records = table.len();
    assert_eq!(table.clear(spare, Some(active)), Ok(()));
    assert_eq!(
        table.slot_state(spare.slot()),
        Some(RootReplySlotState::Vacant)
    );
    assert_eq!(
        table.state(spare),
        Err(RootReplyReplacementError::StaleIdentity)
    );
    let reused = table.insert_free(30).unwrap();
    assert_eq!(reused.slot(), spare.slot());
    assert_eq!(table.len(), initial_records);
    assert_ne!(reused, spare);
    assert_eq!(
        table.reserve(active, spare),
        Err(RootReplyReplacementError::StaleIdentity)
    );
    assert_eq!(table.reserve(active, reused).unwrap().replacement(), reused);
}

#[test]
fn fresh_spare_can_be_registered_and_held_ingress_cap_is_skipped() {
    let mut table = RootReplySlotTable::new(1).unwrap();
    let active = table.insert_used(10).unwrap();
    assert_eq!(
        table.reserve_first(active, |_| true),
        Err(RootReplyReplacementError::NoFreeReply)
    );
    assert_eq!(
        table.insert_free(0),
        Err(RootReplyReplacementError::InvalidCap)
    );
    let held = table.insert_free(20).unwrap();
    let spare = table.insert_free(30).unwrap();
    assert_eq!(
        table.insert_free(30),
        Err(RootReplyReplacementError::DuplicateCap)
    );
    let lease = table.reserve_first(active, |cap| cap != 20).unwrap();
    assert_eq!(lease.replacement(), spare);
    assert_eq!(table.state(held), Ok(RootReplySlotState::Free));
    assert_eq!(table.commit(lease), Ok(spare));
}

#[test]
fn another_table_cannot_use_a_matching_cap_and_slot_number() {
    let (mut first, active, spare) = two_replies();
    let (mut second, second_active, second_spare) = two_replies();
    let lease = first.reserve(active, spare).unwrap();
    assert_eq!(
        second.reserve(active, second_spare),
        Err(RootReplyReplacementError::StaleIdentity)
    );
    assert_eq!(
        second.commit(lease),
        Err(RootReplyReplacementError::StaleLease)
    );
    assert_eq!(second.state(second_active), Ok(RootReplySlotState::Used));
}

#[test]
fn used_and_live_counts_distinguish_reserved_and_vacant() {
    let (mut table, active, spare) = two_replies();
    assert_eq!(
        (table.len(), table.live_count(), table.used_count()),
        (2, 2, 1)
    );
    let lease = table.reserve(active, spare).unwrap();
    assert_eq!((table.live_count(), table.used_count()), (2, 1));
    table.cancel_no_effects(lease).unwrap();
    table.clear(spare, Some(active)).unwrap();
    assert_eq!(
        (table.len(), table.live_count(), table.used_count()),
        (2, 1, 1)
    );
}

#[test]
fn already_free_main_reply_can_rotate_to_a_new_hosted_call() {
    let (mut table, old_main, spare) = two_replies();
    // A prior acknowledged Reply has returned the cap to the free pool while the root's
    // receive selector still names it. Releasing it again during hosted delivery is harmless.
    let old_free = table.retire_used(old_main, None).unwrap();
    let hosted = table.insert_used(30).unwrap();
    assert_eq!(table.replace_main_after_free_observation(old_free, hosted), Ok(()));
    assert_eq!(table.state(old_free), Ok(RootReplySlotState::Free));
    assert_eq!(table.state(hosted), Ok(RootReplySlotState::Used));
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Free));
}

#[test]
fn hosted_import_refusal_clears_only_exact_new_reply_or_retains_its_effect() {
    let (mut table, original_main, reserved_main) = two_replies();
    let _reservation = table.reserve(original_main, reserved_main).unwrap();
    let incoming = table.insert_used(30).unwrap();
    assert_eq!(
        table.replace_main_after_free_observation(reserved_main, incoming),
        Err(RootReplyReplacementError::ReservedReply)
    );
    assert_eq!(table.clear(incoming, Some(reserved_main)), Ok(()));
    assert_eq!(table.state(reserved_main), Ok(RootReplySlotState::Reserved));
    assert_eq!(table.find_cap(30), None);

    let incoming = table.insert_used(30).unwrap();
    assert_eq!(
        table.clear(incoming, Some(incoming)),
        Err(RootReplyReplacementError::ActiveReply)
    );
    assert_eq!(table.state(incoming), Ok(RootReplySlotState::Used));
    assert_eq!(table.state(reserved_main), Ok(RootReplySlotState::Reserved));
}

#[test]
fn hosted_main_rotation_checks_both_slots_before_releasing_old_main() {
    let (mut table, old_main, spare) = two_replies();
    assert_eq!(
        table.replace_main_after_free_observation(old_main, spare),
        Err(RootReplyReplacementError::NotUsed)
    );
    assert_eq!(table.state(old_main), Ok(RootReplySlotState::Used));
    let hosted = table.insert_used(30).unwrap();
    assert_eq!(table.replace_main_after_free_observation(old_main, hosted), Ok(()));
    assert_eq!(table.state(old_main), Err(RootReplyReplacementError::StaleIdentity));
    assert_eq!(table.find_cap(10).and_then(|id| table.state(id).ok()), Some(RootReplySlotState::Free));
    assert_eq!(table.state(hosted), Ok(RootReplySlotState::Used));
}

#[test]
fn private_reply_deletion_rotates_both_slot_states_before_main_changes() {
    let (mut table, active, spare) = two_replies();
    let lease = table.reserve(active, spare).unwrap();
    let (new_main, old_free) = table.commit_retiring_active(lease, RootReplyRetypeOutcome::Acknowledged).unwrap();
    let old_free = old_free.unwrap();
    assert_eq!(new_main, spare);
    assert_eq!(old_free.cap(), active.cap());
    assert_ne!(old_free, active);
    assert_eq!(
        table.state(active),
        Err(RootReplyReplacementError::StaleIdentity)
    );
    assert_eq!(table.state(old_free), Ok(RootReplySlotState::Free));
    assert_eq!(table.state(new_main), Ok(RootReplySlotState::Used));
    assert_eq!(
        table.commit_retiring_active(lease, RootReplyRetypeOutcome::Acknowledged),
        Err(RootReplyReplacementError::StaleLease)
    );
}

#[test]
fn reserve_refuses_when_post_delete_retirement_would_exhaust_generation() {
    let (mut table, active, spare) = two_replies();
    table.next_generation = u64::MAX - 1;

    // A successful reservation authorizes the native delete. Its later retirement commit
    // must therefore have already secured every generation it needs.
    assert_eq!(
        table.reserve(active, spare),
        Err(RootReplyReplacementError::NoCapacity)
    );
    assert_eq!(table.state(active), Ok(RootReplySlotState::Used));
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Free));
}

#[test]
fn failed_old_retype_never_returns_deleted_cap_to_free_pool() {
    let (mut table, active, spare) = two_replies();
    let lease = table.reserve(active, spare).unwrap();
    assert_eq!(
        table.commit_retiring_active(lease, RootReplyRetypeOutcome::NoEffects),
        Ok((spare, None))
    );
    assert_eq!(
        table.slot_state(active.slot()),
        Some(RootReplySlotState::Vacant)
    );
    assert_eq!(table.find_cap(active.cap()), None);
    assert_eq!(table.find_free(|_| true), None);
}

#[test]
fn uncertain_old_retype_retains_cap_outside_the_free_pool() {
    let (mut table, active, spare) = two_replies();
    let lease = table.reserve(active, spare).unwrap();
    assert_eq!(
        table.commit_retiring_active(lease, RootReplyRetypeOutcome::Uncertain),
        Ok((spare, None))
    );
    assert_eq!(table.find_cap(active.cap()), Some(active));
    assert_eq!(table.state(active), Ok(RootReplySlotState::Quarantined));
    assert_eq!(table.mark_free(active, None), Err(RootReplyReplacementError::QuarantinedReply));
    assert_eq!(table.clear(active, None), Err(RootReplyReplacementError::QuarantinedReply));
    assert_eq!(table.find_free(|_| true), None);
    assert_eq!(table.state(spare), Ok(RootReplySlotState::Used));
}

#[test]
fn uninitialized_static_table_has_zero_stats_and_cannot_claim_a_reply() {
    let mut table = RootReplySlotTable::uninitialized();
    assert!(!table.is_initialized());
    assert_eq!(
        (table.len(), table.live_count(), table.used_count()),
        (0, 0, 0)
    );
    assert_eq!(table.find_cap(10), None);
    assert_eq!(
        table.insert_used(10),
        Err(RootReplyReplacementError::Uninitialized)
    );
    assert_eq!(
        table.insert_free(20),
        Err(RootReplyReplacementError::Uninitialized)
    );
}

#[test]
fn spare_preparation_refuses_exhausted_generation_before_native_allocation() {
    let mut table = RootReplySlotTable::new(0).unwrap();
    table.next_generation = u64::MAX;
    let before = (table.len(), table.live_count(), table.used_count());
    assert_eq!(table.prepare_spare(), Err(RootReplyReplacementError::NoCapacity));
    assert_eq!((table.len(), table.live_count(), table.used_count()), before);
}

#[test]
fn prepared_spare_excludes_reuse_until_exact_publication() {
    let mut table = RootReplySlotTable::new(1).unwrap();
    let lease = table.prepare_spare().unwrap();
    assert_eq!(table.slot_state(0), Some(RootReplySlotState::SparePrepared));
    assert_eq!(table.at(0), None);
    assert_eq!(table.find_free(|_| true), None);
    let independent = table.insert_free(20).unwrap();
    assert_ne!(independent.slot(), 0);
    let bound = table.bind_spare(&lease, 30).unwrap();
    assert_eq!(table.state(bound), Ok(RootReplySlotState::SparePrepared));
    assert_eq!(table.find_free(|_| true), Some(independent));
    assert_eq!(table.publish_spare(lease), Ok(bound));
    assert_eq!(table.state(bound), Ok(RootReplySlotState::Free));
}

#[test]
fn spare_publication_needs_no_generation_after_native_retype() {
    let mut table = RootReplySlotTable::new(0).unwrap();
    let lease = table.prepare_spare().unwrap();
    let bound = table.bind_spare(&lease, 30).unwrap();
    table.next_generation = u64::MAX;
    assert_eq!(table.publish_spare(lease), Ok(bound));
    assert_eq!(table.state(bound), Ok(RootReplySlotState::Free));
}

#[test]
fn uncertain_spare_retype_quarantines_exact_bound_cap() {
    let mut table = RootReplySlotTable::new(0).unwrap();
    let lease = table.prepare_spare().unwrap();
    let bound = table.bind_spare(&lease, 30).unwrap();
    assert_eq!(table.quarantine_spare(lease), Ok(bound));
    assert_eq!(table.find_cap(30), Some(bound));
    assert_eq!(table.state(bound), Ok(RootReplySlotState::Quarantined));
    assert_eq!(table.find_free(|_| true), None);
    assert_eq!(table.mark_free(bound, None), Err(RootReplyReplacementError::QuarantinedReply));
    assert_eq!(table.clear(bound, None), Err(RootReplyReplacementError::QuarantinedReply));
}

#[test]
fn certified_no_effect_spare_cancellation_invalidates_old_lease() {
    let mut table = RootReplySlotTable::new(0).unwrap();
    let lease = table.prepare_spare().unwrap();
    let bound = table.bind_spare(&lease, 30).unwrap();
    let stale = RootReplySpareLease {
        table_generation: lease.table_generation,
        slot: lease.slot,
        slot_generation: lease.slot_generation,
    };
    assert_eq!(table.cancel_spare_no_effects(lease), Ok(()));
    assert_eq!(table.find_cap(30), None);
    let reused = table.insert_free(30).unwrap();
    assert_eq!(reused.slot(), bound.slot());
    assert_ne!(reused, bound);
    assert_eq!(table.publish_spare(stale), Err(RootReplyReplacementError::StaleLease));
}

#[test]
fn duplicate_spare_cap_cannot_displace_existing_reply() {
    let mut table = RootReplySlotTable::new(0).unwrap();
    let existing = table.insert_used(10).unwrap();
    let lease = table.prepare_spare().unwrap();
    assert_eq!(table.bind_spare(&lease, 10), Err(RootReplyReplacementError::DuplicateCap));
    assert_eq!(table.find_cap(10), Some(existing));
    assert_eq!(table.state(existing), Ok(RootReplySlotState::Used));
    assert_eq!(table.cancel_spare_no_effects(lease), Ok(()));
}
