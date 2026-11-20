use super::*;

fn identity(dispatch_id: u64, generation: u64) -> SharedPageLeaseIdentity {
    SharedPageLeaseIdentity {
        dispatch: DispatchContext {
            lane: nt_component_suspension::LaneHandle { index: 3, generation },
            dispatch_id,
            ssn: 0x122f,
            ..DispatchContext::EMPTY
        },
        client: SharedPageClientIdentity {
            pi: 8,
            pid: 96,
            generation,
            tid: 100,
            badge: 30,
            tcb: 0x400,
        },
    }
}

fn snapshot(owner: SharedPageLeaseIdentity, marker: u64) -> SharedPageSnapshot {
    let mut request = [0; SHARED_CALLBACK_REQUEST_WORDS];
    request[0] = owner.dispatch.ssn;
    request[1] = marker;
    SharedPageSnapshot {
        header: CallbackHeader::idle(
            owner.dispatch.dispatch_id, owner.client.pi, owner.client.tid, owner.client.badge,
        ),
        callback_payload: {
            let mut payload = [0; CALLBACK_PAYLOAD_MAX];
            payload[..8].copy_from_slice(&marker.to_le_bytes());
            payload
        },
        publication: SharedCallbackPublication::new(request, [marker; 6]),
        request_owner: owner.client,
        request_ssn: owner.dispatch.ssn,
    }
}

#[test]
fn parked_page_restores_outer_callback_payload_after_nested_overwrite() {
    let outer = identity(91, 1);
    let inner = identity(92, 1);
    let outer_page = snapshot(outer, 0x1234);
    let inner_page = snapshot(inner, 0x5678);
    let mut authority = SharedPageAuthority::<2>::new();
    authority.enter(outer, ReplyToken(core::cell::Cell::new(7))).unwrap();
    assert_eq!(authority.capture_and_park(outer, outer_page), Ok(()));
    authority.enter(inner, ReplyToken(core::cell::Cell::new(8))).unwrap();
    assert_eq!(authority.capture_and_park(inner, inner_page), Ok(()));
    let restored = authority.reacquire(outer).unwrap();
    assert_eq!(&restored.callback_payload[..8], &0x1234u64.to_le_bytes());
    assert_ne!(restored.callback_payload, inner_page.callback_payload);
    assert_eq!(authority.acknowledge_restore(outer,
        SharedPageRestoreEffect::Applied(restored)), Ok(()));
}

#[test]
fn global_page_owner_refuses_a_foreign_request_word_even_with_matching_metadata() {
    let parent = identity(91, 1);
    let mut foreign = snapshot(parent, 4655);
    let mut words = *foreign.publication.request();
    words[0] = 4098;
    foreign.publication = SharedCallbackPublication::new(
        words, *foreign.publication.context(),
    );
    let mut page = SharedPageAuthority::<2>::new();
    page.enter(parent, ReplyToken(core::cell::Cell::new(67220)))
        .unwrap_or_else(|_| panic!("parent owns the physical page"));
    assert_eq!(page.capture_and_park(parent, foreign),
        Err(SharedPageLeaseError::WrongSnapshot));
    assert_eq!(page.capture_and_park(parent, snapshot(parent, 4655)), Ok(()),
        "refused capture must keep the original active owner");
}

#[test]
fn nested_overwrite_hands_full_outer_publication_to_exact_owner_once() {
    let outer = identity(91, 1);
    let mut inner = identity(92, 1);
    inner.client.pi = 7;
    inner.client.tid = 108;
    inner.client.badge = 729;
    let old = snapshot(outer, 4655);
    let new = snapshot(inner, 4098);
    let mut leases = SharedPageLeaseStack::<2>::new();
    assert_eq!(leases.begin(outer), Ok(()));
    assert_eq!(leases.displace(outer, old), Ok(()));
    assert_eq!(leases.begin(inner), Ok(()));
    assert_eq!(leases.finish(inner, Some(new)), Ok(new));
    assert_eq!(leases.finish(outer, None), Ok(old));
    assert_eq!(leases.finish(outer, None), Err(SharedPageLeaseError::Empty));
}

#[test]
fn foreign_stale_duplicate_and_overflow_cannot_take_or_replay_a_lease() {
    let outer = identity(91, 1);
    let mut inner = identity(92, 1);
    inner.client.tid = 108;
    let stale = identity(91, 2);
    let mut leases = SharedPageLeaseStack::<2>::new();
    assert_eq!(leases.begin(outer), Ok(()));
    assert_eq!(leases.begin(outer), Err(SharedPageLeaseError::Duplicate));
    assert_eq!(leases.displace(stale, snapshot(outer, 1)), Err(SharedPageLeaseError::NotTop));
    assert_eq!(leases.begin(inner), Ok(()));
    assert_eq!(leases.begin(identity(93, 1)), Err(SharedPageLeaseError::Capacity));
    assert_eq!(leases.displace(outer, snapshot(outer, 1)), Err(SharedPageLeaseError::NotTop));
    assert_eq!(leases.displace(inner, snapshot(outer, 1)), Err(SharedPageLeaseError::WrongSnapshot));
    let mut mixed = snapshot(inner, 2);
    mixed.request_owner = outer.client;
    assert_eq!(leases.displace(inner, mixed), Err(SharedPageLeaseError::WrongSnapshot));
    assert_eq!(leases.finish(outer, None), Err(SharedPageLeaseError::NotTop));
    assert_eq!(leases.finish(inner, Some(snapshot(inner, 2))), Ok(snapshot(inner, 2)));
    assert_eq!(leases.displace(outer, snapshot(outer, 1)), Ok(()));
    assert_eq!(leases.displace(outer, snapshot(outer, 1)), Err(SharedPageLeaseError::AlreadyDisplaced));
    assert_eq!(leases.finish(stale, None), Err(SharedPageLeaseError::NotTop));
    assert_eq!(leases.finish(outer, None), Ok(snapshot(outer, 1)));
}

#[test]
fn executive_provider_identity_requires_a_complete_zero_client_tuple() {
    let mut executive = identity(93, 1);
    executive.dispatch.ssn = 0;
    executive.client = SharedPageClientIdentity {
        pi: 7, pid: 0, generation: 0, tid: 0, badge: 0, tcb: 0,
    };
    let saved = snapshot(executive, 3);
    let mut leases = SharedPageLeaseStack::<1>::new();
    assert_eq!(leases.begin(executive), Ok(()));
    assert_eq!(leases.finish(executive, Some(saved)), Ok(saved));

    for partial in [
        SharedPageClientIdentity { pid: 96, ..executive.client },
        SharedPageClientIdentity { generation: 1, ..executive.client },
        SharedPageClientIdentity { tid: 100, ..executive.client },
        SharedPageClientIdentity { badge: 30, ..executive.client },
        SharedPageClientIdentity { tcb: 0x400, ..executive.client },
    ] {
        let mut invalid = executive;
        invalid.client = partial;
        assert_eq!(leases.begin(invalid), Err(SharedPageLeaseError::InvalidIdentity));
    }
}

#[test]
fn physical_page_owner_admits_an_authenticated_hosted_zero_ssn_control() {
    let mut hosted = identity(94, 1);
    hosted.dispatch.ssn = 0;
    let saved = snapshot(hosted, 7);
    let mut page = SharedPageAuthority::<1>::new();
    let reply = page.enter(hosted, ReplyToken(core::cell::Cell::new(94)))
        .unwrap_or_else(|_| panic!("the native adapter authenticates the hosted PS request class"));
    assert_eq!(reply.0.get(), 94);
    assert_eq!(page.capture_and_park(hosted, saved), Ok(()));
    assert_eq!(page.reacquire(hosted), Ok(saved));
}

#[test]
fn restored_outer_lease_uses_new_publication_and_refusal_keeps_displaced_owner() {
    let outer = identity(91, 1);
    let inner = identity(92, 1);
    let old = snapshot(outer, 4655);
    let updated = snapshot(outer, 9999);
    let mut leases = SharedPageLeaseStack::<2>::new();
    assert_eq!(leases.begin(outer), Ok(()));
    assert_eq!(leases.displace(outer, old), Ok(()));
    assert_eq!(leases.begin(inner), Ok(()));
    assert_eq!(leases.finish(inner, Some(snapshot(inner, 4098))), Ok(snapshot(inner, 4098)));
    assert_eq!(leases.acknowledge_restore(outer, SharedPageRestoreEffect::NoEffect),
        Err(SharedPageLeaseError::RestoreNotApplied));
    assert_eq!(leases.finish(outer, Some(updated)), Err(SharedPageLeaseError::UnexpectedCurrent));
    assert_eq!(leases.acknowledge_restore(outer, SharedPageRestoreEffect::Applied(old)), Ok(()));
    assert_eq!(leases.finish(outer, Some(updated)), Ok(updated));
}

#[test]
fn uncertain_restore_quarantines_displaced_publication_without_replay() {
    let outer = identity(91, 1);
    let mut leases = SharedPageLeaseStack::<1>::new();
    assert_eq!(leases.begin(outer), Ok(()));
    assert_eq!(leases.displace(outer, snapshot(outer, 1)), Ok(()));
    assert_eq!(leases.acknowledge_restore(outer, SharedPageRestoreEffect::Uncertain),
        Err(SharedPageLeaseError::Uncertain));
    assert_eq!(leases.finish(outer, None), Err(SharedPageLeaseError::Uncertain));
    assert_eq!(leases.acknowledge_restore(outer, SharedPageRestoreEffect::Applied(snapshot(outer, 1))),
        Err(SharedPageLeaseError::Uncertain));
}

#[test]
fn only_live_exact_terminal_child_can_finish_without_publication() {
    let outer = identity(91, 1);
    let inner = identity(92, 1);
    let saved = snapshot(outer, 4655);
    let mut leases = SharedPageLeaseStack::<2>::new();
    assert_eq!(leases.begin(outer), Ok(()));
    assert_eq!(leases.displace(outer, saved), Ok(()));
    assert_eq!(leases.begin(inner), Ok(()));
    assert_eq!(leases.finish(inner, None), Err(SharedPageLeaseError::MissingSnapshot));
    assert_eq!(leases.finish_terminal(outer), Err(SharedPageLeaseError::NotTop));
    assert_eq!(leases.finish_terminal(inner), Ok(()));
    assert_eq!(leases.finish_terminal(outer), Err(SharedPageLeaseError::AlreadyDisplaced));
    assert_eq!(leases.finish(outer, None), Ok(saved));
}

#[derive(Debug)]
struct ReplyToken(core::cell::Cell<u64>);

fn provisional(owner: SharedPageLeaseIdentity, request_kind: u64) -> SharedPageProvisionalIdentity {
    SharedPageProvisionalIdentity {
        dispatch_id: owner.dispatch.dispatch_id,
        client: owner.client,
        request_ssn: owner.dispatch.ssn,
        request_kind,
    }
}

#[test]
fn provisional_owner_fences_writes_before_a_physical_lane_exists() {
    let parent = identity(91, 1);
    let child = identity(92, 1);
    let saved = snapshot(parent, 4655);
    let candidate = provisional(child, 0);
    let mut page = SharedPageAuthority::<2>::new();
    page.enter(parent, ReplyToken(core::cell::Cell::new(91))).unwrap();
    page.capture_and_park(parent, saved).unwrap();

    let reply = page.reserve(candidate, ReplyToken(core::cell::Cell::new(92))).unwrap();
    assert_eq!(reply.0.get(), 92);
    let (_, refused) = page.enter(identity(93, 1), ReplyToken(core::cell::Cell::new(93)))
        .err().expect("no writer can enter during pre-lane effects");
    assert_eq!(refused.0.get(), 93);
    assert_eq!(page.reacquire(parent), Err(SharedPageLeaseError::NotTop));

    let mut wrong_lane_owner = child;
    wrong_lane_owner.client.generation = 2;
    assert_eq!(page.promote(candidate, wrong_lane_owner),
        Err(SharedPageLeaseError::InvalidIdentity));
    assert_eq!(page.promote(candidate, child), Ok(()));
    assert_eq!(page.finish_active(child), Ok(()));
    assert_eq!(page.reacquire(parent), Ok(saved));
}

#[test]
fn provisional_cancellation_requires_certified_no_effect_and_preserves_reply() {
    let first = provisional(identity(91, 1), 0);
    let second = provisional(identity(92, 1), 0);
    let mut page = SharedPageAuthority::<1>::new();
    page.reserve(first, ReplyToken(core::cell::Cell::new(91))).unwrap();
    assert_eq!(page.cancel_reservation(second, SharedPageReservationEffect::NoEffect),
        Err(SharedPageLeaseError::NotTop));
    let (_, reply) = page.reserve(second, ReplyToken(core::cell::Cell::new(92)))
        .err().expect("the first reservation retains the physical page");
    assert_eq!(reply.0.get(), 92);
    assert_eq!(page.cancel_reservation(first, SharedPageReservationEffect::NoEffect), Ok(()));
    assert_eq!(page.reserve(second, reply).unwrap().0.get(), 92);
    assert_eq!(page.cancel_reservation(second, SharedPageReservationEffect::Applied),
        Err(SharedPageLeaseError::Uncertain));
    assert_eq!(page.promote(second, identity(92, 1)), Err(SharedPageLeaseError::Uncertain));
    assert_eq!(page.cancel_reservation(second, SharedPageReservationEffect::NoEffect),
        Err(SharedPageLeaseError::Uncertain));
    assert_eq!(page.reserve(first, ReplyToken(core::cell::Cell::new(91))).err().unwrap().1.0.get(), 91);
}

#[test]
fn provisional_promotion_requires_exact_request_and_dispatch_identity() {
    let owner = identity(91, 1);
    let candidate = provisional(owner, 0);
    let mut page = SharedPageAuthority::<1>::new();
    page.reserve(candidate, ReplyToken(core::cell::Cell::new(91))).unwrap();
    let mut wrong_kind = candidate;
    wrong_kind.request_kind += 1;
    assert_eq!(page.promote(wrong_kind, owner), Err(SharedPageLeaseError::NotTop));
    let mut wrong_ssn = owner;
    wrong_ssn.dispatch.ssn += 1;
    assert_eq!(page.promote(candidate, wrong_ssn), Err(SharedPageLeaseError::InvalidIdentity));
    let mut wrong_dispatch = owner;
    wrong_dispatch.dispatch.dispatch_id += 1;
    assert_eq!(page.promote(candidate, wrong_dispatch), Err(SharedPageLeaseError::InvalidIdentity));
    assert_eq!(page.promote(candidate, owner), Ok(()));
    assert_eq!(page.finish_active(owner), Ok(()));

    let mut invalid = candidate;
    invalid.dispatch_id = 0;
    let (_, reply) = page.reserve(invalid, ReplyToken(core::cell::Cell::new(92)))
        .err().expect("zero dispatch identity cannot reserve the page");
    assert_eq!(reply.0.get(), 92);
}

#[test]
fn global_page_owner_parks_a_full_publication_before_foreign_header_write() {
    let winlogon = identity(91, 1);
    let mut csrss = identity(92, 1);
    csrss.client.pi = 7;
    csrss.client.pid = 80;
    csrss.client.tid = 108;
    csrss.client.badge = 729;
    csrss.client.tcb = 0x500;
    let saved = snapshot(winlogon, 4655);
    let mut page = SharedPageAuthority::<4>::new();

    let reply = page.enter(winlogon, ReplyToken(core::cell::Cell::new(91)))
        .unwrap_or_else(|_| panic!("Winlogon must enter an empty page"));
    assert_eq!(reply.0.get(), 91);
    let blocked = page.enter(csrss, ReplyToken(core::cell::Cell::new(92)));
    let (_, reply) = blocked.err().expect("active Winlogon must fence CSRSS publication");
    assert_eq!(reply.0.get(), 92, "Busy preserves the non-Copy incoming Reply");

    page.capture_and_park(winlogon, saved).expect("full exact page is durable before release");
    let reply = page.enter(csrss, reply)
        .unwrap_or_else(|_| panic!("CSRSS may enter after Winlogon is durably parked"));
    assert_eq!(reply.0.get(), 92);
    assert!(page.reacquire(winlogon).is_err(), "a parked owner cannot overwrite an active child");
    page.finish_active(csrss).expect("only terminal child releases its active publication");
    assert_eq!(page.reacquire(winlogon), Ok(saved));
    assert_eq!(page.acknowledge_restore(winlogon, SharedPageRestoreEffect::Applied(saved)), Ok(()));
    page.finish_active(winlogon).expect("restored parent retires once");
}

#[test]
fn global_page_owner_refuses_stale_reacquire_and_pins_uncertain_effects() {
    let current = identity(91, 1);
    let stale = identity(91, 2);
    let other = identity(92, 1);
    let saved = snapshot(current, 4655);
    let mut page = SharedPageAuthority::<2>::new();
    page.enter(current, ReplyToken(core::cell::Cell::new(91)))
        .unwrap_or_else(|_| panic!("initial owner enters"));
    assert!(page.capture_and_park(stale, saved).is_err(), "wrong generation cannot park");
    page.capture_and_park(current, saved).expect("exact owner parks");
    assert!(page.reacquire(stale).is_err(), "recycled identity cannot restore an old page");
    assert!(page.reacquire(other).is_err(), "foreign dispatch cannot restore the old page");
    assert_eq!(page.reacquire(current), Ok(saved));
    assert_eq!(page.acknowledge_restore(current, SharedPageRestoreEffect::Uncertain),
        Err(SharedPageLeaseError::Uncertain));
    let (_, retained) = page.enter(other, ReplyToken(core::cell::Cell::new(92)))
        .err().expect("uncertain restoration fences all new writers");
    assert_eq!(retained.0.get(), 92);
    assert!(page.finish_active(current).is_err(), "uncertain owner cannot be released or replayed");
    assert!(page.reacquire(current).is_err(), "uncertain restoration cannot be retried");
}

#[test]
fn wrong_applied_restore_quarantines_both_page_owners() {
    let outer = identity(91, 1);
    let other = identity(92, 1);
    let saved = snapshot(outer, 4655);
    let wrong = snapshot(outer, 9999);

    let mut leases = SharedPageLeaseStack::<1>::new();
    leases.begin(outer).unwrap();
    leases.displace(outer, saved).unwrap();
    assert_eq!(leases.acknowledge_restore(outer, SharedPageRestoreEffect::Applied(wrong)),
        Err(SharedPageLeaseError::WrongSnapshot));
    assert_eq!(leases.acknowledge_restore(outer, SharedPageRestoreEffect::Applied(saved)),
        Err(SharedPageLeaseError::Uncertain),
        "an applied foreign publication cannot be retried as the saved page");
    assert_eq!(leases.finish(outer, None), Err(SharedPageLeaseError::Uncertain));

    let mut page = SharedPageAuthority::<1>::new();
    page.enter(outer, ReplyToken(core::cell::Cell::new(91))).unwrap();
    page.capture_and_park(outer, saved).unwrap();
    assert_eq!(page.reacquire(outer), Ok(saved));
    assert_eq!(page.acknowledge_restore(outer, SharedPageRestoreEffect::Applied(wrong)),
        Err(SharedPageLeaseError::WrongSnapshot));
    assert_eq!(page.acknowledge_restore(outer, SharedPageRestoreEffect::Applied(saved)),
        Err(SharedPageLeaseError::Uncertain));
    assert_eq!(page.finish_active(outer), Err(SharedPageLeaseError::Uncertain));
    let (_, reply) = page.enter(other, ReplyToken(core::cell::Cell::new(92)))
        .err().expect("wrong applied bytes fence all future publication");
    assert_eq!(reply.0.get(), 92);
}

#[test]
fn audit_repairs_leave_the_authority_consistent_for_the_next_transition() {
    let mut authority = SharedPageAuthority::<4>::new();
    let first = identity(10, 1);
    let second = identity(11, 1);
    assert_eq!(authority.audit_holder(), SharedPageAuditHolder::None);
    authority.enter(first, ()).unwrap();
    assert_eq!(authority.audit_holder(), SharedPageAuditHolder::Active(10));
    // A missed park: the second dispatch is refused, then audit forces it active.
    assert_eq!(authority.enter(second, ()).err().map(|(error, _)| error), Some(SharedPageLeaseError::NotTop));
    authority.audit_force_active(second);
    assert_eq!(authority.audit_holder(), SharedPageAuditHolder::Active(11));
    // A forced park is reacquirable and a forced clear forgets the dispatch.
    authority.audit_force_park(second, snapshot(second, 7));
    assert!(!authority.is_held());
    assert_eq!(authority.reacquire(second), Ok(snapshot(second, 7)));
    authority.audit_force_clear(11);
    assert!(!authority.is_held());
    assert_eq!(authority.reacquire(second), Err(SharedPageLeaseError::Empty));
    authority.enter(first, ()).unwrap();
    authority.finish_active(first).unwrap();
}

// #419 boot 44647857225: the provider-finalizer callout for a process whose last thread has
// retired named pi/tid 7/0 and was refused as an invalid identity.
#[test]
fn process_scoped_finalizer_callout_owns_the_page_without_a_thread() {
    let mut finalizer = identity(13, 1);
    finalizer.dispatch.ssn = 0;
    finalizer.client = SharedPageClientIdentity {
        pi: 7, pid: 76, generation: 1, tid: 0, badge: 30, tcb: 0,
    };
    let mut page = SharedPageAuthority::<1>::new();
    page.enter(finalizer, ()).unwrap_or_else(|_| panic!("a process-scoped callout is a real owner"));
    assert_eq!(page.settle(finalizer, SharedPagePumpSettlement::Completed), Ok(()));
    // A thread identity still needs its whole tuple.
    for partial in [
        SharedPageClientIdentity { tcb: 0x400, ..finalizer.client },
        SharedPageClientIdentity { generation: 0, ..finalizer.client },
        SharedPageClientIdentity { pid: 0, ..finalizer.client },
    ] {
        let mut invalid = finalizer;
        invalid.client = partial;
        assert_eq!(page.enter(invalid, ()).err().map(|(error, _)| error),
            Some(SharedPageLeaseError::InvalidIdentity));
    }
}

// #419 boot 44647857225: a provider-wait resume that waited again built its pending record
// without parking, so every later resume of the same dispatch found it still active (not-top)
// and every root ingress found the page held. Each pump return settles the page once.
#[test]
fn a_resumed_dispatch_that_waits_again_parks_before_its_next_resume() {
    let waiter = identity(92, 1);
    let root = identity(95, 1);
    let mut page = SharedPageAuthority::<2>::new();
    page.enter(waiter, ()).unwrap_or_else(|_| panic!("first entry"));
    assert_eq!(page.settle(waiter, SharedPagePumpSettlement::Yielded(Some(snapshot(waiter, 1)))), Ok(()));
    for round in 2..5 {
        let saved = page.reacquire(waiter).expect("the parked waiter takes the page back");
        assert_eq!(page.acknowledge_restore(waiter, SharedPageRestoreEffect::Applied(saved)), Ok(()));
        assert_eq!(page.settle(waiter, SharedPagePumpSettlement::Yielded(Some(snapshot(waiter, round)))),
            Ok(()), "the resumed pump waited again");
        // Between resumes the page is free for an unrelated root dispatch.
        page.enter(root, ()).unwrap_or_else(|_| panic!("the page is free while the waiter is parked"));
        assert_eq!(page.settle(root, SharedPagePumpSettlement::Completed), Ok(()));
    }
    let saved = page.reacquire(waiter).unwrap();
    assert_eq!(page.acknowledge_restore(waiter, SharedPageRestoreEffect::Applied(saved)), Ok(()));
    assert_eq!(page.settle(waiter, SharedPagePumpSettlement::Retained), Ok(()));
    assert_eq!(page.settle(waiter, SharedPagePumpSettlement::Completed), Ok(()));
    assert!(!page.is_held());
}

#[test]
fn a_yield_without_its_exact_page_pins_the_owner() {
    let owner = identity(40, 1);
    let mut page = SharedPageAuthority::<1>::new();
    page.enter(owner, ()).unwrap_or_else(|_| panic!("entry"));
    assert_eq!(page.settle(owner, SharedPagePumpSettlement::Yielded(None)),
        Err(SharedPageLeaseError::MissingSnapshot));
    assert_eq!(page.enter(identity(41, 1), ()).err().map(|(error, _)| error),
        Some(SharedPageLeaseError::Uncertain), "nobody may write over an uncaptured page");
    assert_eq!(page.settle(identity(41, 1), SharedPagePumpSettlement::Retained),
        Err(SharedPageLeaseError::Uncertain));
}

// #419 boot 44647857225: after a refused reacquire the audit repair made the dispatch active,
// so its own correct restore was reported as not-displaced. The repair restores instead.
#[test]
fn audit_repair_of_a_refused_reacquire_judges_the_restore_on_its_own() {
    let owner = identity(91, 1);
    let mut page = SharedPageAuthority::<1>::new();
    page.enter(owner, ()).unwrap_or_else(|_| panic!("entry"));
    assert_eq!(page.reacquire(owner), Err(SharedPageLeaseError::NotTop), "never parked");
    let saved = snapshot(owner, 5);
    page.audit_force_restoring(owner, saved);
    assert_eq!(page.audit_holder(), SharedPageAuditHolder::Restoring(91));
    assert_eq!(page.acknowledge_restore(owner, SharedPageRestoreEffect::Applied(saved)), Ok(()));
    assert_eq!(page.audit_holder(), SharedPageAuditHolder::Active(91));
}
