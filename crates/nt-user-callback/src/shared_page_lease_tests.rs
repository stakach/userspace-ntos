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
    request[0] = marker;
    SharedPageSnapshot {
        header: CallbackHeader::idle(
            owner.dispatch.dispatch_id, owner.client.pi, owner.client.tid, owner.client.badge,
        ),
        publication: SharedCallbackPublication::new(request, [marker; 6]),
        request_owner: owner.client,
        request_ssn: owner.dispatch.ssn,
    }
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
fn executive_provider_identity_admits_zero_client_tuple_and_zero_ssn_only_as_a_unit() {
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
