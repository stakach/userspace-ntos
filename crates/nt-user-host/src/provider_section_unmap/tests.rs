use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    route: u64,
    dispatch: u64,
    caller: u64,
    token: u64,
}

fn owner() -> Owner {
    Owner {
        route: 1,
        dispatch: 2,
        caller: 3,
        token: 4,
    }
}

#[test]
fn success_requires_exact_ack_before_retirement() {
    let owner = owner();
    let mut publication = UnmapPublication::new(owner, 0x1000_u64);
    assert_eq!(publication.begin_effect(owner), Ok(()));
    assert_eq!(publication.complete(owner, 0), Ok(()));
    assert_eq!(publication.phase(owner), Ok(UnmapPhase::PublishedUnacknowledged));
    assert_eq!(
        publication.acknowledge(owner),
        Ok(UnmapCompletion {
            view: 0x1000,
            status: 0,
        })
    );
    assert_eq!(publication.phase(owner), Ok(UnmapPhase::Acknowledged));
    assert_eq!(publication.acknowledge(owner), Err(UnmapError::InvalidPhase));
}

#[test]
fn lost_reply_keeps_the_exact_view_and_refuses_replay() {
    let owner = owner();
    let mut publication = UnmapPublication::new(owner, 0x1000_u64);
    publication.begin_effect(owner).unwrap();
    publication.complete(owner, 0).unwrap();
    assert_eq!(publication.retire_dispatch(owner), Ok(UnmapPhase::EffectUncertain));
    assert_eq!(publication.view(owner), Ok(0x1000));
    assert_eq!(publication.begin_effect(owner), Err(UnmapError::InvalidPhase));
    assert_eq!(publication.acknowledge(owner), Err(UnmapError::InvalidPhase));
    assert_eq!(publication.abort_before_effect(owner), Err(UnmapError::InvalidPhase));
}

#[test]
fn wrong_owner_or_token_cannot_mutate_attempt() {
    let owner = owner();
    let mut publication = UnmapPublication::new(owner, 0x1000_u64);
    for wrong in [
        Owner { route: 5, ..owner },
        Owner { dispatch: 5, ..owner },
        Owner { caller: 5, ..owner },
        Owner { token: 5, ..owner },
    ] {
        assert_eq!(publication.begin_effect(wrong), Err(UnmapError::WrongOwner));
        assert_eq!(publication.complete(wrong, 0), Err(UnmapError::WrongOwner));
        assert_eq!(publication.retire_dispatch(wrong), Err(UnmapError::WrongOwner));
        assert_eq!(publication.view(wrong), Err(UnmapError::WrongOwner));
    }
    assert_eq!(publication.phase(owner), Ok(UnmapPhase::Prepared));
}

#[test]
fn error_completion_is_published_and_acknowledged_without_becoming_success() {
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
    let owner = owner();
    let mut publication = UnmapPublication::new(owner, 0x1000_u64);
    publication.begin_effect(owner).unwrap();
    publication.complete(owner, STATUS_INSUFFICIENT_RESOURCES).unwrap();
    assert_eq!(publication.begin_effect(owner), Err(UnmapError::InvalidPhase));
    assert_eq!(
        publication.acknowledge(owner),
        Ok(UnmapCompletion {
            view: 0x1000,
            status: STATUS_INSUFFICIENT_RESOURCES,
        })
    );
}

#[test]
fn retirement_during_effect_is_uncertain_but_pre_effect_retirement_is_definite_abort() {
    let owner = owner();
    let mut prepared = UnmapPublication::new(owner, 0x1000_u64);
    assert_eq!(prepared.retire_dispatch(owner), Ok(UnmapPhase::Aborted));
    assert_eq!(prepared.begin_effect(owner), Err(UnmapError::InvalidPhase));

    let mut in_flight = UnmapPublication::new(owner, 0x2000_u64);
    in_flight.begin_effect(owner).unwrap();
    assert_eq!(in_flight.retire_dispatch(owner), Ok(UnmapPhase::EffectUncertain));
    assert_eq!(in_flight.complete(owner, 0), Err(UnmapError::InvalidPhase));
    assert_eq!(in_flight.begin_effect(owner), Err(UnmapError::InvalidPhase));
    assert_eq!(in_flight.view(owner), Ok(0x2000));
}
