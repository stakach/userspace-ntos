use super::*;

fn owner() -> DirectoryQueryOwner<u64, u64, u64> {
    DirectoryQueryOwner {
        route: 1,
        dispatch: 7,
        caller: 11,
        token: 13,
    }
}

#[test]
fn exact_owner_guards_read_mutation_and_ack() {
    let mut snapshots = DirectoryQuerySnapshots::new();
    snapshots.begin(owner(), 42).unwrap();
    for wrong in [
        DirectoryQueryOwner {
            route: 2,
            ..owner()
        },
        DirectoryQueryOwner {
            dispatch: 8,
            ..owner()
        },
        DirectoryQueryOwner {
            caller: 12,
            ..owner()
        },
        DirectoryQueryOwner {
            token: 14,
            ..owner()
        },
    ] {
        assert_eq!(snapshots.get(wrong), Err(DirectoryQueryError::WrongOwner));
        assert_eq!(
            snapshots.get_mut(wrong),
            Err(DirectoryQueryError::WrongOwner)
        );
        assert_eq!(snapshots.ack(wrong), Err(DirectoryQueryError::WrongOwner));
    }
    *snapshots.get_mut(owner()).unwrap() = 43;
    assert_eq!(snapshots.get(owner()), Ok(&43));
    assert_eq!(snapshots.ack(owner()), Ok(43));
    assert_eq!(
        snapshots.ack(owner()),
        Err(DirectoryQueryError::AlreadyAcknowledged)
    );
    assert_eq!(
        snapshots.get(owner()),
        Err(DirectoryQueryError::AlreadyAcknowledged)
    );
}

#[test]
fn multiple_tokens_share_a_dispatch_but_each_is_one_shot() {
    let mut snapshots = DirectoryQuerySnapshots::new();
    snapshots.begin(owner(), 1).unwrap();
    assert_eq!(
        snapshots.begin(owner(), 2),
        Err(DirectoryQueryError::RouteOccupied)
    );
    let next = DirectoryQueryOwner {
        token: 14,
        ..owner()
    };
    snapshots.begin(next, 2).unwrap();
    assert_eq!(snapshots.get(next), Ok(&2));
    assert_eq!(
        snapshots.begin(
            DirectoryQueryOwner {
                dispatch: 8,
                token: 15,
                ..owner()
            },
            3
        ),
        Err(DirectoryQueryError::RouteOccupied)
    );
    snapshots.ack(owner()).unwrap();
    assert_eq!(
        snapshots.begin(owner(), 2),
        Err(DirectoryQueryError::RouteOccupied)
    );
    assert_eq!(snapshots.get(next), Ok(&2));
    snapshots.retire_matching(|entry| {
        entry.route == owner().route && entry.dispatch == owner().dispatch
    });
    assert_eq!(snapshots.get(owner()), Err(DirectoryQueryError::WrongOwner));
    snapshots
        .begin(
            DirectoryQueryOwner {
                dispatch: 8,
                ..owner()
            },
            3,
        )
        .unwrap();
}

#[test]
fn retirement_isolates_other_routes_and_dispatches() {
    let mut snapshots = DirectoryQuerySnapshots::new();
    let other = DirectoryQueryOwner {
        route: 2,
        ..owner()
    };
    snapshots.begin(owner(), 1).unwrap();
    snapshots.begin(other, 2).unwrap();
    snapshots.retire_matching(|entry| entry.route == owner().route && entry.dispatch == 8);
    assert_eq!(snapshots.get(owner()), Ok(&1));
    snapshots.retire_matching(|entry| {
        entry.route == owner().route && entry.dispatch == owner().dispatch
    });
    assert_eq!(snapshots.get(owner()), Err(DirectoryQueryError::WrongOwner));
    assert_eq!(snapshots.get(other), Ok(&2));
}
