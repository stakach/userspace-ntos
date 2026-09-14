use super::*;

fn fixture() -> (ProviderStackActivationCatalog, ProviderStackLaneHandle) {
    let mut catalog = ProviderStackActivationCatalog::new(3, 4).unwrap();
    let lane = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
    (catalog, lane)
}

#[test]
fn nested_and_sibling_activations_have_independent_irql() {
    let (mut catalog, first) = fixture();
    let second = catalog.register_lane(2, 0x3000, 0x1000).unwrap();
    let outer = catalog.begin(first, 10).unwrap();
    let backing = outer.backing();
    assert_eq!(catalog.raise_irql(outer, 2), Ok(0));
    let inner = catalog.begin(first, 11).unwrap();
    let sibling = catalog.begin(second, 20).unwrap();
    assert_eq!(catalog.current_irql(inner), Ok(0));
    assert_eq!(catalog.current_irql(sibling), Ok(0));
    assert_eq!(catalog.raise_irql(inner, 1), Ok(0));
    assert_eq!(catalog.raise_irql(sibling, 3), Ok(0));
    assert_eq!(catalog.current_irql(inner), Ok(1));
    catalog.lower_irql(inner, 0).unwrap();
    catalog.finish(inner).unwrap();
    assert_eq!(catalog.active(first), Ok(outer));
    assert_eq!(catalog.current_irql(outer), Ok(2));
    assert_eq!(outer.backing(), backing);
    catalog.lower_irql(outer, 0).unwrap();
    catalog.finish(outer).unwrap();
    assert_eq!(catalog.current_irql(sibling), Ok(3));
    catalog.lower_irql(sibling, 0).unwrap();
    catalog.finish(sibling).unwrap();
}

#[test]
fn non_top_and_forged_identity_cannot_read_or_mutate_irql() {
    let (mut catalog, lane) = fixture();
    let outer = catalog.begin(lane, 10).unwrap();
    let inner = catalog.begin(lane, 11).unwrap();
    let mut wrong_dispatch = inner;
    wrong_dispatch.dispatch_id += 1;
    let mut wrong_generation = inner;
    wrong_generation.generation += 1;
    let mut wrong_lane_id = inner;
    wrong_lane_id.lane_id += 1;
    for rejected in [outer, wrong_dispatch, wrong_generation, wrong_lane_id] {
        assert_eq!(
            catalog.current_irql(rejected),
            Err(ProviderStackActivationError::NotTop)
        );
        assert_eq!(
            catalog.raise_irql(rejected, 2),
            Err(ProviderStackActivationError::NotTop)
        );
        assert_eq!(
            catalog.lower_irql(rejected, 0),
            Err(ProviderStackActivationError::NotTop)
        );
        assert_eq!(
            catalog.can_wait(rejected, ProviderWaitTimeoutKind::Poll),
            Err(ProviderStackActivationError::NotTop)
        );
        assert_eq!(
            catalog.finish(rejected),
            Err(ProviderStackActivationError::NotTop)
        );
    }
    assert_eq!(catalog.current_irql(inner), Ok(0));
    catalog.finish(inner).unwrap();
    catalog.finish(outer).unwrap();
}

#[test]
fn finished_activation_and_reused_lane_never_authorize_current_irql() {
    let (mut catalog, lane) = fixture();
    let old = catalog.begin(lane, 10).unwrap();
    catalog.finish(old).unwrap();
    let next = catalog.begin(lane, 10).unwrap();
    assert_ne!(old, next);
    assert_eq!(
        catalog.raise_irql(old, 2),
        Err(ProviderStackActivationError::NotTop)
    );
    assert_eq!(catalog.current_irql(next), Ok(0));
    catalog.finish(next).unwrap();
    catalog.unregister_lane(lane).unwrap();
    let fresh_lane = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
    let fresh = catalog.begin(fresh_lane, 10).unwrap();
    assert_eq!(
        catalog.raise_irql(next, 2),
        Err(ProviderStackActivationError::StaleLane)
    );
    assert_eq!(
        catalog.can_wait(next, ProviderWaitTimeoutKind::Infinite),
        Err(ProviderStackActivationError::StaleLane)
    );
    assert_eq!(catalog.current_irql(fresh), Ok(0));
}

#[test]
fn invalid_direction_and_x64_range_preserve_the_current_level() {
    let (mut catalog, lane) = fixture();
    let activation = catalog.begin(lane, 10).unwrap();
    assert_eq!(catalog.raise_irql(activation, 2), Ok(0));
    assert_eq!(
        catalog.raise_irql(activation, 1),
        Err(ProviderStackActivationError::InvalidIrqlTransition)
    );
    assert_eq!(
        catalog.lower_irql(activation, 3),
        Err(ProviderStackActivationError::InvalidIrqlTransition)
    );
    for invalid in 16..=u8::MAX {
        assert_eq!(
            catalog.raise_irql(activation, invalid),
            Err(ProviderStackActivationError::InvalidIrql)
        );
        assert_eq!(
            catalog.lower_irql(activation, invalid),
            Err(ProviderStackActivationError::InvalidIrql)
        );
        assert_eq!(catalog.current_irql(activation), Ok(2));
    }
    assert_eq!(catalog.raise_irql(activation, 2), Ok(2));
    assert_eq!(catalog.lower_irql(activation, 2), Ok(()));
    assert_eq!(catalog.raise_irql(activation, 15), Ok(2));
    assert_eq!(catalog.current_irql(activation), Ok(15));
    catalog.lower_irql(activation, 0).unwrap();
}

#[test]
fn zero_timeout_poll_has_a_distinct_irql_limit_from_blocking_forms() {
    let (mut catalog, lane) = fixture();
    let activation = catalog.begin(lane, 10).unwrap();
    for level in 0..=15 {
        catalog.raise_irql(activation, level).unwrap();
        assert_eq!(
            catalog.can_wait(activation, ProviderWaitTimeoutKind::Poll),
            Ok(level <= 2)
        );
        for timeout in [
            ProviderWaitTimeoutKind::Infinite,
            ProviderWaitTimeoutKind::Relative,
            ProviderWaitTimeoutKind::Absolute,
        ] {
            assert_eq!(catalog.can_wait(activation, timeout), Ok(level <= 1));
        }
        assert_eq!(catalog.current_irql(activation), Ok(level));
    }
}

#[test]
fn unbalanced_finish_retains_exact_activation_until_restored() {
    let (mut catalog, lane) = fixture();
    let activation = catalog.begin(lane, 10).unwrap();
    catalog.raise_irql(activation, 1).unwrap();
    assert_eq!(
        catalog.finish(activation),
        Err(ProviderStackActivationError::UnbalancedIrql)
    );
    assert_eq!(catalog.active(lane), Ok(activation));
    assert_eq!(catalog.current_irql(activation), Ok(1));
    assert_eq!(
        catalog.unregister_lane(lane),
        Err(ProviderStackActivationError::LaneActive)
    );
    catalog.lower_irql(activation, 0).unwrap();
    catalog.finish(activation).unwrap();
    catalog.unregister_lane(lane).unwrap();
}
