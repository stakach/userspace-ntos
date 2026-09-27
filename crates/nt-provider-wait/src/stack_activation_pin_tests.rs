use super::*;

#[test]
fn pin_refuses_lane_retirement_until_each_exact_receipt_is_released() {
    let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
    let lane = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
    let activation = catalog.begin(lane, 1).unwrap();
    let (binding, first) = catalog.pin_active_range(activation, 0x1100, 0x10).unwrap();
    let (_, second) = catalog.pin_active_range(activation, 0x1200, 0x20).unwrap();
    assert_eq!(binding, catalog.binding(lane).unwrap());
    assert_eq!(first.handle(), lane);
    assert_eq!(first.range(), (0x1100, 0x10));
    assert_eq!(catalog.validate_pin(first), Ok(binding));

    assert_eq!(
        catalog.finish(activation),
        Err(ProviderStackActivationError::LanePinned)
    );
    assert_eq!(
        catalog.unregister_lane(lane),
        Err(ProviderStackActivationError::LanePinned)
    );
    catalog.release_pin(first).unwrap();
    assert_eq!(
        catalog.validate_pin(first),
        Err(ProviderStackActivationError::StalePin)
    );
    assert_eq!(
        catalog.release_pin(first),
        Err(ProviderStackActivationError::StalePin)
    );
    assert_eq!(
        catalog.unregister_lane(lane),
        Err(ProviderStackActivationError::LanePinned)
    );
    catalog.release_pin(second).unwrap();
    catalog.finish(activation).unwrap();
    catalog.unregister_lane(lane).unwrap();
}

#[test]
fn pin_requires_entire_nonempty_range_inside_one_live_lane() {
    let mut catalog = ProviderStackActivationCatalog::new(2, 1).unwrap();
    let lane = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
    catalog.register_lane(8, 0x2000, 0x1000).unwrap();
    let activation = catalog.begin(lane, 1).unwrap();
    for (address, bytes) in [(0x1100, 0), (0x1ff0, 0x20), (0x3000, 1), (u64::MAX, 2)] {
        assert_eq!(
            catalog.pin_active_range(activation, address, bytes),
            Err(ProviderStackActivationError::AddressOutsideLane)
        );
    }
    assert_eq!(
        catalog.pin_active_range(activation, 0x2100, 0x10),
        Err(ProviderStackActivationError::CrossLaneStorage)
    );
    catalog.finish(activation).unwrap();
    assert_eq!(
        catalog.pin_active_range(activation, 0x1100, 0x10),
        Err(ProviderStackActivationError::NotTop)
    );
}

#[test]
fn colliding_catalogs_and_reused_lane_slot_cannot_release_another_pin() {
    let mut first = ProviderStackActivationCatalog::new(1, 1).unwrap();
    let mut second = ProviderStackActivationCatalog::new(1, 1).unwrap();
    let old = first.register_lane(7, 0x1000, 0x1000).unwrap();
    let other = second.register_lane(7, 0x1000, 0x1000).unwrap();
    assert_eq!(old, other);
    let first_activation = first.begin(old, 1).unwrap();
    let second_activation = second.begin(other, 1).unwrap();
    let (_, first_pin) = first
        .pin_active_range(first_activation, 0x1100, 0x10)
        .unwrap();
    let (_, second_pin) = second
        .pin_active_range(second_activation, 0x1100, 0x10)
        .unwrap();
    assert_eq!(
        first.release_pin(second_pin),
        Err(ProviderStackActivationError::StalePin)
    );
    assert_eq!(
        second.release_pin(first_pin),
        Err(ProviderStackActivationError::StalePin)
    );
    assert_eq!(
        first.unregister_lane(old),
        Err(ProviderStackActivationError::LanePinned)
    );
    assert_eq!(
        first.finish(first_activation),
        Err(ProviderStackActivationError::LanePinned)
    );
    first.release_pin(first_pin).unwrap();
    first.finish(first_activation).unwrap();
    first.unregister_lane(old).unwrap();
    let fresh = first.register_lane(8, 0x1000, 0x1000).unwrap();
    assert_eq!(fresh.slot(), old.slot());
    assert_ne!(fresh.generation(), old.generation());
    let fresh_activation = first.begin(fresh, 2).unwrap();
    let (_, fresh_pin) = first
        .pin_active_range(fresh_activation, 0x1100, 0x10)
        .unwrap();
    assert_eq!(
        first.release_pin(first_pin),
        Err(ProviderStackActivationError::StalePin)
    );
    assert_eq!(
        first.unregister_lane(fresh),
        Err(ProviderStackActivationError::LanePinned)
    );
    first.release_pin(fresh_pin).unwrap();
    first.finish(fresh_activation).unwrap();
    first.unregister_lane(fresh).unwrap();
    second.release_pin(second_pin).unwrap();
    second.finish(second_activation).unwrap();
    second.unregister_lane(other).unwrap();
}

#[test]
fn pin_tracks_exact_activation_across_nested_dispatch() {
    let mut catalog = ProviderStackActivationCatalog::new(1, 3).unwrap();
    let lane = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
    let outer = catalog.begin(lane, 1).unwrap();
    let (binding, outer_pin) = catalog.pin_active_range(outer, 0x1100, 0x10).unwrap();
    let inner = catalog.begin(lane, 2).unwrap();
    assert_eq!(catalog.validate_pin(outer_pin), Ok(binding));
    assert_eq!(
        catalog.pin_active_range(outer, 0x1200, 0x10),
        Err(ProviderStackActivationError::NotTop)
    );
    let (_, inner_pin) = catalog.pin_active_range(inner, 0x1200, 0x10).unwrap();
    assert_eq!(
        catalog.finish(inner),
        Err(ProviderStackActivationError::LanePinned)
    );
    catalog.release_pin(inner_pin).unwrap();
    catalog.finish(inner).unwrap();
    assert_eq!(catalog.validate_pin(outer_pin), Ok(binding));
    assert_eq!(
        catalog.finish(outer),
        Err(ProviderStackActivationError::LanePinned)
    );
    catalog.release_pin(outer_pin).unwrap();
    catalog.finish(outer).unwrap();
    catalog.unregister_lane(lane).unwrap();
}

#[test]
fn pin_rejects_a_forged_or_stale_activation_identity() {
    let mut catalog = ProviderStackActivationCatalog::new(1, 2).unwrap();
    let lane = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
    let first = catalog.begin(lane, 1).unwrap();
    let (_, first_pin) = catalog.pin_active_range(first, 0x1100, 0x10).unwrap();
    let nested = catalog.begin(lane, 2).unwrap();
    let forged = ProviderStackLanePin {
        activation: nested,
        ..first_pin
    };
    assert_eq!(
        catalog.validate_pin(forged),
        Err(ProviderStackActivationError::StalePin)
    );
    assert_eq!(
        catalog.release_pin(forged),
        Err(ProviderStackActivationError::StalePin)
    );
    catalog.finish(nested).unwrap();
    catalog.release_pin(first_pin).unwrap();
    catalog.finish(first).unwrap();
    let next = catalog.begin(lane, 1).unwrap();
    assert_ne!(next, first);
    assert_eq!(
        catalog.validate_pin(first_pin),
        Err(ProviderStackActivationError::StalePin)
    );
    catalog.finish(next).unwrap();
}
