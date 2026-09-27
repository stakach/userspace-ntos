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

    // An asynchronous call can return while the caller's stack lane remains published.
    catalog.finish(activation).unwrap();
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
    first.finish(first_activation).unwrap();
    first.release_pin(first_pin).unwrap();
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
    first.finish(fresh_activation).unwrap();
    first.release_pin(fresh_pin).unwrap();
    first.unregister_lane(fresh).unwrap();
    second.finish(second_activation).unwrap();
    second.release_pin(second_pin).unwrap();
    second.unregister_lane(other).unwrap();
}
