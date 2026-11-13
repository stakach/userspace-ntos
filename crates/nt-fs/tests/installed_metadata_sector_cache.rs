use nt_fs::InstalledMetadataSectorCache;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Route {
    mount: u64,
    provider_generation: u64,
}

#[test]
fn reuses_only_exact_mount_route_and_sector() {
    let mut cache = InstalledMetadataSectorCache::<Route, 2>::new();
    let route = Route { mount: 7, provider_generation: 3 };
    let mut sector = [0u8; 512];
    sector[4] = 0xa5;
    assert_eq!(cache.lookup(route, 42), None);
    cache.publish(route, 42, &sector);
    sector.fill(0);

    assert_eq!(cache.lookup(route, 42).map(|bytes| bytes[4]), Some(0xa5));
    assert_eq!(cache.lookup(Route { mount: 8, ..route }, 42), None);
    assert_eq!(cache.lookup(Route { provider_generation: 4, ..route }, 42), None);
    assert_eq!(cache.lookup(route, 43), None);
}

#[test]
fn capacity_is_bounded_and_replacement_is_deterministic() {
    let mut cache = InstalledMetadataSectorCache::<Route, 2>::new();
    let route = Route { mount: 7, provider_generation: 3 };
    assert!(!cache.is_full());
    assert!(!cache.publish(route, 10, &[1; 512]));
    assert!(!cache.is_full());
    assert!(!cache.publish(route, 11, &[2; 512]));
    assert!(cache.is_full());
    assert!(cache.publish(route, 12, &[3; 512]));
    assert_eq!(cache.lookup(route, 10), None);
    assert_eq!(cache.lookup(route, 11).map(|bytes| bytes[0]), Some(2));
    assert_eq!(cache.lookup(route, 12).map(|bytes| bytes[0]), Some(3));

    assert!(!cache.publish(route, 11, &[4; 512]));
    assert_eq!(cache.lookup(route, 11).map(|bytes| bytes[0]), Some(4));
    assert!(cache.publish(route, 13, &[5; 512]));
    assert_eq!(cache.lookup(route, 11).map(|bytes| bytes[0]), Some(4));
    assert_eq!(cache.lookup(route, 12), None);
    assert_eq!(cache.lookup(route, 13).map(|bytes| bytes[0]), Some(5));
}

#[test]
fn invalidation_and_zero_capacity_never_return_old_bytes() {
    let route = Route { mount: 7, provider_generation: 3 };
    let mut cache = InstalledMetadataSectorCache::<Route, 1>::new();
    cache.publish(route, 42, &[1; 512]);
    cache.invalidate();
    assert!(!cache.is_full());
    assert_eq!(cache.lookup(route, 42), None);

    let mut disabled = InstalledMetadataSectorCache::<Route, 0>::new();
    assert!(!disabled.is_full());
    assert!(!disabled.publish(route, 42, &[2; 512]));
    assert_eq!(disabled.lookup(route, 42), None);
}
