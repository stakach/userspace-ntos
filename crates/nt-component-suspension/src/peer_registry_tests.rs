use super::*;

fn identity(executor: u64) -> PeerIdentity {
    PeerIdentity {
        domain: 1,
        domain_generation: 1,
        executor,
        lane: LaneHandle {
            index: executor as u32,
            generation: 1,
        },
    }
}

fn active(registry: &mut PeerRegistry, executor: u64) -> PeerRoute {
    let mut registration = registry.stage(identity(executor)).unwrap();
    registry.publish(&mut registration).unwrap()
}

#[test]
fn staging_is_invisible_and_publish_consumes_the_exact_registration() {
    let mut registry = PeerRegistry::new(10, 2);
    let mut registration = registry.stage(identity(1)).unwrap();
    let route = registration.route().unwrap();
    assert_eq!(route.endpoint(), 10);
    assert_eq!(route.identity(), identity(1));
    assert_eq!(registry.resolve(route.badge()), None);
    assert_eq!(registry.state(route), Ok((PeerPhase::Staged, 0)));
    assert_eq!(registry.retain(route).unwrap_err(), PeerError::WrongPhase);
    assert_eq!(registry.begin_retirement(route), Err(PeerError::WrongPhase));
    assert_eq!(
        registry.finish_retirement(route),
        Err(PeerError::WrongPhase)
    );
    assert_eq!(registry.publish(&mut registration), Ok(route));
    assert_eq!(registration.route(), None);
    assert_eq!(registry.resolve(route.badge()), Some(route));
    assert_eq!(
        registry.publish(&mut registration),
        Err(PeerError::WrongOwner)
    );
    assert_eq!(
        registry.abort(&mut registration),
        Err(PeerError::WrongOwner)
    );
    assert_eq!(registry.state(route), Ok((PeerPhase::Active, 0)));
}

#[test]
fn wrong_registry_publish_and_abort_preserve_registration_and_both_owners() {
    let mut owner = PeerRegistry::new(10, 1);
    let mut other = PeerRegistry::new(10, 1);
    let mut registration = owner.stage(identity(1)).unwrap();
    let route = registration.route().unwrap();
    let other_route = active(&mut other, 1);
    assert_eq!(other.publish(&mut registration), Err(PeerError::WrongOwner));
    assert_eq!(other.abort(&mut registration), Err(PeerError::WrongOwner));
    assert_eq!(registration.route(), Some(route));
    assert_eq!(owner.state(route), Ok((PeerPhase::Staged, 0)));
    assert_eq!(other.state(other_route), Ok((PeerPhase::Active, 0)));
    assert_eq!(owner.abort(&mut registration), Ok(()));
    assert_eq!(registration.route(), None);
    assert_eq!(owner.state(route), Err(PeerError::WrongOwner));
    assert_eq!(owner.abort(&mut registration), Err(PeerError::WrongOwner));
    assert_eq!(owner.publish(&mut registration), Err(PeerError::WrongOwner));
}

#[test]
fn invalid_identities_do_not_consume_capacity_or_badges() {
    let counter = AtomicU64::new(7);
    let mut registry = PeerRegistry::new(10, 1);
    for invalid in [
        PeerIdentity {
            domain: 0,
            ..identity(1)
        },
        PeerIdentity {
            domain_generation: 0,
            ..identity(1)
        },
        PeerIdentity {
            executor: 0,
            ..identity(1)
        },
        PeerIdentity {
            lane: LaneHandle::INVALID,
            ..identity(1)
        },
    ] {
        assert_eq!(
            registry.stage_with_counter(invalid, &counter).unwrap_err(),
            PeerError::InvalidIdentity
        );
        assert!(registry.entries.is_empty());
        assert_eq!(counter.load(Ordering::Relaxed), 7);
    }
    let mut invalid_endpoint = PeerRegistry::new(0, 1);
    assert_eq!(
        invalid_endpoint
            .stage_with_counter(identity(1), &counter)
            .unwrap_err(),
        PeerError::InvalidIdentity
    );
    assert!(invalid_endpoint.entries.is_empty());
    assert_eq!(counter.load(Ordering::Relaxed), 7);
}

#[test]
fn duplicate_executor_or_physical_lane_is_rejected_in_every_phase() {
    let mut registry = PeerRegistry::new(10, 4);
    let mut registration = registry.stage(identity(1)).unwrap();
    let route = registration.route().unwrap();
    for phase in [PeerPhase::Staged, PeerPhase::Active, PeerPhase::Retiring] {
        if phase == PeerPhase::Active {
            registry.publish(&mut registration).unwrap();
        }
        if phase == PeerPhase::Retiring {
            registry.begin_retirement(route).unwrap();
        }
        let counter = AtomicU64::new(100);
        for duplicate in [
            PeerIdentity {
                domain: 2,
                lane: identity(2).lane,
                ..identity(1)
            },
            PeerIdentity {
                executor: 2,
                ..identity(1)
            },
        ] {
            assert_eq!(
                registry
                    .stage_with_counter(duplicate, &counter)
                    .unwrap_err(),
                PeerError::DuplicatePeer
            );
            assert_eq!(registry.state(route), Ok((phase, 0)));
            assert_eq!(registry.entries.len(), 1);
            assert_eq!(counter.load(Ordering::Relaxed), 100);
        }
    }
}

#[test]
fn equal_lane_handles_in_distinct_domains_or_generations_are_distinct_peers() {
    let mut registry = PeerRegistry::new(10, 3);
    let first = active(&mut registry, 1);
    for peer in [
        PeerIdentity {
            domain: 2,
            executor: 2,
            ..identity(1)
        },
        PeerIdentity {
            domain_generation: 2,
            executor: 3,
            ..identity(1)
        },
    ] {
        let mut registration = registry.stage(peer).unwrap();
        let route = registry.publish(&mut registration).unwrap();
        assert_eq!(route.identity().lane, first.identity().lane);
        assert_ne!(route.badge(), first.badge());
        assert_eq!(registry.resolve(route.badge()), Some(route));
    }
}

#[test]
fn badges_are_not_reused_after_abort_retirement_or_registry_recreation() {
    let mut registry = PeerRegistry::new(10, 1);
    let mut registration = registry.stage(identity(1)).unwrap();
    let aborted = registration.route().unwrap();
    registry.abort(&mut registration).unwrap();
    let retired = active(&mut registry, 1);
    assert!(retired.badge() > aborted.badge());
    registry.begin_retirement(retired).unwrap();
    registry.finish_retirement(retired).unwrap();
    let current = active(&mut registry, 1);
    assert!(current.badge() > retired.badge());
    assert_eq!(registry.resolve(aborted.badge()), None);
    assert_eq!(registry.resolve(retired.badge()), None);
    drop(registry);
    let mut replacement = PeerRegistry::new(10, 1);
    let next = active(&mut replacement, 1);
    assert!(next.badge() > current.badge());
    assert_eq!(replacement.resolve(current.badge()), None);
    assert_eq!(
        replacement.retain(current).unwrap_err(),
        PeerError::WrongOwner
    );
}

#[test]
fn capacity_is_bounded_and_reclaimed_only_on_removal() {
    let counter = AtomicU64::new(100);
    let mut registry = PeerRegistry::new(10, 1);
    let mut registration = registry.stage(identity(1)).unwrap();
    assert_eq!(
        registry
            .stage_with_counter(identity(2), &counter)
            .unwrap_err(),
        PeerError::NoCapacity
    );
    assert_eq!(counter.load(Ordering::Relaxed), 100);
    registry.abort(&mut registration).unwrap();
    let route = active(&mut registry, 2);
    registry.begin_retirement(route).unwrap();
    assert_eq!(
        registry
            .stage_with_counter(identity(3), &counter)
            .unwrap_err(),
        PeerError::NoCapacity
    );
    registry.finish_retirement(route).unwrap();
    assert!(registry.stage(identity(3)).is_ok());
    let mut zero_capacity = PeerRegistry::new(10, 0);
    assert_eq!(
        zero_capacity
            .stage_with_counter(identity(1), &counter)
            .unwrap_err(),
        PeerError::NoCapacity
    );
    assert_eq!(counter.load(Ordering::Relaxed), 100);
}

#[test]
fn badge_exhaustion_never_wraps_or_changes_existing_entries() {
    for value in [0, ENDPOINT_BADGE_MAX + 1, u64::MAX] {
        let counter = AtomicU64::new(value);
        let mut registry = PeerRegistry::new(10, 2);
        let route = active(&mut registry, 1);
        assert_eq!(
            registry
                .stage_with_counter(identity(2), &counter)
                .unwrap_err(),
            PeerError::BadgeExhausted
        );
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(registry.state(route), Ok((PeerPhase::Active, 0)));
        assert_eq!(counter.load(Ordering::Relaxed), value);
    }
    let counter = AtomicU64::new(ENDPOINT_BADGE_MAX);
    let mut registry = PeerRegistry::new(10, 2);
    let registration = registry.stage_with_counter(identity(1), &counter).unwrap();
    assert_eq!(registration.route().unwrap().badge(), ENDPOINT_BADGE_MAX);
    assert_eq!(counter.load(Ordering::Relaxed), ENDPOINT_BADGE_MAX + 1);
    assert_eq!(
        registry
            .stage_with_counter(identity(2), &counter)
            .unwrap_err(),
        PeerError::BadgeExhausted
    );
    assert_eq!(registry.entries.len(), 1);
}

#[test]
fn retirement_stops_lookup_but_accepts_retention_for_draining() {
    let mut registry = PeerRegistry::new(10, 1);
    let route = active(&mut registry, 1);
    let mut first = registry.retain(route).unwrap();
    let mut second = registry.retain(route).unwrap();
    assert_eq!(
        registry.finish_retirement(route),
        Err(PeerError::WrongPhase)
    );
    registry.begin_retirement(route).unwrap();
    assert_eq!(registry.resolve(route.badge()), None);
    assert_eq!(registry.begin_retirement(route), Err(PeerError::WrongPhase));
    let mut queued = registry.retain(route).unwrap();
    assert_eq!(registry.state(route), Ok((PeerPhase::Retiring, 3)));
    assert_eq!(
        registry.finish_retirement(route),
        Err(PeerError::RetainedWork)
    );
    registry.release(&mut second).unwrap();
    registry.release(&mut queued).unwrap();
    assert_eq!(registry.state(route), Ok((PeerPhase::Retiring, 1)));
    assert_eq!(
        registry.finish_retirement(route),
        Err(PeerError::RetainedWork)
    );
    registry.release(&mut first).unwrap();
    registry.finish_retirement(route).unwrap();
    assert_eq!(registry.state(route), Err(PeerError::WrongOwner));
}

#[test]
fn dropping_registration_does_not_release_the_staged_reservation() {
    let mut registry = PeerRegistry::new(10, 1);
    let registration = registry.stage(identity(1)).unwrap();
    let route = registration.route().unwrap();
    drop(registration);
    assert_eq!(registry.resolve(route.badge()), None);
    assert_eq!(registry.state(route), Ok((PeerPhase::Staged, 0)));
    assert_eq!(
        registry.stage(identity(2)).unwrap_err(),
        PeerError::NoCapacity
    );
    assert_eq!(
        registry.stage(identity(1)).unwrap_err(),
        PeerError::DuplicatePeer
    );
}

#[test]
fn dropping_retention_does_not_acknowledge_work() {
    let mut registry = PeerRegistry::new(10, 1);
    let route = active(&mut registry, 1);
    drop(registry.retain(route).unwrap());
    registry.begin_retirement(route).unwrap();
    assert_eq!(registry.state(route), Ok((PeerPhase::Retiring, 1)));
    assert_eq!(
        registry.finish_retirement(route),
        Err(PeerError::RetainedWork)
    );
}

#[test]
fn wrong_owner_and_consumed_release_do_not_change_counts_or_tickets() {
    let mut owner = PeerRegistry::new(10, 1);
    let mut other = PeerRegistry::new(10, 1);
    let route = active(&mut owner, 1);
    let other_route = active(&mut other, 1);
    let mut ticket = owner.retain(route).unwrap();
    assert_eq!(other.release(&mut ticket), Err(PeerError::WrongOwner));
    assert_eq!(ticket.route(), Some(route));
    assert_eq!(owner.state(route), Ok((PeerPhase::Active, 1)));
    assert_eq!(other.state(other_route), Ok((PeerPhase::Active, 0)));
    owner.release(&mut ticket).unwrap();
    assert_eq!(ticket.route(), None);
    assert_eq!(owner.release(&mut ticket), Err(PeerError::WrongOwner));
    assert_eq!(owner.state(route), Ok((PeerPhase::Active, 0)));
}

#[test]
fn retention_count_overflow_fails_without_mutation() {
    let mut registry = PeerRegistry::new(10, 1);
    let route = active(&mut registry, 1);
    registry.entries[0].retained = usize::MAX;
    assert_eq!(registry.retain(route).unwrap_err(), PeerError::NoCapacity);
    assert_eq!(registry.state(route), Ok((PeerPhase::Active, usize::MAX)));
    assert_eq!(registry.resolve(route.badge()), Some(route));
}

#[test]
fn retiring_lookup_routes_only_drainable_peers_without_reusing_badges() {
    let mut registry = PeerRegistry::new(10, 1);
    let mut registration = registry.stage(identity(1)).unwrap();
    let route = registration.route().unwrap();
    assert_eq!(registry.resolve_retiring(route.badge()), None);
    registry.publish(&mut registration).unwrap();
    assert_eq!(registry.resolve_retiring(route.badge()), None);
    registry.begin_retirement(route).unwrap();
    assert_eq!(registry.resolve(route.badge()), None);
    let draining = registry.resolve_retiring(route.badge()).unwrap();
    assert_eq!(draining, route);
    let mut late_call = registry.retain(draining).unwrap();
    assert_eq!(
        registry.finish_retirement(route),
        Err(PeerError::RetainedWork)
    );
    registry.release(&mut late_call).unwrap();
    registry.finish_retirement(route).unwrap();
    assert_eq!(registry.resolve_retiring(route.badge()), None);
    let replacement = active(&mut registry, 1);
    assert_ne!(replacement.badge(), route.badge());
    assert_eq!(registry.resolve_retiring(route.badge()), None);
    assert_eq!(registry.resolve_retiring(replacement.badge()), None);
}
