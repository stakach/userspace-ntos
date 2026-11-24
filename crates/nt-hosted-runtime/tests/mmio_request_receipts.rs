use nt_hosted_runtime::{
    GopPciBarAuthority, MmioRequest, MmioRequestAuthority, MmioRequestBacking,
    MmioRequestLedger, MmioRequestOwner,
    MmioRequestPhase,
};
use nt_pnp_context::{ContextLeaseIdentity, ContextRegistry};
use std::sync::OnceLock;

fn shared_lease() -> ContextLeaseIdentity {
    static LEASE: OnceLock<ContextLeaseIdentity> = OnceLock::new();
    *LEASE.get_or_init(|| {
        let mut registry = ContextRegistry::new();
        registry.publish((), ()).unwrap();
        registry.acquire_active().unwrap().identity()
    })
}

fn different_lease() -> ContextLeaseIdentity {
    let mut registry = ContextRegistry::new();
    registry.publish((), ()).unwrap();
    registry.acquire_active().unwrap().identity()
}

fn make_owner(domain_cookie: u64, device_id: u64) -> MmioRequestOwner {
    MmioRequestOwner {
        domain_id: 7,
        domain_cookie,
        authority: MmioRequestAuthority::Pnp { device_id, context_lease: shared_lease() },
    }
}

fn owner_for_lease(lease: ContextLeaseIdentity) -> MmioRequestOwner {
    MmioRequestOwner {
        domain_id: 7,
        domain_cookie: 11,
        authority: MmioRequestAuthority::Pnp {
            device_id: 23,
            context_lease: lease,
        },
    }
}

fn gop_owner(publication: u64, inventory_generation: u64) -> MmioRequestOwner {
    gop_owner_at(publication, inventory_generation, 1)
}

fn gop_owner_at(publication: u64, inventory_generation: u64, pci_device: u8)
    -> MmioRequestOwner
{
    let bar = GopPciBarAuthority::new(
        0, pci_device, 0, 0, 0xe000_0000, 16,
        0xe000_1000, 0x4000, inventory_generation, 7, 11, publication,
    ).unwrap();
    MmioRequestOwner {
        domain_id: 7,
        domain_cookie: 11,
        authority: MmioRequestAuthority::Gop {
            instance: 4, bar, publication, inventory_generation,
        },
    }
}

fn make_request(owner: MmioRequestOwner) -> MmioRequest {
    MmioRequest {
        owner,
        physical_start: 0xe000_1000,
        length: 0x1000,
        cache: 0,
    }
}

#[test]
fn identical_maps_have_distinct_receipts_and_each_unmap_retires_one() {
    let mut ledger = MmioRequestLedger::new();
    let owner = make_owner(11, 23);
    let first = ledger.prepare(make_request(owner)).unwrap();
    assert_eq!(ledger.phase(first), Some(MmioRequestPhase::Pending));
    ledger.complete(first, 0x7000_1000, MmioRequestBacking::Assigned {
        resource_id: 61,
        mapping_id: 101,
    }).unwrap();
    let second = ledger.prepare(make_request(owner)).unwrap();
    ledger.complete(second, 0x7000_1000, MmioRequestBacking::Assigned {
        resource_id: 61,
        mapping_id: 102,
    }).unwrap();

    assert_ne!(first, second, "each MmMapIoSpace call owns its own receipt");
    assert_eq!(ledger.live_count(), 2);
    let (selected, backing) = ledger.begin_unmap(owner, 0x7000_1000, 0x1000).unwrap();
    assert_eq!(selected, second, "an identical unmap retires just one request");
    assert_eq!(backing, MmioRequestBacking::Assigned {
        resource_id: 61,
        mapping_id: 102,
    });
    ledger.acknowledge_unmap(selected).unwrap();
    assert_eq!(ledger.live_count(), 1);

    let (selected, backing) = ledger.begin_unmap(owner, 0x7000_1000, 0x1000).unwrap();
    assert_eq!(selected, first);
    assert_eq!(backing, MmioRequestBacking::Assigned {
        resource_id: 61,
        mapping_id: 101,
    });
    ledger.acknowledge_unmap(selected).unwrap();
    assert_eq!(ledger.live_count(), 0);
    assert!(ledger.begin_unmap(owner, 0x7000_1000, 0x1000).is_err(),
        "a third unmap is stale and must not replay a resource-manager unmap");
}

#[test]
fn retiring_an_unrelated_request_preserves_duplicate_unmap_order() {
    let mut ledger = MmioRequestLedger::new();
    let owner = make_owner(11, 23);
    let unrelated = make_owner(11, 24);
    let other = ledger.prepare(make_request(unrelated)).unwrap();
    ledger.complete(other, 0x7100_1000, MmioRequestBacking::Assigned {
        resource_id: 62, mapping_id: 100,
    }).unwrap();
    let first = ledger.prepare(make_request(owner)).unwrap();
    ledger.complete(first, 0x7000_1000, MmioRequestBacking::Assigned {
        resource_id: 61, mapping_id: 101,
    }).unwrap();
    let second = ledger.prepare(make_request(owner)).unwrap();
    ledger.complete(second, 0x7000_1000, MmioRequestBacking::Assigned {
        resource_id: 61, mapping_id: 102,
    }).unwrap();
    let (selected, _) = ledger.begin_unmap(unrelated, 0x7100_1000, 0x1000).unwrap();
    ledger.acknowledge_unmap(selected).unwrap();
    let (selected, _) = ledger.begin_unmap(owner, 0x7000_1000, 0x1000).unwrap();
    assert_eq!(selected, second, "an unrelated retirement cannot reorder duplicate calls");
}

#[test]
fn owner_generation_base_and_length_must_match_the_exact_request() {
    let mut ledger = MmioRequestLedger::new();
    let owner = make_owner(11, 23);
    let receipt = ledger.prepare(make_request(owner)).unwrap();
    ledger.complete(receipt, 0x7000_1000, MmioRequestBacking::Assigned {
        resource_id: 61,
        mapping_id: 101,
    }).unwrap();

    for (caller, base, length) in [
        (MmioRequestOwner { domain_id: 8, ..owner }, 0x7000_1000, 0x1000),
        (make_owner(12, 23), 0x7000_1000, 0x1000), // recycled domain generation
        (make_owner(11, 24), 0x7000_1000, 0x1000), // another device in this domain
        (MmioRequestOwner { authority: MmioRequestAuthority::Pnp {
            device_id: 23, context_lease: different_lease(),
        }, ..owner }, 0x7000_1000, 0x1000),
        (owner, 0x7000_1001, 0x1000),         // interior VA
        (owner, 0x7000_1000, 0x0fff),         // shortened length
        (owner, 0x7000_1000, 0x2000),         // expanded length
    ] {
        assert!(ledger.begin_unmap(caller, base, length).is_err());
        assert_eq!(ledger.phase(receipt), Some(MmioRequestPhase::Ready),
            "a rejected unmap must preserve the original request");
        assert_eq!(ledger.live_count(), 1);
    }

    let (selected, _) = ledger.begin_unmap(owner, 0x7000_1000, 0x1000).unwrap();
    assert_eq!(selected, receipt);
    ledger.acknowledge_unmap(selected).unwrap();
}

#[test]
fn equal_numeric_lease_tokens_from_different_registries_are_not_the_same_owner() {
    let mut registry_a = ContextRegistry::new();
    let mut registry_b = ContextRegistry::new();
    registry_a.publish((), ()).unwrap();
    registry_b.publish((), ()).unwrap();
    let lease_a = registry_a.acquire_active().unwrap().identity();
    let lease_b = registry_b.acquire_active().unwrap().identity();
    assert_eq!(lease_a.token(), lease_b.token());
    assert_ne!(lease_a, lease_b, "registry authority distinguishes equal token values");

    let owner_a = owner_for_lease(lease_a);
    let owner_b = owner_for_lease(lease_b);
    let mut ledger = MmioRequestLedger::new();
    let receipt = ledger.prepare(make_request(owner_a)).unwrap();
    ledger.complete(receipt, 0x7000_1000, MmioRequestBacking::Assigned {
        resource_id: 61, mapping_id: 101,
    }).unwrap();
    assert!(ledger.begin_unmap(owner_b, 0x7000_1000, 0x1000).is_err(),
        "an equal token from another authority cannot retire this MMIO request");
    assert_eq!(ledger.phase(receipt), Some(MmioRequestPhase::Ready));
    assert_eq!(ledger.begin_unmap(owner_a, 0x7000_1000, 0x1000).unwrap().0, receipt);
}

#[test]
fn uncertain_map_and_unmap_effects_remain_owned_and_cannot_be_replayed() {
    let mut ledger = MmioRequestLedger::new();
    let owner = make_owner(11, 23);
    let request = make_request(owner);
    let uncertain_map = ledger.prepare(request).unwrap();
    assert!(ledger.prepare(request).is_err(),
        "a pending map must not be admitted again before its outcome is known");
    ledger.mark_map_uncertain(uncertain_map).unwrap();
    assert_eq!(ledger.phase(uncertain_map), Some(MmioRequestPhase::MapUncertain));
    assert!(ledger.prepare(request).is_err(),
        "an ambiguous map effect must fence the same physical request");

    let other_owner = gop_owner(91, 17);
    let mut independent = make_request(other_owner);
    independent.physical_start += 0x2000;
    let live = ledger.prepare(independent).unwrap();
    ledger.complete(live, 0x7100_1000, MmioRequestBacking::Gop {
        publication: 91,
        inventory_generation: 17,
    }).unwrap();
    let (selected, _) = ledger.begin_unmap(other_owner, 0x7100_1000, 0x1000).unwrap();
    assert_eq!(selected, live);
    ledger.mark_unmap_uncertain(selected).unwrap();
    assert_eq!(ledger.phase(live), Some(MmioRequestPhase::UnmapUncertain));
    assert!(ledger.begin_unmap(other_owner, 0x7100_1000, 0x1000).is_err(),
        "an ambiguous unmap effect must not be replayed");
    assert_eq!(ledger.live_count(), 2, "uncertain receipts retain their owners");
}

#[test]
fn uncertain_map_fences_every_overlapping_physical_request() {
    let mut ledger = MmioRequestLedger::new();
    let owner = make_owner(11, 23);
    let uncertain = ledger.prepare(make_request(owner)).unwrap();
    ledger.mark_map_uncertain(uncertain).unwrap();

    let mut overlapping = make_request(make_owner(11, 24));
    overlapping.physical_start += 0x800;
    overlapping.cache = 2;
    assert!(ledger.prepare(overlapping).is_err(),
        "a different owner and cache cannot bypass an uncertain physical alias");
    assert_eq!(ledger.phase(uncertain), Some(MmioRequestPhase::MapUncertain));

    overlapping.physical_start += 0x2000;
    assert!(ledger.prepare(overlapping).is_ok(),
        "a disjoint physical request remains independent");
}

#[test]
fn gop_publication_and_inventory_are_the_lease_without_a_pnp_context() {
    let mut ledger = MmioRequestLedger::new();
    let owner = gop_owner(91, 17);
    let receipt = ledger.prepare(make_request(owner)).unwrap();
    assert!(ledger.complete(receipt, 0x7100_1000, MmioRequestBacking::Gop {
        publication: 92, inventory_generation: 17,
    }).is_err(), "another publication cannot complete this request");
    assert_eq!(ledger.phase(receipt), Some(MmioRequestPhase::Pending));
    ledger.complete(receipt, 0x7100_1000, MmioRequestBacking::Gop {
        publication: 91, inventory_generation: 17,
    }).unwrap();
    assert!(ledger.begin_unmap(gop_owner(91, 18), 0x7100_1000, 0x1000).is_err());
    assert!(ledger.begin_unmap(gop_owner(92, 17), 0x7100_1000, 0x1000).is_err());
    assert!(ledger.begin_unmap(gop_owner_at(91, 17, 2), 0x7100_1000, 0x1000).is_err(),
        "a different PCI function cannot retire the owning BAR projection");
    let (selected, _) = ledger.begin_unmap(owner, 0x7100_1000, 0x1000).unwrap();
    assert_eq!(selected, receipt);
}

#[test]
fn known_effect_free_rejection_can_cancel_only_its_prepared_receipt() {
    let mut ledger = MmioRequestLedger::new();
    let request = make_request(make_owner(11, 23));
    let prepared = ledger.prepare(request).unwrap();
    assert_eq!(ledger.phase(prepared), Some(MmioRequestPhase::Pending));
    ledger.cancel_prepared(prepared).unwrap();
    assert_eq!(ledger.live_count(), 0);
    assert!(ledger.phase(prepared).is_none());
    assert!(ledger.cancel_prepared(prepared).is_err(), "cancel is single use");

    let replacement = ledger.prepare(request).unwrap();
    assert_ne!(prepared, replacement, "retired receipts cannot be reused");
    ledger.mark_map_uncertain(replacement).unwrap();
    assert!(ledger.cancel_prepared(replacement).is_err(),
        "a possibly effected map cannot be cancelled as if it were rejected");
}
