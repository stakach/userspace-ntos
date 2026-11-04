use nt_fs::{InstalledMetadataReadThroughFence, PhysicalSectorRange, PossibleScsiEffect};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Disk { controller: u64, physical_pdo: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Route { mount: u64, relation_generation: u64 }

fn fixture() -> InstalledMetadataReadThroughFence<Disk, Route> {
    InstalledMetadataReadThroughFence::new(
        Disk { controller: 3, physical_pdo: 9 },
        Route { mount: 7, relation_generation: 11 },
        PhysicalSectorRange::new(2048, 1000).unwrap(),
        Some(PhysicalSectorRange::new(4096, 512).unwrap()),
    ).unwrap()
}

#[test]
fn eligibility_requires_exact_authenticated_disk_and_route_generation() {
    let fence = fixture();
    let disk = Disk { controller: 3, physical_pdo: 9 };
    let route = Route { mount: 7, relation_generation: 11 };
    assert!(fence.eligible(&disk, &route));
    assert!(!fence.eligible(&Disk { physical_pdo: 10, ..disk }, &route));
    assert!(!fence.eligible(&disk, &Route { relation_generation: 12, ..route }));
    assert!(!fence.eligible(&disk, &Route { mount: 8, ..route }));
    assert!(!fence.poisoned());
}

#[test]
fn possible_installed_write_poisons_before_effect_and_never_reenables() {
    let fence = fixture();
    let disk = Disk { controller: 3, physical_pdo: 9 };
    let route = Route { mount: 7, relation_generation: 11 };
    fence.before_effect(&disk, PossibleScsiEffect::Write { lba: 2050, sectors: 1 });
    assert!(fence.poisoned());
    assert!(!fence.eligible(&disk, &route));
    // Failure, cancellation, and uncertain completion cannot undo a pre-effect poison.
    fence.before_effect(&disk, PossibleScsiEffect::ProvenReadOnly);
    assert!(!fence.eligible(&disk, &route));
    fence.before_effect(&disk, PossibleScsiEffect::Write { lba: 4096, sectors: 1 });
    assert!(!fence.eligible(&disk, &route));
}

#[test]
fn only_bounded_disjoint_reserve_writes_preserve_read_through() {
    let disk = Disk { controller: 3, physical_pdo: 9 };
    let route = Route { mount: 7, relation_generation: 11 };
    let fence = fixture();
    fence.before_effect(&disk, PossibleScsiEffect::ProvenReadOnly);
    fence.before_effect(&disk, PossibleScsiEffect::Write { lba: 4096, sectors: 512 });
    assert!(fence.eligible(&disk, &route));

    // A write merely outside the installed range is insufficient without the reserve proof.
    fence.before_effect(&disk, PossibleScsiEffect::Write { lba: 5000, sectors: 1 });
    assert!(fence.poisoned());
    for effect in [
        PossibleScsiEffect::Write { lba: 4095, sectors: 2 },
        PossibleScsiEffect::Write { lba: 4607, sectors: 2 },
        PossibleScsiEffect::Write { lba: u64::MAX, sectors: 2 },
        PossibleScsiEffect::Write { lba: 4096, sectors: 0 },
        PossibleScsiEffect::PossiblyMutating,
    ] {
        let fence = fixture();
        fence.before_effect(&disk, effect);
        assert!(fence.poisoned(), "unproven effect: {effect:?}");
    }
}

#[test]
fn wrong_disk_does_not_poison_but_same_disk_new_generation_does() {
    let disk = Disk { controller: 3, physical_pdo: 9 };
    let route = Route { mount: 7, relation_generation: 11 };
    let fence = fixture();
    fence.before_effect(&Disk { controller: 4, ..disk }, PossibleScsiEffect::PossiblyMutating);
    assert!(fence.eligible(&disk, &route));
    // An authenticated later relation to the same physical disk can still mutate old bytes.
    fence.before_effect(&disk, PossibleScsiEffect::PossiblyMutating);
    assert!(!fence.eligible(&disk, &route));
}

#[test]
fn invalid_or_overlapping_geometry_cannot_claim_a_disjoint_reserve() {
    assert!(PhysicalSectorRange::new(5, 0).is_none());
    assert!(PhysicalSectorRange::new(u64::MAX, 2).is_none());
    assert!(InstalledMetadataReadThroughFence::new(
        1u64, 2u64,
        PhysicalSectorRange::new(100, 100).unwrap(),
        Some(PhysicalSectorRange::new(199, 10).unwrap()),
    ).is_none());
}
