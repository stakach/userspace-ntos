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

// Exact pointer-free legacy SRB/CDB layout emitted by nt_io_manager::ScsiBlockCommand.
fn srb(cdb_len: u8, opcode: u8, flags: u32, transfer: u32) -> [u8; 0x58] {
    let mut srb = [0; 0x58];
    srb[..2].copy_from_slice(&0x58u16.to_le_bytes());
    srb[0x0a] = cdb_len;
    srb[0x0c..0x10].copy_from_slice(&flags.to_le_bytes());
    srb[0x10..0x14].copy_from_slice(&transfer.to_le_bytes());
    srb[0x48] = opcode;
    srb
}

#[test]
fn exact_read_capacity_reads_and_flush_are_proven_nonmutating() {
    let mut capacity = srb(16, 0x9e, 0x40, 32);
    capacity[0x49] = 0x10;
    capacity[0x52..0x56].copy_from_slice(&32u32.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&capacity), PossibleScsiEffect::ProvenReadOnly);

    let mut read10 = srb(10, 0x28, 0x40, 2 * 512);
    read10[0x4a..0x4e].copy_from_slice(&2048u32.to_be_bytes());
    read10[0x4f..0x51].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&read10), PossibleScsiEffect::ProvenReadOnly);

    let mut read16 = srb(16, 0x88, 0x40, 512);
    read16[0x4a..0x52].copy_from_slice(&(u32::MAX as u64 + 1).to_be_bytes());
    read16[0x52..0x56].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&read16), PossibleScsiEffect::ProvenReadOnly);

    assert_eq!(PossibleScsiEffect::from_legacy_srb(&srb(10, 0x35, 0, 0)),
        PossibleScsiEffect::ProvenReadOnly);
}

#[test]
fn exact_write_10_and_16_report_checked_physical_ranges() {
    let mut write10 = srb(10, 0x2a, 0x80, 3 * 512);
    write10[0x4a..0x4e].copy_from_slice(&4096u32.to_be_bytes());
    write10[0x4f..0x51].copy_from_slice(&3u16.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&write10),
        PossibleScsiEffect::Write { lba: 4096, sectors: 3 });

    let mut write16 = srb(16, 0x8a, 0x80, 512);
    write16[0x4a..0x52].copy_from_slice(&(u32::MAX as u64 + 1).to_be_bytes());
    write16[0x52..0x56].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&write16),
        PossibleScsiEffect::Write { lba: u32::MAX as u64 + 1, sectors: 1 });
}

#[test]
fn malformed_unknown_or_unbounded_srb_fails_closed() {
    let mut write = srb(10, 0x2a, 0x80, 512);
    write[0x4a..0x4e].copy_from_slice(&4096u32.to_be_bytes());
    write[0x4f..0x51].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&write[..0x57]),
        PossibleScsiEffect::PossiblyMutating);
    let mut cases = Vec::new();
    let mut changed = write; changed[..2].copy_from_slice(&0x57u16.to_le_bytes()); cases.push(changed);
    let mut changed = write; changed[2] = 1; cases.push(changed);
    let mut changed = write; changed[0x0a] = 16; cases.push(changed);
    let mut changed = write; changed[0x0c..0x10].copy_from_slice(&0xc0u32.to_le_bytes()); cases.push(changed);
    let mut changed = write; changed[0x10..0x14].copy_from_slice(&1024u32.to_le_bytes()); cases.push(changed);
    let mut changed = write; changed[0x4f..0x51].fill(0); cases.push(changed);
    let mut changed = write; changed[0x49] = 1; cases.push(changed);
    let mut changed = write; changed[0x48] = 0x42; cases.push(changed);
    let mut changed = write; changed[0x57] = 1; cases.push(changed);
    let mut overflow = srb(16, 0x8a, 0x80, 1024);
    overflow[0x4a..0x52].copy_from_slice(&u64::MAX.to_be_bytes());
    overflow[0x52..0x56].copy_from_slice(&2u32.to_be_bytes());
    cases.push(overflow);
    for case in cases {
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&case),
            PossibleScsiEffect::PossiblyMutating, "unproven CDB {:x}", case[0x48]);
    }
}
