use nt_fs::{InstalledMetadataReadThroughFence, PhysicalSectorRange, PossibleScsiEffect};

#[test]
fn only_storage_property_query_is_proven_read_only_device_control() {
    // FILE_DEVICE_MASS_STORAGE, function 0x500, buffered, any access.
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1400, 12, 8),
        PossibleScsiEffect::ProvenReadOnly);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1400, 12, 64),
        PossibleScsiEffect::ProvenReadOnly);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1400, 11, 8),
        PossibleScsiEffect::PossiblyMutating);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1400, 12, 7),
        PossibleScsiEffect::PossiblyMutating);
    // The adjacent property-set control and unknown controls cannot keep copied metadata live.
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_93fc, 12, 8),
        PossibleScsiEffect::PossiblyMutating);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1401, 12, 8),
        PossibleScsiEffect::PossiblyMutating);
}

#[test]
fn storage_device_number_query_cannot_mutate_media() {
    // The disk class issues this buffered query during StartDevice; its result is a
    // 12-byte STORAGE_DEVICE_NUMBER, with no input payload.
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1080, 0, 12),
        PossibleScsiEffect::ProvenReadOnly);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1080, 1, 12),
        PossibleScsiEffect::PossiblyMutating);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x002d_1080, 0, 11),
        PossibleScsiEffect::PossiblyMutating);
}

#[test]
fn disk_geometry_query_cannot_mutate_media() {
    // PartMgr sends this disk-class query while enumerating installed partitions.
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0007_00a0, 0, 40),
        PossibleScsiEffect::ProvenReadOnly);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0007_00a0, 1, 40),
        PossibleScsiEffect::PossiblyMutating);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0007_00a0, 0, 39),
        PossibleScsiEffect::PossiblyMutating);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0007_00a1, 0, 40),
        PossibleScsiEffect::PossiblyMutating);
}

#[test]
fn basic_disk_geometry_query_preserves_read_through_only_for_its_exact_shape() {
    // LiberNT disk class issues the buffered, input-free DISK_GEOMETRY query
    // with its 24-byte output during StartDevice.
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0007_0000, 0, 24),
        PossibleScsiEffect::ProvenReadOnly);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0007_0000, 0, 32),
        PossibleScsiEffect::ProvenReadOnly);
    for (code, input, output) in [
        (0x0007_0000, 1, 24),
        (0x0007_0000, 0, 23),
        (0x0007_0001, 0, 24),
        (0x0007_0004, 0, 24),
    ] {
        assert_eq!(PossibleScsiEffect::from_disk_device_control(code, input, output),
            PossibleScsiEffect::PossiblyMutating);
    }
}

#[test]
fn scsi_address_query_preserves_read_through_only_for_its_exact_shape() {
    // Disk class asks for the 8-byte SCSI_ADDRESS using a buffered query.
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0004_1018, 0, 8),
        PossibleScsiEffect::ProvenReadOnly);
    assert_eq!(PossibleScsiEffect::from_disk_device_control(0x0004_1018, 0, 16),
        PossibleScsiEffect::ProvenReadOnly);
    for (code, input, output) in [
        (0x0004_1018, 1, 8),
        (0x0004_1018, 0, 7),
        (0x0004_1014, 0, 8), // pass-through direct
        (0x0004_101c, 0, 8), // rescan bus
    ] {
        assert_eq!(PossibleScsiEffect::from_disk_device_control(code, input, output),
            PossibleScsiEffect::PossiblyMutating);
    }
}

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
fn classpnp_read_ten_with_port_sense_and_cache_policy_does_not_poison_metadata() {
    // LiberNT ClassPnP's READ(10) reached the native route with DATA_IN,
    // NO_QUEUE_FREEZE, ADAPTER_CACHE_ENABLE and PORT_DRIVER_ALLOCSENSE.
    let mut read = srb(10, 0x28, 0x20_0340, 512);
    read[0x4f..0x51].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&read),
        PossibleScsiEffect::ProvenReadOnly);

    let mut data_out = read;
    data_out[0x0c..0x10].copy_from_slice(&0x20_03c0u32.to_le_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&data_out),
        PossibleScsiEffect::PossiblyMutating);

    let mut unknown_flag = read;
    unknown_flag[0x0c..0x10].copy_from_slice(&0x20_0740u32.to_le_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&unknown_flag),
        PossibleScsiEffect::PossiblyMutating);

    let mut missing_direction = read;
    missing_direction[0x0c..0x10].copy_from_slice(&0x20_0300u32.to_le_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&missing_direction),
        PossibleScsiEffect::PossiblyMutating);

    let mut force_unit_access = read;
    force_unit_access[0x49] = 0x08;
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&force_unit_access),
        PossibleScsiEffect::PossiblyMutating);

    let mut wrong_transfer = read;
    wrong_transfer[0x10..0x14].copy_from_slice(&1024u32.to_le_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&wrong_transfer),
        PossibleScsiEffect::PossiblyMutating);

    let mut write = read;
    write[0x48] = 0x2a;
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&write),
        PossibleScsiEffect::PossiblyMutating);
}

#[test]
fn source_backed_scsi_inquiry_shapes_do_not_mutate_installed_media() {
    let mut standard = srb(6, 0x12, 0x48, 36);
    standard[0x4c] = 36;
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&standard),
        PossibleScsiEffect::ProvenReadOnly);

    let mut vpd = srb(6, 0x12, 0x148, 512);
    vpd[0x49] = 1; // EVPD
    vpd[0x4a] = 0x8f; // token limits page
    vpd[0x4c] = 255; // transfer buffer can be larger than CDB allocation
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&vpd),
        PossibleScsiEffect::ProvenReadOnly);

    for changed in [
        { let mut x = vpd; x[0x0a] = 10; x },
        { let mut x = vpd; x[0x0c..0x10].copy_from_slice(&0x80u32.to_le_bytes()); x },
        { let mut x = vpd; x[0x0c..0x10].copy_from_slice(&0x248u32.to_le_bytes()); x },
        { let mut x = vpd; x[0x10..0x14].fill(0); x },
        { let mut x = vpd; x[0x49] = 2; x },
        { let mut x = vpd; x[0x4b] = 1; x },
        { let mut x = vpd; x[0x4d] = 1; x },
        { let mut x = standard; x[0x4a] = 1; x },
    ] {
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&changed),
            PossibleScsiEffect::PossiblyMutating);
    }
}

#[test]
fn class_inquiry_port_policy_preserves_installed_metadata_read_through() {
    // KVM 41893363837: released disk class sent EVPD INQUIRY(6) with a 255-byte
    // receive buffer and the same port-policy flag used by MODE SENSE(6).
    let mut inquiry = srb(6, 0x12, 0x20_0148, 255);
    inquiry[0x49] = 1; // EVPD
    inquiry[0x4c] = 255;
    assert_eq!(&inquiry[0x48..0x4e], &[0x12, 0x01, 0x00, 0x00, 0xff, 0x00]);
    let effect = PossibleScsiEffect::from_legacy_srb(&inquiry);
    assert_eq!(effect, PossibleScsiEffect::ProvenReadOnly);
    let disk = Disk { controller: 3, physical_pdo: 9 };
    let route = Route { mount: 7, relation_generation: 11 };
    let fence = fixture();
    fence.before_effect(&disk, effect);
    assert!(fence.eligible(&disk, &route));

    for changed in [
        { let mut x = inquiry; x[0x0a] = 10; x },
        { let mut x = inquiry; x[0x0c..0x10].copy_from_slice(&0x20_0108u32.to_le_bytes()); x },
        { let mut x = inquiry; x[0x0c..0x10].copy_from_slice(&0x20_01c8u32.to_le_bytes()); x },
        { let mut x = inquiry; x[0x0c..0x10].copy_from_slice(&0x20_0548u32.to_le_bytes()); x },
        { let mut x = inquiry; x[0x10..0x14].fill(0); x },
        { let mut x = inquiry; x[0x49] = 2; x },
        { let mut x = inquiry; x[0x49] = 0; x[0x4a] = 1; x }, // standard inquiry has no page
        { let mut x = inquiry; x[0x4b] = 1; x },
        { let mut x = inquiry; x[0x4c] = 0; x },
        { let mut x = inquiry; x[0x4d] = 1; x },
    ] {
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&changed),
            PossibleScsiEffect::PossiblyMutating, "unexpected INQUIRY shape: {changed:?}");
    }
}

#[test]
fn mode_sense_six_data_in_keeps_installed_metadata_read_through_eligible() {
    // The released disk class sent MODE SENSE(6) for the fault-reporting page:
    // CDB 1A 00 1C 00 C0 00, DATA_IN plus observed port policy, 192-byte buffer.
    let mut sense = srb(6, 0x1a, 0x20_0148, 192);
    sense[0x4a] = 0x1c;
    sense[0x4c] = 192;
    let effect = PossibleScsiEffect::from_legacy_srb(&sense);
    assert_eq!(effect, PossibleScsiEffect::ProvenReadOnly);
    let disk = Disk { controller: 3, physical_pdo: 9 };
    let route = Route { mount: 7, relation_generation: 11 };
    let fence = fixture();
    fence.before_effect(&disk, effect);
    assert!(fence.eligible(&disk, &route));
    assert!(!fence.poisoned());

    // Page choice is data selection rather than a media write, and a larger
    // receive buffer is safe when it covers the CDB's allocation length.
    let mut another_page = sense;
    another_page[0x4a] = 0x3f;
    another_page[0x10..0x14].copy_from_slice(&256u32.to_le_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&another_page),
        PossibleScsiEffect::ProvenReadOnly);

    for changed in [
        { let mut x = sense; x[0x0a] = 10; x },
        { let mut x = sense; x[0x0c..0x10].copy_from_slice(&0x20_0108u32.to_le_bytes()); x },
        { let mut x = sense; x[0x0c..0x10].copy_from_slice(&0x20_01c8u32.to_le_bytes()); x },
        { let mut x = sense; x[0x0c..0x10].copy_from_slice(&0x20_0548u32.to_le_bytes()); x },
        { let mut x = sense; x[0x10..0x14].fill(0); x },
        { let mut x = sense; x[0x10..0x14].copy_from_slice(&191u32.to_le_bytes()); x },
        { let mut x = sense; x[0x4c] = 0; x },
        { let mut x = sense; x[0x49] = 1; x },
        { let mut x = sense; x[0x4d] = 1; x },
        { let mut x = sense; x[0x4e] = 1; x },
    ] {
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&changed),
            PossibleScsiEffect::PossiblyMutating, "unexpected MODE SENSE shape: {changed:?}");
    }
}

#[test]
fn exact_class_device_claim_does_not_mutate_media_or_transfer_write_authority() {
    // The pinned LiberNT ClassClaimDevice zero-initializes the SRB and sets only Length and
    // SRB_FUNCTION_CLAIM_DEVICE before filling the pointer fields stripped by the wire owner.
    let mut claim = srb(0, 0, 0, 0);
    claim[2] = 1;
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&claim),
        PossibleScsiEffect::ProvenReadOnly);

    let mut malformed = claim;
    malformed[0x0a] = 10;
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
        PossibleScsiEffect::PossiblyMutating);
    let mut malformed = claim;
    malformed[0x10..0x14].copy_from_slice(&512u32.to_le_bytes());
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
        PossibleScsiEffect::PossiblyMutating);
    let mut release = claim;
    release[2] = 2; // RELEASE_DEVICE can transfer subsequent write authority.
    assert_eq!(PossibleScsiEffect::from_legacy_srb(&release),
        PossibleScsiEffect::PossiblyMutating);
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
