use super::*;

fn recover_with_test_floor(device: CachedDisk, floor: WalSnapshotAnchor)
    -> Result<RegistryWal<CachedDisk>, RegistryWalError> {
    // Each test constructs the anchored prefix on this exact CachedDisk before corruption.
    unsafe { RegistryWal::recover_with_floor(device, floor) }
}

#[test]
fn paired_floor_preserves_later_marked_records_and_clears_torn_suffix_before_reuse() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    let system = b"CMWAL001 first".to_vec();
    let other_hive = crate::encode_hive_log_wal_payload(crate::HiveLogWalPayload {
        file_id: 43,
        expected_log_len: 0,
        path: r"\??\C:\ReactOS\System32\Config\SOFTWARE.LOG",
        record: b"HLR1 other hive mutation",
    }).unwrap();
    for payload in [&system, &other_hive] {
        wal.begin(payload.clone()).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    let floor = WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 };
    assert_eq!(wal.settled_anchor().unwrap().serial, 2);
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    device.corrupt(6); // An incomplete next header has no trustworthy frame length.

    let mut recovered = recover_with_test_floor(device, floor).unwrap();
    assert_eq!(recovered.records().len(), 2);
    assert_eq!(recovered.records()[0].payload, system);
    assert_eq!(recovered.records()[1].payload, other_hive);
    assert_eq!(recovered.verified_record_end_lba(1), Some(3));
    assert_eq!(recovered.verified_record_end_lba(2), Some(6));
    assert_eq!(recovered.state(), RegistryWalState::RecoveredUncommitted);
    assert_eq!(recovered.begin(b"CMWAL001 third".to_vec()), Err(RegistryWalError::InvalidState));
    recovered.clear_recovered_tail().unwrap();
    assert!(recovered.device_mut_for_test().stable[6 * 512..].iter().all(|byte| *byte == 0));
    recovered.begin(b"CMWAL001 third".to_vec()).unwrap();
    recovered.prepare().unwrap();
    recovered.commit().unwrap();
    let mut device = recovered.into_device().unwrap();
    device.power_cut();
    let replayed = RegistryWal::recover(device, 77).unwrap();
    assert_eq!(replayed.records().len(), 3);
    assert_eq!(replayed.records()[2].payload, b"CMWAL001 third");
}

#[test]
fn paired_floor_clears_dirty_sectors_after_an_empty_next_header() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(b"CMWAL001 first".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    device.cache[4 * 512] = 0x5a;
    device.stable[4 * 512] = 0x5a;
    let floor = WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 };
    let mut recovered = recover_with_test_floor(device, floor).unwrap();
    assert_eq!(recovered.state(), RegistryWalState::RecoveredUncommitted);
    assert_eq!(recovered.verified_record_end_lba(1), Some(3));
    recovered.clear_recovered_tail().unwrap();
    let mut device = recovered.into_device().unwrap();
    device.power_cut();
    assert!(device.stable[3 * 512..].iter().all(|byte| *byte == 0));
}

#[test]
fn paired_floor_refuses_corruption_or_an_inexact_boundary_within_anchored_prefix() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(b"CMWAL001 first".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    device.corrupt(0);
    assert!(matches!(
        recover_with_test_floor(device, WalSnapshotAnchor {
            incarnation: 77, serial: 1, end_lba: 3,
        }),
        Err(RegistryWalError::Corrupt)
    ));

    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(b"CMWAL001 first".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    assert!(matches!(
        recover_with_test_floor(device, WalSnapshotAnchor {
            incarnation: 77, serial: 1, end_lba: 4,
        }),
        Err(RegistryWalError::Corrupt)
    ));

    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(b"CMWAL001 first".to_vec()).unwrap();
    wal.prepare().unwrap();
    let mut device = wal.into_device_for_test();
    device.power_cut();
    assert!(matches!(
        recover_with_test_floor(device, WalSnapshotAnchor {
            incarnation: 77, serial: 1, end_lba: 3,
        }),
        Err(RegistryWalError::Corrupt)
    ));
}

#[test]
fn paired_floor_does_not_discard_a_marked_record_with_corrupt_payload() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    for payload in [b"CMWAL001 first".as_slice(), b"CMWAL001 second".as_slice()] {
        wal.begin(payload.to_vec()).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    device.corrupt(4); // The second frame still has a valid durable COMMIT marker.
    assert!(matches!(
        recover_with_test_floor(device, WalSnapshotAnchor {
            incarnation: 77, serial: 1, end_lba: 3,
        }),
        Err(RegistryWalError::Corrupt)
    ));
}

#[test]
fn paired_floor_refuses_a_complete_but_noncontiguous_next_header() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(b"CMWAL001 first".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    let wrong = framed_sector(512, PREPARE_MAGIC, 77, 99, 1, crc32c(b"x")).unwrap();
    device.stable[3 * 512..4 * 512].copy_from_slice(&wrong);
    device.cache[3 * 512..4 * 512].copy_from_slice(&wrong);
    assert!(matches!(
        recover_with_test_floor(device, WalSnapshotAnchor {
            incarnation: 77, serial: 1, end_lba: 3,
        }),
        Err(RegistryWalError::Corrupt)
    ));
}

#[test]
fn paired_floor_torn_suffix_clear_keeps_lease_on_uncertain_write() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(b"CMWAL001 first".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut device = wal.into_device().unwrap();
    device.power_cut();
    device.corrupt(3);
    let floor = WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 };
    let mut recovered = recover_with_test_floor(device, floor).unwrap();
    let next_event = recovered.device_mut_for_test().events.len();
    // Clear the 28 sectors after LBA 3, then fail the durability barrier after
    // one of those writes reaches stable storage.
    recovered.device_mut_for_test().fail_event = Some(next_event + 28);
    recovered.device_mut_for_test().partial_flush = true;
    assert_eq!(
        recovered.clear_recovered_tail(),
        Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
    );
    assert_eq!(recovered.state(), RegistryWalState::Uncertain);
    assert_eq!(recovered.begin(b"CMWAL001 second".to_vec()), Err(RegistryWalError::Uncertain));
    core::mem::forget(recovered);
}

#[test]
fn paired_floor_torn_suffix_clear_survives_each_flush_power_cut() {
    let floor = WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 };
    for flush_offset in [28, 30] {
        let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
        wal.begin(b"CMWAL001 first".to_vec()).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
        let mut device = wal.into_device().unwrap();
        device.power_cut();
        device.corrupt(3);
        let mut recovered = recover_with_test_floor(device, floor).unwrap();
        let next_event = recovered.device_mut_for_test().events.len();
        recovered.device_mut_for_test().fail_event = Some(next_event + flush_offset);
        recovered.device_mut_for_test().partial_flush = true;
        assert_eq!(
            recovered.clear_recovered_tail(),
            Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
        );
        assert_eq!(recovered.state(), RegistryWalState::Uncertain);
        let mut device = recovered.into_device_for_test(); // Simulated process death.
        device.power_cut();
        let mut rebooted = recover_with_test_floor(device, floor).unwrap();
        assert_eq!(rebooted.records()[0].payload, b"CMWAL001 first");
        if rebooted.state() == RegistryWalState::RecoveredUncommitted {
            rebooted.clear_recovered_tail().unwrap();
        }
        assert_eq!(rebooted.state(), RegistryWalState::Ready);
    }
}
