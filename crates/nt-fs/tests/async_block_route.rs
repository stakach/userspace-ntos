use nt_fs::{BlockOperation, BlockRouteError, BlockRouteOwner, BlockSource, BlockSourceKind};

#[test]
fn draining_fences_both_mounted_backends_without_a_second_boot_ticket_ledger() {
    let mut owner = BlockRouteOwner::new(11, 4096).unwrap();
    owner
        .admit_boot(
            11,
            BlockSource::Fat,
            BlockOperation::Read {
                lba: 32,
                sectors: 1,
            },
        )
        .unwrap();
    owner
        .admit_boot(
            11,
            BlockSource::Snapshot,
            BlockOperation::Write {
                lba: 3000,
                sectors: 1,
            },
        )
        .unwrap();
    owner.begin_drain(11).unwrap();
    assert_eq!(owner.source_kind(), BlockSourceKind::Draining);
    assert_eq!(
        owner.admit_boot(
            11,
            BlockSource::Fat,
            BlockOperation::Read {
                lba: 33,
                sectors: 1
            }
        ),
        Err(BlockRouteError::WrongPhase)
    );
    assert_eq!(
        owner.admit_boot(11, BlockSource::Snapshot, BlockOperation::Flush),
        Err(BlockRouteError::WrongPhase)
    );
    // The controller's PciDmaHandoff owns exact direct AHCI tickets and checks their drain
    // before calling this mount-level commit with an authenticated native route.
    owner.commit_native(11, 77).unwrap();
    assert_eq!(owner.source_kind(), BlockSourceKind::Native);
    assert_eq!(
        owner.admit_boot(
            11,
            BlockSource::Snapshot,
            BlockOperation::Read {
                lba: 3000,
                sectors: 1
            }
        ),
        Err(BlockRouteError::WrongPhase)
    );
}

#[test]
fn uncertain_native_write_retains_only_its_exact_completion_and_blocks_replay() {
    let mut owner = BlockRouteOwner::new(11, 4096).unwrap();
    owner.begin_drain(11).unwrap();
    owner.commit_native(11, 77).unwrap();
    let write = owner
        .enter_native(
            11,
            BlockSource::Snapshot,
            BlockOperation::Write {
                lba: 3000,
                sectors: 1,
            },
        )
        .unwrap();
    owner.lose_native(write).unwrap();
    assert_eq!(
        owner.enter_native(
            11,
            BlockSource::Fat,
            BlockOperation::Read {
                lba: 32,
                sectors: 1
            }
        ),
        Err(BlockRouteError::NativeIoOutstanding)
    );
    let mut wrong = write;
    wrong.route = 78;
    assert_eq!(
        owner.complete_native(wrong, 512),
        Err(BlockRouteError::WrongTicket)
    );
    owner.complete_native(write, 512).unwrap();
    assert_eq!(
        owner.complete_native(write, 512),
        Err(BlockRouteError::WrongTicket)
    );
    assert!(owner
        .enter_native(
            11,
            BlockSource::Fat,
            BlockOperation::Read {
                lba: 32,
                sectors: 1
            }
        )
        .is_ok());
}

#[test]
fn copied_fat_handles_and_snapshot_reserve_share_one_mount_fence() {
    let mut mount = BlockRouteOwner::new(31, 4096).unwrap();
    let copied_fat_mount = 31;
    let reserve_mount = 31;
    mount.admit_boot(copied_fat_mount, BlockSource::Fat,
        BlockOperation::Read { lba: 12, sectors: 1 }).unwrap();
    mount.admit_boot(reserve_mount, BlockSource::Snapshot,
        BlockOperation::Flush).unwrap();
    assert_eq!(mount.admit_boot(32, BlockSource::Fat,
        BlockOperation::Read { lba: 12, sectors: 1 }), Err(BlockRouteError::WrongMount));
    assert_eq!(mount.admit_boot(reserve_mount, BlockSource::Snapshot,
        BlockOperation::Write { lba: 4095, sectors: 2 }), Err(BlockRouteError::InvalidGeometry));
    mount.begin_drain(31).unwrap();
    for source in [BlockSource::Fat, BlockSource::Snapshot] {
        assert_eq!(mount.admit_boot(31, source, BlockOperation::Read { lba: 12, sectors: 1 }),
            Err(BlockRouteError::WrongPhase));
        assert_eq!(mount.admit_boot(31, source, BlockOperation::Flush),
            Err(BlockRouteError::WrongPhase));
    }
}
