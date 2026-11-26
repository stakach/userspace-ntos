use crate::snapshot_test_device::CachedDisk;
use crate::{RegistryWal, RegistryWalError, RegistryWalFrameRoom};

#[test]
fn settled_room_tracks_the_exact_cursor_and_cancel_does_not_consume_it() {
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(8), 77).unwrap();
    let initial = RegistryWalFrameRoom {
        remaining_sectors: 8,
        sector_bytes: 512,
    };
    assert_eq!(wal.frame_room(), Ok(initial));

    wal.begin(alloc::vec![1]).unwrap();
    assert_eq!(wal.frame_room(), Err(RegistryWalError::InvalidState));
    wal.cancel_pending().unwrap();
    assert_eq!(wal.frame_room(), Ok(initial));

    wal.begin(alloc::vec![1]).unwrap();
    wal.prepare().unwrap();
    assert_eq!(wal.frame_room(), Err(RegistryWalError::InvalidState));
    wal.commit().unwrap();
    assert_eq!(
        wal.frame_room(),
        Ok(RegistryWalFrameRoom {
            remaining_sectors: 5,
            sector_bytes: 512,
        })
    );
}

#[test]
fn full_settled_wal_reports_zero_without_claiming_append_authority() {
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(3), 77).unwrap();
    wal.begin(alloc::vec![1]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    assert_eq!(
        wal.frame_room(),
        Ok(RegistryWalFrameRoom {
            remaining_sectors: 0,
            sector_bytes: 512,
        })
    );
    assert_eq!(wal.begin(alloc::vec![2]), Err(RegistryWalError::OutOfSpace));
}

#[test]
fn uncertain_wal_refuses_capacity_query_and_retains_its_device() {
    let mut disk = CachedDisk::with_sectors(8);
    disk.fail_event = Some(0);
    let mut wal = RegistryWal::recover(disk, 77).unwrap();
    wal.begin(alloc::vec![1]).unwrap();
    assert!(matches!(wal.prepare(), Err(RegistryWalError::Storage(_))));
    assert_eq!(wal.frame_room(), Err(RegistryWalError::Uncertain));
    let _retained = wal.into_device_for_test();
}

#[test]
fn refused_owned_frame_returns_the_exact_bytes_without_consuming_room() {
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(3), 77).unwrap();
    let bytes = alloc::vec![0xa5; 513];
    let pointer = bytes.as_ptr();
    let (error, returned) = wal.begin_owned(bytes).unwrap_err();
    assert_eq!(error, RegistryWalError::OutOfSpace);
    assert_eq!(returned.as_ptr(), pointer);
    assert_eq!(returned, alloc::vec![0xa5; 513]);
    assert_eq!(wal.frame_room().unwrap().remaining_sectors, 3);

    wal.begin_owned(alloc::vec![0x5a]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
}
