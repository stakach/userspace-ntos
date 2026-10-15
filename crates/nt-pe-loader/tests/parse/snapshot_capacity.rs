//! Full file snapshots retain EOF-sized storage, independent of read chunk size.

use nt_pe_loader::{reserve_file_snapshot_capacity, PeError};

#[test]
fn complete_chunked_snapshot_reserves_exact_eof_before_first_read() {
    for file_size in [0, 1, 4095, 4096, 4097, 0x2aa000, 0x893000] {
        let mut bytes = Vec::new();
        reserve_file_snapshot_capacity(&mut bytes, file_size).unwrap();
        assert!(bytes.is_empty(), "reservation is not captured image data");
        assert_eq!(bytes.capacity(), file_size, "no geometric retained capacity slack");
        let storage = bytes.as_ptr();
        let mut offset = 0;
        while offset < file_size {
            reserve_file_snapshot_capacity(&mut bytes, file_size).unwrap();
            let length = 4096.min(file_size - offset);
            bytes.extend((offset..offset + length).map(|index| index as u8));
            offset += length;
            assert_eq!(bytes.as_ptr(), storage, "accepted chunks never relocate storage");
            assert_eq!(bytes.capacity(), file_size);
        }
        assert_eq!(bytes.len(), file_size, "retain complete bytes, not only PE headers");
        assert!(bytes.iter().enumerate().all(|(index, byte)| *byte == index as u8));
    }
}

#[test]
fn reservation_preserves_already_captured_prefix() {
    let mut bytes = vec![0x31, 0x72, 0xa5];
    reserve_file_snapshot_capacity(&mut bytes, 4097).unwrap();
    assert_eq!(bytes, [0x31, 0x72, 0xa5]);
    assert_eq!(bytes.capacity(), 4097);
    let storage = bytes.as_ptr();
    reserve_file_snapshot_capacity(&mut bytes, 4097).unwrap();
    assert_eq!(bytes.as_ptr(), storage);
    assert_eq!(bytes, [0x31, 0x72, 0xa5]);
}

#[test]
fn impossible_reservation_leaves_captured_owner_unchanged() {
    let mut bytes = vec![0x31, 0x72, 0xa5];
    let storage = bytes.as_ptr();
    let capacity = bytes.capacity();
    assert_eq!(reserve_file_snapshot_capacity(&mut bytes, usize::MAX),
        Err(PeError::InsufficientResources));
    assert_eq!(bytes.as_ptr(), storage);
    assert_eq!(bytes.capacity(), capacity);
    assert_eq!(bytes, [0x31, 0x72, 0xa5]);
}

#[test]
fn admitted_eof_cannot_exclude_already_captured_bytes() {
    let mut bytes = vec![0x31, 0x72, 0xa5];
    let storage = bytes.as_ptr();
    let capacity = bytes.capacity();
    assert_eq!(reserve_file_snapshot_capacity(&mut bytes, 2), Err(PeError::BadImageSize));
    assert_eq!(bytes.as_ptr(), storage);
    assert_eq!(bytes.capacity(), capacity);
    assert_eq!(bytes, [0x31, 0x72, 0xa5]);
}
