use nt_pnp_manager::target_device_change::{CustomTargetNotification, NotificationError};

const HEADER: usize = 36;

fn packet(event: u32, version: u16, size: u16, file_object: u64, name_offset: i32) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    bytes[0..2].copy_from_slice(&version.to_le_bytes());
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..8].copy_from_slice(&event.to_le_bytes());
    if (0xcb3a4006..=0xcb3a4008).contains(&event) {
        bytes[8..20].copy_from_slice(&[
            0xf0, 0x46, 0xd0, 0x11, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f,
        ]);
    }
    bytes[24..32].copy_from_slice(&file_object.to_le_bytes());
    bytes[32..36].copy_from_slice(&name_offset.to_le_bytes());
    bytes
}

#[test]
fn custom_notification_is_an_owned_exact_length_copy() {
    let mut source = packet(0x1020_3040, 1, 40, 0, -1);
    source[36..40].copy_from_slice(&[1, 2, 3, 4]);
    let owned = CustomTargetNotification::parse(&source).unwrap();
    source[36] = 99;
    assert_eq!(owned.bytes().len(), 40);
    assert_eq!(&owned.bytes()[36..40], &[1, 2, 3, 4]);
    assert_eq!(owned.event()[..4], 0x1020_3040u32.to_le_bytes());
}

#[test]
fn system_remove_events_and_invalid_headers_cannot_be_queued() {
    for event in 0xcb3a4006..=0xcb3a4008 {
        assert_eq!(CustomTargetNotification::parse(&packet(event, 1, 40, 0, -1)),
            Err(NotificationError::SystemEvent));
    }
    assert_eq!(CustomTargetNotification::parse(&packet(42, 2, 40, 0, -1)),
        Err(NotificationError::Version));
    assert_eq!(CustomTargetNotification::parse(&packet(42, 1, 40, 1, -1)),
        Err(NotificationError::FileObject));
    assert_eq!(CustomTargetNotification::parse(&packet(42, 1, 40, 0, 41)),
        Err(NotificationError::NameOffset));
    assert_eq!(CustomTargetNotification::parse(&packet(42, 1, 40, 0, -2)),
        Err(NotificationError::NameOffset));
    assert_eq!(CustomTargetNotification::parse(&packet(42, 1, 40, 0, 20)),
        Err(NotificationError::NameOffset));
    assert_eq!(CustomTargetNotification::parse(&packet(42, 1, 40, 0, 37)),
        Err(NotificationError::NameOffset));
    let mut short = packet(42, 1, 40, 0, -1);
    short.truncate(HEADER - 1);
    assert_eq!(CustomTargetNotification::parse(&short), Err(NotificationError::Size));
    let mut mismatch = packet(42, 1, 40, 0, -1);
    mismatch[2..4].copy_from_slice(&48u16.to_le_bytes());
    assert_eq!(CustomTargetNotification::parse(&mismatch), Err(NotificationError::Size));
}
