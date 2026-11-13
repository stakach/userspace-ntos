//! Owned wire image of a driver-reported target-device custom notification.
//!
//! The native caller must first prove that the source range belongs to a live allocation.
//! This parser validates the bounded copy before an asynchronous report can be queued.

use alloc::vec::Vec;

const HEADER_BYTES: usize = 36;
const REMOVAL_TAIL: [u8; 12] = [
    0xf0, 0x46, 0xd0, 0x11, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationError {
    Size,
    Version,
    FileObject,
    SystemEvent,
    NameOffset,
    Allocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomTargetNotification {
    bytes: Vec<u8>,
    event: [u8; 16],
}

impl CustomTargetNotification {
    pub fn parse(source: &[u8]) -> Result<Self, NotificationError> {
        if source.len() < HEADER_BYTES || source.len() > u16::MAX as usize {
            return Err(NotificationError::Size);
        }
        let size = u16::from_le_bytes([source[2], source[3]]) as usize;
        if size != source.len() {
            return Err(NotificationError::Size);
        }
        if u16::from_le_bytes([source[0], source[1]]) != 1 {
            return Err(NotificationError::Version);
        }
        if source[24..32].iter().any(|byte| *byte != 0) {
            return Err(NotificationError::FileObject);
        }
        let event: [u8; 16] = source[4..20].try_into().expect("header bounds");
        if matches!(u32::from_le_bytes(event[..4].try_into().expect("GUID bounds")),
            0xcb3a4006..=0xcb3a4008) && event[4..] == REMOVAL_TAIL
        {
            return Err(NotificationError::SystemEvent);
        }
        let offset = i32::from_le_bytes(source[32..36].try_into().expect("header bounds"));
        if offset < -1 || (offset > 0 && ((offset as usize) < HEADER_BYTES
            || (offset as usize).checked_add(2).is_none_or(|end| end > size)
            || offset & 1 != 0)) {
            return Err(NotificationError::NameOffset);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| NotificationError::Allocation)?;
        bytes.extend_from_slice(source);
        Ok(Self { bytes, event })
    }

    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub fn event(&self) -> &[u8; 16] { &self.event }
}
