//! ABI and callback results for VideoPort child enumeration.
//!
//! ReactOS `videoprt` starts at child index 1, passes a 256-byte descriptor,
//! and interprets the miniport's VP_STATUS independently of the child type.

pub const VIDEO_CHILD_ENUM_INFO_X64_SIZE: usize = 24;
pub const VIDEO_CHILD_DESCRIPTOR_SIZE: u32 = 256;
pub const VIDEO_CHILD_TYPE_MONITOR: u32 = 1;
pub const VIDEO_CHILD_TYPE_NON_PRIMARY_CHIP: u32 = 2;
pub const VIDEO_CHILD_TYPE_VIDEO_CHIP: u32 = 3;
pub const VIDEO_CHILD_TYPE_OTHER: u32 = 4;
pub const DISPLAY_ADAPTER_HW_ID: u32 = u32::MAX;

pub const VIDEO_ENUM_INVALID_DEVICE: u32 = 123; // ERROR_INVALID_NAME
pub const VIDEO_ENUM_MORE_DEVICES: u32 = 1246; // ERROR_CONTINUE
pub const VIDEO_ENUM_NO_MORE_DEVICES: u32 = 1248; // ERROR_NO_MORE_DEVICES

/// The x64 layout of `VIDEO_CHILD_ENUM_INFO` from `video.h`.
///
/// The pointer is an address in the miniport's address space. This value
/// describes the ABI only; it does not grant access to that memory.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoChildEnumInfoX64 {
    pub size: u32,
    pub child_descriptor_size: u32,
    pub child_index: u32,
    pub acpi_hw_id: u32,
    pub child_hw_device_extension: u64,
}

impl VideoChildEnumInfoX64 {
    pub const fn new(child_index: u32, child_hw_device_extension: u64) -> Self {
        Self {
            size: VIDEO_CHILD_ENUM_INFO_X64_SIZE as u32,
            child_descriptor_size: VIDEO_CHILD_DESCRIPTOR_SIZE,
            child_index,
            acpi_hw_id: 0,
            child_hw_device_extension,
        }
    }

    /// Encode fields explicitly so the result never contains host padding.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), VideoChildEnumInfoError> {
        let bytes = output
            .get_mut(..VIDEO_CHILD_ENUM_INFO_X64_SIZE)
            .ok_or(VideoChildEnumInfoError::BufferTooSmall {
                needed: VIDEO_CHILD_ENUM_INFO_X64_SIZE,
            })?;
        bytes[0..4].copy_from_slice(&self.size.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.child_descriptor_size.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.child_index.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.acpi_hw_id.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.child_hw_device_extension.to_le_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoChildEnumInfoError {
    BufferTooSmall { needed: usize },
}

/// ReactOS VideoPort's handling of `HwGetVideoChildDescriptor` VP_STATUS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoChildCallbackAction {
    Publish,
    Skip,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoChildCallbackError {
    UnknownStatus(u32),
}

pub const fn classify_video_child_callback_status(
    status: u32,
) -> Result<VideoChildCallbackAction, VideoChildCallbackError> {
    match status {
        VIDEO_ENUM_MORE_DEVICES => Ok(VideoChildCallbackAction::Publish),
        VIDEO_ENUM_INVALID_DEVICE => Ok(VideoChildCallbackAction::Skip),
        VIDEO_ENUM_NO_MORE_DEVICES => Ok(VideoChildCallbackAction::Stop),
        unknown => Err(VideoChildCallbackError::UnknownStatus(unknown)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_enum_info_matches_reactos_x64_layout_and_probe_values() {
        assert_eq!(core::mem::size_of::<VideoChildEnumInfoX64>(), 24);
        assert_eq!(core::mem::align_of::<VideoChildEnumInfoX64>(), 8);
        let info = VideoChildEnumInfoX64::new(1, 0x1234_5678_9abc_def0);
        let mut bytes = [0xa5; VIDEO_CHILD_ENUM_INFO_X64_SIZE + 1];
        info.encode_into(&mut bytes).unwrap();
        assert_eq!(&bytes[0..4], &24u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &256u32.to_le_bytes());
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
        assert_eq!(&bytes[12..16], &0u32.to_le_bytes());
        assert_eq!(&bytes[16..24], &0x1234_5678_9abc_def0u64.to_le_bytes());
        assert_eq!(bytes[24], 0xa5);
        assert_eq!(DISPLAY_ADAPTER_HW_ID, u32::MAX);
    }

    #[test]
    fn child_enum_info_refuses_short_output_without_writing_it() {
        let info = VideoChildEnumInfoX64::new(1, 0);
        let mut short = [0xa5; VIDEO_CHILD_ENUM_INFO_X64_SIZE - 1];
        assert_eq!(
            info.encode_into(&mut short),
            Err(VideoChildEnumInfoError::BufferTooSmall { needed: 24 })
        );
        assert!(short.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn bochs_child_results_follow_videoprt_enumeration_policy() {
        // bochsmp: index 0 is invalid, index 1 is a monitor, later indices end.
        assert_eq!(
            classify_video_child_callback_status(VIDEO_ENUM_INVALID_DEVICE),
            Ok(VideoChildCallbackAction::Skip)
        );
        assert_eq!(
            classify_video_child_callback_status(VIDEO_ENUM_MORE_DEVICES),
            Ok(VideoChildCallbackAction::Publish)
        );
        assert_eq!(
            classify_video_child_callback_status(VIDEO_ENUM_NO_MORE_DEVICES),
            Ok(VideoChildCallbackAction::Stop)
        );
        for status in [0, 1, 997, 0xc000_0001, u32::MAX] {
            assert_eq!(
                classify_video_child_callback_status(status),
                Err(VideoChildCallbackError::UnknownStatus(status))
            );
        }
    }
}
