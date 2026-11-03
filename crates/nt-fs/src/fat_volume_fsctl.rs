//! Buffered FSCTLs on an opened FAT volume File.

use crate::{STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER};

pub const FSCTL_IS_VOLUME_DIRTY: u32 = 0x0009_0078;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// Encode only the dirty state actually captured from the validated mounted BPB.
/// File identity and access are checked by the mounted backend before this call.
pub fn encode_fat_volume_fsctl(
    code: u32,
    input_len: u32,
    output: &mut [u8],
    volume_dirty: bool,
) -> Result<usize, u32> {
    if code != FSCTL_IS_VOLUME_DIRTY {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    if input_len != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if output.len() < core::mem::size_of::<u32>() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    output[..4].copy_from_slice(&u32::from(volume_dirty).to_le_bytes());
    Ok(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_exact_clean_and_dirty_masks_without_touching_the_tail() {
        let mut output = [0xa5; 8];
        assert_eq!(encode_fat_volume_fsctl(FSCTL_IS_VOLUME_DIRTY, 0, &mut output, false), Ok(4));
        assert_eq!(output, [0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]);
        assert_eq!(encode_fat_volume_fsctl(FSCTL_IS_VOLUME_DIRTY, 0, &mut output, true), Ok(4));
        assert_eq!(output, [1, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]);
    }

    #[test]
    fn rejects_other_codes_and_invalid_payload_without_writing_output() {
        let mut output = [0xa5; 4];
        assert_eq!(encode_fat_volume_fsctl(0x0009_0074, 0, &mut output, false), Err(STATUS_INVALID_DEVICE_REQUEST));
        assert_eq!(encode_fat_volume_fsctl(FSCTL_IS_VOLUME_DIRTY, 1, &mut output, false), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(encode_fat_volume_fsctl(FSCTL_IS_VOLUME_DIRTY, 0, &mut output[..3], false), Err(STATUS_BUFFER_TOO_SMALL));
        assert_eq!(output, [0xa5; 4]);
    }
}
