//! Initial x64 volume parameter block for mountable DEVICE_OBJECTs.

use super::{put_i16, put_u64, put_u16, zero, WdmLayoutError};

pub const WDM_X64_VPB_SIZE: usize = 0x60;
pub const WDM_X64_IO_TYPE_VPB: i16 = 10;

/// ReactOS IoCreateDevice attaches a VPB to disks, virtual disks, CD-ROMs and tapes.
pub const fn device_type_needs_vpb(device_type: u32) -> bool {
    matches!(device_type, 0x02 | 0x07 | 0x1f | 0x24)
}

/// Construct an unpublished VPB. The caller owns its separate allocation and publication.
pub fn write_wdm_vpb(bytes: &mut [u8], real_device: u64) -> Result<(), WdmLayoutError> {
    if bytes.len() < WDM_X64_VPB_SIZE || real_device == 0 {
        return Err(if bytes.len() < WDM_X64_VPB_SIZE {
            WdmLayoutError::BufferTooSmall
        } else {
            WdmLayoutError::InvalidField
        });
    }
    zero(&mut bytes[..WDM_X64_VPB_SIZE]);
    put_i16(bytes, 0, WDM_X64_IO_TYPE_VPB);
    put_u16(bytes, 2, WDM_X64_VPB_SIZE as u16);
    put_u64(bytes, 0x10, real_device);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountable_types_receive_exact_initialized_vpb() {
        for device_type in [0x02, 0x07, 0x1f, 0x24] {
            assert!(device_type_needs_vpb(device_type));
        }
        for device_type in [0, 0x08, 0x20, 0x22] {
            assert!(!device_type_needs_vpb(device_type));
        }
        let mut bytes = [0xcc; WDM_X64_VPB_SIZE];
        write_wdm_vpb(&mut bytes, 0x1234_5678).unwrap();
        assert_eq!(i16::from_le_bytes(bytes[0..2].try_into().unwrap()), WDM_X64_IO_TYPE_VPB);
        assert_eq!(u16::from_le_bytes(bytes[2..4].try_into().unwrap()), WDM_X64_VPB_SIZE as u16);
        assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(bytes[0x10..0x18].try_into().unwrap()), 0x1234_5678);
        assert!(bytes[0x18..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn invalid_vpb_destination_has_no_partial_write() {
        let mut short = [0xcc; WDM_X64_VPB_SIZE - 1];
        assert_eq!(write_wdm_vpb(&mut short, 0x1000), Err(WdmLayoutError::BufferTooSmall));
        assert!(short.iter().all(|byte| *byte == 0xcc));
        let mut bytes = [0xcc; WDM_X64_VPB_SIZE];
        assert_eq!(write_wdm_vpb(&mut bytes, 0), Err(WdmLayoutError::InvalidField));
        assert!(bytes.iter().all(|byte| *byte == 0xcc));
    }
}
