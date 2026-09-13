//! Typed `IRP_MJ_LOCK_CONTROL` parameters.

use nt_types::AccessMask;

pub const IRP_MN_LOCK: u8 = 0x01;
pub const IRP_MN_UNLOCK_SINGLE: u8 = 0x02;
pub const SL_FAIL_IMMEDIATELY: u8 = 0x01;
pub const SL_EXCLUSIVE_LOCK: u8 = 0x02;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LockControlParameters {
    pub minor: u8,
    pub byte_offset: u64,
    pub length: u64,
    pub key: u32,
}

pub fn lock_control_access_granted(granted: AccessMask) -> bool {
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    granted
        .intersects(AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE | AccessMask::GENERIC_ALL)
        || granted.bits() & (FILE_READ_DATA | FILE_WRITE_DATA) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_locks_accept_read_or_write_data_access() {
        for granted in [
            AccessMask::from_bits_retain(1),
            AccessMask::from_bits_retain(2),
            AccessMask::from_bits_retain(3),
            AccessMask::GENERIC_READ,
            AccessMask::GENERIC_WRITE,
            AccessMask::GENERIC_ALL,
        ] {
            assert!(lock_control_access_granted(granted), "{granted:?}");
        }
    }

    #[test]
    fn byte_locks_refuse_append_only_and_metadata_access() {
        for bits in [0, 4, 0x80, 0x100, 0x0010_0000, 0x0002_0000, 0x0012_0184] {
            assert!(!lock_control_access_granted(AccessMask::from_bits_retain(
                bits
            )));
        }
        assert!(!lock_control_access_granted(AccessMask::GENERIC_EXECUTE));
    }
}
