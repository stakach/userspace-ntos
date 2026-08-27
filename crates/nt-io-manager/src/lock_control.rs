//! Typed `IRP_MJ_LOCK_CONTROL` parameters.

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
