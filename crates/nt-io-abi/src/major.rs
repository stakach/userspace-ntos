//! IRP major-function codes (spec §13.4).
//!
//! The public WDK values (also used by ReactOS). Not all are implemented in
//! v0.1 — see the module docs of `nt-io-manager` for the functional subset.

pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_QUERY_EA: u8 = 0x07;
pub const IRP_MJ_SET_EA: u8 = 0x08;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0a;
pub const IRP_MJ_SET_VOLUME_INFORMATION: u8 = 0x0b;
pub const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0c;
pub const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0d;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0e;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;
pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
pub const IRP_MJ_LOCK_CONTROL: u8 = 0x11;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_CREATE_MAILSLOT: u8 = 0x13;
pub const IRP_MJ_QUERY_SECURITY: u8 = 0x14;
pub const IRP_MJ_SET_SECURITY: u8 = 0x15;
pub const IRP_MJ_POWER: u8 = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
pub const IRP_MJ_DEVICE_CHANGE: u8 = 0x18;
pub const IRP_MJ_QUERY_QUOTA: u8 = 0x19;
pub const IRP_MJ_SET_QUOTA: u8 = 0x1a;
pub const IRP_MJ_PNP: u8 = 0x1b;

/// Number of major-function slots (`IRP_MJ_MAXIMUM_FUNCTION + 1`).
pub const IO_MAJOR_FUNCTION_COUNT: usize = 0x1c;

/// True if `major` is a defined major-function code.
#[inline]
pub const fn is_valid_major(major: u8) -> bool {
    (major as usize) < IO_MAJOR_FUNCTION_COUNT
}
