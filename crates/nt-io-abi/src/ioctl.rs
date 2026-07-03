//! IOCTL `CTL_CODE` helpers (spec §14.3).
//!
//! `CTL_CODE(DeviceType, Function, Method, Access)` packs a 32-bit control code:
//! `DeviceType` in bits 16..32, `Access` in bits 14..16, `Function` in bits
//! 2..14, `Method` in bits 0..2. v0.1 implements `METHOD_BUFFERED` only.

/// Transfer method — low 2 bits of a control code.
pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_NEITHER: u32 = 3;

/// Access check — bits 14..16 of a control code.
pub const FILE_ANY_ACCESS: u32 = 0;
pub const FILE_READ_ACCESS: u32 = 1;
pub const FILE_WRITE_ACCESS: u32 = 2;

/// Build a control code from its four fields (the WDK `CTL_CODE` macro).
#[inline]
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// The device type (bits 16..32).
#[inline]
pub const fn device_type(code: u32) -> u32 {
    code >> 16
}

/// The function number (bits 2..14).
#[inline]
pub const fn function(code: u32) -> u32 {
    (code >> 2) & 0x0fff
}

/// The transfer method (bits 0..2).
#[inline]
pub const fn method(code: u32) -> u32 {
    code & 0x3
}

/// The required access (bits 14..16).
#[inline]
pub const fn access(code: u32) -> u32 {
    (code >> 14) & 0x3
}
