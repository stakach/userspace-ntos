//! SURT opcodes for the I/O Manager (spec §16.1–16.2, §17.1).
//!
//! Two reserved ranges: client-facing (`0x3000..=0x30ff`) and I/O Manager ↔
//! driver-peer (`0x3100..=0x31ff`).

/// Client-facing I/O Manager service opcodes (`0x3000..=0x30ff`).
pub mod client {
    pub const IO_OP_PING: u16 = 0x3000;
    pub const IO_OP_OPEN: u16 = 0x3001;
    pub const IO_OP_CLEANUP: u16 = 0x3002;
    pub const IO_OP_CLOSE: u16 = 0x3003;
    pub const IO_OP_READ: u16 = 0x3004;
    pub const IO_OP_WRITE: u16 = 0x3005;
    pub const IO_OP_DEVICE_CONTROL: u16 = 0x3006;
    pub const IO_OP_INTERNAL_CONTROL: u16 = 0x3007;
    pub const IO_OP_FLUSH: u16 = 0x3008;
    pub const IO_OP_CANCEL: u16 = 0x3009;
    pub const IO_OP_QUERY_INFORMATION: u16 = 0x300a;
    pub const IO_OP_SET_INFORMATION: u16 = 0x300b;
}

/// I/O Manager → driver-peer opcodes (`0x3100..=0x317f`).
pub mod driver {
    pub const IODRV_OP_DISPATCH_IRP: u16 = 0x3100;
    pub const IODRV_OP_CANCEL_IRP: u16 = 0x3101;
    pub const IODRV_OP_CLOSE_FILE_CONTEXT: u16 = 0x3102;
    pub const IODRV_OP_DEVICE_DELETED: u16 = 0x3103;
    pub const IODRV_OP_QUERY_CAPS: u16 = 0x3104;
    pub const IODRV_OP_SHUTDOWN: u16 = 0x3105;
}

/// Driver-peer → I/O Manager opcodes (`0x3180..=0x31ff`).
pub mod peer {
    pub const IODRV_OP_COMPLETE_IRP: u16 = 0x3180;
    pub const IODRV_OP_MARK_PENDING: u16 = 0x3181;
    pub const IODRV_OP_REQUEST_BUFFER_MAP: u16 = 0x3182;
    pub const IODRV_OP_TRACE_EVENT: u16 = 0x3183;
    pub const IODRV_OP_FAULT_REPORT: u16 = 0x3184;
}

/// Inclusive bounds of the client-facing opcode range.
pub const IO_CLIENT_OPCODE_MIN: u16 = 0x3000;
pub const IO_CLIENT_OPCODE_MAX: u16 = 0x30ff;
/// Inclusive bounds of the driver-peer opcode range (both directions).
pub const IO_DRIVER_OPCODE_MIN: u16 = 0x3100;
pub const IO_DRIVER_OPCODE_MAX: u16 = 0x31ff;

/// True for any opcode in the client-facing range.
#[inline]
pub const fn is_client_opcode(op: u16) -> bool {
    op >= IO_CLIENT_OPCODE_MIN && op <= IO_CLIENT_OPCODE_MAX
}

/// True for any opcode in the driver-peer range.
#[inline]
pub const fn is_driver_opcode(op: u16) -> bool {
    op >= IO_DRIVER_OPCODE_MIN && op <= IO_DRIVER_OPCODE_MAX
}
