//! # `nt-power-abi` — the NT Power Manager wire ABI
//!
//! Opcodes + fixed-layout `#[repr(C)]` request structs shared between the Power
//! Manager and its clients (spec: NT Power Manager, Milestone 13, §15). `no_std`,
//! no allocation, no seL4 dependency, no raw pointers. Responses use the SURT CQE
//! convention: `status` = NTSTATUS, `detail0` = old state, `detail1` = new state.

#![no_std]

pub use nt_power_types as types;

/// ABI version.
pub const POWER_ABI_VERSION: u16 = 1;

// --- opcodes (spec §15; Power range 0x7000..=0x70ff) -------------------------

pub const POWER_OP_PING: u16 = 0x7000;
pub const POWER_OP_REGISTER_DEVICE: u16 = 0x7001;
pub const POWER_OP_UNREGISTER_DEVICE: u16 = 0x7002;

pub const POWER_OP_QUERY_DEVICE_STATE: u16 = 0x7010;
pub const POWER_OP_SET_DEVICE_POWER: u16 = 0x7011;
pub const POWER_OP_QUERY_SYSTEM_STATE: u16 = 0x7012;
pub const POWER_OP_SET_SYSTEM_POWER: u16 = 0x7013;

pub const POWER_OP_SEND_QUERY_POWER: u16 = 0x7020;
pub const POWER_OP_SEND_SET_POWER: u16 = 0x7021;
pub const POWER_OP_POWER_IRP_COMPLETED: u16 = 0x7022;

pub const POWER_OP_DRIVER_REPORTED_STATE: u16 = 0x7030;
pub const POWER_OP_DEVICE_POWER_CHANGED: u16 = 0x7031;
pub const POWER_OP_DUMP_STATE: u16 = 0x7040;

/// A `POWER_STATE` on the wire (spec §15.1).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PowerStateWire {
    pub state_type: u32,
    pub state: u32,
}

/// `POWER_OP_SET_DEVICE_POWER` request (spec §15.2).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PowerSetDeviceReq {
    pub abi_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub devnode_id: u64,
    pub target_device_state: u32,
    pub timeout_ms: u32,
    pub request_id: u64,
}

/// `POWER_OP_REGISTER_DEVICE` request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PowerRegisterDeviceReq {
    pub abi_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub devnode_id: u64,
    pub pdo_object_id: u64,
    pub fdo_object_id: u64,
    pub top_device_object_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn set_device_req_layout() {
        assert_eq!(align_of::<PowerSetDeviceReq>(), 8);
        assert_eq!(offset_of!(PowerSetDeviceReq, devnode_id), 8);
        assert_eq!(offset_of!(PowerSetDeviceReq, target_device_state), 16);
        assert_eq!(offset_of!(PowerSetDeviceReq, request_id), 24);
    }

    #[test]
    fn power_state_wire_layout() {
        assert_eq!(size_of::<PowerStateWire>(), 8);
        assert_eq!(offset_of!(PowerStateWire, state), 4);
    }

    #[test]
    fn opcodes_in_range() {
        assert_eq!(POWER_OP_SET_DEVICE_POWER, 0x7011);
        assert_eq!(POWER_OP_DUMP_STATE, 0x7040);
    }
}
