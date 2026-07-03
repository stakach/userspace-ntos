//! # `nt-pnp-abi` — the NT PnP Manager wire ABI
//!
//! Opcodes, IDs, the v0.1 devnode state enum, PnP IRP major/minor function
//! constants, and fixed-layout `#[repr(C)]` request/response structs shared between
//! the PnP Manager and its clients (spec: NT PnP Manager, Milestone 12, §8, §19).
//! `no_std`, no allocation, no seL4 dependency, no raw pointers.

#![no_std]

/// Opaque identifiers.
pub type DevnodeId = u64;
pub type ObjectId = u64;
pub type DriverId = u64;

/// ABI version.
pub const PNP_ABI_VERSION: u16 = 1;

// --- opcodes (spec §19; PnP range 0x6000..=0x60ff) ---------------------------

pub const PNP_OP_PING: u16 = 0x6000;
pub const PNP_OP_REGISTER_CLIENT: u16 = 0x6001;
pub const PNP_OP_ENUMERATE_FIXTURES: u16 = 0x6010;
pub const PNP_OP_CREATE_DEVNODE: u16 = 0x6011;
pub const PNP_OP_LOAD_DRIVER: u16 = 0x6012;
pub const PNP_OP_CALL_ADD_DEVICE: u16 = 0x6013;
pub const PNP_OP_START_DEVICE: u16 = 0x6014;
pub const PNP_OP_QUERY_STOP_DEVICE: u16 = 0x6015;
pub const PNP_OP_STOP_DEVICE: u16 = 0x6016;
pub const PNP_OP_QUERY_REMOVE_DEVICE: u16 = 0x6017;
pub const PNP_OP_REMOVE_DEVICE: u16 = 0x6018;
pub const PNP_OP_QUERY_DEVNODE: u16 = 0x6020;
pub const PNP_OP_DUMP_DEVNODES: u16 = 0x6021;

// --- PnP IRP major/minor functions (WDK) -------------------------------------

/// `IRP_MJ_PNP`.
pub const IRP_MJ_PNP: u8 = 0x1b;

pub const IRP_MN_START_DEVICE: u8 = 0x00;
pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
pub const IRP_MN_STOP_DEVICE: u8 = 0x04;
pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x05;
pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x06;
pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;

/// The v0.1 devnode state machine (spec §8.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceState {
    Uninitialized = 0,
    Enumerated = 1,
    DriverLoaded = 2,
    AddDeviceCalled = 3,
    DeviceStackBuilt = 4,
    ResourcesAssigned = 5,
    StartIrpSent = 6,
    Started = 7,
    QueryStopPending = 8,
    Stopped = 9,
    QueryRemovePending = 10,
    RemovePending = 11,
    Removed = 12,
    Failed = 13,
}

/// `PNP_OP_CREATE_DEVNODE` / `PNP_OP_QUERY_DEVNODE` request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PnpDevnodeReq {
    pub abi_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub devnode_id: u64,
    pub instance_id_buffer: u64,
    pub instance_id_len: u32,
    pub reserved2: u32,
}

/// `PNP_OP_START_DEVICE` / `PNP_OP_REMOVE_DEVICE` etc. request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PnpLifecycleReq {
    pub abi_size: u16,
    pub minor_function: u8,
    pub flags: u8,
    pub reserved: u32,
    pub devnode_id: u64,
    pub driver_host_id: u64,
    pub top_device_object_id: u64,
}

/// A devnode's queryable state (`PNP_OP_QUERY_DEVNODE` response payload).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PnpDevnodeInfo {
    pub devnode_id: u64,
    pub generation: u64,
    pub state: u32,
    pub problem: u32,
    pub pdo_object_id: u64,
    pub fdo_object_id: u64,
    pub driver_id: u64,
    pub resource_count: u32,
    pub reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn state_repr_is_u32() {
        assert_eq!(size_of::<DeviceState>(), 4);
        assert_eq!(DeviceState::Started as u32, 7);
        assert_eq!(DeviceState::Removed as u32, 12);
    }

    #[test]
    fn lifecycle_req_layout() {
        assert_eq!(align_of::<PnpLifecycleReq>(), 8);
        assert_eq!(offset_of!(PnpLifecycleReq, minor_function), 2);
        assert_eq!(offset_of!(PnpLifecycleReq, devnode_id), 8);
        assert_eq!(offset_of!(PnpLifecycleReq, top_device_object_id), 24);
    }

    #[test]
    fn devnode_info_layout() {
        assert_eq!(offset_of!(PnpDevnodeInfo, state), 16);
        assert_eq!(offset_of!(PnpDevnodeInfo, pdo_object_id), 24);
        assert_eq!(offset_of!(PnpDevnodeInfo, fdo_object_id), 32);
    }

    #[test]
    fn irp_constants() {
        assert_eq!(IRP_MJ_PNP, 27);
        assert_eq!(IRP_MN_START_DEVICE, 0);
        assert_eq!(IRP_MN_REMOVE_DEVICE, 2);
    }
}
