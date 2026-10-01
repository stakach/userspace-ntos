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
pub const IRP_MN_QUERY_DEVICE_RELATIONS: u8 = 0x07;
pub const IRP_MN_QUERY_INTERFACE: u8 = 0x08;
pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09;
pub const IRP_MN_QUERY_RESOURCES: u8 = 0x0A;
pub const IRP_MN_QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0B;
pub const IRP_MN_FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0D;
pub const IRP_MN_QUERY_ID: u8 = 0x13;
pub const IRP_MN_QUERY_BUS_INFORMATION: u8 = 0x15;

/// Native NT5 x64 `DEVICE_CAPABILITIES` extent.
pub const DEVICE_CAPABILITIES_X64_SIZE: usize = 64;
pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;

/// In-memory GUID bytes, matching `GUID_BUS_INTERFACE_STANDARD` in wdmguid.h.
pub const GUID_BUS_INTERFACE_STANDARD: [u8; 16] = [
    0x80, 0x82, 0x6b, 0x49, 0x25, 0x6f, 0xd0, 0x11, 0xbe, 0xaf, 0x08, 0x00, 0x2b, 0xe2,
    0x09, 0x2f,
];
pub const BUS_INTERFACE_STANDARD_X64_SIZE: u16 = 64;
pub const BUS_INTERFACE_QUERY_REQUEST_BYTES: usize = 20;
pub const BUS_INTERFACE_QUERY_REPLY_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusInterfaceQueryError {
    InvalidLength,
    UnsupportedGuid,
    UnsupportedVersion,
    BufferTooSmall,
    InvalidLease,
}

/// Pointer-free form of the `IRP_MN_QUERY_INTERFACE` stack parameters. The native interface
/// buffer and its callback pointers are deliberately not transported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusInterfaceQueryRequest {
    pub interface_type: [u8; 16],
    pub size: u16,
    pub version: u16,
}

impl BusInterfaceQueryRequest {
    pub const fn standard() -> Self {
        Self {
            interface_type: GUID_BUS_INTERFACE_STANDARD,
            size: BUS_INTERFACE_STANDARD_X64_SIZE,
            version: 1,
        }
    }

    pub fn validate(self) -> Result<(), BusInterfaceQueryError> {
        if self.interface_type != GUID_BUS_INTERFACE_STANDARD {
            return Err(BusInterfaceQueryError::UnsupportedGuid);
        }
        if self.version < 1 {
            return Err(BusInterfaceQueryError::UnsupportedVersion);
        }
        if self.size < BUS_INTERFACE_STANDARD_X64_SIZE {
            return Err(BusInterfaceQueryError::BufferTooSmall);
        }
        Ok(())
    }

    pub fn encode(self) -> [u8; BUS_INTERFACE_QUERY_REQUEST_BYTES] {
        let mut bytes = [0; BUS_INTERFACE_QUERY_REQUEST_BYTES];
        bytes[..16].copy_from_slice(&self.interface_type);
        bytes[16..18].copy_from_slice(&self.size.to_le_bytes());
        bytes[18..20].copy_from_slice(&self.version.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BusInterfaceQueryError> {
        if bytes.len() != BUS_INTERFACE_QUERY_REQUEST_BYTES {
            return Err(BusInterfaceQueryError::InvalidLength);
        }
        let mut interface_type = [0; 16];
        interface_type.copy_from_slice(&bytes[..16]);
        let request = Self {
            interface_type,
            size: u16::from_le_bytes([bytes[16], bytes[17]]),
            version: u16::from_le_bytes([bytes[18], bytes[19]]),
        };
        request.validate()?;
        Ok(request)
    }
}

/// A lease identifier, not a provider-domain `Context` or function pointer. A consumer-local
/// projection must mint its own callbacks after authenticating this response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusInterfaceQueryReply {
    pub size: u16,
    pub version: u16,
    pub lease_id: u64,
    pub device_id: u64,
}

impl BusInterfaceQueryReply {
    pub fn encode(self) -> [u8; BUS_INTERFACE_QUERY_REPLY_BYTES] {
        let mut bytes = [0; BUS_INTERFACE_QUERY_REPLY_BYTES];
        bytes[..2].copy_from_slice(&self.size.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.lease_id.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.device_id.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BusInterfaceQueryError> {
        if bytes.len() != BUS_INTERFACE_QUERY_REPLY_BYTES || bytes[4..8] != [0; 4] {
            return Err(BusInterfaceQueryError::InvalidLength);
        }
        let reply = Self {
            size: u16::from_le_bytes([bytes[0], bytes[1]]),
            version: u16::from_le_bytes([bytes[2], bytes[3]]),
            lease_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            device_id: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        };
        if reply.size != BUS_INTERFACE_STANDARD_X64_SIZE
            || reply.version != 1
            || reply.lease_id == 0
            || reply.device_id == 0
        {
            return Err(BusInterfaceQueryError::InvalidLease);
        }
        Ok(reply)
    }
}

pub const BUS_RELATIONS: u32 = 0;
pub const EJECTION_RELATIONS: u32 = 1;
pub const POWER_RELATIONS: u32 = 2;
pub const REMOVAL_RELATIONS: u32 = 3;
pub const TARGET_DEVICE_RELATION: u32 = 4;
pub const SINGLE_BUS_RELATIONS: u32 = 5;
pub const TRANSPORT_RELATIONS: u32 = 6;

pub const BUS_QUERY_DEVICE_ID: u32 = 0;
pub const BUS_QUERY_HARDWARE_IDS: u32 = 1;
pub const BUS_QUERY_COMPATIBLE_IDS: u32 = 2;
pub const BUS_QUERY_INSTANCE_ID: u32 = 3;
pub const BUS_QUERY_DEVICE_SERIAL_NUMBER: u32 = 4;
pub const BUS_QUERY_CONTAINER_ID: u32 = 5;

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

pub const PNP_DEVNODE_NAME_MAX: usize = 160;

/// `PNP_OP_CREATE_DEVNODE` payload carried in the request shared-data frame.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PnpCreateDevnodeReq {
    pub abi_size: u16,
    pub flags: u16,
    pub instance_id_len: u16,
    pub service_len: u16,
    pub pdo_object_id: u64,
    pub mem_start: u64,
    pub mem_length: u32,
    pub int_vector: u32,
    pub int_level: u32,
    pub int_affinity: u64,
    pub int_latched: u8,
    pub reserved: [u8; 7],
    pub instance_id: [u8; PNP_DEVNODE_NAME_MAX],
    pub service: [u8; PNP_DEVNODE_NAME_MAX],
}

impl PnpCreateDevnodeReq {
    pub fn new(
        pdo_object_id: u64,
        mem_start: u64,
        mem_length: u32,
        int_vector: u32,
        int_level: u32,
        int_affinity: u64,
        int_latched: bool,
    ) -> Self {
        Self {
            abi_size: core::mem::size_of::<Self>() as u16,
            pdo_object_id,
            mem_start,
            mem_length,
            int_vector,
            int_level,
            int_affinity,
            int_latched: int_latched as u8,
            ..Default::default()
        }
    }

    pub fn set_instance_id(&mut self, value: &str) -> bool {
        if value.len() > PNP_DEVNODE_NAME_MAX || value.len() > u16::MAX as usize {
            return false;
        }
        self.instance_id = [0; PNP_DEVNODE_NAME_MAX];
        self.instance_id[..value.len()].copy_from_slice(value.as_bytes());
        self.instance_id_len = value.len() as u16;
        true
    }

    pub fn set_service(&mut self, value: &str) -> bool {
        if value.len() > PNP_DEVNODE_NAME_MAX || value.len() > u16::MAX as usize {
            return false;
        }
        self.service = [0; PNP_DEVNODE_NAME_MAX];
        self.service[..value.len()].copy_from_slice(value.as_bytes());
        self.service_len = value.len() as u16;
        true
    }

    pub fn instance_id(&self) -> Option<&str> {
        let len = self.instance_id_len as usize;
        if len > PNP_DEVNODE_NAME_MAX {
            return None;
        }
        core::str::from_utf8(&self.instance_id[..len]).ok()
    }

    pub fn service(&self) -> Option<&str> {
        let len = self.service_len as usize;
        if len > PNP_DEVNODE_NAME_MAX {
            return None;
        }
        if len == 0 {
            return None;
        }
        core::str::from_utf8(&self.service[..len]).ok()
    }
}

impl Default for PnpCreateDevnodeReq {
    fn default() -> Self {
        Self {
            abi_size: core::mem::size_of::<Self>() as u16,
            flags: 0,
            instance_id_len: 0,
            service_len: 0,
            pdo_object_id: 0,
            mem_start: 0,
            mem_length: 0,
            int_vector: 0,
            int_level: 0,
            int_affinity: 0,
            int_latched: 0,
            reserved: [0; 7],
            instance_id: [0; PNP_DEVNODE_NAME_MAX],
            service: [0; PNP_DEVNODE_NAME_MAX],
        }
    }
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
    fn native_bus_property_query_minors_match_nt() {
        assert_eq!(IRP_MN_QUERY_CAPABILITIES, 0x09);
        assert_eq!(IRP_MN_QUERY_RESOURCES, 0x0A);
        assert_eq!(IRP_MN_QUERY_RESOURCE_REQUIREMENTS, 0x0B);
        assert_eq!(IRP_MN_FILTER_RESOURCE_REQUIREMENTS, 0x0D);
        assert_eq!(IRP_MN_QUERY_BUS_INFORMATION, 0x15);
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
    fn create_devnode_req_layout_and_strings() {
        assert_eq!(align_of::<PnpCreateDevnodeReq>(), 8);
        assert_eq!(offset_of!(PnpCreateDevnodeReq, pdo_object_id), 8);
        assert_eq!(offset_of!(PnpCreateDevnodeReq, mem_start), 16);
        assert_eq!(offset_of!(PnpCreateDevnodeReq, instance_id), 56);

        let mut req = PnpCreateDevnodeReq::new(0x1234, 0x1000_0000, 0x1000, 5, 5, 1, false);
        assert!(req.set_instance_id(r"ROOT\USERSPACE_NTOS_PNP_MMIO\0001"));
        assert!(req.set_service("PnpMmioInterruptTest"));
        assert_eq!(
            req.instance_id(),
            Some(r"ROOT\USERSPACE_NTOS_PNP_MMIO\0001")
        );
        assert_eq!(req.service(), Some("PnpMmioInterruptTest"));
        assert_eq!(req.pdo_object_id, 0x1234);
        assert_eq!(req.mem_start, 0x1000_0000);
    }

    #[test]
    fn irp_constants() {
        assert_eq!(IRP_MJ_PNP, 27);
        assert_eq!(IRP_MN_START_DEVICE, 0);
        assert_eq!(IRP_MN_REMOVE_DEVICE, 2);
        assert_eq!(IRP_MN_QUERY_DEVICE_RELATIONS, 7);
        assert_eq!(IRP_MN_QUERY_INTERFACE, 8);
        assert_eq!(IRP_MN_QUERY_ID, 0x13);
        assert_eq!(BUS_RELATIONS, 0);
        assert_eq!(BUS_QUERY_INSTANCE_ID, 3);
    }

    #[test]
    fn bus_interface_query_wire_is_pointer_free_and_strict() {
        let request = BusInterfaceQueryRequest::standard();
        assert_eq!(BusInterfaceQueryRequest::decode(&request.encode()), Ok(request));
        let mut too_old = request;
        too_old.version = 0;
        assert_eq!(too_old.validate(), Err(BusInterfaceQueryError::UnsupportedVersion));
        let mut too_small = request;
        too_small.size = BUS_INTERFACE_STANDARD_X64_SIZE - 1;
        assert_eq!(too_small.validate(), Err(BusInterfaceQueryError::BufferTooSmall));
        let mut other = request;
        other.interface_type[0] ^= 1;
        assert_eq!(other.validate(), Err(BusInterfaceQueryError::UnsupportedGuid));
        assert_eq!(BusInterfaceQueryRequest::decode(&request.encode()[..19]),
            Err(BusInterfaceQueryError::InvalidLength));
        let reply = BusInterfaceQueryReply {
            size: BUS_INTERFACE_STANDARD_X64_SIZE,
            version: 1,
            lease_id: 3,
            device_id: 7,
        };
        assert_eq!(BusInterfaceQueryReply::decode(&reply.encode()), Ok(reply));
        let mut invalid = reply.encode();
        invalid[4] = 1;
        assert_eq!(BusInterfaceQueryReply::decode(&invalid),
            Err(BusInterfaceQueryError::InvalidLength));
    }
}
