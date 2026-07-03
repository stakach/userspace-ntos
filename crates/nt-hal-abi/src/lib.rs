//! # `nt-hal-abi` — the SURT HAL / Resource Manager wire ABI
//!
//! Fixed-layout `#[repr(C)]` structs + opcodes shared between the Driver Host's
//! HAL client and the HAL / Resource Manager service (spec: NT HAL, Resource
//! Manager, and Interrupt Delivery — Milestone 11). Everything here is plain data:
//! `no_std`, no allocation, no seL4 or Driver Host dependency, no raw pointers or
//! `usize`/`bool`. IDs are opaque `u64`s; **raw addresses and function pointers
//! never cross this boundary** (spec §6.2, §16.3) — the request carries a
//! `physical_address` the service validates against a resource assignment, and ISR
//! callbacks are opaque tokens meaningful only to the Driver Host.

#![no_std]

/// ABI version — bump on any layout change.
pub const HAL_ABI_VERSION: u16 = 1;

/// Opaque identifiers (meaningful across the SURT boundary).
pub type ResourceId = u64;
pub type MappingId = u64;
pub type InterruptId = u64;
pub type DriverHostId = u64;
pub type DeviceObjectId = u64;

// --- opcodes (spec §10; HAL/resource range 0x5000..=0x50ff) ------------------

pub const HAL_OP_PING: u16 = 0x5000;
pub const HAL_OP_REGISTER_DRIVER_HOST: u16 = 0x5001;
pub const HAL_OP_CLOSE_DRIVER_HOST: u16 = 0x5002;

pub const HAL_OP_QUERY_DEVICE_RESOURCES: u16 = 0x5010;
pub const HAL_OP_MAP_IO_SPACE: u16 = 0x5011;
pub const HAL_OP_UNMAP_IO_SPACE: u16 = 0x5012;
pub const HAL_OP_READ_REGISTER: u16 = 0x5013;
pub const HAL_OP_WRITE_REGISTER: u16 = 0x5014;

pub const HAL_OP_CONNECT_INTERRUPT: u16 = 0x5020;
pub const HAL_OP_DISCONNECT_INTERRUPT: u16 = 0x5021;
pub const HAL_OP_SET_INTERRUPT_ACTIVE: u16 = 0x5022;
pub const HAL_OP_INJECT_INTERRUPT: u16 = 0x5023;
pub const HAL_OP_INTERRUPT_CLAIMED: u16 = 0x5024;

pub const HAL_OP_RESOURCE_GRANT: u16 = 0x5030;
pub const HAL_OP_RESOURCE_REVOKE: u16 = 0x5031;
pub const HAL_OP_QUERY_MAPPING: u16 = 0x5032;

// --- resource kinds (spec §7.1) ----------------------------------------------

pub const RES_KIND_MEMORY: u16 = 1;
pub const RES_KIND_PORT: u16 = 2;
pub const RES_KIND_INTERRUPT: u16 = 3;
pub const RES_KIND_DMA: u16 = 4;
pub const RES_KIND_BUS_NUMBER: u16 = 5;
pub const RES_KIND_DEVICE_PRIVATE: u16 = 6;

// --- memory caching types (Windows `MEMORY_CACHING_TYPE`, spec §8.5) ----------

pub const MM_NON_CACHED: u32 = 0;
pub const MM_CACHED: u32 = 1;
pub const MM_WRITE_COMBINED: u32 = 2;

// --- access rights bits (spec §7.3 `rights`) ---------------------------------

pub const RIGHT_READ: u64 = 0b01;
pub const RIGHT_WRITE: u64 = 0b10;

// --- interrupt mode + share disposition (spec §7.3, §9) ----------------------

pub const INT_MODE_LEVEL_SENSITIVE: u8 = 0;
pub const INT_MODE_LATCHED: u8 = 1;

pub const SHARE_EXCLUSIVE: u16 = 0;
pub const SHARE_SHARED: u16 = 1;

// --- wire structs (spec §10) -------------------------------------------------

/// A raw *or* translated resource descriptor (spec §10.2). For `RES_KIND_MEMORY`,
/// `arg0` = cache type, `arg1` = rights. For `RES_KIND_INTERRUPT`, `arg0` low 32 =
/// vector, high 8 = irql; `arg1` low 32 = affinity, high 8 = mode.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalResourceDescriptor {
    pub kind: u16,
    pub flags: u16,
    pub share: u16,
    pub reserved0: u16,
    pub resource_id: u64,
    pub raw_start: u64,
    pub translated_start: u64,
    pub length: u64,
    pub arg0: u64,
    pub arg1: u64,
}

impl HalResourceDescriptor {
    /// Encode an interrupt descriptor's `arg0`/`arg1` (spec §10.2).
    pub fn interrupt_args(vector: u32, irql: u8, affinity: u32, mode: u8) -> (u64, u64) {
        let arg0 = (vector as u64) | ((irql as u64) << 32);
        let arg1 = (affinity as u64) | ((mode as u64) << 32);
        (arg0, arg1)
    }

    /// Decode `(vector, irql, affinity, mode)` from an interrupt descriptor.
    pub fn interrupt_fields(&self) -> (u32, u8, u32, u8) {
        let vector = self.arg0 as u32;
        let irql = (self.arg0 >> 32) as u8;
        let affinity = self.arg1 as u32;
        let mode = (self.arg1 >> 32) as u8;
        (vector, irql, affinity, mode)
    }
}

/// `HAL_OP_QUERY_DEVICE_RESOURCES` request (spec §10.1).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalQueryDeviceResourcesReq {
    pub abi_size: u16,
    pub flags: u16,
    pub driver_host_id: u64,
    pub device_object_id: u64,
    pub output_buffer_id: u64,
    pub output_offset: u64,
    pub output_len: u32,
    pub reserved: u32,
}

/// `HAL_OP_MAP_IO_SPACE` request (spec §10.3).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalMapIoSpaceReq {
    pub abi_size: u16,
    pub flags: u16,
    pub cache_type: u32,
    pub driver_host_id: u64,
    pub device_object_id: u64,
    pub physical_address: u64,
    pub length: u64,
}

/// `HAL_OP_UNMAP_IO_SPACE` request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalUnmapIoSpaceReq {
    pub abi_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub driver_host_id: u64,
    pub device_object_id: u64,
    pub mapping_id: u64,
    pub length: u64,
}

/// `HAL_OP_CONNECT_INTERRUPT` request (spec §10.4). The `*_token` fields are opaque
/// to the service — only the Driver Host resolves them to local pointers.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalConnectInterruptReq {
    pub abi_size: u16,
    pub version: u16,
    pub flags: u32,
    pub driver_host_id: u64,
    pub device_object_id: u64,
    pub resource_id: u64,
    pub service_routine_token: u64,
    pub service_context_token: u64,
    pub vector: u32,
    pub irql: u8,
    pub mode: u8,
    pub share: u8,
    pub reserved: u8,
    pub affinity: u64,
}

/// `HAL_OP_DISCONNECT_INTERRUPT` request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalDisconnectInterruptReq {
    pub abi_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub driver_host_id: u64,
    pub device_object_id: u64,
    pub interrupt_id: u64,
}

/// `HAL_OP_INJECT_INTERRUPT` request — from the privileged test/injection endpoint.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalInjectInterruptReq {
    pub abi_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub resource_id: u64,
    pub interrupt_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn resource_descriptor_layout() {
        assert_eq!(size_of::<HalResourceDescriptor>(), 56);
        assert_eq!(align_of::<HalResourceDescriptor>(), 8);
        assert_eq!(offset_of!(HalResourceDescriptor, resource_id), 8);
        assert_eq!(offset_of!(HalResourceDescriptor, raw_start), 16);
        assert_eq!(offset_of!(HalResourceDescriptor, translated_start), 24);
        assert_eq!(offset_of!(HalResourceDescriptor, length), 32);
        assert_eq!(offset_of!(HalResourceDescriptor, arg0), 40);
        assert_eq!(offset_of!(HalResourceDescriptor, arg1), 48);
    }

    #[test]
    fn map_req_layout() {
        assert_eq!(size_of::<HalMapIoSpaceReq>(), 40);
        assert_eq!(offset_of!(HalMapIoSpaceReq, cache_type), 4);
        assert_eq!(offset_of!(HalMapIoSpaceReq, physical_address), 24);
        assert_eq!(offset_of!(HalMapIoSpaceReq, length), 32);
    }

    #[test]
    fn connect_req_fits_and_tokens_present() {
        // Every field 8-aligned + the opaque tokens present.
        assert_eq!(align_of::<HalConnectInterruptReq>(), 8);
        assert_eq!(
            offset_of!(HalConnectInterruptReq, service_routine_token),
            32
        );
        assert_eq!(
            offset_of!(HalConnectInterruptReq, service_context_token),
            40
        );
    }

    #[test]
    fn interrupt_arg_roundtrip() {
        let (a0, a1) = HalResourceDescriptor::interrupt_args(5, 5, 1, INT_MODE_LEVEL_SENSITIVE);
        let d = HalResourceDescriptor {
            kind: RES_KIND_INTERRUPT,
            arg0: a0,
            arg1: a1,
            ..Default::default()
        };
        assert_eq!(d.interrupt_fields(), (5, 5, 1, INT_MODE_LEVEL_SENSITIVE));
    }
}
