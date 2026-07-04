//! # `nt-dma-abi` — the NT DMA Manager wire ABI
//!
//! Opcodes + fixed-layout `#[repr(C)]` request structs shared between the Driver
//! Host and the DMA Manager (spec: NT DMA/MDL/IOMMU, Milestone 14, §18). `no_std`,
//! no allocation, no seL4 dependency, no raw pointers — DMA logical addresses are
//! allocator-controlled fakes, never real host physical addresses (spec §10.4).

#![no_std]

/// Opaque wire identifiers (spec §18.1).
pub type DmaAdapterId = u64;
pub type CommonBufferId = u64;
pub type DmaMappingId = u64;
pub type MdlId = u64;
pub type ScatterGatherListId = u64;

// --- opcodes (spec §18; DMA range 0x8000..=0x80ff) ---------------------------

pub const DMA_OP_PING: u16 = 0x8000;
pub const DMA_OP_REGISTER_DEVICE: u16 = 0x8001;
pub const DMA_OP_UNREGISTER_DEVICE: u16 = 0x8002;

pub const DMA_OP_GET_ADAPTER: u16 = 0x8010;
pub const DMA_OP_PUT_ADAPTER: u16 = 0x8011;
pub const DMA_OP_QUERY_ADAPTER: u16 = 0x8012;

pub const DMA_OP_ALLOC_COMMON_BUFFER: u16 = 0x8020;
pub const DMA_OP_FREE_COMMON_BUFFER: u16 = 0x8021;
pub const DMA_OP_MAP_LOGICAL: u16 = 0x8022;
pub const DMA_OP_UNMAP_LOGICAL: u16 = 0x8023;

pub const DMA_OP_REGISTER_MDL: u16 = 0x8030;
pub const DMA_OP_FREE_MDL: u16 = 0x8031;
pub const DMA_OP_MAP_TRANSFER: u16 = 0x8032;
pub const DMA_OP_FLUSH_ADAPTER_BUFFERS: u16 = 0x8033;
pub const DMA_OP_FREE_MAP_REGISTERS: u16 = 0x8034;

pub const DMA_OP_GET_SCATTER_GATHER_LIST: u16 = 0x8040;
pub const DMA_OP_PUT_SCATTER_GATHER_LIST: u16 = 0x8041;

pub const DMA_OP_SIM_DEVICE_COMMAND: u16 = 0x8050;
pub const DMA_OP_DUMP_STATE: u16 = 0x80f0;

/// DMA direction (spec §10.3 — internal preference avoids `WriteToDevice` ambiguity).
pub const DMA_DIR_DEVICE_READS_MEMORY: u32 = 0; // WriteToDevice = TRUE
pub const DMA_DIR_DEVICE_WRITES_MEMORY: u32 = 1; // WriteToDevice = FALSE
pub const DMA_DIR_BIDIRECTIONAL: u32 = 2;

/// `DMA_OP_ALLOC_COMMON_BUFFER` request (spec §18.2).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DmaAllocCommonBufferReq {
    pub abi_size: u16,
    pub flags: u16,
    pub cache_enabled: u32,
    pub driver_host_id: u64,
    pub devnode_id: u64,
    pub dma_adapter_id: u64,
    pub length: u64,
    pub alignment: u32,
    pub address_bits: u32,
}

/// `DMA_OP_MAP_TRANSFER` request (spec §18.3).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DmaMapTransferReq {
    pub abi_size: u16,
    pub flags: u16,
    pub direction: u32,
    pub driver_host_id: u64,
    pub devnode_id: u64,
    pub dma_adapter_id: u64,
    pub mdl_id: u64,
    pub current_va_offset: u64,
    pub requested_length: u64,
    pub map_register_token: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn alloc_common_buffer_layout() {
        assert_eq!(align_of::<DmaAllocCommonBufferReq>(), 8);
        assert_eq!(offset_of!(DmaAllocCommonBufferReq, driver_host_id), 8);
        assert_eq!(offset_of!(DmaAllocCommonBufferReq, dma_adapter_id), 24);
        assert_eq!(offset_of!(DmaAllocCommonBufferReq, length), 32);
    }

    #[test]
    fn map_transfer_layout() {
        assert_eq!(size_of::<DmaMapTransferReq>(), 64);
        assert_eq!(offset_of!(DmaMapTransferReq, mdl_id), 32);
        assert_eq!(offset_of!(DmaMapTransferReq, requested_length), 48);
    }

    #[test]
    fn opcodes_in_range() {
        assert_eq!(DMA_OP_ALLOC_COMMON_BUFFER, 0x8020);
        assert_eq!(DMA_OP_DUMP_STATE, 0x80f0);
    }
}
