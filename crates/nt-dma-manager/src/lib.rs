//! # `nt-dma-manager` — the DMA Manager core
//!
//! The DMA adapter registry, common-buffer allocator, and fake logical-address
//! decoder (spec: NT DMA/MDL/IOMMU, Milestone 14, §9-§11, §19). DMA logical/device
//! addresses are **allocator-controlled fakes** — never real host physical addresses
//! (spec §10.4, §25). A device may DMA only to a common buffer or MDL slice mapped
//! for it (the IOMMU-facade policy, §19.2). `no_std` + `alloc`; holds no raw driver
//! pointers, only IDs + address/length values.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// Identifies the requester of a DMA operation (spec §10.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DmaOwner {
    pub driver_host_id: u64,
    pub driver_host_cookie: u64,
    pub devnode_id: u64,
}

impl DmaOwner {
    pub fn new(driver_host_id: u64, driver_host_cookie: u64, devnode_id: u64) -> Self {
        Self {
            driver_host_id,
            driver_host_cookie,
            devnode_id,
        }
    }
}

/// Why a DMA operation was rejected (spec §17.4, §25).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaError {
    /// No such adapter / buffer / mapping (or stale after free).
    StaleId,
    /// The object belongs to a different owner.
    WrongOwner,
    /// The adapter was put back / the device is not usable.
    Inactive,
    /// A parameter (length / logical address) is out of the allowed range.
    OutOfRange,
    /// The logical address is not owned by / mapped for this device (§19.2).
    LogicalViolation,
    /// A live adapter already exists for the owner with different properties.
    AdapterConflict,
}

/// Bus-facing properties supplied by `IoGetDmaAdapter` after validating the caller's
/// `DEVICE_DESCRIPTION`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DmaAdapterRequest {
    pub scatter_gather: bool,
    pub maximum_length: u64,
    pub dma64: bool,
}

pub const NT5_DEVICE_DESCRIPTION_SIZE: usize = 40;
pub const NT5_DEVICE_DESCRIPTION_MAX_VERSION: u32 = 2;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceDescriptionError {
    BufferTooSmall,
    UnsupportedVersion,
    ReservedBitSet,
    InvalidDmaWidth,
    InvalidDmaSpeed,
    InvalidTransport,
}

/// Pointer-free NT5 `DEVICE_DESCRIPTION` supplied to `IoGetDmaAdapter`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Nt5DeviceDescription {
    pub version: u32,
    pub master: bool,
    pub scatter_gather: bool,
    pub demand_mode: bool,
    pub auto_initialize: bool,
    pub dma32: bool,
    pub ignore_count: bool,
    pub dma64: bool,
    pub bus_number: u32,
    pub dma_channel: u32,
    pub interface_type: i32,
    pub dma_width: u32,
    pub dma_speed: u32,
    pub maximum_length: u32,
    pub dma_port: u32,
}

impl Nt5DeviceDescription {
    pub fn parse(bytes: &[u8]) -> Result<Self, DeviceDescriptionError> {
        if bytes.len() < NT5_DEVICE_DESCRIPTION_SIZE {
            return Err(DeviceDescriptionError::BufferTooSmall);
        }
        let version = read_le_u32(&bytes[0..4]);
        if version > NT5_DEVICE_DESCRIPTION_MAX_VERSION {
            return Err(DeviceDescriptionError::UnsupportedVersion);
        }
        if bytes[10] != 0 {
            return Err(DeviceDescriptionError::ReservedBitSet);
        }
        let dma_width = read_le_u32(&bytes[24..28]);
        if dma_width >= 3 {
            return Err(DeviceDescriptionError::InvalidDmaWidth);
        }
        let dma_speed = read_le_u32(&bytes[28..32]);
        if dma_speed >= 5 {
            return Err(DeviceDescriptionError::InvalidDmaSpeed);
        }
        Ok(Self {
            version,
            master: bytes[4] != 0,
            scatter_gather: bytes[5] != 0,
            demand_mode: bytes[6] != 0,
            auto_initialize: bytes[7] != 0,
            dma32: bytes[8] != 0,
            ignore_count: bytes[9] != 0,
            dma64: bytes[11] != 0,
            bus_number: read_le_u32(&bytes[12..16]),
            dma_channel: read_le_u32(&bytes[16..20]),
            interface_type: read_le_u32(&bytes[20..24]) as i32,
            dma_width,
            dma_speed,
            maximum_length: read_le_u32(&bytes[32..36]),
            dma_port: read_le_u32(&bytes[36..40]),
        })
    }

    pub fn adapter_request(self) -> DmaAdapterRequest {
        DmaAdapterRequest {
            scatter_gather: self.scatter_gather,
            maximum_length: self.maximum_length as u64,
            dma64: self.dma64,
        }
    }

    /// Losslessly normalize the NT5 structure into the four message registers following the PDO.
    pub fn service_words(self) -> [u64; 4] {
        let flags = u8::from(self.master)
            | u8::from(self.scatter_gather) << 1
            | u8::from(self.demand_mode) << 2
            | u8::from(self.auto_initialize) << 3
            | u8::from(self.dma32) << 4
            | u8::from(self.ignore_count) << 5
            | u8::from(self.dma64) << 6;
        [
            self.version as u64 | (flags as u64) << 32,
            self.bus_number as u64 | (self.dma_channel as u64) << 32,
            self.interface_type as u32 as u64
                | (self.dma_width as u64) << 32
                | (self.dma_speed as u64) << 40,
            self.maximum_length as u64 | (self.dma_port as u64) << 32,
        ]
    }

    pub fn from_service_words(words: [u64; 4]) -> Result<Self, DeviceDescriptionError> {
        let flags = (words[0] >> 32) as u8;
        if words[0] >> 40 != 0 || flags & 0x80 != 0 || words[2] >> 48 != 0 {
            return Err(DeviceDescriptionError::InvalidTransport);
        }
        let description = Self {
            version: words[0] as u32,
            master: flags & 1 != 0,
            scatter_gather: flags & 2 != 0,
            demand_mode: flags & 4 != 0,
            auto_initialize: flags & 8 != 0,
            dma32: flags & 0x10 != 0,
            ignore_count: flags & 0x20 != 0,
            dma64: flags & 0x40 != 0,
            bus_number: words[1] as u32,
            dma_channel: (words[1] >> 32) as u32,
            interface_type: words[2] as u32 as i32,
            dma_width: (words[2] >> 32) as u8 as u32,
            dma_speed: (words[2] >> 40) as u8 as u32,
            maximum_length: words[3] as u32,
            dma_port: (words[3] >> 32) as u32,
        };
        if description.version > NT5_DEVICE_DESCRIPTION_MAX_VERSION {
            return Err(DeviceDescriptionError::UnsupportedVersion);
        }
        if description.dma_width >= 3 {
            return Err(DeviceDescriptionError::InvalidDmaWidth);
        }
        if description.dma_speed >= 5 {
            return Err(DeviceDescriptionError::InvalidDmaSpeed);
        }
        Ok(description)
    }
}

/// Result of an idempotent adapter request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DmaAdapterGrant {
    pub adapter_id: u64,
    pub num_map_registers: u32,
    pub created: bool,
}

struct Adapter {
    id: u64,
    owner: DmaOwner,
    num_map_registers: u32,
    sg_supported: bool,
    max_length: u64,
    dma64: bool,
    active: bool,
}

struct CommonBuffer {
    id: u64,
    adapter_id: u64,
    owner: DmaOwner,
    logical_base: u64,
    length: u64,
    backing_va: u64,
    active: bool,
}

struct Mapping {
    id: u64,
    owner: DmaOwner,
    logical_base: u64,
    length: u64,
    backing_va: u64,
    active: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaLogicalRangeKind {
    CommonBuffer,
    TransferMapping,
}

/// One descriptor completed through an owner-scoped DMA translation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FixedDescriptorCompletion {
    pub descriptor_index: u64,
    pub descriptor_backing_va: u64,
    pub buffer_logical: u64,
    pub buffer_backing_va: u64,
    pub transfer_length: u64,
    pub range_kind: DmaLogicalRangeKind,
}

/// The result of `alloc_common_buffer`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommonBufferGrant {
    pub common_buffer_id: u64,
    pub logical_base: u64,
}

/// The result of a `map_transfer`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MapGrant {
    pub mapping_id: u64,
    pub logical_base: u64,
    pub mapped_length: u64,
}

/// Layout for a fixed-size device descriptor ring whose records contain a
/// little-endian device/logical buffer address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FixedDescriptorLayout {
    pub stride: usize,
    pub address_offset: usize,
    pub length_offset: Option<usize>,
    pub status_offset: Option<usize>,
    pub completion_status_mask: u8,
    pub min_buffer_probe_len: u64,
}

/// Observation produced from a live descriptor ring.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedDescriptorObservation {
    pub descriptor_count: u64,
    pub trailing_bytes: u64,
    pub descriptors_with_device_address: u64,
    pub descriptors_with_decodable_buffer: u64,
    pub descriptors_with_common_buffer: u64,
    pub descriptors_with_transfer_mapping: u64,
    pub descriptors_with_length: u64,
    pub completed_descriptors: u64,
    pub completed_common_buffer_descriptors: u64,
    pub completed_transfer_mapping_descriptors: u64,
    pub malformed_descriptors: u64,
}

/// The canonical DMA state.
pub struct DmaManager {
    adapters: Vec<Adapter>,
    common_buffers: Vec<CommonBuffer>,
    mappings: Vec<Mapping>,
    next_adapter_id: u64,
    next_cb_id: u64,
    next_mapping_id: u64,
    next_logical: u64,
}

impl Default for DmaManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaManager {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
            common_buffers: Vec::new(),
            mappings: Vec::new(),
            next_adapter_id: 1,
            next_cb_id: 1,
            next_mapping_id: 1,
            // Fake device-address space; each allocation gets a 64 KiB-aligned base.
            next_logical: 0x8000_0000,
        }
    }

    fn alloc_logical(&mut self) -> u64 {
        let l = self.next_logical;
        self.next_logical += 0x1_0000;
        l
    }

    /// `IoGetDmaAdapter` (spec §9): register a bus-master adapter for `owner`.
    /// Returns the adapter ID; `num_map_registers` is a generous fixed quota (§9.5).
    pub fn register_adapter(
        &mut self,
        owner: DmaOwner,
        sg_supported: bool,
        max_length: u64,
        dma64: bool,
    ) -> u64 {
        let id = self.next_adapter_id;
        self.next_adapter_id += 1;
        self.adapters.push(Adapter {
            id,
            owner,
            num_map_registers: 64,
            sg_supported,
            max_length,
            dma64,
            active: true,
        });
        id
    }

    /// Resolve one live DMA adapter for an exact hosted devnode generation.
    ///
    /// An exact retry returns the existing adapter. A different request cannot mutate a live
    /// adapter, and a retired owner generation never aliases a replacement adapter ID.
    pub fn request_adapter(
        &mut self,
        owner: DmaOwner,
        request: DmaAdapterRequest,
    ) -> Result<DmaAdapterGrant, DmaError> {
        if owner.driver_host_id == 0
            || owner.driver_host_cookie == 0
            || owner.devnode_id == 0
            || request.maximum_length == 0
        {
            return Err(DmaError::OutOfRange);
        }
        if let Some(adapter) = self
            .adapters
            .iter()
            .find(|adapter| adapter.owner == owner && adapter.active)
        {
            if adapter.sg_supported != request.scatter_gather
                || adapter.max_length != request.maximum_length
                || adapter.dma64 != request.dma64
            {
                return Err(DmaError::AdapterConflict);
            }
            return Ok(DmaAdapterGrant {
                adapter_id: adapter.id,
                num_map_registers: adapter.num_map_registers,
                created: false,
            });
        }

        let adapter_id = self.register_adapter(
            owner,
            request.scatter_gather,
            request.maximum_length,
            request.dma64,
        );
        Ok(DmaAdapterGrant {
            adapter_id,
            num_map_registers: 64,
            created: true,
        })
    }

    pub fn num_map_registers(&self, adapter_id: u64) -> Option<u32> {
        self.adapters
            .iter()
            .find(|a| a.id == adapter_id)
            .map(|a| a.num_map_registers)
    }

    /// Whether the adapter advertised scatter/gather support (spec §9.4).
    pub fn sg_supported(&self, adapter_id: u64) -> Option<bool> {
        self.adapters
            .iter()
            .find(|a| a.id == adapter_id)
            .map(|a| a.sg_supported)
    }

    /// Whether `cb_id` is a live common buffer, and its owning adapter.
    pub fn common_buffer_adapter(&self, cb_id: u64) -> Option<u64> {
        self.common_buffers
            .iter()
            .find(|c| c.id == cb_id && c.active)
            .map(|c| c.adapter_id)
    }

    fn adapter(&self, id: u64, owner: DmaOwner) -> Result<&Adapter, DmaError> {
        let a = self
            .adapters
            .iter()
            .find(|a| a.id == id)
            .ok_or(DmaError::StaleId)?;
        if a.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if !a.active {
            return Err(DmaError::Inactive);
        }
        Ok(a)
    }

    /// `PutDmaAdapter` — release the adapter (spec §9.3).
    pub fn put_adapter(&mut self, adapter_id: u64) {
        if let Some(a) = self.adapters.iter_mut().find(|a| a.id == adapter_id) {
            a.active = false;
        }
    }

    /// `AllocateCommonBuffer` (spec §11.1): allocate a fake logical address for a
    /// common buffer backed by `backing_va` (a real Driver-Host address). Validates
    /// the adapter is owned + active, and the length fits the adapter maximum + the
    /// device's address-bit limit (§10.4).
    pub fn alloc_common_buffer(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        length: u64,
        backing_va: u64,
    ) -> Result<CommonBufferGrant, DmaError> {
        let logical_base = self.alloc_logical();
        self.register_common_buffer_at(owner, adapter_id, logical_base, length, backing_va)
    }

    /// Register a broker-provided common buffer at a caller-selected device logical address.
    /// This is used when a trusted bus/PnP broker already installed an IOMMU mapping and the
    /// driver-visible logical address must match that mapping.
    pub fn register_common_buffer_at(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        logical_base: u64,
        length: u64,
        backing_va: u64,
    ) -> Result<CommonBufferGrant, DmaError> {
        let (max_length, dma64) = {
            let a = self.adapter(adapter_id, owner)?;
            (a.max_length, a.dma64)
        };
        if logical_base == 0 || length == 0 || length > max_length {
            return Err(DmaError::OutOfRange);
        }
        let logical_end = logical_base
            .checked_add(length)
            .ok_or(DmaError::OutOfRange)?;
        if !dma64 && logical_end > 0x1_0000_0000 {
            return Err(DmaError::OutOfRange);
        }
        if self.logical_range_in_use(owner, logical_base, length) {
            return Err(DmaError::LogicalViolation);
        }
        let id = self.next_cb_id;
        self.next_cb_id += 1;
        self.common_buffers.push(CommonBuffer {
            id,
            adapter_id,
            owner,
            logical_base,
            length,
            backing_va,
            active: true,
        });
        Ok(CommonBufferGrant {
            common_buffer_id: id,
            logical_base,
        })
    }

    /// Idempotently learn a broker-provided common buffer. Exact live replays return the
    /// existing grant; overlaps or mismatched metadata still fail.
    pub fn ensure_common_buffer_at(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        logical_base: u64,
        length: u64,
        backing_va: u64,
    ) -> Result<CommonBufferGrant, DmaError> {
        if let Some(existing) = self.common_buffers.iter().find(|c| {
            c.active
                && c.owner == owner
                && c.adapter_id == adapter_id
                && c.logical_base == logical_base
                && c.length == length
                && c.backing_va == backing_va
        }) {
            return Ok(CommonBufferGrant {
                common_buffer_id: existing.id,
                logical_base,
            });
        }
        self.register_common_buffer_at(owner, adapter_id, logical_base, length, backing_va)
    }

    fn logical_range_in_use(&self, owner: DmaOwner, logical_base: u64, length: u64) -> bool {
        let Some(end) = logical_base.checked_add(length) else {
            return true;
        };
        for cb in self
            .common_buffers
            .iter()
            .filter(|c| c.active && c.owner == owner)
        {
            let Some(cb_end) = cb.logical_base.checked_add(cb.length) else {
                return true;
            };
            if logical_base < cb_end && cb.logical_base < end {
                return true;
            }
        }
        for mapping in self
            .mappings
            .iter()
            .filter(|m| m.active && m.owner == owner)
        {
            let Some(mapping_end) = mapping.logical_base.checked_add(mapping.length) else {
                return true;
            };
            if logical_base < mapping_end && mapping.logical_base < end {
                return true;
            }
        }
        false
    }

    /// `FreeCommonBuffer` (spec §11.2): validate the logical address + length belong
    /// to a live common buffer owned by `owner`, then revoke it.
    pub fn free_common_buffer(
        &mut self,
        owner: DmaOwner,
        logical_base: u64,
        length: u64,
    ) -> Result<(), DmaError> {
        let has_other_owner = self
            .common_buffers
            .iter()
            .any(|c| c.logical_base == logical_base && c.active && c.owner != owner);
        let cb = self
            .common_buffers
            .iter_mut()
            .find(|c| c.logical_base == logical_base && c.active && c.owner == owner)
            .ok_or(if has_other_owner {
                DmaError::WrongOwner
            } else {
                DmaError::StaleId
            })?;
        if cb.length != length {
            return Err(DmaError::OutOfRange);
        }
        cb.active = false;
        Ok(())
    }

    /// Decode an owner-scoped device logical address to the backing Driver-Host address — the
    /// IOMMU-facade lookup a simulated device uses to touch memory (spec §19.2). Only
    /// resolves addresses within a live common buffer or active mapping; a device
    /// cannot reach unowned memory.
    pub fn decode_owner_logical(
        &self,
        owner: DmaOwner,
        logical: u64,
        length: u64,
    ) -> Result<u64, DmaError> {
        self.decode_owner_logical_with_kind(owner, logical, length)
            .map(|decoded| decoded.0)
    }

    /// Owner-scoped logical decode with the backing range class. Device models use
    /// this when their behavior must distinguish persistent common buffers from
    /// one-shot packet-transfer mappings while preserving the same IOMMU boundary as
    /// [`Self::decode_owner_logical`].
    pub fn decode_owner_logical_with_kind(
        &self,
        owner: DmaOwner,
        logical: u64,
        length: u64,
    ) -> Result<(u64, DmaLogicalRangeKind), DmaError> {
        for cb in self
            .common_buffers
            .iter()
            .filter(|c| c.active && c.owner == owner)
        {
            let end = logical.checked_add(length).ok_or(DmaError::OutOfRange)?;
            let cb_end = cb
                .logical_base
                .checked_add(cb.length)
                .ok_or(DmaError::OutOfRange)?;
            if logical >= cb.logical_base && end <= cb_end {
                return Ok((
                    cb.backing_va + (logical - cb.logical_base),
                    DmaLogicalRangeKind::CommonBuffer,
                ));
            }
        }
        for m in self
            .mappings
            .iter()
            .filter(|m| m.active && m.owner == owner)
        {
            let end = logical.checked_add(length).ok_or(DmaError::OutOfRange)?;
            let map_end = m
                .logical_base
                .checked_add(m.length)
                .ok_or(DmaError::OutOfRange)?;
            if logical >= m.logical_base && end <= map_end {
                return Ok((
                    m.backing_va + (logical - m.logical_base),
                    DmaLogicalRangeKind::TransferMapping,
                ));
            }
        }
        Err(DmaError::LogicalViolation)
    }

    /// Legacy single-device decode helper. New device simulations should use
    /// [`Self::decode_owner_logical`] so identical IOVAs in different device domains
    /// remain unambiguous.
    pub fn decode_logical(&self, logical: u64, length: u64) -> Result<u64, DmaError> {
        for cb in self.common_buffers.iter().filter(|c| c.active) {
            let end = logical.checked_add(length).ok_or(DmaError::OutOfRange)?;
            let cb_end = cb
                .logical_base
                .checked_add(cb.length)
                .ok_or(DmaError::OutOfRange)?;
            if logical >= cb.logical_base && end <= cb_end {
                return Ok(cb.backing_va + (logical - cb.logical_base));
            }
        }
        for m in self.mappings.iter().filter(|m| m.active) {
            let end = logical.checked_add(length).ok_or(DmaError::OutOfRange)?;
            let map_end = m
                .logical_base
                .checked_add(m.length)
                .ok_or(DmaError::OutOfRange)?;
            if logical >= m.logical_base && end <= map_end {
                return Ok(m.backing_va + (logical - m.logical_base));
            }
        }
        Err(DmaError::LogicalViolation)
    }

    /// Observe a live fixed-size descriptor ring through the same owner-scoped
    /// logical-address decoder that a simulated device uses. The ring itself must be
    /// a live DMA object for `owner`; every non-zero descriptor buffer address is
    /// counted as decodable only if it resolves inside that owner's DMA domain.
    pub fn observe_fixed_descriptor_ring(
        &self,
        owner: DmaOwner,
        descriptor_logical: u64,
        descriptor_backing_va: u64,
        ring: &[u8],
        layout: FixedDescriptorLayout,
    ) -> Result<FixedDescriptorObservation, DmaError> {
        if ring.is_empty()
            || layout.stride == 0
            || layout.address_offset.checked_add(8).is_none()
            || layout.address_offset + 8 > layout.stride
            || layout
                .length_offset
                .map(|offset| offset.checked_add(2).is_none() || offset + 2 > layout.stride)
                .unwrap_or(false)
            || layout
                .status_offset
                .map(|offset| offset >= layout.stride)
                .unwrap_or(false)
            || layout.min_buffer_probe_len == 0
        {
            return Err(DmaError::OutOfRange);
        }
        let ring_len = ring.len() as u64;
        let decoded_ring = self.decode_owner_logical(owner, descriptor_logical, ring_len)?;
        if decoded_ring != descriptor_backing_va {
            return Err(DmaError::LogicalViolation);
        }

        let descriptor_count = ring.len() / layout.stride;
        let mut observation = FixedDescriptorObservation {
            descriptor_count: descriptor_count as u64,
            trailing_bytes: (ring.len() % layout.stride) as u64,
            ..FixedDescriptorObservation::default()
        };
        let mut index = 0usize;
        while index < descriptor_count {
            let base = index * layout.stride;
            let address = read_le_u64(&ring[base + layout.address_offset..]);
            let length = layout
                .length_offset
                .map(|offset| read_le_u16(&ring[base + offset..]) as u64)
                .unwrap_or(layout.min_buffer_probe_len);
            if length != 0 {
                observation.descriptors_with_length += 1;
            }
            if let Some(offset) = layout.status_offset {
                if ring[base + offset] & layout.completion_status_mask != 0 {
                    observation.completed_descriptors += 1;
                }
            }
            let completed = layout
                .status_offset
                .map(|offset| ring[base + offset] & layout.completion_status_mask != 0)
                .unwrap_or(false);
            if address != 0 {
                observation.descriptors_with_device_address += 1;
                let probe_len = if length == 0 {
                    layout.min_buffer_probe_len
                } else {
                    length
                };
                match self.decode_owner_logical_with_kind(owner, address, probe_len) {
                    Ok((_, DmaLogicalRangeKind::CommonBuffer)) => {
                        observation.descriptors_with_decodable_buffer += 1;
                        observation.descriptors_with_common_buffer += 1;
                        if completed {
                            observation.completed_common_buffer_descriptors += 1;
                        }
                    }
                    Ok((_, DmaLogicalRangeKind::TransferMapping)) => {
                        observation.descriptors_with_decodable_buffer += 1;
                        observation.descriptors_with_transfer_mapping += 1;
                        if completed {
                            observation.completed_transfer_mapping_descriptors += 1;
                        }
                    }
                    Err(_) => observation.malformed_descriptors += 1,
                }
            }
            index += 1;
        }
        Ok(observation)
    }

    /// Complete one fixed-size device descriptor after validating both the descriptor
    /// ring and the descriptor-owned buffer through the owner-scoped DMA decoder.
    ///
    /// This is the device side of a bus-master write-back: callers may write a final
    /// length first (for receive descriptors whose length is produced by hardware),
    /// then OR the descriptor status byte with `status_bits`.
    pub fn complete_fixed_descriptor_at(
        &self,
        owner: DmaOwner,
        descriptor_logical: u64,
        descriptor_backing_va: u64,
        ring: &mut [u8],
        layout: FixedDescriptorLayout,
        descriptor_index: usize,
        write_length: Option<u16>,
        status_bits: u8,
    ) -> Result<FixedDescriptorCompletion, DmaError> {
        if ring.is_empty()
            || layout.stride == 0
            || layout.address_offset.checked_add(8).is_none()
            || layout.address_offset + 8 > layout.stride
            || layout
                .length_offset
                .map(|offset| offset.checked_add(2).is_none() || offset + 2 > layout.stride)
                .unwrap_or(false)
            || layout
                .status_offset
                .map(|offset| offset >= layout.stride)
                .unwrap_or(true)
            || layout.min_buffer_probe_len == 0
            || status_bits == 0
        {
            return Err(DmaError::OutOfRange);
        }
        let ring_len = ring.len() as u64;
        let decoded_ring = self.decode_owner_logical(owner, descriptor_logical, ring_len)?;
        if decoded_ring != descriptor_backing_va {
            return Err(DmaError::LogicalViolation);
        }

        let descriptor_count = ring.len() / layout.stride;
        if descriptor_index >= descriptor_count {
            return Err(DmaError::OutOfRange);
        }
        let base = descriptor_index * layout.stride;
        let address = read_le_u64(&ring[base + layout.address_offset..]);
        if address == 0 {
            return Err(DmaError::LogicalViolation);
        }
        let descriptor_length = layout
            .length_offset
            .map(|offset| read_le_u16(&ring[base + offset..]) as u64)
            .unwrap_or(layout.min_buffer_probe_len);
        let transfer_length = match write_length {
            Some(length) if length != 0 => length as u64,
            Some(_) => return Err(DmaError::OutOfRange),
            None if descriptor_length != 0 => descriptor_length,
            None => layout.min_buffer_probe_len,
        };
        let (buffer_backing_va, range_kind) =
            self.decode_owner_logical_with_kind(owner, address, transfer_length)?;

        if let Some(length) = write_length {
            let offset = layout.length_offset.ok_or(DmaError::OutOfRange)?;
            ring[base + offset..base + offset + 2].copy_from_slice(&length.to_le_bytes());
        }
        let status_offset = layout.status_offset.ok_or(DmaError::OutOfRange)?;
        ring[base + status_offset] |= status_bits;

        Ok(FixedDescriptorCompletion {
            descriptor_index: descriptor_index as u64,
            descriptor_backing_va: descriptor_backing_va + base as u64,
            buffer_logical: address,
            buffer_backing_va,
            transfer_length,
            range_kind,
        })
    }

    /// `MapTransfer` (spec §12.2): map a `[backing_va, backing_va+length)` slice to a
    /// fresh logical address for a packet transfer, clipping to the adapter maximum.
    pub fn map_transfer(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        backing_va: u64,
        length: u64,
    ) -> Result<MapGrant, DmaError> {
        let max_length = self.adapter(adapter_id, owner)?.max_length;
        if length == 0 {
            return Err(DmaError::OutOfRange);
        }
        let mapped_length = length.min(max_length);
        let logical_base = self.alloc_logical();
        self.register_mapping_at(owner, adapter_id, logical_base, backing_va, mapped_length)
    }

    /// Register a packet-transfer mapping at a caller-selected device logical address.
    /// Bus/IOMMU brokers use this when the driver-visible IOVA was allocated in a
    /// component-local map-register table and the canonical manager must learn the same
    /// address for later device decode/revocation.
    pub fn register_mapping_at(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        logical_base: u64,
        backing_va: u64,
        length: u64,
    ) -> Result<MapGrant, DmaError> {
        let (max_length, dma64) = {
            let a = self.adapter(adapter_id, owner)?;
            (a.max_length, a.dma64)
        };
        if logical_base == 0 || length == 0 || length > max_length {
            return Err(DmaError::OutOfRange);
        }
        let logical_end = logical_base
            .checked_add(length)
            .ok_or(DmaError::OutOfRange)?;
        if !dma64 && logical_end > 0x1_0000_0000 {
            return Err(DmaError::OutOfRange);
        }
        if self.logical_range_in_use(owner, logical_base, length) {
            return Err(DmaError::LogicalViolation);
        }
        let id = self.next_mapping_id;
        self.next_mapping_id += 1;
        self.mappings.push(Mapping {
            id,
            owner,
            logical_base,
            length,
            backing_va,
            active: true,
        });
        Ok(MapGrant {
            mapping_id: id,
            logical_base,
            mapped_length: length,
        })
    }

    /// Idempotently learn a broker-provided packet-transfer mapping. Exact live
    /// replays return the existing grant; overlaps or mismatched metadata still fail.
    pub fn ensure_mapping_at(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        logical_base: u64,
        backing_va: u64,
        length: u64,
    ) -> Result<MapGrant, DmaError> {
        if let Some(existing) = self.mappings.iter().find(|m| {
            m.active
                && m.owner == owner
                && m.logical_base == logical_base
                && m.length == length
                && m.backing_va == backing_va
        }) {
            return Ok(MapGrant {
                mapping_id: existing.id,
                logical_base,
                mapped_length: length,
            });
        }
        self.register_mapping_at(owner, adapter_id, logical_base, backing_va, length)
    }

    /// `FreeMapRegisters` / `PutScatterGatherList` — release a mapping (spec §12.4).
    pub fn free_mapping(&mut self, mapping_id: u64) -> Result<(), DmaError> {
        let m = self
            .mappings
            .iter_mut()
            .find(|m| m.id == mapping_id && m.active)
            .ok_or(DmaError::StaleId)?;
        m.active = false;
        Ok(())
    }

    /// Owner-validated mapping release used by hosted bus brokers.
    pub fn free_mapping_for_owner(
        &mut self,
        owner: DmaOwner,
        mapping_id: u64,
    ) -> Result<(), DmaError> {
        let has_other_owner = self
            .mappings
            .iter()
            .any(|m| m.id == mapping_id && m.active && m.owner != owner);
        let m = self
            .mappings
            .iter_mut()
            .find(|m| m.id == mapping_id && m.active && m.owner == owner)
            .ok_or(if has_other_owner {
                DmaError::WrongOwner
            } else {
                DmaError::StaleId
            })?;
        m.active = false;
        Ok(())
    }

    /// Driver-host fault / device remove cleanup (spec §15.3, §17.4): revoke every
    /// common buffer + mapping owned by `owner`. Returns `(buffers, mappings)` revoked.
    pub fn revoke_owner(&mut self, owner: DmaOwner) -> (usize, usize) {
        let mut b = 0;
        for cb in self.common_buffers.iter_mut() {
            if cb.owner == owner && cb.active {
                cb.active = false;
                b += 1;
            }
        }
        let mut m = 0;
        for mp in self.mappings.iter_mut() {
            if mp.owner == owner && mp.active {
                mp.active = false;
                m += 1;
            }
        }
        for a in self.adapters.iter_mut() {
            if a.owner == owner {
                a.active = false;
            }
        }
        (b, m)
    }
}

fn read_le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> DmaOwner {
        DmaOwner::new(1, 100, 10)
    }

    fn adapter_request() -> DmaAdapterRequest {
        DmaAdapterRequest {
            scatter_gather: true,
            maximum_length: 4096,
            dma64: true,
        }
    }

    fn nt5_device_description() -> [u8; NT5_DEVICE_DESCRIPTION_SIZE] {
        let mut bytes = [0u8; NT5_DEVICE_DESCRIPTION_SIZE];
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[8] = 1;
        bytes[11] = 1;
        bytes[12..16].copy_from_slice(&7u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&5u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&2u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x20_000u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&0xcf8u32.to_le_bytes());
        bytes
    }

    #[test]
    fn nt5_device_description_decodes_without_driver_pointers() {
        let description = Nt5DeviceDescription::parse(&nt5_device_description()).unwrap();

        assert_eq!(
            description,
            Nt5DeviceDescription {
                version: 2,
                master: true,
                scatter_gather: true,
                demand_mode: false,
                auto_initialize: false,
                dma32: true,
                ignore_count: false,
                dma64: true,
                bus_number: 7,
                dma_channel: 3,
                interface_type: 5,
                dma_width: 2,
                dma_speed: 1,
                maximum_length: 0x20_000,
                dma_port: 0xcf8,
            }
        );
        assert_eq!(
            description.adapter_request(),
            DmaAdapterRequest {
                scatter_gather: true,
                maximum_length: 0x20_000,
                dma64: true,
            }
        );
    }

    #[test]
    fn nt5_device_description_rejects_truncated_new_or_reserved_forms() {
        let bytes = nt5_device_description();
        assert_eq!(
            Nt5DeviceDescription::parse(&bytes[..NT5_DEVICE_DESCRIPTION_SIZE - 1]),
            Err(DeviceDescriptionError::BufferTooSmall)
        );

        let mut unsupported = bytes;
        unsupported[0..4].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            Nt5DeviceDescription::parse(&unsupported),
            Err(DeviceDescriptionError::UnsupportedVersion)
        );

        let mut reserved = bytes;
        reserved[10] = 1;
        assert_eq!(
            Nt5DeviceDescription::parse(&reserved),
            Err(DeviceDescriptionError::ReservedBitSet)
        );

        let mut width = bytes;
        width[24..28].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            Nt5DeviceDescription::parse(&width),
            Err(DeviceDescriptionError::InvalidDmaWidth)
        );

        let mut speed = bytes;
        speed[28..32].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            Nt5DeviceDescription::parse(&speed),
            Err(DeviceDescriptionError::InvalidDmaSpeed)
        );
    }

    #[test]
    fn nt5_device_description_service_codec_is_lossless_and_canonical() {
        let description = Nt5DeviceDescription::parse(&nt5_device_description()).unwrap();
        let words = description.service_words();

        assert_eq!(
            Nt5DeviceDescription::from_service_words(words),
            Ok(description)
        );

        let mut noncanonical = words;
        noncanonical[2] |= 1 << 63;
        assert_eq!(
            Nt5DeviceDescription::from_service_words(noncanonical),
            Err(DeviceDescriptionError::InvalidTransport)
        );
    }

    #[test]
    fn adapter_request_is_exact_and_idempotent() {
        let mut d = DmaManager::new();
        let first = d.request_adapter(owner(), adapter_request()).unwrap();
        let replay = d.request_adapter(owner(), adapter_request()).unwrap();

        assert!(first.created);
        assert_eq!(first.num_map_registers, 64);
        assert_eq!(
            replay,
            DmaAdapterGrant {
                created: false,
                ..first
            }
        );
        assert_eq!(d.num_map_registers(first.adapter_id), Some(64));
    }

    #[test]
    fn live_adapter_request_rejects_property_changes_without_mutation() {
        let mut d = DmaManager::new();
        let first = d.request_adapter(owner(), adapter_request()).unwrap();

        assert_eq!(
            d.request_adapter(
                owner(),
                DmaAdapterRequest {
                    maximum_length: 8192,
                    ..adapter_request()
                }
            ),
            Err(DmaError::AdapterConflict)
        );
        assert_eq!(
            d.request_adapter(owner(), adapter_request())
                .unwrap()
                .adapter_id,
            first.adapter_id
        );
    }

    #[test]
    fn retired_adapter_request_allocates_a_fresh_identity() {
        let mut d = DmaManager::new();
        let first = d.request_adapter(owner(), adapter_request()).unwrap();
        d.put_adapter(first.adapter_id);
        let replacement = d.request_adapter(owner(), adapter_request()).unwrap();

        assert!(replacement.created);
        assert_ne!(replacement.adapter_id, first.adapter_id);
        assert_eq!(
            d.alloc_common_buffer(owner(), first.adapter_id, 16, 0x1000),
            Err(DmaError::Inactive)
        );
    }

    #[test]
    fn adapter_request_rejects_incomplete_owner_and_zero_length() {
        let mut d = DmaManager::new();
        assert_eq!(
            d.request_adapter(
                DmaOwner::new(0, 100, 10),
                DmaAdapterRequest {
                    maximum_length: 0,
                    ..adapter_request()
                }
            ),
            Err(DmaError::OutOfRange)
        );
        assert_eq!(d.num_map_registers(1), None);
    }

    #[test]
    fn adapter_and_common_buffer() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        assert_eq!(d.num_map_registers(a), Some(64));
        let g = d.alloc_common_buffer(owner(), a, 4096, 0x1_0000).unwrap();
        assert_eq!(g.logical_base, 0x8000_0000);
        // The sim device decodes the logical address to the backing buffer.
        assert_eq!(d.decode_logical(g.logical_base, 4096), Ok(0x1_0000));
        assert_eq!(d.decode_logical(g.logical_base + 100, 4), Ok(0x1_0064));
    }

    #[test]
    fn broker_registered_common_buffer_uses_supplied_logical_address() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let g = d
            .register_common_buffer_at(owner(), a, 0x1000, 4096, 0x2_0000)
            .unwrap();

        assert_eq!(g.logical_base, 0x1000);
        assert_eq!(d.decode_logical(0x1000, 16), Ok(0x2_0000));
        assert_eq!(d.decode_logical(0x1080, 4), Ok(0x2_0080));
    }

    #[test]
    fn broker_registered_common_buffer_rejects_logical_overlap() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        d.register_common_buffer_at(owner(), a, 0x1000, 4096, 0x2_0000)
            .unwrap();

        assert_eq!(
            d.register_common_buffer_at(owner(), a, 0x1800, 1024, 0x3_0000),
            Err(DmaError::LogicalViolation)
        );
        assert_eq!(
            d.register_common_buffer_at(owner(), a, 0, 1024, 0x3_0000),
            Err(DmaError::OutOfRange)
        );
    }

    #[test]
    fn broker_common_buffer_replay_is_idempotent() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let first = d
            .ensure_common_buffer_at(owner(), a, 0x1000, 4096, 0x2_0000)
            .unwrap();
        let replay = d
            .ensure_common_buffer_at(owner(), a, 0x1000, 4096, 0x2_0000)
            .unwrap();

        assert_eq!(first, replay);
        assert_eq!(
            d.ensure_common_buffer_at(owner(), a, 0x1000, 4096, 0x3_0000),
            Err(DmaError::LogicalViolation)
        );
    }

    #[test]
    fn logical_addresses_are_scoped_to_dma_owner() {
        let mut d = DmaManager::new();
        let owner_a = owner();
        let owner_b = DmaOwner::new(1, 100, 11);
        let adapter_a = d.register_adapter(owner_a, true, 4096, true);
        let adapter_b = d.register_adapter(owner_b, true, 4096, true);

        d.register_common_buffer_at(owner_a, adapter_a, 0x1000, 4096, 0x2_0000)
            .unwrap();
        d.register_common_buffer_at(owner_b, adapter_b, 0x1000, 4096, 0x3_0000)
            .unwrap();

        assert_eq!(d.decode_owner_logical(owner_a, 0x1080, 4), Ok(0x2_0080));
        assert_eq!(d.decode_owner_logical(owner_b, 0x1080, 4), Ok(0x3_0080));
        assert_eq!(
            d.free_common_buffer(owner_b, 0x1000, 2048),
            Err(DmaError::OutOfRange)
        );
        d.free_common_buffer(owner_b, 0x1000, 4096).unwrap();
        assert_eq!(d.decode_owner_logical(owner_a, 0x1000, 4), Ok(0x2_0000));
    }

    #[test]
    fn owner_decode_reports_range_kind() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 4096, true);
        d.register_common_buffer_at(owner(), adapter, 0x1000, 4096, 0x2_0000)
            .unwrap();
        d.register_mapping_at(owner(), adapter, 0x3000, 512, 1024)
            .unwrap();

        assert_eq!(
            d.decode_owner_logical_with_kind(owner(), 0x1100, 16),
            Ok((0x2_0100, DmaLogicalRangeKind::CommonBuffer))
        );
        assert_eq!(
            d.decode_owner_logical_with_kind(owner(), 0x3200, 16),
            Ok((1024, DmaLogicalRangeKind::TransferMapping))
        );
        assert_eq!(
            d.decode_owner_logical_with_kind(DmaOwner::new(1, 100, 12), 0x3200, 16),
            Err(DmaError::LogicalViolation)
        );
    }

    #[test]
    fn common_buffer_free_validates_and_double_free_fails() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let g = d.alloc_common_buffer(owner(), a, 4096, 0x1_0000).unwrap();
        // Wrong length rejected.
        assert_eq!(
            d.free_common_buffer(owner(), g.logical_base, 2048),
            Err(DmaError::OutOfRange)
        );
        d.free_common_buffer(owner(), g.logical_base, 4096).unwrap();
        // Double free + stale logical decode fail.
        assert_eq!(
            d.free_common_buffer(owner(), g.logical_base, 4096),
            Err(DmaError::StaleId)
        );
        assert_eq!(
            d.decode_logical(g.logical_base, 4),
            Err(DmaError::LogicalViolation)
        );
    }

    #[test]
    fn adapter_ownership_and_limits() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let other = DmaOwner::new(2, 200, 20);
        assert_eq!(
            d.alloc_common_buffer(other, a, 4096, 0),
            Err(DmaError::WrongOwner)
        );
        // Oversize rejected.
        assert_eq!(
            d.alloc_common_buffer(owner(), a, 8192, 0),
            Err(DmaError::OutOfRange)
        );
    }

    #[test]
    fn stale_generation_cannot_access_or_revoke_live_dma() {
        let mut d = DmaManager::new();
        let live = owner();
        let stale = DmaOwner::new(
            live.driver_host_id,
            live.driver_host_cookie - 1,
            live.devnode_id,
        );
        let adapter = d.register_adapter(live, true, 4096, true);
        let buffer = d
            .alloc_common_buffer(live, adapter, 4096, 0x1_0000)
            .unwrap();

        assert_eq!(
            d.alloc_common_buffer(stale, adapter, 4096, 0x2_0000),
            Err(DmaError::WrongOwner)
        );
        assert_eq!(d.revoke_owner(stale), (0, 0));
        assert_eq!(
            d.decode_owner_logical(live, buffer.logical_base, 16),
            Ok(0x1_0000)
        );
    }

    #[test]
    fn map_transfer_clips_and_frees() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 256, true);
        let m = d.map_transfer(owner(), a, 0x5_0000, 1024).unwrap();
        assert_eq!(m.mapped_length, 256); // clipped to adapter max
        assert_eq!(d.decode_logical(m.logical_base, 256), Ok(0x5_0000));
        d.free_mapping(m.mapping_id).unwrap();
        assert_eq!(d.free_mapping(m.mapping_id), Err(DmaError::StaleId));
    }

    #[test]
    fn broker_registered_transfer_mapping_uses_supplied_logical_address() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let m = d
            .register_mapping_at(owner(), a, 0x2000, 1536, 1024)
            .unwrap();

        assert_eq!(m.logical_base, 0x2000);
        assert_eq!(m.mapped_length, 1024);
        assert_eq!(d.decode_owner_logical(owner(), 0x2000, 16), Ok(1536));
        assert_eq!(d.decode_owner_logical(owner(), 0x2200, 32), Ok(2048));
    }

    #[test]
    fn registered_transfer_mapping_rejects_overlap_and_bad_owner() {
        let mut d = DmaManager::new();
        let owner_a = owner();
        let owner_b = DmaOwner::new(2, 200, 20);
        let adapter_a = d.register_adapter(owner_a, true, 4096, true);
        let adapter_b = d.register_adapter(owner_b, true, 4096, true);
        d.register_common_buffer_at(owner_a, adapter_a, 0x1000, 4096, 0x2_0000)
            .unwrap();
        d.register_mapping_at(owner_b, adapter_b, 0x1000, 512, 512)
            .unwrap();

        assert_eq!(
            d.register_mapping_at(owner_a, adapter_a, 0x1800, 0x3_0000, 512),
            Err(DmaError::LogicalViolation)
        );
        assert_eq!(
            d.register_mapping_at(owner_b, adapter_a, 0x3000, 0x4_0000, 512),
            Err(DmaError::WrongOwner)
        );
        assert_eq!(d.decode_owner_logical(owner_b, 0x1000, 16), Ok(512));
    }

    #[test]
    fn broker_transfer_mapping_replay_is_idempotent() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let first = d
            .ensure_mapping_at(owner(), a, 0x3000, 0x6_0000, 512)
            .unwrap();
        let replay = d
            .ensure_mapping_at(owner(), a, 0x3000, 0x6_0000, 512)
            .unwrap();

        assert_eq!(first, replay);
        assert_eq!(
            d.ensure_mapping_at(owner(), a, 0x3000, 0x6_1000, 512),
            Err(DmaError::LogicalViolation)
        );
    }

    #[test]
    fn free_mapping_for_owner_validates_owner() {
        let mut d = DmaManager::new();
        let owner_a = owner();
        let owner_b = DmaOwner::new(2, 200, 20);
        let adapter = d.register_adapter(owner_a, true, 4096, true);
        let m = d
            .register_mapping_at(owner_a, adapter, 0x3000, 0x6_0000, 512)
            .unwrap();

        assert_eq!(
            d.free_mapping_for_owner(owner_b, m.mapping_id),
            Err(DmaError::WrongOwner)
        );
        assert_eq!(
            d.decode_owner_logical(owner_a, m.logical_base, 16),
            Ok(0x6_0000)
        );
        d.free_mapping_for_owner(owner_a, m.mapping_id).unwrap();
        assert_eq!(
            d.decode_owner_logical(owner_a, m.logical_base, 16),
            Err(DmaError::LogicalViolation)
        );
    }

    #[test]
    fn revoke_owner_cleans_up() {
        let mut d = DmaManager::new();
        let a = d.register_adapter(owner(), true, 4096, true);
        let g = d.alloc_common_buffer(owner(), a, 4096, 0x1_0000).unwrap();
        let (b, _m) = d.revoke_owner(owner());
        assert_eq!(b, 1);
        assert_eq!(
            d.decode_logical(g.logical_base, 4),
            Err(DmaError::LogicalViolation)
        );
    }

    #[test]
    fn observes_descriptor_ring_with_owner_decoded_buffers() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 8192, true);
        d.register_common_buffer_at(owner(), adapter, 0x4000, 64, 0x20_0000)
            .unwrap();
        d.register_common_buffer_at(owner(), adapter, 0x8000, 4096, 0x30_0000)
            .unwrap();

        let mut ring = [0u8; 64];
        ring[0..8].copy_from_slice(&0x8000u64.to_le_bytes());
        ring[8..10].copy_from_slice(&128u16.to_le_bytes());
        ring[12] = 1;
        ring[16..24].copy_from_slice(&0x8800u64.to_le_bytes());

        let observation = d
            .observe_fixed_descriptor_ring(
                owner(),
                0x4000,
                0x20_0000,
                &ring,
                FixedDescriptorLayout {
                    stride: 16,
                    address_offset: 0,
                    length_offset: Some(8),
                    status_offset: Some(12),
                    completion_status_mask: 1,
                    min_buffer_probe_len: 1,
                },
            )
            .unwrap();

        assert_eq!(observation.descriptor_count, 4);
        assert_eq!(observation.descriptors_with_device_address, 2);
        assert_eq!(observation.descriptors_with_decodable_buffer, 2);
        assert_eq!(observation.descriptors_with_common_buffer, 2);
        assert_eq!(observation.descriptors_with_transfer_mapping, 0);
        assert_eq!(observation.descriptors_with_length, 1);
        assert_eq!(observation.completed_descriptors, 1);
        assert_eq!(observation.completed_common_buffer_descriptors, 1);
        assert_eq!(observation.completed_transfer_mapping_descriptors, 0);
        assert_eq!(observation.malformed_descriptors, 0);
    }

    #[test]
    fn descriptor_observation_classifies_transfer_mappings() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 8192, true);
        d.register_common_buffer_at(owner(), adapter, 0x4000, 64, 0x20_0000)
            .unwrap();
        d.register_mapping_at(owner(), adapter, 0x9000, 0x50_0000, 512)
            .unwrap();

        let mut ring = [0u8; 32];
        ring[0..8].copy_from_slice(&0x9000u64.to_le_bytes());
        ring[8..10].copy_from_slice(&128u16.to_le_bytes());
        ring[12] = 1;
        ring[16..24].copy_from_slice(&0x9080u64.to_le_bytes());
        ring[24..26].copy_from_slice(&64u16.to_le_bytes());

        let observation = d
            .observe_fixed_descriptor_ring(
                owner(),
                0x4000,
                0x20_0000,
                &ring,
                FixedDescriptorLayout {
                    stride: 16,
                    address_offset: 0,
                    length_offset: Some(8),
                    status_offset: Some(12),
                    completion_status_mask: 1,
                    min_buffer_probe_len: 1,
                },
            )
            .unwrap();

        assert_eq!(observation.descriptor_count, 2);
        assert_eq!(observation.descriptors_with_device_address, 2);
        assert_eq!(observation.descriptors_with_decodable_buffer, 2);
        assert_eq!(observation.descriptors_with_common_buffer, 0);
        assert_eq!(observation.descriptors_with_transfer_mapping, 2);
        assert_eq!(observation.descriptors_with_length, 2);
        assert_eq!(observation.completed_descriptors, 1);
        assert_eq!(observation.completed_common_buffer_descriptors, 0);
        assert_eq!(observation.completed_transfer_mapping_descriptors, 1);
        assert_eq!(observation.malformed_descriptors, 0);
    }

    #[test]
    fn descriptor_observation_rejects_unowned_buffers() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 4096, true);
        d.register_common_buffer_at(owner(), adapter, 0x4000, 16, 0x20_0000)
            .unwrap();

        let mut ring = [0u8; 16];
        ring[0..8].copy_from_slice(&0x9000u64.to_le_bytes());

        let observation = d
            .observe_fixed_descriptor_ring(
                owner(),
                0x4000,
                0x20_0000,
                &ring,
                FixedDescriptorLayout {
                    stride: 16,
                    address_offset: 0,
                    length_offset: Some(8),
                    status_offset: Some(12),
                    completion_status_mask: 1,
                    min_buffer_probe_len: 1,
                },
            )
            .unwrap();

        assert_eq!(observation.descriptors_with_device_address, 1);
        assert_eq!(observation.descriptors_with_decodable_buffer, 0);
        assert_eq!(observation.malformed_descriptors, 1);
    }

    #[test]
    fn completes_receive_descriptor_after_owner_decode() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 8192, true);
        d.register_common_buffer_at(owner(), adapter, 0x4000, 16, 0x20_0000)
            .unwrap();
        d.register_common_buffer_at(owner(), adapter, 0x8000, 2048, 0x30_0000)
            .unwrap();

        let layout = FixedDescriptorLayout {
            stride: 16,
            address_offset: 0,
            length_offset: Some(8),
            status_offset: Some(12),
            completion_status_mask: 1,
            min_buffer_probe_len: 1,
        };
        let mut ring = [0u8; 16];
        ring[0..8].copy_from_slice(&0x8000u64.to_le_bytes());

        let completion = d
            .complete_fixed_descriptor_at(
                owner(),
                0x4000,
                0x20_0000,
                &mut ring,
                layout,
                0,
                Some(64),
                3,
            )
            .unwrap();

        assert_eq!(completion.descriptor_index, 0);
        assert_eq!(completion.descriptor_backing_va, 0x20_0000);
        assert_eq!(completion.buffer_logical, 0x8000);
        assert_eq!(completion.buffer_backing_va, 0x30_0000);
        assert_eq!(completion.transfer_length, 64);
        assert_eq!(completion.range_kind, DmaLogicalRangeKind::CommonBuffer);
        assert_eq!(read_le_u16(&ring[8..]), 64);
        assert_eq!(ring[12], 3);

        let observation = d
            .observe_fixed_descriptor_ring(owner(), 0x4000, 0x20_0000, &ring, layout)
            .unwrap();
        assert_eq!(observation.completed_descriptors, 1);
        assert_eq!(observation.completed_common_buffer_descriptors, 1);
    }

    #[test]
    fn completes_transfer_mapping_descriptor_after_owner_decode() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 8192, true);
        d.register_common_buffer_at(owner(), adapter, 0x4000, 16, 0x20_0000)
            .unwrap();
        d.register_mapping_at(owner(), adapter, 0x9000, 0x50_0000, 512)
            .unwrap();

        let layout = FixedDescriptorLayout {
            stride: 16,
            address_offset: 0,
            length_offset: Some(8),
            status_offset: Some(12),
            completion_status_mask: 1,
            min_buffer_probe_len: 1,
        };
        let mut ring = [0u8; 16];
        ring[0..8].copy_from_slice(&0x9000u64.to_le_bytes());
        ring[8..10].copy_from_slice(&128u16.to_le_bytes());

        let completion = d
            .complete_fixed_descriptor_at(owner(), 0x4000, 0x20_0000, &mut ring, layout, 0, None, 1)
            .unwrap();

        assert_eq!(completion.range_kind, DmaLogicalRangeKind::TransferMapping);
        assert_eq!(completion.transfer_length, 128);
        assert_eq!(ring[12], 1);

        let observation = d
            .observe_fixed_descriptor_ring(owner(), 0x4000, 0x20_0000, &ring, layout)
            .unwrap();
        assert_eq!(observation.completed_descriptors, 1);
        assert_eq!(observation.completed_transfer_mapping_descriptors, 1);
    }

    #[test]
    fn descriptor_completion_rejects_unowned_buffer() {
        let mut d = DmaManager::new();
        let adapter = d.register_adapter(owner(), true, 4096, true);
        d.register_common_buffer_at(owner(), adapter, 0x4000, 16, 0x20_0000)
            .unwrap();

        let mut ring = [0u8; 16];
        ring[0..8].copy_from_slice(&0x9000u64.to_le_bytes());

        assert_eq!(
            d.complete_fixed_descriptor_at(
                owner(),
                0x4000,
                0x20_0000,
                &mut ring,
                FixedDescriptorLayout {
                    stride: 16,
                    address_offset: 0,
                    length_offset: Some(8),
                    status_offset: Some(12),
                    completion_status_mask: 1,
                    min_buffer_probe_len: 1,
                },
                0,
                Some(60),
                3,
            ),
            Err(DmaError::LogicalViolation)
        );
        assert_eq!(ring[8], 0);
        assert_eq!(ring[12], 0);
    }
}
