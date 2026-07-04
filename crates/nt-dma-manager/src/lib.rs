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
    pub devnode_id: u64,
}

impl DmaOwner {
    pub fn new(driver_host_id: u64, devnode_id: u64) -> Self {
        Self {
            driver_host_id,
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
        let (max_length, dma64) = {
            let a = self.adapter(adapter_id, owner)?;
            (a.max_length, a.dma64)
        };
        if length == 0 || length > max_length {
            return Err(DmaError::OutOfRange);
        }
        let logical_base = self.alloc_logical();
        if !dma64 && logical_base + length > 0xFFFF_FFFF {
            return Err(DmaError::OutOfRange);
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

    /// `FreeCommonBuffer` (spec §11.2): validate the logical address + length belong
    /// to a live common buffer owned by `owner`, then revoke it.
    pub fn free_common_buffer(
        &mut self,
        owner: DmaOwner,
        logical_base: u64,
        length: u64,
    ) -> Result<(), DmaError> {
        let cb = self
            .common_buffers
            .iter_mut()
            .find(|c| c.logical_base == logical_base && c.active)
            .ok_or(DmaError::StaleId)?;
        if cb.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if cb.length != length {
            return Err(DmaError::OutOfRange);
        }
        cb.active = false;
        Ok(())
    }

    /// Decode a device logical address to the backing Driver-Host address — the
    /// IOMMU-facade lookup a simulated device uses to touch memory (spec §19.2). Only
    /// resolves addresses within a live common buffer or active mapping; a device
    /// cannot reach unowned memory.
    pub fn decode_logical(&self, logical: u64, length: u64) -> Result<u64, DmaError> {
        for cb in self.common_buffers.iter().filter(|c| c.active) {
            if logical >= cb.logical_base && logical + length <= cb.logical_base + cb.length {
                return Ok(cb.backing_va + (logical - cb.logical_base));
            }
        }
        for m in self.mappings.iter().filter(|m| m.active) {
            if logical >= m.logical_base && logical + length <= m.logical_base + m.length {
                return Ok(m.backing_va + (logical - m.logical_base));
            }
        }
        Err(DmaError::LogicalViolation)
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
        let id = self.next_mapping_id;
        self.next_mapping_id += 1;
        self.mappings.push(Mapping {
            id,
            owner,
            logical_base,
            length: mapped_length,
            backing_va,
            active: true,
        });
        Ok(MapGrant {
            mapping_id: id,
            logical_base,
            mapped_length,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> DmaOwner {
        DmaOwner::new(1, 10)
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
        let other = DmaOwner::new(2, 20);
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
}
