//! # `nt-resource-manager` — canonical resource assignment store
//!
//! The authority behind the HAL service (spec: Milestone 11, §7/§8/§9): it holds
//! device→resource assignments from a static fixture, validates that every
//! `MmMapIoSpace` / `IoConnectInterrupt` request targets a resource **assigned to
//! that requesting driver host** and within its bounds, tracks MMIO mapping +
//! interrupt lifetimes, and rejects stale (revoked / unknown) mapping and interrupt
//! IDs. `no_std` + `alloc`. It never touches driver code or raw pointers — it works
//! purely in physical addresses + opaque IDs (spec §16).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use nt_hal_abi::{
    HalResourceDescriptor, RES_KIND_INTERRUPT, RES_KIND_MEMORY, RIGHT_READ, RIGHT_WRITE,
};

/// Identifies the requester of a resource operation (spec §7.4). Every map/connect
/// is validated against the resource's owner.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceOwner {
    pub driver_host_id: u64,
    pub device_object_id: u64,
}

impl ResourceOwner {
    pub fn new(driver_host_id: u64, device_object_id: u64) -> Self {
        Self {
            driver_host_id,
            device_object_id,
        }
    }
}

/// Why a resource operation was rejected (spec §6.1, §15.2, §22).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HalError {
    /// No assigned resource covers the requested physical range.
    NotAssigned,
    /// The request extends beyond the assigned resource's bounds.
    OutOfRange,
    /// The resource is assigned to a different owner.
    WrongOwner,
    /// The resource / mapping / interrupt was revoked.
    Revoked,
    /// The mapping / interrupt ID is unknown or stale.
    StaleId,
    /// An exclusive interrupt is already connected.
    AlreadyConnected,
    /// The requested access rights exceed the assignment's grant.
    AccessDenied,
}

struct MemoryResource {
    resource_id: u64,
    owner: ResourceOwner,
    phys_start: u64,
    translated_start: u64,
    length: u64,
    cache: u32,
    rights: u64,
    revoked: bool,
}

struct InterruptResource {
    resource_id: u64,
    owner: ResourceOwner,
    vector: u32,
    irql: u8,
    affinity: u32,
    mode: u8,
    revoked: bool,
}

struct Mapping {
    mapping_id: u64,
    resource_id: u64,
    owner: ResourceOwner,
    translated_start: u64,
    length: u64,
    valid: bool,
}

struct Interrupt {
    interrupt_id: u64,
    resource_id: u64,
    owner: ResourceOwner,
    vector: u32,
    irql: u8,
    service_routine_token: u64,
    service_context_token: u64,
    connected: bool,
}

/// The result of a successful `map_io_space`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Granted {
    pub mapping_id: u64,
    pub resource_id: u64,
    pub translated_start: u64,
    pub length: u64,
    pub rights: u64,
}

/// A connected interrupt's Driver-Host callback tokens, returned on injection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InterruptTokens {
    pub interrupt_id: u64,
    pub service_routine_token: u64,
    pub service_context_token: u64,
    pub irql: u8,
    pub vector: u32,
}

/// The canonical resource assignment store.
#[derive(Default)]
pub struct ResourceManager {
    memory: Vec<MemoryResource>,
    interrupts_res: Vec<InterruptResource>,
    mappings: Vec<Mapping>,
    connected: Vec<Interrupt>,
    next_mapping_id: u64,
    next_interrupt_id: u64,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            next_mapping_id: 1,
            next_interrupt_id: 1,
            ..Default::default()
        }
    }

    /// The static fixture for the `MmioInterruptTest` device (spec §7.3): a memory
    /// resource at phys `0x1000_0000` (len `0x1000`, read/write, non-cached) and an
    /// exclusive level-sensitive interrupt on vector 5, both owned by `owner`.
    pub fn with_mmio_test_fixture(owner: ResourceOwner) -> Self {
        let mut rm = Self::new();
        rm.assign_memory(
            owner,
            100,
            0x1000_0000,
            0x1000_0000,
            0x1000,
            nt_hal_abi::MM_NON_CACHED,
            RIGHT_READ | RIGHT_WRITE,
        );
        rm.assign_interrupt(owner, 200, 5, 5, 1, nt_hal_abi::INT_MODE_LEVEL_SENSITIVE);
        rm
    }

    /// Assign a memory resource to `owner` (fixture construction).
    #[allow(clippy::too_many_arguments)]
    pub fn assign_memory(
        &mut self,
        owner: ResourceOwner,
        resource_id: u64,
        phys_start: u64,
        translated_start: u64,
        length: u64,
        cache: u32,
        rights: u64,
    ) {
        self.revoke_memory_resource_usage(resource_id);
        let resource = MemoryResource {
            resource_id,
            owner,
            phys_start,
            translated_start,
            length,
            cache,
            rights,
            revoked: false,
        };
        if let Some(existing) = self
            .memory
            .iter_mut()
            .find(|existing| existing.resource_id == resource_id)
        {
            *existing = resource;
        } else {
            self.memory.push(resource);
        }
    }

    /// Assign an interrupt resource to `owner`.
    pub fn assign_interrupt(
        &mut self,
        owner: ResourceOwner,
        resource_id: u64,
        vector: u32,
        irql: u8,
        affinity: u32,
        mode: u8,
    ) {
        self.revoke_interrupt_resource_usage(resource_id);
        let resource = InterruptResource {
            resource_id,
            owner,
            vector,
            irql,
            affinity,
            mode,
            revoked: false,
        };
        if let Some(existing) = self
            .interrupts_res
            .iter_mut()
            .find(|existing| existing.resource_id == resource_id)
        {
            *existing = resource;
        } else {
            self.interrupts_res.push(resource);
        }
    }

    fn revoke_memory_resource_usage(&mut self, resource_id: u64) {
        for mapping in self.mappings.iter_mut() {
            if mapping.resource_id == resource_id && mapping.valid {
                mapping.valid = false;
            }
        }
    }

    fn revoke_interrupt_resource_usage(&mut self, resource_id: u64) {
        for interrupt in self.connected.iter_mut() {
            if interrupt.resource_id == resource_id && interrupt.connected {
                interrupt.connected = false;
            }
        }
    }

    /// Raw + translated resource descriptors assigned to `owner` (spec §10.1/§7.2).
    pub fn query_resources(&self, owner: ResourceOwner) -> Vec<HalResourceDescriptor> {
        let mut out = Vec::new();
        for m in self
            .memory
            .iter()
            .filter(|m| m.owner == owner && !m.revoked)
        {
            out.push(HalResourceDescriptor {
                kind: RES_KIND_MEMORY,
                resource_id: m.resource_id,
                raw_start: m.phys_start,
                translated_start: m.translated_start,
                length: m.length,
                arg0: m.cache as u64,
                arg1: m.rights,
                ..Default::default()
            });
        }
        for i in self
            .interrupts_res
            .iter()
            .filter(|i| i.owner == owner && !i.revoked)
        {
            let (arg0, arg1) =
                HalResourceDescriptor::interrupt_args(i.vector, i.irql, i.affinity, i.mode);
            out.push(HalResourceDescriptor {
                kind: RES_KIND_INTERRUPT,
                resource_id: i.resource_id,
                arg0,
                arg1,
                ..Default::default()
            });
        }
        out
    }

    /// `MmMapIoSpace` (spec §8.2, §6.1): map succeeds only if `[phys, phys+len)` lies
    /// within a memory resource assigned to `owner`, not revoked, and the assignment
    /// grants at least read access.
    pub fn map_io_space(
        &mut self,
        owner: ResourceOwner,
        phys: u64,
        length: u64,
        _cache: u32,
    ) -> Result<Granted, HalError> {
        let m = self
            .memory
            .iter()
            .find(|m| {
                m.phys_start == phys || (phys >= m.phys_start && phys < m.phys_start + m.length)
            })
            .ok_or(HalError::NotAssigned)?;
        if m.revoked {
            return Err(HalError::Revoked);
        }
        if m.owner != owner {
            return Err(HalError::WrongOwner);
        }
        let offset = phys - m.phys_start;
        if length == 0 || offset + length > m.length {
            return Err(HalError::OutOfRange);
        }
        if m.rights & RIGHT_READ == 0 {
            return Err(HalError::AccessDenied);
        }
        let mapping_id = self.next_mapping_id;
        self.next_mapping_id += 1;
        let g = Granted {
            mapping_id,
            resource_id: m.resource_id,
            translated_start: m.translated_start + offset,
            length,
            rights: m.rights,
        };
        self.mappings.push(Mapping {
            mapping_id,
            resource_id: m.resource_id,
            owner,
            translated_start: g.translated_start,
            length,
            valid: true,
        });
        Ok(g)
    }

    /// `MmUnmapIoSpace` — invalidate a mapping owned by `owner` (spec §8.4).
    pub fn unmap_io_space(
        &mut self,
        owner: ResourceOwner,
        mapping_id: u64,
    ) -> Result<(), HalError> {
        let m = self
            .mappings
            .iter_mut()
            .find(|m| m.mapping_id == mapping_id && m.valid)
            .ok_or(HalError::StaleId)?;
        if m.owner != owner {
            return Err(HalError::WrongOwner);
        }
        m.valid = false;
        Ok(())
    }

    /// Whether `mapping_id` is a currently-valid mapping (spec §8.6 access check).
    pub fn mapping_valid(&self, mapping_id: u64) -> bool {
        self.mappings
            .iter()
            .any(|m| m.mapping_id == mapping_id && m.valid)
    }

    /// `HAL_OP_QUERY_MAPPING` — a valid mapping's `(resource_id, translated_start,
    /// length)` (spec §10 opcode 0x5032).
    pub fn mapping_info(&self, mapping_id: u64) -> Option<(u64, u64, u64)> {
        self.mappings
            .iter()
            .find(|m| m.mapping_id == mapping_id && m.valid)
            .map(|m| (m.resource_id, m.translated_start, m.length))
    }

    /// `IoConnectInterrupt` (spec §9.3): connect an ISR to the interrupt resource
    /// `resource_id` assigned to `owner`. Exclusive — a second connect fails.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_interrupt(
        &mut self,
        owner: ResourceOwner,
        resource_id: u64,
        service_routine_token: u64,
        service_context_token: u64,
    ) -> Result<u64, HalError> {
        let res = self
            .interrupts_res
            .iter()
            .find(|i| i.resource_id == resource_id)
            .ok_or(HalError::NotAssigned)?;
        if res.revoked {
            return Err(HalError::Revoked);
        }
        if res.owner != owner {
            return Err(HalError::WrongOwner);
        }
        if self
            .connected
            .iter()
            .any(|c| c.resource_id == resource_id && c.connected)
        {
            return Err(HalError::AlreadyConnected);
        }
        let interrupt_id = self.next_interrupt_id;
        self.next_interrupt_id += 1;
        self.connected.push(Interrupt {
            interrupt_id,
            resource_id,
            owner,
            vector: res.vector,
            irql: res.irql,
            service_routine_token,
            service_context_token,
            connected: true,
        });
        Ok(interrupt_id)
    }

    /// `IoDisconnectInterrupt` (spec §9.6).
    pub fn disconnect_interrupt(
        &mut self,
        owner: ResourceOwner,
        interrupt_id: u64,
    ) -> Result<(), HalError> {
        let c = self
            .connected
            .iter_mut()
            .find(|c| c.interrupt_id == interrupt_id && c.connected)
            .ok_or(HalError::StaleId)?;
        if c.owner != owner {
            return Err(HalError::WrongOwner);
        }
        c.connected = false;
        Ok(())
    }

    /// Resolve a simulated interrupt injection on `vector` to the connected ISR's
    /// Driver-Host tokens (spec §9.4). `None` if nothing is connected on that vector
    /// (an injection for a disconnected / unowned interrupt is dropped).
    pub fn inject_vector(&self, vector: u32) -> Option<InterruptTokens> {
        self.connected
            .iter()
            .find(|c| c.connected && c.vector == vector)
            .map(|c| InterruptTokens {
                interrupt_id: c.interrupt_id,
                service_routine_token: c.service_routine_token,
                service_context_token: c.service_context_token,
                irql: c.irql,
                vector: c.vector,
            })
    }

    /// Resolve injection by canonical `interrupt_id` (spec §9.4, `HAL_OP_INJECT`).
    pub fn inject_interrupt(&self, interrupt_id: u64) -> Option<InterruptTokens> {
        self.connected
            .iter()
            .find(|c| c.connected && c.interrupt_id == interrupt_id)
            .map(|c| InterruptTokens {
                interrupt_id: c.interrupt_id,
                service_routine_token: c.service_routine_token,
                service_context_token: c.service_context_token,
                irql: c.irql,
                vector: c.vector,
            })
    }

    /// Device removal cleanup: revoke every assignment, mapping, and interrupt owned by one
    /// driver/device pair. Returns `(memory_resources, interrupt_resources, mappings,
    /// interrupts)`.
    pub fn revoke_owner(&mut self, owner: ResourceOwner) -> (usize, usize, usize, usize) {
        let mut memory_resources = 0;
        for m in self.memory.iter_mut() {
            if m.owner == owner && !m.revoked {
                m.revoked = true;
                memory_resources += 1;
            }
        }
        let mut interrupt_resources = 0;
        for i in self.interrupts_res.iter_mut() {
            if i.owner == owner && !i.revoked {
                i.revoked = true;
                interrupt_resources += 1;
            }
        }
        let mut mappings = 0;
        for m in self.mappings.iter_mut() {
            if m.owner == owner && m.valid {
                m.valid = false;
                mappings += 1;
            }
        }
        let mut interrupts = 0;
        for c in self.connected.iter_mut() {
            if c.owner == owner && c.connected {
                c.connected = false;
                interrupts += 1;
            }
        }
        (memory_resources, interrupt_resources, mappings, interrupts)
    }

    /// Driver Host fault / unload cleanup (spec §15.1): revoke every mapping and
    /// disconnect every interrupt owned by `driver_host_id`. Returns
    /// `(mappings_revoked, interrupts_disconnected)`.
    pub fn revoke_host(&mut self, driver_host_id: u64) -> (usize, usize) {
        let mut maps = 0;
        for m in self.mappings.iter_mut() {
            if m.owner.driver_host_id == driver_host_id && m.valid {
                m.valid = false;
                maps += 1;
            }
        }
        let mut ints = 0;
        for c in self.connected.iter_mut() {
            if c.owner.driver_host_id == driver_host_id && c.connected {
                c.connected = false;
                ints += 1;
            }
        }
        (maps, ints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rm() -> (ResourceManager, ResourceOwner) {
        let owner = ResourceOwner::new(1, 10);
        (ResourceManager::with_mmio_test_fixture(owner), owner)
    }

    #[test]
    fn maps_within_assigned_range() {
        let (mut rm, owner) = rm();
        let g = rm
            .map_io_space(owner, 0x1000_0000, 0x1000, nt_hal_abi::MM_NON_CACHED)
            .unwrap();
        assert_eq!(g.resource_id, 100);
        assert_eq!(g.translated_start, 0x1000_0000);
        assert!(rm.mapping_valid(g.mapping_id));
    }

    #[test]
    fn rejects_unassigned_and_oversize_and_wrong_owner() {
        let (mut rm, owner) = rm();
        assert_eq!(
            rm.map_io_space(owner, 0x2000_0000, 0x1000, 0),
            Err(HalError::NotAssigned)
        );
        assert_eq!(
            rm.map_io_space(owner, 0x1000_0000, 0x2000, 0),
            Err(HalError::OutOfRange)
        );
        let other = ResourceOwner::new(2, 20);
        assert_eq!(
            rm.map_io_space(other, 0x1000_0000, 0x1000, 0),
            Err(HalError::WrongOwner)
        );
    }

    #[test]
    fn unmap_then_stale_rejected() {
        let (mut rm, owner) = rm();
        let g = rm.map_io_space(owner, 0x1000_0000, 0x1000, 0).unwrap();
        rm.unmap_io_space(owner, g.mapping_id).unwrap();
        assert!(!rm.mapping_valid(g.mapping_id));
        // Unmapping again (stale ID) fails.
        assert_eq!(
            rm.unmap_io_space(owner, g.mapping_id),
            Err(HalError::StaleId)
        );
    }

    #[test]
    fn connect_disconnect_interrupt() {
        let (mut rm, owner) = rm();
        let id = rm.connect_interrupt(owner, 200, 0xAA, 0xBB).unwrap();
        // Exclusive: a second connect fails.
        assert_eq!(
            rm.connect_interrupt(owner, 200, 0, 0),
            Err(HalError::AlreadyConnected)
        );
        // Injection resolves to the tokens.
        let t = rm.inject_vector(5).unwrap();
        assert_eq!(t.service_routine_token, 0xAA);
        assert_eq!(t.service_context_token, 0xBB);
        assert_eq!(t.irql, 5);

        rm.disconnect_interrupt(owner, id).unwrap();
        // Injection after disconnect is dropped.
        assert!(rm.inject_vector(5).is_none());
        // Disconnect again (stale) fails.
        assert_eq!(rm.disconnect_interrupt(owner, id), Err(HalError::StaleId));
    }

    #[test]
    fn connect_wrong_owner_rejected() {
        let (mut rm, _owner) = rm();
        let other = ResourceOwner::new(2, 20);
        assert_eq!(
            rm.connect_interrupt(other, 200, 0, 0),
            Err(HalError::WrongOwner)
        );
    }

    #[test]
    fn reassigned_memory_resource_revokes_stale_mapping() {
        let (mut rm, old_owner) = rm();
        let mapping = rm.map_io_space(old_owner, 0x1000_0000, 0x1000, 0).unwrap();
        let new_owner = ResourceOwner::new(3, 30);

        rm.assign_memory(
            new_owner,
            100,
            0x2000_0000,
            0x3000_0000,
            0x1000,
            nt_hal_abi::MM_NON_CACHED,
            RIGHT_READ | RIGHT_WRITE,
        );

        assert!(!rm.mapping_valid(mapping.mapping_id));
        assert_eq!(
            rm.unmap_io_space(old_owner, mapping.mapping_id),
            Err(HalError::StaleId)
        );
        assert_eq!(
            rm.map_io_space(old_owner, 0x2000_0000, 0x1000, 0),
            Err(HalError::WrongOwner)
        );

        let new_mapping = rm.map_io_space(new_owner, 0x2000_0000, 0x1000, 0).unwrap();
        assert_eq!(new_mapping.translated_start, 0x3000_0000);
    }

    #[test]
    fn reassigned_interrupt_resource_disconnects_stale_isr() {
        let (mut rm, old_owner) = rm();
        let old_interrupt = rm.connect_interrupt(old_owner, 200, 0xAA, 0xBB).unwrap();
        let new_owner = ResourceOwner::new(4, 40);

        rm.assign_interrupt(
            new_owner,
            200,
            7,
            7,
            1,
            nt_hal_abi::INT_MODE_LEVEL_SENSITIVE,
        );

        assert!(rm.inject_interrupt(old_interrupt).is_none());
        assert_eq!(
            rm.disconnect_interrupt(old_owner, old_interrupt),
            Err(HalError::StaleId)
        );
        assert_eq!(
            rm.connect_interrupt(old_owner, 200, 0, 0),
            Err(HalError::WrongOwner)
        );

        let new_interrupt = rm.connect_interrupt(new_owner, 200, 0xCC, 0xDD).unwrap();
        let tokens = rm.inject_interrupt(new_interrupt).unwrap();
        assert_eq!(tokens.vector, 7);
        assert_eq!(tokens.service_routine_token, 0xCC);
    }

    #[test]
    fn revoke_owner_revokes_assignments_and_usage() {
        let (mut rm, owner) = rm();
        let mapping = rm.map_io_space(owner, 0x1000_0000, 0x1000, 0).unwrap();
        let interrupt = rm.connect_interrupt(owner, 200, 0xAA, 0xBB).unwrap();

        assert_eq!(rm.revoke_owner(owner), (1, 1, 1, 1));

        assert!(!rm.mapping_valid(mapping.mapping_id));
        assert!(rm.inject_interrupt(interrupt).is_none());
        assert_eq!(
            rm.map_io_space(owner, 0x1000_0000, 0x1000, 0),
            Err(HalError::Revoked)
        );
        assert_eq!(
            rm.connect_interrupt(owner, 200, 0, 0),
            Err(HalError::Revoked)
        );
    }

    #[test]
    fn revoke_host_cleans_up() {
        let (mut rm, owner) = rm();
        let g = rm.map_io_space(owner, 0x1000_0000, 0x1000, 0).unwrap();
        rm.connect_interrupt(owner, 200, 1, 2).unwrap();
        let (maps, ints) = rm.revoke_host(owner.driver_host_id);
        assert_eq!((maps, ints), (1, 1));
        assert!(!rm.mapping_valid(g.mapping_id));
        assert!(rm.inject_vector(5).is_none());
    }
}
