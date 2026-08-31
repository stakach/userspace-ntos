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
    HalResourceDescriptor, INT_MODE_LATCHED, INT_MODE_LEVEL_SENSITIVE, MM_CACHED, MM_NON_CACHED,
    MM_WRITE_COMBINED, RES_KIND_INTERRUPT, RES_KIND_MEMORY, RES_KIND_PORT, RIGHT_READ, RIGHT_WRITE,
    SHARE_EXCLUSIVE, SHARE_SHARED,
};

/// Identifies the requester of a resource operation (spec §7.4). Every map/connect
/// is validated against the resource's owner.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceOwner {
    pub driver_host_id: u64,
    pub driver_host_cookie: u64,
    pub device_object_id: u64,
}

impl ResourceOwner {
    pub fn new(driver_host_id: u64, driver_host_cookie: u64, device_object_id: u64) -> Self {
        Self {
            driver_host_id,
            driver_host_cookie,
            device_object_id,
        }
    }
}

/// Explicit authority for one device-owned port resource to occupy a subrange of a live platform
/// reservation. This is intentionally resource-id based: address overlap alone never delegates
/// authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortResourceDelegation {
    pub parent_owner: ResourceOwner,
    pub parent_resource_id: u64,
    pub resource_id: u64,
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
    /// The requested resource has an empty or overflowing address range.
    InvalidRange,
    /// The requested address range overlaps another live assignment.
    ConflictingAddress,
    /// The assignment store could not grow.
    InsufficientResources,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryResource {
    resource_id: u64,
    owner: ResourceOwner,
    phys_start: u64,
    translated_start: u64,
    length: u64,
    cache: u32,
    rights: u64,
    flags: u16,
    share: u16,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InterruptResource {
    resource_id: u64,
    owner: ResourceOwner,
    line: u32,
    translated_vector: u32,
    vector: u32,
    irql: u8,
    affinity: u32,
    mode: u8,
    flags: u16,
    share: u16,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortResource {
    resource_id: u64,
    owner: ResourceOwner,
    raw_start: u64,
    translated_start: u64,
    length: u64,
    flags: u16,
    share: u16,
    revoked: bool,
    delegated_from: Option<(ResourceOwner, u64)>,
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

/// A connected interrupt's Driver-Host callback tokens.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InterruptTokens {
    pub interrupt_id: u64,
    pub service_routine_token: u64,
    pub service_context_token: u64,
    pub irql: u8,
    pub vector: u32,
}

/// Canonical hardware route and callback tokens for one live interrupt connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnectedInterrupt {
    pub tokens: InterruptTokens,
    pub resource_id: u64,
    pub line: u32,
    pub translated_vector: u32,
    pub mode: u8,
    pub share: u16,
}

fn validate_range(start: u64, length: u64) -> Result<u64, HalError> {
    start
        .checked_add(length.checked_sub(1).ok_or(HalError::InvalidRange)?)
        .ok_or(HalError::InvalidRange)
}

fn ranges_overlap(first_start: u64, first_len: u64, second_start: u64, second_len: u64) -> bool {
    let Some(first_end) = first_start.checked_add(first_len.saturating_sub(1)) else {
        return true;
    };
    let Some(second_end) = second_start.checked_add(second_len.saturating_sub(1)) else {
        return true;
    };
    first_start <= second_end && second_start <= first_end
}

fn range_contains_address(start: u64, length: u64, address: u64) -> bool {
    length != 0 && address >= start && address - start < length
}

fn range_contains_range(
    outer_start: u64,
    outer_len: u64,
    inner_start: u64,
    inner_len: u64,
) -> bool {
    let Some(outer_end) = outer_start.checked_add(outer_len) else {
        return false;
    };
    let Some(inner_end) = inner_start.checked_add(inner_len) else {
        return false;
    };
    inner_len != 0 && inner_start >= outer_start && inner_end <= outer_end
}

/// The canonical resource assignment store.
#[derive(Default)]
pub struct ResourceManager {
    memory: Vec<MemoryResource>,
    ports: Vec<PortResource>,
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
            flags: 0,
            share: SHARE_EXCLUSIVE,
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
            line: vector,
            translated_vector: vector,
            vector,
            irql,
            affinity,
            mode,
            flags: 0,
            share: SHARE_EXCLUSIVE,
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

    /// Atomically replace every PnP resource assignment owned by one device.
    ///
    /// Validation and allocation complete before any live assignment or usage is revoked. An error
    /// therefore leaves the previous assignment set, MMIO mappings, and interrupt connections
    /// intact. A changed successful replacement invalidates all usage of the previous set.
    pub fn replace_owner_assignments(
        &mut self,
        owner: ResourceOwner,
        assignments: &[HalResourceDescriptor],
    ) -> Result<(), HalError> {
        self.replace_owner_assignments_with_port_delegations(owner, assignments, &[])
    }

    /// Atomically replace one device's assignments while admitting only the listed port subleases.
    ///
    /// Each delegation must name a live parent port resource, and the child's raw and translated
    /// ranges must both be contained by that resource. Any unlisted overlap remains a conflict.
    pub fn replace_owner_assignments_with_port_delegations(
        &mut self,
        owner: ResourceOwner,
        assignments: &[HalResourceDescriptor],
        port_delegations: &[PortResourceDelegation],
    ) -> Result<(), HalError> {
        if self.query_resources(owner) == assignments
            && self.port_delegations_match(owner, assignments, port_delegations)
        {
            return Ok(());
        }

        for (index, delegation) in port_delegations.iter().enumerate() {
            if delegation.parent_owner == owner
                || delegation.parent_resource_id == 0
                || delegation.resource_id == 0
                || port_delegations[..index]
                    .iter()
                    .any(|prior| prior.resource_id == delegation.resource_id)
                || !assignments.iter().any(|assignment| {
                    assignment.kind == RES_KIND_PORT
                        && assignment.resource_id == delegation.resource_id
                })
            {
                return Err(HalError::ConflictingAddress);
            }
        }

        let mut memory = Vec::new();
        let mut ports = Vec::new();
        let mut interrupts = Vec::new();
        memory
            .try_reserve_exact(assignments.len())
            .map_err(|_| HalError::InsufficientResources)?;
        ports
            .try_reserve_exact(assignments.len())
            .map_err(|_| HalError::InsufficientResources)?;
        interrupts
            .try_reserve_exact(assignments.len())
            .map_err(|_| HalError::InsufficientResources)?;

        for (index, descriptor) in assignments.iter().copied().enumerate() {
            if descriptor.resource_id == 0
                || assignments[..index]
                    .iter()
                    .any(|prior| prior.resource_id == descriptor.resource_id)
                || self.live_resource_id_owned_by_other(owner, descriptor.resource_id)
                || !matches!(descriptor.share, SHARE_EXCLUSIVE | SHARE_SHARED)
            {
                return Err(HalError::ConflictingAddress);
            }
            match descriptor.kind {
                RES_KIND_MEMORY => {
                    validate_range(descriptor.raw_start, descriptor.length)?;
                    validate_range(descriptor.translated_start, descriptor.length)?;
                    if !matches!(
                        descriptor.arg0 as u32,
                        MM_NON_CACHED | MM_CACHED | MM_WRITE_COMBINED
                    ) || descriptor.arg1 & RIGHT_READ == 0
                        || descriptor.arg1 & !(RIGHT_READ | RIGHT_WRITE) != 0
                    {
                        return Err(HalError::AccessDenied);
                    }
                    let candidate = MemoryResource {
                        resource_id: descriptor.resource_id,
                        owner,
                        phys_start: descriptor.raw_start,
                        translated_start: descriptor.translated_start,
                        length: descriptor.length,
                        cache: descriptor.arg0 as u32,
                        rights: descriptor.arg1,
                        flags: descriptor.flags,
                        share: descriptor.share,
                        revoked: false,
                    };
                    if self.memory.iter().any(|existing| {
                        existing.owner != owner
                            && !existing.revoked
                            && ranges_overlap(
                                candidate.translated_start,
                                candidate.length,
                                existing.translated_start,
                                existing.length,
                            )
                            && (candidate.share == SHARE_EXCLUSIVE
                                || existing.share == SHARE_EXCLUSIVE)
                    }) || memory.iter().any(|existing: &MemoryResource| {
                        ranges_overlap(
                            candidate.translated_start,
                            candidate.length,
                            existing.translated_start,
                            existing.length,
                        ) && (candidate.share == SHARE_EXCLUSIVE
                            || existing.share == SHARE_EXCLUSIVE)
                    }) {
                        return Err(HalError::ConflictingAddress);
                    }
                    memory.push(candidate);
                }
                RES_KIND_PORT => {
                    let raw_end = validate_range(descriptor.raw_start, descriptor.length)?;
                    let translated_end =
                        validate_range(descriptor.translated_start, descriptor.length)?;
                    if raw_end > u16::MAX as u64 || translated_end > u16::MAX as u64 {
                        return Err(HalError::InvalidRange);
                    }
                    let delegated_from = if let Some(delegation) = port_delegations
                        .iter()
                        .find(|delegation| delegation.resource_id == descriptor.resource_id)
                    {
                        let parent = self
                            .ports
                            .iter()
                            .find(|parent| {
                                !parent.revoked
                                    && parent.owner == delegation.parent_owner
                                    && parent.resource_id == delegation.parent_resource_id
                            })
                            .ok_or(HalError::NotAssigned)?;
                        if !range_contains_range(
                            parent.raw_start,
                            parent.length,
                            descriptor.raw_start,
                            descriptor.length,
                        ) || !range_contains_range(
                            parent.translated_start,
                            parent.length,
                            descriptor.translated_start,
                            descriptor.length,
                        ) {
                            return Err(HalError::OutOfRange);
                        }
                        Some((parent.owner, parent.resource_id))
                    } else {
                        None
                    };
                    let candidate = PortResource {
                        resource_id: descriptor.resource_id,
                        owner,
                        raw_start: descriptor.raw_start,
                        translated_start: descriptor.translated_start,
                        length: descriptor.length,
                        flags: descriptor.flags,
                        share: descriptor.share,
                        revoked: false,
                        delegated_from,
                    };
                    if self.ports.iter().any(|existing| {
                        let delegated_parent = candidate.delegated_from.is_some_and(
                            |(parent_owner, parent_resource_id)| {
                                existing.owner == parent_owner
                                    && existing.resource_id == parent_resource_id
                            },
                        );
                        existing.owner != owner
                            && !existing.revoked
                            && ranges_overlap(
                                candidate.translated_start,
                                candidate.length,
                                existing.translated_start,
                                existing.length,
                            )
                            && (candidate.share == SHARE_EXCLUSIVE
                                || existing.share == SHARE_EXCLUSIVE)
                            && !delegated_parent
                    }) || ports.iter().any(|existing: &PortResource| {
                        ranges_overlap(
                            candidate.translated_start,
                            candidate.length,
                            existing.translated_start,
                            existing.length,
                        ) && (candidate.share == SHARE_EXCLUSIVE
                            || existing.share == SHARE_EXCLUSIVE)
                    }) {
                        return Err(HalError::ConflictingAddress);
                    }
                    ports.push(candidate);
                }
                RES_KIND_INTERRUPT => {
                    let (vector, irql, affinity, mode) = descriptor.interrupt_fields();
                    if vector == 0
                        || descriptor.raw_start > u32::MAX as u64
                        || descriptor.translated_start > u32::MAX as u64
                        || descriptor.raw_start == 0
                        || descriptor.translated_start == 0
                        || descriptor.translated_start as u32 != vector
                        || descriptor.length != 1
                        || affinity == 0
                        || !matches!(mode, INT_MODE_LEVEL_SENSITIVE | INT_MODE_LATCHED)
                    {
                        return Err(HalError::InvalidRange);
                    }
                    let candidate = InterruptResource {
                        resource_id: descriptor.resource_id,
                        owner,
                        line: descriptor.raw_start as u32,
                        translated_vector: descriptor.translated_start as u32,
                        vector,
                        irql,
                        affinity,
                        mode,
                        flags: descriptor.flags,
                        share: descriptor.share,
                        revoked: false,
                    };
                    if self.interrupts_res.iter().any(|existing| {
                        existing.owner != owner
                            && !existing.revoked
                            && existing.line == candidate.line
                            && (candidate.share == SHARE_EXCLUSIVE
                                || existing.share == SHARE_EXCLUSIVE)
                    }) || interrupts.iter().any(|existing: &InterruptResource| {
                        existing.line == candidate.line
                            && (candidate.share == SHARE_EXCLUSIVE
                                || existing.share == SHARE_EXCLUSIVE)
                    }) {
                        return Err(HalError::ConflictingAddress);
                    }
                    interrupts.push(candidate);
                }
                _ => return Err(HalError::InvalidRange),
            }
        }

        self.memory
            .try_reserve(memory.len())
            .map_err(|_| HalError::InsufficientResources)?;
        self.ports
            .try_reserve(ports.len())
            .map_err(|_| HalError::InsufficientResources)?;
        self.interrupts_res
            .try_reserve(interrupts.len())
            .map_err(|_| HalError::InsufficientResources)?;

        self.revoke_owner(owner);
        for resource in memory {
            if let Some(existing) = self
                .memory
                .iter_mut()
                .find(|existing| existing.resource_id == resource.resource_id)
            {
                *existing = resource;
            } else {
                self.memory.push(resource);
            }
        }
        for resource in ports {
            if let Some(existing) = self
                .ports
                .iter_mut()
                .find(|existing| existing.resource_id == resource.resource_id)
            {
                *existing = resource;
            } else {
                self.ports.push(resource);
            }
        }
        for resource in interrupts {
            if let Some(existing) = self
                .interrupts_res
                .iter_mut()
                .find(|existing| existing.resource_id == resource.resource_id)
            {
                *existing = resource;
            } else {
                self.interrupts_res.push(resource);
            }
        }
        Ok(())
    }

    fn port_delegations_match(
        &self,
        owner: ResourceOwner,
        assignments: &[HalResourceDescriptor],
        delegations: &[PortResourceDelegation],
    ) -> bool {
        if delegations.iter().enumerate().any(|(index, delegation)| {
            delegation.parent_owner == owner
                || delegation.parent_resource_id == 0
                || delegation.resource_id == 0
                || delegations[..index]
                    .iter()
                    .any(|prior| prior.resource_id == delegation.resource_id)
        }) {
            return false;
        }
        assignments
            .iter()
            .filter(|assignment| assignment.kind == RES_KIND_PORT)
            .all(|assignment| {
                let expected = delegations
                    .iter()
                    .find(|delegation| delegation.resource_id == assignment.resource_id)
                    .map(|delegation| (delegation.parent_owner, delegation.parent_resource_id));
                self.ports.iter().any(|port| {
                    port.owner == owner
                        && port.resource_id == assignment.resource_id
                        && !port.revoked
                        && port.delegated_from == expected
                })
            })
            && delegations.iter().all(|delegation| {
                assignments.iter().any(|assignment| {
                    assignment.kind == RES_KIND_PORT
                        && assignment.resource_id == delegation.resource_id
                })
            })
    }

    fn live_resource_id_owned_by_other(&self, owner: ResourceOwner, resource_id: u64) -> bool {
        self.memory.iter().any(|resource| {
            !resource.revoked && resource.resource_id == resource_id && resource.owner != owner
        }) || self.ports.iter().any(|resource| {
            !resource.revoked && resource.resource_id == resource_id && resource.owner != owner
        }) || self.interrupts_res.iter().any(|resource| {
            !resource.revoked && resource.resource_id == resource_id && resource.owner != owner
        })
    }

    /// Claim an exclusive I/O-port range for `owner`.
    ///
    /// Exact replays by the same owner/resource id are idempotent. Any overlap with another live
    /// claim fails without modifying the assignment store.
    pub fn claim_port(
        &mut self,
        owner: ResourceOwner,
        resource_id: u64,
        start: u64,
        length: u64,
    ) -> Result<(), HalError> {
        let end = start
            .checked_add(length.checked_sub(1).ok_or(HalError::InvalidRange)?)
            .ok_or(HalError::InvalidRange)?;
        if end > u16::MAX as u64 {
            return Err(HalError::InvalidRange);
        }
        if let Some(existing) = self
            .ports
            .iter()
            .find(|port| port.resource_id == resource_id && !port.revoked)
        {
            return if existing.owner == owner
                && existing.raw_start == start
                && existing.translated_start == start
                && existing.length == length
            {
                Ok(())
            } else if existing.owner != owner {
                Err(HalError::WrongOwner)
            } else {
                Err(HalError::ConflictingAddress)
            };
        }
        if self.ports.iter().any(|port| {
            if port.revoked {
                return false;
            }
            let Some(port_end) = port.raw_start.checked_add(port.length - 1) else {
                return true;
            };
            start <= port_end && port.raw_start <= end
        }) {
            return Err(HalError::ConflictingAddress);
        }
        let resource = PortResource {
            resource_id,
            owner,
            raw_start: start,
            translated_start: start,
            length,
            flags: 0,
            share: SHARE_EXCLUSIVE,
            revoked: false,
            delegated_from: None,
        };
        if let Some(existing) = self
            .ports
            .iter_mut()
            .find(|port| port.resource_id == resource_id)
        {
            *existing = resource;
        } else {
            self.ports
                .try_reserve(1)
                .map_err(|_| HalError::InsufficientResources)?;
            self.ports.push(resource);
        }
        Ok(())
    }

    /// Release one exact I/O-port assignment, used to roll back failed capability publication and
    /// to release driver-reported supplemental resources.
    pub fn release_port(&mut self, owner: ResourceOwner, resource_id: u64) -> Result<(), HalError> {
        let port = self
            .ports
            .iter_mut()
            .find(|port| port.resource_id == resource_id && !port.revoked)
            .ok_or(HalError::StaleId)?;
        if port.owner != owner {
            return Err(HalError::WrongOwner);
        }
        port.revoked = true;
        self.revoke_orphaned_port_delegations();
        Ok(())
    }

    fn revoke_orphaned_port_delegations(&mut self) -> usize {
        let mut revoked = 0;
        loop {
            let mut changed = false;
            for index in 0..self.ports.len() {
                let Some((parent_owner, parent_resource_id)) = self.ports[index].delegated_from
                else {
                    continue;
                };
                if self.ports[index].revoked {
                    continue;
                }
                let parent_live = self.ports.iter().any(|parent| {
                    !parent.revoked
                        && parent.owner == parent_owner
                        && parent.resource_id == parent_resource_id
                });
                if !parent_live {
                    self.ports[index].revoked = true;
                    revoked += 1;
                    changed = true;
                }
            }
            if !changed {
                return revoked;
            }
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
                flags: m.flags,
                share: m.share,
                resource_id: m.resource_id,
                raw_start: m.phys_start,
                translated_start: m.translated_start,
                length: m.length,
                arg0: m.cache as u64,
                arg1: m.rights,
                ..Default::default()
            });
        }
        for port in self
            .ports
            .iter()
            .filter(|port| port.owner == owner && !port.revoked)
        {
            out.push(HalResourceDescriptor {
                kind: RES_KIND_PORT,
                flags: port.flags,
                share: port.share,
                resource_id: port.resource_id,
                raw_start: port.raw_start,
                translated_start: port.translated_start,
                length: port.length,
                arg0: RIGHT_READ | RIGHT_WRITE,
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
                flags: i.flags,
                share: i.share,
                resource_id: i.resource_id,
                raw_start: i.line as u64,
                translated_start: i.translated_vector as u64,
                length: 1,
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
                !m.revoked
                    && m.owner == owner
                    && range_contains_address(m.translated_start, m.length, phys)
            })
            .or_else(|| {
                self.memory.iter().find(|m| {
                    !m.revoked && range_contains_address(m.translated_start, m.length, phys)
                })
            })
            .ok_or_else(|| {
                if self.memory.iter().any(|m| {
                    m.revoked
                        && m.owner == owner
                        && range_contains_address(m.translated_start, m.length, phys)
                }) {
                    HalError::Revoked
                } else {
                    HalError::NotAssigned
                }
            })?;
        if m.owner != owner {
            return Err(HalError::WrongOwner);
        }
        let offset = phys - m.translated_start;
        if length == 0 || offset > m.length || length > m.length - offset {
            return Err(HalError::OutOfRange);
        }
        if m.rights & RIGHT_READ == 0 {
            return Err(HalError::AccessDenied);
        }
        self.mappings
            .try_reserve(1)
            .map_err(|_| HalError::InsufficientResources)?;
        let mapping_id = self.next_mapping_id;
        self.next_mapping_id = self
            .next_mapping_id
            .checked_add(1)
            .ok_or(HalError::InsufficientResources)?;
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

    /// Resolve a live connection by canonical `interrupt_id`.
    ///
    /// Hardware delivery and test stimulus share this ownership lookup, but the resource manager
    /// does not manufacture either one. The caller must already possess the interrupt authority.
    pub fn connected_interrupt(&self, interrupt_id: u64) -> Option<InterruptTokens> {
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

    /// Resolve a live connection together with the exact hardware route retained by its assigned
    /// PnP resource. This is the production delivery lookup; it never creates an interrupt.
    pub fn connected_interrupt_route(&self, interrupt_id: u64) -> Option<ConnectedInterrupt> {
        let connection = self
            .connected
            .iter()
            .find(|connection| connection.connected && connection.interrupt_id == interrupt_id)?;
        let resource = self.interrupts_res.iter().find(|resource| {
            !resource.revoked
                && resource.resource_id == connection.resource_id
                && resource.owner == connection.owner
        })?;
        Some(ConnectedInterrupt {
            tokens: InterruptTokens {
                interrupt_id: connection.interrupt_id,
                service_routine_token: connection.service_routine_token,
                service_context_token: connection.service_context_token,
                irql: connection.irql,
                vector: connection.vector,
            },
            resource_id: resource.resource_id,
            line: resource.line,
            translated_vector: resource.translated_vector,
            mode: resource.mode,
            share: resource.share,
        })
    }

    /// Fixture-only compatibility alias for the isolated HAL/component tests.
    pub fn inject_interrupt(&self, interrupt_id: u64) -> Option<InterruptTokens> {
        self.connected_interrupt(interrupt_id)
    }

    /// Device removal cleanup: revoke every assignment, mapping, and interrupt owned by one
    /// driver/device pair. Returns `(memory_resources, port_resources, interrupt_resources,
    /// mappings, interrupts)`.
    pub fn revoke_owner(&mut self, owner: ResourceOwner) -> (usize, usize, usize, usize, usize) {
        let mut memory_resources = 0;
        for m in self.memory.iter_mut() {
            if m.owner == owner && !m.revoked {
                m.revoked = true;
                memory_resources += 1;
            }
        }
        let mut port_resources = 0;
        for port in self.ports.iter_mut() {
            if port.owner == owner && !port.revoked {
                port.revoked = true;
                port_resources += 1;
            }
        }
        port_resources += self.revoke_orphaned_port_delegations();
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
        (
            memory_resources,
            port_resources,
            interrupt_resources,
            mappings,
            interrupts,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rm() -> (ResourceManager, ResourceOwner) {
        let owner = ResourceOwner::new(1, 100, 10);
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
        let other = ResourceOwner::new(2, 200, 20);
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
        let other = ResourceOwner::new(2, 200, 20);
        assert_eq!(
            rm.connect_interrupt(other, 200, 0, 0),
            Err(HalError::WrongOwner)
        );
    }

    #[test]
    fn port_claims_are_exact_idempotent_and_conflict_checked() {
        let (mut rm, owner) = rm();
        let other = ResourceOwner::new(2, 200, 20);
        assert_eq!(rm.claim_port(owner, 300, 0x1ce, 2), Ok(()));
        assert_eq!(rm.claim_port(owner, 300, 0x1ce, 2), Ok(()));
        assert_eq!(
            rm.claim_port(other, 301, 0x1cf, 2),
            Err(HalError::ConflictingAddress)
        );
        assert_eq!(
            rm.claim_port(owner, 302, u16::MAX as u64, 2),
            Err(HalError::InvalidRange)
        );
        let resources = rm.query_resources(owner);
        let port = resources
            .iter()
            .find(|resource| resource.kind == RES_KIND_PORT)
            .unwrap();
        assert_eq!(port.raw_start, 0x1ce);
        assert_eq!(port.length, 2);
        assert_eq!(rm.release_port(owner, 300), Ok(()));
        assert_eq!(rm.claim_port(other, 301, 0x1cf, 2), Ok(()));
    }

    #[test]
    fn port_delegation_requires_a_live_containing_parent_and_revokes_with_it() {
        let mut rm = ResourceManager::new();
        let platform = ResourceOwner::new(1, 10, 100);
        let acpi = ResourceOwner::new(2, 20, 200);
        rm.claim_port(platform, 300, 0xcf8, 8).unwrap();
        let reset = HalResourceDescriptor {
            kind: RES_KIND_PORT,
            share: SHARE_EXCLUSIVE,
            resource_id: 301,
            raw_start: 0xcf9,
            translated_start: 0xcf9,
            length: 1,
            arg0: RIGHT_READ | RIGHT_WRITE,
            ..Default::default()
        };

        assert_eq!(
            rm.replace_owner_assignments(acpi, &[reset]),
            Err(HalError::ConflictingAddress)
        );
        let delegation = PortResourceDelegation {
            parent_owner: platform,
            parent_resource_id: 300,
            resource_id: 301,
        };
        assert_eq!(
            rm.replace_owner_assignments_with_port_delegations(acpi, &[reset], &[delegation]),
            Ok(())
        );
        assert_eq!(rm.query_resources(acpi), alloc::vec![reset]);

        let outside = HalResourceDescriptor {
            raw_start: 0xd00,
            translated_start: 0xd00,
            ..reset
        };
        assert_eq!(
            rm.replace_owner_assignments_with_port_delegations(acpi, &[outside], &[delegation]),
            Err(HalError::OutOfRange)
        );
        assert_eq!(rm.query_resources(acpi), alloc::vec![reset]);

        assert_eq!(rm.release_port(platform, 300), Ok(()));
        assert!(rm.query_resources(acpi).is_empty());
    }

    #[test]
    fn reassigned_memory_resource_revokes_stale_mapping() {
        let (mut rm, old_owner) = rm();
        let mapping = rm.map_io_space(old_owner, 0x1000_0000, 0x1000, 0).unwrap();
        let new_owner = ResourceOwner::new(3, 300, 30);

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
            rm.map_io_space(old_owner, 0x3000_0000, 0x1000, 0),
            Err(HalError::WrongOwner)
        );

        let new_mapping = rm.map_io_space(new_owner, 0x3000_0000, 0x1000, 0).unwrap();
        assert_eq!(new_mapping.translated_start, 0x3000_0000);
    }

    #[test]
    fn reassigned_interrupt_resource_disconnects_stale_isr() {
        let (mut rm, old_owner) = rm();
        let old_interrupt = rm.connect_interrupt(old_owner, 200, 0xAA, 0xBB).unwrap();
        let new_owner = ResourceOwner::new(4, 400, 40);

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

        assert_eq!(rm.revoke_owner(owner), (1, 0, 1, 1, 1));

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
    fn stale_generation_cannot_access_or_revoke_live_resources() {
        let (mut rm, owner) = rm();
        let mapping = rm.map_io_space(owner, 0x1000_0000, 0x1000, 0).unwrap();
        let interrupt = rm.connect_interrupt(owner, 200, 1, 2).unwrap();
        let stale = ResourceOwner::new(
            owner.driver_host_id,
            owner.driver_host_cookie - 1,
            owner.device_object_id,
        );

        assert_eq!(
            rm.map_io_space(stale, 0x1000_0000, 0x1000, 0),
            Err(HalError::WrongOwner)
        );
        assert_eq!(rm.revoke_owner(stale), (0, 0, 0, 0, 0));
        assert!(rm.mapping_valid(mapping.mapping_id));
        assert!(rm.inject_interrupt(interrupt).is_some());
    }

    fn batch_memory(id: u64, raw: u64, translated: u64, length: u64) -> HalResourceDescriptor {
        HalResourceDescriptor {
            kind: RES_KIND_MEMORY,
            share: SHARE_EXCLUSIVE,
            resource_id: id,
            raw_start: raw,
            translated_start: translated,
            length,
            arg0: MM_NON_CACHED as u64,
            arg1: RIGHT_READ | RIGHT_WRITE,
            ..Default::default()
        }
    }

    fn batch_interrupt(id: u64, vector: u32) -> HalResourceDescriptor {
        let (arg0, arg1) = HalResourceDescriptor::interrupt_args(
            vector,
            vector as u8,
            1,
            INT_MODE_LEVEL_SENSITIVE,
        );
        HalResourceDescriptor {
            kind: RES_KIND_INTERRUPT,
            share: SHARE_SHARED,
            resource_id: id,
            raw_start: vector as u64,
            translated_start: vector as u64,
            length: 1,
            arg0,
            arg1,
            ..Default::default()
        }
    }

    #[test]
    fn connected_interrupt_retains_physical_route() {
        let owner = ResourceOwner::new(9, 900, 90);
        let mut rm = ResourceManager::new();
        let mut descriptor = batch_interrupt(0x990, 0x51);
        descriptor.raw_start = 11;
        rm.replace_owner_assignments(owner, &[descriptor]).unwrap();

        let interrupt_id = rm
            .connect_interrupt(owner, descriptor.resource_id, 0xAA, 0xBB)
            .unwrap();
        let route = rm.connected_interrupt_route(interrupt_id).unwrap();
        assert_eq!(route.resource_id, descriptor.resource_id);
        assert_eq!(route.line, 11);
        assert_eq!(route.translated_vector, 0x51);
        assert_eq!(route.tokens.vector, 0x51);
        assert_eq!(route.tokens.service_routine_token, 0xAA);
        assert_eq!(route.tokens.service_context_token, 0xBB);
        assert_eq!(route.mode, INT_MODE_LEVEL_SENSITIVE);
        assert_eq!(route.share, SHARE_SHARED);

        rm.disconnect_interrupt(owner, interrupt_id).unwrap();
        assert!(rm.connected_interrupt_route(interrupt_id).is_none());
    }

    #[test]
    fn batch_replaces_complete_multi_resource_assignment() {
        let owner = ResourceOwner::new(7, 700, 70);
        let mut rm = ResourceManager::new();
        let descriptors = [
            batch_memory(0x710, 0x1000_0000, 0x2000_0000, 0x2000),
            batch_memory(0x712, 0x3000_0000, 0x4000_0000, 0x1000),
            HalResourceDescriptor {
                kind: RES_KIND_PORT,
                share: SHARE_EXCLUSIVE,
                resource_id: 0x720,
                raw_start: 0xc000,
                translated_start: 0xc000,
                length: 0x20,
                arg0: RIGHT_READ | RIGHT_WRITE,
                ..Default::default()
            },
            batch_interrupt(0x730, 19),
        ];

        assert_eq!(rm.replace_owner_assignments(owner, &descriptors), Ok(()));
        assert_eq!(rm.query_resources(owner), descriptors);
        let first = rm.map_io_space(owner, 0x2000_0800, 0x800, MM_NON_CACHED);
        assert_eq!(first.unwrap().resource_id, 0x710);
        let second = rm.map_io_space(owner, 0x4000_0000, 0x1000, MM_NON_CACHED);
        assert_eq!(second.unwrap().resource_id, 0x712);
    }

    #[test]
    fn rejected_batch_preserves_assignments_and_live_usage() {
        let (mut rm, owner) = rm();
        let mapping = rm
            .map_io_space(owner, 0x1000_0000, 0x1000, MM_NON_CACHED)
            .unwrap();
        let interrupt = rm.connect_interrupt(owner, 200, 0xaa, 0xbb).unwrap();
        let before = rm.query_resources(owner);
        let invalid = [
            batch_memory(0x810, 0x5000_0000, 0x6000_0000, 0x1000),
            HalResourceDescriptor {
                kind: RES_KIND_PORT,
                share: SHARE_EXCLUSIVE,
                resource_id: 0x820,
                raw_start: u16::MAX as u64,
                translated_start: u16::MAX as u64,
                length: 2,
                ..Default::default()
            },
        ];

        assert_eq!(
            rm.replace_owner_assignments(owner, &invalid),
            Err(HalError::InvalidRange)
        );
        assert_eq!(rm.query_resources(owner), before);
        assert!(rm.mapping_valid(mapping.mapping_id));
        assert!(rm.inject_interrupt(interrupt).is_some());
    }

    #[test]
    fn exact_batch_replay_preserves_mapping_and_interrupt_ids() {
        let owner = ResourceOwner::new(8, 800, 80);
        let mut rm = ResourceManager::new();
        let descriptors = [
            batch_memory(0x910, 0x7000_0000, 0x8000_0000, 0x1000),
            batch_interrupt(0x930, 18),
        ];
        rm.replace_owner_assignments(owner, &descriptors).unwrap();
        let mapping = rm
            .map_io_space(owner, 0x8000_0000, 0x1000, MM_NON_CACHED)
            .unwrap();
        let interrupt = rm.connect_interrupt(owner, 0x930, 1, 2).unwrap();

        assert_eq!(rm.replace_owner_assignments(owner, &descriptors), Ok(()));
        assert!(rm.mapping_valid(mapping.mapping_id));
        assert!(rm.inject_interrupt(interrupt).is_some());
    }
}
