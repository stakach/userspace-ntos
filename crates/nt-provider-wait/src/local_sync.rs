//! Exact provider-domain ownership for embedded semaphores and mutants.
//!
//! The same catalog contract is used on each side of the isolation boundary. A component
//! records its physical storage and binds the canonical identity returned by the executive;
//! the executive publishes that identity and owns authoritative dispatcher state. Neither a
//! provider virtual address nor a caller-supplied header is authority for a wait.

use alloc::vec::Vec;

use crate::{
    ProviderAllocationCatalog, ProviderAllocationIdentity, ProviderDomainIdentity,
    ProviderEventBacking, ProviderEventStorage, ProviderWaitObject, ProviderWaitObjectType,
    ProviderWaitOwner, SuspensionCaller, PROVIDER_WAIT_MAX_OBJECT_GENERATION,
    PROVIDER_WAIT_MAX_OBJECT_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSyncKind {
    Semaphore { initial_count: i32, limit: i32 },
    Mutant,
}

impl ProviderSyncKind {
    pub const fn storage_bytes(self) -> u64 {
        match self {
            Self::Semaphore { .. } => 0x20,
            Self::Mutant => 0x38,
        }
    }

    fn object_type(self) -> ProviderWaitObjectType {
        match self {
            Self::Semaphore { .. } => ProviderWaitObjectType::Semaphore,
            Self::Mutant => ProviderWaitObjectType::Mutant,
        }
    }

    fn valid(self) -> bool {
        match self {
            Self::Semaphore {
                initial_count,
                limit,
            } => limit > 0 && initial_count >= 0 && initial_count <= limit,
            Self::Mutant => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalSyncId(u64);

impl ProviderLocalSyncId {
    pub const fn raw(self) -> u64 {
        self.0
    }
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    fn new(slot: usize, generation: u32) -> Result<Self, ProviderLocalSyncError> {
        let slot = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        Ok(Self((u64::from(generation) << 32) | u64::from(slot)))
    }

    fn parts(self) -> Option<(usize, u32)> {
        let slot = (self.0 as u32).checked_sub(1)? as usize;
        let generation = (self.0 >> 32) as u32;
        (generation != 0).then_some((slot, generation))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLocalSyncError {
    InvalidProvider,
    InvalidStorage,
    InvalidState,
    AddressInUse,
    StorageInUse,
    IdentityExhausted,
    NoCapacity,
    NotFound,
    StaleIdentity,
    NotPublished,
    AlreadyPublished,
    CanonicalIdentityInUse,
    DeletePending,
    ActiveLeases,
    ActiveObjects,
    OwnedMutant,
    WrongLease,
    WrongCaller,
    CountLimit,
    RecursionLimit,
    RetirementMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalSyncLease {
    pub id: ProviderLocalSyncId,
    pub canonical: ProviderWaitObject,
    pub caller: SuspensionCaller,
    serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalSyncOperationLease {
    pub id: ProviderLocalSyncId,
    pub canonical: ProviderWaitObject,
    serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalSyncSnapshot {
    pub id: ProviderLocalSyncId,
    pub body: u64,
    pub storage: ProviderEventStorage,
    pub kind: ProviderSyncKind,
    pub canonical: Option<ProviderWaitObject>,
    pub delete_pending: bool,
    pub wait_leases: u32,
    pub operation_leases: u32,
    /// Semaphore count, or the NT mutant SignalState (one when unowned).
    pub signal_state: i32,
    pub mutant_owner: Option<SuspensionCaller>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalSyncRetirement {
    pub id: ProviderLocalSyncId,
    pub canonical: ProviderWaitObject,
}

#[derive(Clone, Copy)]
struct Row {
    generation: u32,
    live: bool,
    body: u64,
    storage: ProviderEventStorage,
    kind: ProviderSyncKind,
    canonical: Option<ProviderWaitObject>,
    delete_pending: bool,
    wait_leases: u32,
    operation_leases: u32,
    signal_state: i32,
    mutant_owner: Option<SuspensionCaller>,
}

impl Row {
    const EMPTY: Self = Self {
        generation: 0,
        live: false,
        body: 0,
        storage: ProviderEventStorage {
            backing: ProviderEventBacking::Static {
                instance_generation: 0,
            },
            offset: 0,
        },
        kind: ProviderSyncKind::Mutant,
        canonical: None,
        delete_pending: false,
        wait_leases: 0,
        operation_leases: 0,
        signal_state: 1,
        mutant_owner: None,
    };

    fn snapshot(self, slot: usize) -> ProviderLocalSyncSnapshot {
        ProviderLocalSyncSnapshot {
            id: ProviderLocalSyncId::new(slot, self.generation).unwrap(),
            body: self.body,
            storage: self.storage,
            kind: self.kind,
            canonical: self.canonical,
            delete_pending: self.delete_pending,
            wait_leases: self.wait_leases,
            operation_leases: self.operation_leases,
            signal_state: self.signal_state,
            mutant_owner: self.mutant_owner,
        }
    }

    fn may_retire(self) -> Result<(), ProviderLocalSyncError> {
        if self.delete_pending {
            return Err(ProviderLocalSyncError::DeletePending);
        }
        if self.wait_leases != 0 || self.operation_leases != 0 {
            return Err(ProviderLocalSyncError::ActiveLeases);
        }
        if self.mutant_owner.is_some() {
            return Err(ProviderLocalSyncError::OwnedMutant);
        }
        if self.canonical.is_none() {
            return Err(ProviderLocalSyncError::NotPublished);
        }
        Ok(())
    }
}

pub struct ProviderLocalSyncCatalog {
    provider: ProviderDomainIdentity,
    rows: Vec<Row>,
    waits: Vec<ProviderLocalSyncLease>,
    operations: Vec<ProviderLocalSyncOperationLease>,
    next_serial: u64,
}

impl ProviderLocalSyncCatalog {
    pub fn new(provider: ProviderDomainIdentity) -> Result<Self, ProviderLocalSyncError> {
        if !provider.is_valid() {
            return Err(ProviderLocalSyncError::InvalidProvider);
        }
        Ok(Self {
            provider,
            rows: Vec::new(),
            waits: Vec::new(),
            operations: Vec::new(),
            next_serial: 1,
        })
    }

    pub const fn provider(&self) -> ProviderDomainIdentity {
        self.provider
    }

    pub fn active_count(&self) -> usize {
        self.rows.iter().filter(|row| row.live).count()
    }

    /// A domain catalog may be replaced only after every exact row and lease has retired.
    pub fn is_empty(&self) -> bool {
        self.active_count() == 0 && self.waits.is_empty() && self.operations.is_empty()
    }

    pub fn validate_domain_retirement(&self) -> Result<(), ProviderLocalSyncError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(ProviderLocalSyncError::ActiveObjects)
        }
    }

    fn initialize(
        &mut self,
        body: u64,
        storage: ProviderEventStorage,
        kind: ProviderSyncKind,
    ) -> Result<ProviderLocalSyncId, ProviderLocalSyncError> {
        if body == 0 || !storage.backing.is_valid(self.provider) {
            return Err(ProviderLocalSyncError::InvalidStorage);
        }
        if !kind.valid() {
            return Err(ProviderLocalSyncError::InvalidState);
        }
        if self.rows.iter().any(|row| row.live && row.body == body) {
            return Err(ProviderLocalSyncError::AddressInUse);
        }
        let end = storage
            .offset
            .checked_add(kind.storage_bytes())
            .ok_or(ProviderLocalSyncError::InvalidStorage)?;
        if self.rows.iter().any(|row| {
            if !row.live || row.storage.backing != storage.backing {
                return false;
            }
            let other_end = row.storage.offset + row.kind.storage_bytes();
            storage.offset < other_end && row.storage.offset < end
        }) {
            return Err(ProviderLocalSyncError::StorageInUse);
        }
        let slot = if let Some(slot) = self.rows.iter().position(|row| !row.live) {
            slot
        } else {
            self.rows
                .try_reserve(1)
                .map_err(|_| ProviderLocalSyncError::NoCapacity)?;
            self.rows.push(Row::EMPTY);
            self.rows.len() - 1
        };
        let generation = self.rows[slot]
            .generation
            .checked_add(1)
            .filter(|generation| u64::from(*generation) <= PROVIDER_WAIT_MAX_OBJECT_GENERATION)
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        let id = ProviderLocalSyncId::new(slot, generation)?;
        self.rows[slot] = Row {
            generation,
            live: true,
            body,
            storage,
            kind,
            signal_state: match kind {
                ProviderSyncKind::Semaphore { initial_count, .. } => initial_count,
                ProviderSyncKind::Mutant => 1,
            },
            ..Row::EMPTY
        };
        Ok(id)
    }

    pub fn initialize_static(
        &mut self,
        body: u64,
        offset: u64,
        kind: ProviderSyncKind,
    ) -> Result<ProviderLocalSyncId, ProviderLocalSyncError> {
        self.initialize(
            body,
            ProviderEventStorage {
                backing: ProviderEventBacking::Static {
                    instance_generation: self.provider.generation,
                },
                offset,
            },
            kind,
        )
    }

    pub fn initialize_stack(
        &mut self,
        body: u64,
        lane_id: u64,
        lane_generation: u64,
        dispatch_id: u64,
        activation_generation: u64,
        offset: u64,
        kind: ProviderSyncKind,
    ) -> Result<ProviderLocalSyncId, ProviderLocalSyncError> {
        self.initialize(
            body,
            ProviderEventStorage {
                backing: ProviderEventBacking::Stack {
                    lane_id,
                    lane_generation,
                    dispatch_id,
                    activation_generation,
                },
                offset,
            },
            kind,
        )
    }

    pub fn initialize_in_allocation(
        &mut self,
        allocations: &ProviderAllocationCatalog,
        allocation_identity: ProviderAllocationIdentity,
        body: u64,
        storage_bytes: u64,
        kind: ProviderSyncKind,
    ) -> Result<ProviderLocalSyncId, ProviderLocalSyncError> {
        let allocation = allocations
            .snapshot_active(allocation_identity)
            .map_err(|_| ProviderLocalSyncError::InvalidStorage)?;
        let offset = allocation
            .offset_of(body)
            .ok_or(ProviderLocalSyncError::InvalidStorage)?;
        let allocation_end = allocation
            .base
            .checked_add(allocation.capacity)
            .ok_or(ProviderLocalSyncError::InvalidStorage)?;
        if storage_bytes < kind.storage_bytes()
            || body
                .checked_add(storage_bytes)
                .is_none_or(|end| end > allocation_end)
        {
            return Err(ProviderLocalSyncError::InvalidStorage);
        }
        self.initialize(
            body,
            ProviderEventStorage {
                backing: ProviderEventBacking::from_allocation(allocation),
                offset,
            },
            kind,
        )
    }

    /// Executive publication uses its locally minted slot and generation. The local identity
    /// is an opaque broker key, not physical storage authority. The caller authenticates it.
    pub fn publish(
        &mut self,
        local_identity: u64,
        kind: ProviderSyncKind,
    ) -> Result<ProviderWaitObject, ProviderLocalSyncError> {
        // The broker key identifies the provider's local generation; it is not an address.
        // Give each root catalog slot its own disjoint synthetic range. initialize() chooses
        // the same first vacant slot, and retirement fences reuse until acknowledgement.
        let next_slot = self.rows.iter().position(|row| !row.live).unwrap_or(self.rows.len());
        let offset = u64::try_from(next_slot).ok()
            .and_then(|slot| slot.checked_mul(0x40))
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        let id = self.initialize_static(local_identity, offset, kind)?;
        let (slot, generation) = id.parts().unwrap();
        let object_id = (slot as u64)
            .checked_add(1)
            .filter(|id| *id <= PROVIDER_WAIT_MAX_OBJECT_ID)
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        let canonical =
            ProviderWaitObject::new(kind.object_type(), object_id, u64::from(generation));
        self.bind_canonical(id, canonical)?;
        Ok(canonical)
    }

    pub fn bind_canonical(
        &mut self,
        id: ProviderLocalSyncId,
        canonical: ProviderWaitObject,
    ) -> Result<(), ProviderLocalSyncError> {
        let slot = self.slot(id)?;
        if canonical.typed() != Some(self.rows[slot].kind.object_type())
            || canonical.flags != 0
            || canonical.object_id == 0
            || canonical.object_id > PROVIDER_WAIT_MAX_OBJECT_ID
            || canonical.object_generation == 0
            || canonical.object_generation > PROVIDER_WAIT_MAX_OBJECT_GENERATION
        {
            return Err(ProviderLocalSyncError::NotPublished);
        }
        if self.rows[slot].delete_pending {
            return Err(ProviderLocalSyncError::DeletePending);
        }
        if let Some(existing) = self.rows[slot].canonical {
            return if existing == canonical {
                Ok(())
            } else {
                Err(ProviderLocalSyncError::AlreadyPublished)
            };
        }
        if self
            .rows
            .iter()
            .enumerate()
            .any(|(index, row)| index != slot && row.live && row.canonical == Some(canonical))
        {
            return Err(ProviderLocalSyncError::CanonicalIdentityInUse);
        }
        self.rows[slot].canonical = Some(canonical);
        Ok(())
    }

    pub fn snapshot(
        &self,
        id: ProviderLocalSyncId,
    ) -> Result<ProviderLocalSyncSnapshot, ProviderLocalSyncError> {
        let slot = self.slot(id)?;
        Ok(self.rows[slot].snapshot(slot))
    }

    pub fn snapshot_for_body(
        &self,
        body: u64,
    ) -> Result<ProviderLocalSyncSnapshot, ProviderLocalSyncError> {
        let (slot, row) = self
            .rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.live && row.body == body)
            .ok_or(ProviderLocalSyncError::NotFound)?;
        Ok(row.snapshot(slot))
    }

    /// Read a root-owned state only for the exact local and canonical generation binding.
    pub fn snapshot_bound(
        &self,
        body: u64,
        canonical: ProviderWaitObject,
    ) -> Result<ProviderLocalSyncSnapshot, ProviderLocalSyncError> {
        let snapshot = self.snapshot_for_body(body)?;
        if snapshot.canonical != Some(canonical) || snapshot.delete_pending {
            return Err(ProviderLocalSyncError::StaleIdentity);
        }
        Ok(snapshot)
    }

    pub fn snapshot_for_canonical(
        &self,
        object: ProviderWaitObject,
    ) -> Result<ProviderLocalSyncSnapshot, ProviderLocalSyncError> {
        let (slot, row) = self
            .rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.live && row.canonical == Some(object) && !row.delete_pending)
            .ok_or(ProviderLocalSyncError::NotFound)?;
        Ok(row.snapshot(slot))
    }

    pub fn rollback_unpublished(
        &mut self,
        id: ProviderLocalSyncId,
    ) -> Result<(), ProviderLocalSyncError> {
        let slot = self.slot(id)?;
        let row = self.rows[slot];
        if row.canonical.is_some()
            || row.delete_pending
            || row.wait_leases != 0
            || row.operation_leases != 0
        {
            return Err(ProviderLocalSyncError::AlreadyPublished);
        }
        self.rows[slot].live = false;
        Ok(())
    }

    fn next_lease_serial(&mut self) -> Result<u64, ProviderLocalSyncError> {
        let serial = self.next_serial;
        self.next_serial = serial
            .checked_add(1)
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        Ok(serial)
    }

    pub fn acquire_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<ProviderLocalSyncLease, ProviderLocalSyncError> {
        if !owner.is_valid()
            || (owner.provider_domain, owner.provider_generation)
                != (self.provider.domain, self.provider.generation)
        {
            return Err(ProviderLocalSyncError::InvalidProvider);
        }
        let snapshot = self.snapshot_for_canonical(object)?;
        let slot = self.slot(snapshot.id)?;
        let next = self.rows[slot]
            .wait_leases
            .checked_add(1)
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        self.waits
            .try_reserve(1)
            .map_err(|_| ProviderLocalSyncError::NoCapacity)?;
        let lease = ProviderLocalSyncLease {
            id: snapshot.id,
            canonical: object,
            caller: owner.caller,
            serial: self.next_lease_serial()?,
        };
        self.waits.push(lease);
        self.rows[slot].wait_leases = next;
        Ok(lease)
    }

    pub fn is_ready(&self, lease: ProviderLocalSyncLease) -> Result<bool, ProviderLocalSyncError> {
        let row = self.row_for_wait(lease)?;
        Ok(match row.kind {
            ProviderSyncKind::Semaphore { .. } => row.signal_state > 0,
            ProviderSyncKind::Mutant => {
                row.signal_state > i32::MIN
                    && (row.mutant_owner.is_none() || row.mutant_owner == Some(lease.caller))
            }
        })
    }

    /// Consume one selected ready object. The root arbiter serializes readiness and selection.
    pub fn consume_ready(
        &mut self,
        lease: ProviderLocalSyncLease,
    ) -> Result<bool, ProviderLocalSyncError> {
        let slot = self.slot(lease.id)?;
        self.row_for_wait(lease)?;
        let row = &mut self.rows[slot];
        match row.kind {
            ProviderSyncKind::Semaphore { .. } if row.signal_state > 0 => {
                row.signal_state -= 1;
                Ok(true)
            }
            ProviderSyncKind::Mutant
                if row.mutant_owner.is_none() || row.mutant_owner == Some(lease.caller) =>
            {
                if row.signal_state == i32::MIN {
                    return Err(ProviderLocalSyncError::RecursionLimit);
                }
                row.signal_state -= 1;
                row.mutant_owner = Some(lease.caller);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn release_wait(
        &mut self,
        lease: ProviderLocalSyncLease,
    ) -> Result<(), ProviderLocalSyncError> {
        self.row_for_wait(lease)?;
        let slot = self.slot(lease.id)?;
        let position = self
            .waits
            .iter()
            .position(|item| *item == lease)
            .ok_or(ProviderLocalSyncError::WrongLease)?;
        self.rows[slot].wait_leases -= 1;
        self.waits.swap_remove(position);
        Ok(())
    }

    /// Pin a provider-side operation across broker IPC without exposing its body as authority.
    pub fn acquire_operation(
        &mut self,
        id: ProviderLocalSyncId,
    ) -> Result<ProviderLocalSyncOperationLease, ProviderLocalSyncError> {
        let slot = self.slot(id)?;
        if self.rows[slot].delete_pending {
            return Err(ProviderLocalSyncError::DeletePending);
        }
        let canonical = self.rows[slot]
            .canonical
            .ok_or(ProviderLocalSyncError::NotPublished)?;
        let next = self.rows[slot]
            .operation_leases
            .checked_add(1)
            .ok_or(ProviderLocalSyncError::IdentityExhausted)?;
        self.operations
            .try_reserve(1)
            .map_err(|_| ProviderLocalSyncError::NoCapacity)?;
        let lease = ProviderLocalSyncOperationLease {
            id,
            canonical,
            serial: self.next_lease_serial()?,
        };
        self.operations.push(lease);
        self.rows[slot].operation_leases = next;
        Ok(lease)
    }

    pub fn release_operation(
        &mut self,
        lease: ProviderLocalSyncOperationLease,
    ) -> Result<(), ProviderLocalSyncError> {
        let slot = self.slot(lease.id)?;
        if self.rows[slot].canonical != Some(lease.canonical) {
            return Err(ProviderLocalSyncError::WrongLease);
        }
        let position = self
            .operations
            .iter()
            .position(|item| *item == lease)
            .ok_or(ProviderLocalSyncError::WrongLease)?;
        self.rows[slot].operation_leases = self.rows[slot]
            .operation_leases
            .checked_sub(1)
            .ok_or(ProviderLocalSyncError::WrongLease)?;
        self.operations.swap_remove(position);
        Ok(())
    }

    pub fn release_semaphore(
        &mut self,
        local: u64,
        adjustment: i32,
    ) -> Result<i32, ProviderLocalSyncError> {
        let id = self.snapshot_for_body(local)?.id;
        let slot = self.slot(id)?;
        if self.rows[slot].delete_pending {
            return Err(ProviderLocalSyncError::DeletePending);
        }
        let ProviderSyncKind::Semaphore { limit, .. } = self.rows[slot].kind else {
            return Err(ProviderLocalSyncError::InvalidState);
        };
        if self.rows[slot].canonical.is_none() {
            return Err(ProviderLocalSyncError::NotPublished);
        }
        if adjustment <= 0 {
            return Err(ProviderLocalSyncError::CountLimit);
        }
        let previous = self.rows[slot].signal_state;
        let next = previous
            .checked_add(adjustment)
            .filter(|next| *next <= limit)
            .ok_or(ProviderLocalSyncError::CountLimit)?;
        self.rows[slot].signal_state = next;
        Ok(previous)
    }

    pub fn release_mutant(
        &mut self,
        local: u64,
        owner: ProviderWaitOwner,
    ) -> Result<i32, ProviderLocalSyncError> {
        if !owner.is_valid()
            || (owner.provider_domain, owner.provider_generation)
                != (self.provider.domain, self.provider.generation)
        {
            return Err(ProviderLocalSyncError::InvalidProvider);
        }
        let id = self.snapshot_for_body(local)?.id;
        let slot = self.slot(id)?;
        let row = &mut self.rows[slot];
        if row.delete_pending {
            return Err(ProviderLocalSyncError::DeletePending);
        }
        if row.kind != ProviderSyncKind::Mutant {
            return Err(ProviderLocalSyncError::InvalidState);
        }
        if row.canonical.is_none() {
            return Err(ProviderLocalSyncError::NotPublished);
        }
        if row.mutant_owner != Some(owner.caller) {
            return Err(ProviderLocalSyncError::WrongCaller);
        }
        let previous = row.signal_state;
        row.signal_state = previous
            .checked_add(1)
            .ok_or(ProviderLocalSyncError::InvalidState)?;
        if row.signal_state == 1 {
            row.mutant_owner = None;
        }
        Ok(previous)
    }

    pub fn backing_sync_count(&self, backing: ProviderEventBacking) -> usize {
        self.rows
            .iter()
            .filter(|row| row.live && row.storage.backing == backing)
            .count()
    }

    pub fn validate_backing_retirement(
        &self,
        backing: ProviderEventBacking,
    ) -> Result<usize, ProviderLocalSyncError> {
        if !backing.is_valid(self.provider) {
            return Err(ProviderLocalSyncError::InvalidStorage);
        }
        let mut count = 0;
        for row in self
            .rows
            .iter()
            .filter(|row| row.live && row.storage.backing == backing)
        {
            row.may_retire()?;
            count += 1;
        }
        Ok(count)
    }

    pub fn begin_retire_sync(
        &mut self,
        id: ProviderLocalSyncId,
    ) -> Result<ProviderLocalSyncRetirement, ProviderLocalSyncError> {
        let slot = self.slot(id)?;
        let row = self.rows[slot];
        row.may_retire()?;
        self.rows[slot].delete_pending = true;
        Ok(ProviderLocalSyncRetirement {
            id,
            canonical: row.canonical.unwrap(),
        })
    }

    pub fn begin_retire_backing(
        &mut self,
        backing: ProviderEventBacking,
    ) -> Result<Vec<ProviderLocalSyncRetirement>, ProviderLocalSyncError> {
        let count = self.validate_backing_retirement(backing)?;
        if count == 0 {
            return Err(ProviderLocalSyncError::NotFound);
        }
        let mut result = Vec::new();
        result
            .try_reserve(count)
            .map_err(|_| ProviderLocalSyncError::NoCapacity)?;
        for (slot, row) in self.rows.iter_mut().enumerate() {
            if row.live && row.storage.backing == backing {
                result.push(ProviderLocalSyncRetirement {
                    id: ProviderLocalSyncId::new(slot, row.generation)?,
                    canonical: row.canonical.unwrap(),
                });
                row.delete_pending = true;
            }
        }
        Ok(result)
    }

    pub fn ack_retirement(
        &mut self,
        retirement: ProviderLocalSyncRetirement,
    ) -> Result<(), ProviderLocalSyncError> {
        let slot = self.slot(retirement.id)?;
        let row = self.rows[slot];
        if !row.delete_pending
            || row.canonical != Some(retirement.canonical)
            || row.wait_leases != 0
            || row.operation_leases != 0
            || row.mutant_owner.is_some()
        {
            return Err(ProviderLocalSyncError::RetirementMismatch);
        }
        self.rows[slot].live = false;
        self.rows[slot].canonical = None;
        self.rows[slot].delete_pending = false;
        Ok(())
    }

    /// Root-only memory-local removal after the canonical wait owner has authorized retirement.
    pub fn retire_local(
        &mut self,
        local: u64,
    ) -> Result<ProviderWaitObject, ProviderLocalSyncError> {
        let id = self.snapshot_for_body(local)?.id;
        let retirement = self.begin_retire_sync(id)?;
        self.ack_retirement(retirement)?;
        Ok(retirement.canonical)
    }

    fn slot(&self, id: ProviderLocalSyncId) -> Result<usize, ProviderLocalSyncError> {
        let (slot, generation) = id.parts().ok_or(ProviderLocalSyncError::StaleIdentity)?;
        self.rows
            .get(slot)
            .filter(|row| row.live && row.generation == generation)
            .map(|_| slot)
            .ok_or(ProviderLocalSyncError::StaleIdentity)
    }

    fn row_for_wait(&self, lease: ProviderLocalSyncLease) -> Result<&Row, ProviderLocalSyncError> {
        let slot = self.slot(lease.id)?;
        let row = &self.rows[slot];
        if row.canonical != Some(lease.canonical) || !self.waits.contains(&lease) {
            return Err(ProviderLocalSyncError::WrongLease);
        }
        Ok(row)
    }
}

#[cfg(test)]
#[path = "local_sync_tests.rs"]
mod tests;
