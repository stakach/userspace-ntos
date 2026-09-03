use alloc::vec::Vec;

use crate::{ProviderDomainIdentity, ProviderWaitObject, ProviderWaitObjectType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEventKind {
    Notification,
    Synchronization,
}

/// Storage whose lifetime owns one or more embedded dispatcher Events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEventBacking {
    Static {
        instance_generation: u64,
    },
    Pool {
        allocation_id: u64,
        allocation_generation: u64,
    },
    Stack {
        dispatch_id: u64,
        activation_generation: u64,
    },
}

impl ProviderEventBacking {
    fn is_valid(self, provider: ProviderDomainIdentity) -> bool {
        match self {
            Self::Static {
                instance_generation,
            } => instance_generation == provider.generation,
            Self::Pool {
                allocation_id,
                allocation_generation,
            } => allocation_id != 0 && allocation_generation != 0,
            Self::Stack {
                dispatch_id,
                activation_generation,
            } => dispatch_id != 0 && activation_generation != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderEventStorage {
    pub backing: ProviderEventBacking,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalEventId(u64);

impl ProviderLocalEventId {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    fn new(slot: usize, generation: u32) -> Result<Self, ProviderLocalEventError> {
        let slot = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(ProviderLocalEventError::IdentityExhausted)?;
        Ok(Self((u64::from(generation) << 32) | u64::from(slot)))
    }

    fn parts(self) -> Option<(usize, u32)> {
        let slot = (self.0 as u32).checked_sub(1)? as usize;
        let generation = (self.0 >> 32) as u32;
        (generation != 0).then_some((slot, generation))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLocalEventLeaseKind {
    Wait,
    Signal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLocalEventError {
    InvalidProvider,
    InvalidStorage,
    StorageInUse,
    AddressInUse,
    IdentityExhausted,
    NoCapacity,
    NotFound,
    StaleIdentity,
    NotPublished,
    AlreadyPublished,
    CanonicalIdentityInUse,
    DeletePending,
    ActiveLeases,
    LeaseOverflow,
    LeaseUnderflow,
    RetirementMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalEventSnapshot {
    pub id: ProviderLocalEventId,
    pub body: u64,
    pub storage: ProviderEventStorage,
    pub kind: ProviderEventKind,
    pub initial_state: bool,
    pub canonical: Option<ProviderWaitObject>,
    pub delete_pending: bool,
    pub wait_leases: u32,
    pub signal_leases: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalEventRetirement {
    pub id: ProviderLocalEventId,
    pub canonical: ProviderWaitObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderLocalEventRecord {
    generation: u32,
    live: bool,
    body: u64,
    storage: ProviderEventStorage,
    kind: ProviderEventKind,
    initial_state: bool,
    canonical: Option<ProviderWaitObject>,
    delete_pending: bool,
    wait_leases: u32,
    signal_leases: u32,
}

impl ProviderLocalEventRecord {
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
        kind: ProviderEventKind::Notification,
        initial_state: false,
        canonical: None,
        delete_pending: false,
        wait_leases: 0,
        signal_leases: 0,
    };

    fn snapshot(self, slot: usize) -> ProviderLocalEventSnapshot {
        ProviderLocalEventSnapshot {
            id: ProviderLocalEventId::new(slot, self.generation).unwrap(),
            body: self.body,
            storage: self.storage,
            kind: self.kind,
            initial_state: self.initial_state,
            canonical: self.canonical,
            delete_pending: self.delete_pending,
            wait_leases: self.wait_leases,
            signal_leases: self.signal_leases,
        }
    }

    const fn has_leases(self) -> bool {
        self.wait_leases != 0 || self.signal_leases != 0
    }
}

/// Component-private ownership catalog for provider-embedded `KEVENT` storage.
///
/// `body` is intentionally retained only here. Requests crossing the isolation boundary use the
/// minted local identity during publication and the canonical dispatcher identity thereafter.
pub struct ProviderLocalEventCatalog {
    provider: ProviderDomainIdentity,
    records: Vec<ProviderLocalEventRecord>,
}

impl ProviderLocalEventCatalog {
    pub fn new(provider: ProviderDomainIdentity) -> Result<Self, ProviderLocalEventError> {
        if !provider.is_valid() {
            return Err(ProviderLocalEventError::InvalidProvider);
        }
        Ok(Self {
            provider,
            records: Vec::new(),
        })
    }

    pub const fn provider(&self) -> ProviderDomainIdentity {
        self.provider
    }

    /// Reserve a fresh local identity before asking the executive to publish a canonical Event.
    /// Existing or delete-pending storage must be retired first, even when no lease is active.
    pub fn initialize(
        &mut self,
        body: u64,
        storage: ProviderEventStorage,
        kind: ProviderEventKind,
        initial_state: bool,
    ) -> Result<ProviderLocalEventId, ProviderLocalEventError> {
        if body == 0 || !storage.backing.is_valid(self.provider) {
            return Err(ProviderLocalEventError::InvalidStorage);
        }
        if self
            .records
            .iter()
            .any(|record| record.live && record.body == body)
        {
            return Err(ProviderLocalEventError::AddressInUse);
        }
        if self
            .records
            .iter()
            .any(|record| record.live && record.storage == storage)
        {
            return Err(ProviderLocalEventError::StorageInUse);
        }

        let slot = if let Some(slot) = self.records.iter().position(|record| !record.live) {
            slot
        } else {
            self.records
                .try_reserve(1)
                .map_err(|_| ProviderLocalEventError::NoCapacity)?;
            self.records.push(ProviderLocalEventRecord::EMPTY);
            self.records.len() - 1
        };
        let generation = self.records[slot]
            .generation
            .checked_add(1)
            .ok_or(ProviderLocalEventError::IdentityExhausted)?;
        let id = ProviderLocalEventId::new(slot, generation)?;
        self.records[slot] = ProviderLocalEventRecord {
            generation,
            live: true,
            body,
            storage,
            kind,
            initial_state,
            ..ProviderLocalEventRecord::EMPTY
        };
        Ok(id)
    }

    pub fn rollback_unpublished(
        &mut self,
        id: ProviderLocalEventId,
    ) -> Result<(), ProviderLocalEventError> {
        let slot = self.slot(id)?;
        let record = self.records[slot];
        if record.canonical.is_some() || record.delete_pending || record.has_leases() {
            return Err(ProviderLocalEventError::AlreadyPublished);
        }
        self.records[slot].live = false;
        Ok(())
    }

    pub fn bind_canonical(
        &mut self,
        id: ProviderLocalEventId,
        canonical: ProviderWaitObject,
    ) -> Result<(), ProviderLocalEventError> {
        if canonical.typed() != Some(ProviderWaitObjectType::Event)
            || canonical.object_id == 0
            || canonical.object_generation == 0
        {
            return Err(ProviderLocalEventError::NotPublished);
        }
        let slot = self.slot(id)?;
        if self.records[slot].delete_pending {
            return Err(ProviderLocalEventError::DeletePending);
        }
        if let Some(existing) = self.records[slot].canonical {
            return if existing == canonical {
                Ok(())
            } else {
                Err(ProviderLocalEventError::AlreadyPublished)
            };
        }
        if self.records.iter().enumerate().any(|(index, record)| {
            index != slot && record.live && record.canonical == Some(canonical)
        }) {
            return Err(ProviderLocalEventError::CanonicalIdentityInUse);
        }
        self.records[slot].canonical = Some(canonical);
        Ok(())
    }

    pub fn snapshot(
        &self,
        id: ProviderLocalEventId,
    ) -> Result<ProviderLocalEventSnapshot, ProviderLocalEventError> {
        let slot = self.slot(id)?;
        Ok(self.records[slot].snapshot(slot))
    }

    pub fn resolve_body(
        &self,
        body: u64,
    ) -> Result<ProviderLocalEventSnapshot, ProviderLocalEventError> {
        let (slot, record) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.body == body)
            .ok_or(ProviderLocalEventError::NotFound)?;
        if record.canonical.is_none() {
            return Err(ProviderLocalEventError::NotPublished);
        }
        if record.delete_pending {
            return Err(ProviderLocalEventError::DeletePending);
        }
        Ok(record.snapshot(slot))
    }

    pub fn acquire_lease(
        &mut self,
        id: ProviderLocalEventId,
        kind: ProviderLocalEventLeaseKind,
    ) -> Result<(), ProviderLocalEventError> {
        let slot = self.slot(id)?;
        let record = &mut self.records[slot];
        if record.canonical.is_none() {
            return Err(ProviderLocalEventError::NotPublished);
        }
        if record.delete_pending {
            return Err(ProviderLocalEventError::DeletePending);
        }
        let count = match kind {
            ProviderLocalEventLeaseKind::Wait => &mut record.wait_leases,
            ProviderLocalEventLeaseKind::Signal => &mut record.signal_leases,
        };
        *count = count
            .checked_add(1)
            .ok_or(ProviderLocalEventError::LeaseOverflow)?;
        Ok(())
    }

    pub fn release_lease(
        &mut self,
        id: ProviderLocalEventId,
        kind: ProviderLocalEventLeaseKind,
    ) -> Result<(), ProviderLocalEventError> {
        let slot = self.slot(id)?;
        let count = match kind {
            ProviderLocalEventLeaseKind::Wait => &mut self.records[slot].wait_leases,
            ProviderLocalEventLeaseKind::Signal => &mut self.records[slot].signal_leases,
        };
        *count = count
            .checked_sub(1)
            .ok_or(ProviderLocalEventError::LeaseUnderflow)?;
        Ok(())
    }

    /// Mark every Event in one allocation/activation/instance delete-pending atomically.
    pub fn begin_retire_backing(
        &mut self,
        backing: ProviderEventBacking,
    ) -> Result<Vec<ProviderLocalEventRetirement>, ProviderLocalEventError> {
        if !backing.is_valid(self.provider) {
            return Err(ProviderLocalEventError::InvalidStorage);
        }
        let count = self
            .records
            .iter()
            .filter(|record| record.live && record.storage.backing == backing)
            .count();
        if count == 0 {
            return Err(ProviderLocalEventError::NotFound);
        }
        if self
            .records
            .iter()
            .any(|record| record.live && record.storage.backing == backing && record.has_leases())
        {
            return Err(ProviderLocalEventError::ActiveLeases);
        }
        let mut retirements = Vec::new();
        retirements
            .try_reserve(count)
            .map_err(|_| ProviderLocalEventError::NoCapacity)?;
        for (slot, record) in self.records.iter().enumerate() {
            if record.live && record.storage.backing == backing {
                let canonical = record
                    .canonical
                    .ok_or(ProviderLocalEventError::NotPublished)?;
                retirements.push(ProviderLocalEventRetirement {
                    id: ProviderLocalEventId::new(slot, record.generation)?,
                    canonical,
                });
            }
        }
        for record in &mut self.records {
            if record.live && record.storage.backing == backing {
                record.delete_pending = true;
            }
        }
        Ok(retirements)
    }

    /// Complete the executive's exact retirement acknowledgement and release local storage.
    pub fn ack_retirement(
        &mut self,
        retirement: ProviderLocalEventRetirement,
    ) -> Result<(), ProviderLocalEventError> {
        let slot = self.slot(retirement.id)?;
        let record = &mut self.records[slot];
        if !record.delete_pending
            || record.has_leases()
            || record.canonical != Some(retirement.canonical)
        {
            return Err(ProviderLocalEventError::RetirementMismatch);
        }
        record.live = false;
        record.canonical = None;
        record.delete_pending = false;
        Ok(())
    }

    fn slot(&self, id: ProviderLocalEventId) -> Result<usize, ProviderLocalEventError> {
        let (slot, generation) = id.parts().ok_or(ProviderLocalEventError::StaleIdentity)?;
        self.records
            .get(slot)
            .filter(|record| record.live && record.generation == generation)
            .map(|_| slot)
            .ok_or(ProviderLocalEventError::StaleIdentity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> ProviderDomainIdentity {
        ProviderDomainIdentity {
            domain: 7,
            generation: 3,
        }
    }

    fn canonical(slot: u64, generation: u64) -> ProviderWaitObject {
        ProviderWaitObject::new(ProviderWaitObjectType::Event, slot, generation)
    }

    fn pool(allocation_id: u64, generation: u64, offset: u64) -> ProviderEventStorage {
        ProviderEventStorage {
            backing: ProviderEventBacking::Pool {
                allocation_id,
                allocation_generation: generation,
            },
            offset,
        }
    }

    #[test]
    fn pool_reuse_requires_exact_two_phase_retirement() {
        let mut catalog = ProviderLocalEventCatalog::new(provider()).unwrap();
        let storage = pool(11, 1, 8);
        let first = catalog
            .initialize(0x1008, storage, ProviderEventKind::Notification, false)
            .unwrap();
        catalog.bind_canonical(first, canonical(5, 2)).unwrap();
        assert_eq!(
            catalog.initialize(0x1008, storage, ProviderEventKind::Notification, true),
            Err(ProviderLocalEventError::AddressInUse)
        );

        let retirement = catalog
            .begin_retire_backing(storage.backing)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            catalog.resolve_body(0x1008),
            Err(ProviderLocalEventError::DeletePending)
        );
        assert_eq!(
            catalog.initialize(
                0x1008,
                pool(11, 2, 8),
                ProviderEventKind::Notification,
                true
            ),
            Err(ProviderLocalEventError::AddressInUse)
        );
        catalog.ack_retirement(retirement).unwrap();

        let second = catalog
            .initialize(
                0x1008,
                pool(11, 2, 8),
                ProviderEventKind::Notification,
                true,
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            catalog.snapshot(first),
            Err(ProviderLocalEventError::StaleIdentity)
        );
    }

    #[test]
    fn wait_and_signal_leases_fence_backing_retirement() {
        let mut catalog = ProviderLocalEventCatalog::new(provider()).unwrap();
        let storage = pool(12, 4, 0);
        let id = catalog
            .initialize(0x2000, storage, ProviderEventKind::Synchronization, false)
            .unwrap();
        catalog.bind_canonical(id, canonical(6, 1)).unwrap();
        catalog
            .acquire_lease(id, ProviderLocalEventLeaseKind::Wait)
            .unwrap();
        catalog
            .acquire_lease(id, ProviderLocalEventLeaseKind::Signal)
            .unwrap();
        assert_eq!(
            catalog.begin_retire_backing(storage.backing),
            Err(ProviderLocalEventError::ActiveLeases)
        );
        catalog
            .release_lease(id, ProviderLocalEventLeaseKind::Wait)
            .unwrap();
        assert_eq!(
            catalog.begin_retire_backing(storage.backing),
            Err(ProviderLocalEventError::ActiveLeases)
        );
        catalog
            .release_lease(id, ProviderLocalEventLeaseKind::Signal)
            .unwrap();
        assert_eq!(
            catalog.begin_retire_backing(storage.backing).unwrap().len(),
            1
        );
    }

    #[test]
    fn a_backing_with_multiple_events_retires_atomically() {
        let mut catalog = ProviderLocalEventCatalog::new(provider()).unwrap();
        let first_storage = pool(13, 1, 0x20);
        let second_storage = pool(13, 1, 0x60);
        let first = catalog
            .initialize(
                0x3020,
                first_storage,
                ProviderEventKind::Notification,
                false,
            )
            .unwrap();
        let second = catalog
            .initialize(
                0x3060,
                second_storage,
                ProviderEventKind::Synchronization,
                false,
            )
            .unwrap();
        catalog.bind_canonical(first, canonical(7, 1)).unwrap();
        catalog.bind_canonical(second, canonical(8, 1)).unwrap();
        catalog
            .acquire_lease(second, ProviderLocalEventLeaseKind::Wait)
            .unwrap();
        assert_eq!(
            catalog.begin_retire_backing(first_storage.backing),
            Err(ProviderLocalEventError::ActiveLeases)
        );
        assert!(!catalog.snapshot(first).unwrap().delete_pending);
        catalog
            .release_lease(second, ProviderLocalEventLeaseKind::Wait)
            .unwrap();
        let retirements = catalog.begin_retire_backing(first_storage.backing).unwrap();
        assert_eq!(retirements.len(), 2);
        assert!(catalog.snapshot(first).unwrap().delete_pending);
        assert!(catalog.snapshot(second).unwrap().delete_pending);
    }

    #[test]
    fn stack_activation_and_static_instance_generations_are_exact() {
        let mut catalog = ProviderLocalEventCatalog::new(provider()).unwrap();
        let stack = ProviderEventStorage {
            backing: ProviderEventBacking::Stack {
                dispatch_id: 41,
                activation_generation: 2,
            },
            offset: 0x18,
        };
        let id = catalog
            .initialize(0x4018, stack, ProviderEventKind::Notification, false)
            .unwrap();
        catalog.bind_canonical(id, canonical(9, 1)).unwrap();
        assert_eq!(catalog.resolve_body(0x4018).unwrap().storage, stack);

        let invalid_static = ProviderEventStorage {
            backing: ProviderEventBacking::Static {
                instance_generation: provider().generation + 1,
            },
            offset: 0x80,
        };
        assert_eq!(
            catalog.initialize(
                0x5080,
                invalid_static,
                ProviderEventKind::Notification,
                false
            ),
            Err(ProviderLocalEventError::InvalidStorage)
        );
    }

    #[test]
    fn publication_is_typed_unique_and_rollback_is_exact() {
        let mut catalog = ProviderLocalEventCatalog::new(provider()).unwrap();
        let first = catalog
            .initialize(
                0x6000,
                pool(20, 1, 0),
                ProviderEventKind::Notification,
                false,
            )
            .unwrap();
        let second = catalog
            .initialize(
                0x7000,
                pool(21, 1, 0),
                ProviderEventKind::Notification,
                false,
            )
            .unwrap();
        assert_eq!(
            catalog.resolve_body(0x6000),
            Err(ProviderLocalEventError::NotPublished)
        );
        catalog.bind_canonical(first, canonical(10, 1)).unwrap();
        assert_eq!(
            catalog.bind_canonical(second, canonical(10, 1)),
            Err(ProviderLocalEventError::CanonicalIdentityInUse)
        );
        catalog.rollback_unpublished(second).unwrap();
        assert_eq!(
            catalog.snapshot(second),
            Err(ProviderLocalEventError::StaleIdentity)
        );
    }
}
