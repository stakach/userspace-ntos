use alloc::vec::Vec;

use nt_time::{Deadline, TimeSnapshot};

use crate::{
    ProviderAllocationCatalog, ProviderAllocationIdentity, ProviderDomainIdentity,
    ProviderEventBacking, ProviderEventStorage, ProviderWaitObject, ProviderWaitObjectType,
    ProviderWaitOwner,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderTimerKind {
    Notification,
    Synchronization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderTimerError {
    InvalidProvider,
    InvalidIdentity,
    InvalidStorage,
    AddressInUse,
    StorageInUse,
    LocalIdentityInUse,
    CanonicalIdentityInUse,
    AlreadyPublished,
    NotPublished,
    NotFound,
    StaleIdentity,
    DeletePending,
    ActiveLeases,
    LeaseOverflow,
    LeaseUnderflow,
    WrongLease,
    RetirementMismatch,
    IdentityExhausted,
    NoCapacity,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalTimerId(u64);

impl ProviderLocalTimerId {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    fn new(slot: usize, generation: u32) -> Result<Self, ProviderTimerError> {
        let slot = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(ProviderTimerError::IdentityExhausted)?;
        if generation == 0 {
            return Err(ProviderTimerError::IdentityExhausted);
        }
        Ok(Self((u64::from(generation) << 32) | u64::from(slot)))
    }

    fn parts(self) -> Option<(usize, u32)> {
        let slot = (self.0 as u32).checked_sub(1)? as usize;
        let generation = (self.0 >> 32) as u32;
        (generation != 0).then_some((slot, generation))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalTimerSnapshot {
    pub id: ProviderLocalTimerId,
    pub body: u64,
    pub storage: ProviderEventStorage,
    pub kind: ProviderTimerKind,
    pub canonical: Option<ProviderWaitObject>,
    pub delete_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLocalTimerRetirement {
    pub id: ProviderLocalTimerId,
    pub canonical: ProviderWaitObject,
}

#[derive(Clone, Copy)]
struct LocalTimerRecord {
    generation: u32,
    live: bool,
    body: u64,
    storage: ProviderEventStorage,
    kind: ProviderTimerKind,
    canonical: Option<ProviderWaitObject>,
    delete_pending: bool,
}

impl LocalTimerRecord {
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
        kind: ProviderTimerKind::Notification,
        canonical: None,
        delete_pending: false,
    };

    fn snapshot(self, slot: usize) -> ProviderLocalTimerSnapshot {
        ProviderLocalTimerSnapshot {
            id: ProviderLocalTimerId::new(slot, self.generation).unwrap(),
            body: self.body,
            storage: self.storage,
            kind: self.kind,
            canonical: self.canonical,
            delete_pending: self.delete_pending,
        }
    }
}

/// Component-private ownership for embedded `KTIMER` storage.
///
/// Provider virtual addresses remain local. Only the minted local identity and the executive's
/// canonical Timer identity cross the isolation boundary.
pub struct ProviderLocalTimerCatalog {
    provider: ProviderDomainIdentity,
    records: Vec<LocalTimerRecord>,
}

impl ProviderLocalTimerCatalog {
    pub fn new(provider: ProviderDomainIdentity) -> Result<Self, ProviderTimerError> {
        if !provider.is_valid() {
            return Err(ProviderTimerError::InvalidProvider);
        }
        Ok(Self {
            provider,
            records: Vec::new(),
        })
    }

    fn initialize(
        &mut self,
        body: u64,
        storage: ProviderEventStorage,
        kind: ProviderTimerKind,
    ) -> Result<ProviderLocalTimerId, ProviderTimerError> {
        if body == 0 || !storage.backing.is_valid(self.provider) {
            return Err(ProviderTimerError::InvalidStorage);
        }
        if self
            .records
            .iter()
            .any(|record| record.live && record.body == body)
        {
            return Err(ProviderTimerError::AddressInUse);
        }
        if self
            .records
            .iter()
            .any(|record| record.live && record.storage == storage)
        {
            return Err(ProviderTimerError::StorageInUse);
        }
        let slot = if let Some(slot) = self.records.iter().position(|record| !record.live) {
            slot
        } else {
            self.records
                .try_reserve(1)
                .map_err(|_| ProviderTimerError::NoCapacity)?;
            self.records.push(LocalTimerRecord::EMPTY);
            self.records.len() - 1
        };
        let generation = self.records[slot]
            .generation
            .checked_add(1)
            .ok_or(ProviderTimerError::IdentityExhausted)?;
        let id = ProviderLocalTimerId::new(slot, generation)?;
        self.records[slot] = LocalTimerRecord {
            generation,
            live: true,
            body,
            storage,
            kind,
            canonical: None,
            delete_pending: false,
        };
        Ok(id)
    }

    pub fn initialize_static(
        &mut self,
        body: u64,
        offset: u64,
        kind: ProviderTimerKind,
    ) -> Result<ProviderLocalTimerId, ProviderTimerError> {
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
        kind: ProviderTimerKind,
    ) -> Result<ProviderLocalTimerId, ProviderTimerError> {
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
        kind: ProviderTimerKind,
    ) -> Result<ProviderLocalTimerId, ProviderTimerError> {
        let allocation = allocations
            .snapshot(allocation_identity)
            .map_err(|_| ProviderTimerError::InvalidStorage)?;
        let offset = allocation
            .offset_of(body)
            .ok_or(ProviderTimerError::InvalidStorage)?;
        if storage_bytes == 0
            || body
                .checked_add(storage_bytes)
                .is_none_or(|end| end > allocation.base + allocation.capacity)
        {
            return Err(ProviderTimerError::InvalidStorage);
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

    pub fn bind_canonical(
        &mut self,
        id: ProviderLocalTimerId,
        canonical: ProviderWaitObject,
    ) -> Result<(), ProviderTimerError> {
        if canonical.typed() != Some(ProviderWaitObjectType::Timer)
            || canonical.object_id == 0
            || canonical.object_generation == 0
        {
            return Err(ProviderTimerError::NotPublished);
        }
        let slot = self.slot(id)?;
        if self.records[slot].delete_pending {
            return Err(ProviderTimerError::DeletePending);
        }
        if let Some(existing) = self.records[slot].canonical {
            return if existing == canonical {
                Ok(())
            } else {
                Err(ProviderTimerError::AlreadyPublished)
            };
        }
        if self.records.iter().enumerate().any(|(index, record)| {
            index != slot && record.live && record.canonical == Some(canonical)
        }) {
            return Err(ProviderTimerError::CanonicalIdentityInUse);
        }
        self.records[slot].canonical = Some(canonical);
        Ok(())
    }

    pub fn resolve_body(
        &self,
        body: u64,
    ) -> Result<ProviderLocalTimerSnapshot, ProviderTimerError> {
        let (slot, record) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.body == body)
            .ok_or(ProviderTimerError::NotFound)?;
        if record.delete_pending {
            return Err(ProviderTimerError::DeletePending);
        }
        if record.canonical.is_none() {
            return Err(ProviderTimerError::NotPublished);
        }
        Ok(record.snapshot(slot))
    }

    pub fn snapshot_for_body(
        &self,
        body: u64,
    ) -> Result<ProviderLocalTimerSnapshot, ProviderTimerError> {
        let (slot, record) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.body == body)
            .ok_or(ProviderTimerError::NotFound)?;
        Ok(record.snapshot(slot))
    }

    pub fn rollback_unpublished(
        &mut self,
        id: ProviderLocalTimerId,
    ) -> Result<(), ProviderTimerError> {
        let slot = self.slot(id)?;
        if self.records[slot].canonical.is_some() || self.records[slot].delete_pending {
            return Err(ProviderTimerError::AlreadyPublished);
        }
        self.records[slot].live = false;
        Ok(())
    }

    pub fn begin_retire(
        &mut self,
        id: ProviderLocalTimerId,
    ) -> Result<ProviderLocalTimerRetirement, ProviderTimerError> {
        let slot = self.slot(id)?;
        let canonical = self.records[slot]
            .canonical
            .ok_or(ProviderTimerError::NotPublished)?;
        self.records[slot].delete_pending = true;
        Ok(ProviderLocalTimerRetirement { id, canonical })
    }

    pub fn ack_retirement(
        &mut self,
        retirement: ProviderLocalTimerRetirement,
    ) -> Result<(), ProviderTimerError> {
        let slot = self.slot(retirement.id)?;
        let record = &mut self.records[slot];
        if !record.delete_pending || record.canonical != Some(retirement.canonical) {
            return Err(ProviderTimerError::RetirementMismatch);
        }
        record.live = false;
        record.canonical = None;
        record.delete_pending = false;
        Ok(())
    }

    fn slot(&self, id: ProviderLocalTimerId) -> Result<usize, ProviderTimerError> {
        let (slot, generation) = id.parts().ok_or(ProviderTimerError::StaleIdentity)?;
        self.records
            .get(slot)
            .filter(|record| record.live && record.generation == generation)
            .map(|_| slot)
            .ok_or(ProviderTimerError::StaleIdentity)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTimerId(u64);

impl ProviderTimerId {
    fn new(slot: usize, generation: u32) -> Result<Self, ProviderTimerError> {
        ProviderLocalTimerId::new(slot, generation).map(|id| Self(id.raw()))
    }

    fn parts(self) -> Option<(usize, u32)> {
        ProviderLocalTimerId::from_raw(self.0).parts()
    }

    pub fn wait_object(self) -> ProviderWaitObject {
        let (slot, generation) = self.parts().expect("live Timer identity must decode");
        ProviderWaitObject::new(
            ProviderWaitObjectType::Timer,
            slot as u64 + 1,
            u64::from(generation),
        )
    }

    pub fn from_wait_object(object: ProviderWaitObject) -> Option<Self> {
        if object.typed() != Some(ProviderWaitObjectType::Timer) {
            return None;
        }
        let slot = usize::try_from(object.object_id.checked_sub(1)?).ok()?;
        let generation = u32::try_from(object.object_generation).ok()?;
        Self::new(slot, generation).ok()
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTimerLeaseId(u64);

impl ProviderTimerLeaseId {
    fn new(slot: usize, generation: u32) -> Result<Self, ProviderTimerError> {
        ProviderLocalTimerId::new(slot, generation).map(|id| Self(id.raw()))
    }

    fn parts(self) -> Option<(usize, u32)> {
        ProviderLocalTimerId::from_raw(self.0).parts()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTimerRetirement {
    pub id: ProviderTimerId,
    pub local_identity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTimerExpiration {
    pub id: ProviderTimerId,
    pub local_identity: u64,
}

#[derive(Clone, Copy)]
struct TimerRecord {
    generation: u32,
    live: bool,
    local_identity: u64,
    kind: ProviderTimerKind,
    deadline: Deadline,
    period_100ns: u64,
    signaled: bool,
    delete_pending: bool,
    wait_leases: u32,
}

impl TimerRecord {
    const EMPTY: Self = Self {
        generation: 0,
        live: false,
        local_identity: 0,
        kind: ProviderTimerKind::Notification,
        deadline: Deadline::Infinite,
        period_100ns: 0,
        signaled: false,
        delete_pending: false,
        wait_leases: 0,
    };
}

#[derive(Clone, Copy)]
struct TimerLease {
    generation: u32,
    live: bool,
    timer: ProviderTimerId,
}

impl TimerLease {
    const EMPTY: Self = Self {
        generation: 0,
        live: false,
        timer: ProviderTimerId(0),
    };
}

/// Executive-owned provider Timer identities and dispatcher state.
pub struct ProviderTimerTable {
    provider: ProviderDomainIdentity,
    timers: Vec<TimerRecord>,
    leases: Vec<TimerLease>,
}

impl ProviderTimerTable {
    pub fn new(provider: ProviderDomainIdentity) -> Result<Self, ProviderTimerError> {
        if !provider.is_valid() {
            return Err(ProviderTimerError::InvalidProvider);
        }
        Ok(Self {
            provider,
            timers: Vec::new(),
            leases: Vec::new(),
        })
    }

    pub fn publish(
        &mut self,
        local_identity: u64,
        kind: ProviderTimerKind,
    ) -> Result<ProviderTimerId, ProviderTimerError> {
        if local_identity == 0 {
            return Err(ProviderTimerError::InvalidIdentity);
        }
        if self
            .timers
            .iter()
            .any(|timer| timer.live && timer.local_identity == local_identity)
        {
            return Err(ProviderTimerError::LocalIdentityInUse);
        }
        let slot = if let Some(slot) = self.timers.iter().position(|timer| !timer.live) {
            slot
        } else {
            self.timers
                .try_reserve(1)
                .map_err(|_| ProviderTimerError::NoCapacity)?;
            self.timers.push(TimerRecord::EMPTY);
            self.timers.len() - 1
        };
        let generation = self.timers[slot]
            .generation
            .checked_add(1)
            .ok_or(ProviderTimerError::IdentityExhausted)?;
        let id = ProviderTimerId::new(slot, generation)?;
        self.timers[slot] = TimerRecord {
            generation,
            live: true,
            local_identity,
            kind,
            ..TimerRecord::EMPTY
        };
        Ok(id)
    }

    pub fn id_for_local(&self, local_identity: u64) -> Option<ProviderTimerId> {
        self.timers
            .iter()
            .enumerate()
            .find(|(_, timer)| timer.live && timer.local_identity == local_identity)
            .and_then(|(slot, timer)| ProviderTimerId::new(slot, timer.generation).ok())
    }

    pub fn set_local(
        &mut self,
        local_identity: u64,
        due_time_100ns: i64,
        period_ms: u32,
        now: TimeSnapshot,
    ) -> Result<bool, ProviderTimerError> {
        let id = self
            .id_for_local(local_identity)
            .ok_or(ProviderTimerError::NotFound)?;
        let slot = self.slot(id)?;
        let timer = &mut self.timers[slot];
        if timer.delete_pending {
            return Err(ProviderTimerError::DeletePending);
        }
        let was_active = timer.deadline != Deadline::Infinite;
        timer.deadline = Deadline::from_nt_timeout(Some(due_time_100ns), now);
        timer.period_100ns = u64::from(period_ms).saturating_mul(10_000);
        timer.signaled = false;
        Ok(was_active)
    }

    pub fn cancel_local(&mut self, local_identity: u64) -> Result<bool, ProviderTimerError> {
        let id = self
            .id_for_local(local_identity)
            .ok_or(ProviderTimerError::NotFound)?;
        let slot = self.slot(id)?;
        let timer = &mut self.timers[slot];
        if timer.delete_pending {
            return Err(ProviderTimerError::DeletePending);
        }
        let was_active = timer.deadline != Deadline::Infinite;
        timer.deadline = Deadline::Infinite;
        timer.period_100ns = 0;
        Ok(was_active)
    }

    pub fn read_state(&self, id: ProviderTimerId) -> Result<bool, ProviderTimerError> {
        self.slot(id).map(|slot| self.timers[slot].signaled)
    }

    pub fn acquire_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<ProviderTimerLeaseId, ProviderTimerError> {
        if owner.provider_domain != self.provider.domain
            || owner.provider_generation != self.provider.generation
        {
            return Err(ProviderTimerError::InvalidProvider);
        }
        let id =
            ProviderTimerId::from_wait_object(object).ok_or(ProviderTimerError::InvalidIdentity)?;
        let timer_slot = self.slot(id)?;
        if self.timers[timer_slot].delete_pending {
            return Err(ProviderTimerError::DeletePending);
        }
        let lease_slot = if let Some(slot) = self.leases.iter().position(|lease| !lease.live) {
            slot
        } else {
            self.leases
                .try_reserve(1)
                .map_err(|_| ProviderTimerError::NoCapacity)?;
            self.leases.push(TimerLease::EMPTY);
            self.leases.len() - 1
        };
        let generation = self.leases[lease_slot]
            .generation
            .checked_add(1)
            .ok_or(ProviderTimerError::IdentityExhausted)?;
        let lease = ProviderTimerLeaseId::new(lease_slot, generation)?;
        self.timers[timer_slot].wait_leases = self.timers[timer_slot]
            .wait_leases
            .checked_add(1)
            .ok_or(ProviderTimerError::LeaseOverflow)?;
        self.leases[lease_slot] = TimerLease {
            generation,
            live: true,
            timer: id,
        };
        Ok(lease)
    }

    pub fn is_ready(&self, lease: ProviderTimerLeaseId) -> Result<bool, ProviderTimerError> {
        let timer = self.timer_for_lease(lease)?;
        self.read_state(timer)
    }

    pub fn consume_ready(&mut self, lease: ProviderTimerLeaseId) -> Result<(), ProviderTimerError> {
        let timer = self.timer_for_lease(lease)?;
        let slot = self.slot(timer)?;
        if !self.timers[slot].signaled {
            return Err(ProviderTimerError::InvalidIdentity);
        }
        if self.timers[slot].kind == ProviderTimerKind::Synchronization {
            self.timers[slot].signaled = false;
        }
        Ok(())
    }

    pub fn release_wait(
        &mut self,
        lease: ProviderTimerLeaseId,
    ) -> Result<Option<ProviderTimerRetirement>, ProviderTimerError> {
        let (lease_slot, generation) = lease.parts().ok_or(ProviderTimerError::WrongLease)?;
        let lease_record = self
            .leases
            .get(lease_slot)
            .copied()
            .filter(|record| record.live && record.generation == generation)
            .ok_or(ProviderTimerError::WrongLease)?;
        let timer_slot = self.slot(lease_record.timer)?;
        self.leases[lease_slot].live = false;
        self.timers[timer_slot].wait_leases = self.timers[timer_slot]
            .wait_leases
            .checked_sub(1)
            .ok_or(ProviderTimerError::LeaseUnderflow)?;
        Ok(self.ready_retirement(timer_slot))
    }

    pub fn request_retire_local(
        &mut self,
        local_identity: u64,
    ) -> Result<Option<ProviderTimerRetirement>, ProviderTimerError> {
        let id = self
            .id_for_local(local_identity)
            .ok_or(ProviderTimerError::NotFound)?;
        let slot = self.slot(id)?;
        let timer = &mut self.timers[slot];
        timer.delete_pending = true;
        timer.deadline = Deadline::Infinite;
        timer.period_100ns = 0;
        Ok(self.ready_retirement(slot))
    }

    pub fn ack_retirement(
        &mut self,
        retirement: ProviderTimerRetirement,
    ) -> Result<(), ProviderTimerError> {
        let slot = self.slot(retirement.id)?;
        let timer = &mut self.timers[slot];
        if !timer.delete_pending
            || timer.wait_leases != 0
            || timer.local_identity != retirement.local_identity
        {
            return Err(ProviderTimerError::RetirementMismatch);
        }
        timer.live = false;
        timer.local_identity = 0;
        timer.signaled = false;
        timer.delete_pending = false;
        Ok(())
    }

    pub fn next_deadline(&self, now: TimeSnapshot) -> Option<u64> {
        self.timers
            .iter()
            .filter(|timer| timer.live && !timer.delete_pending)
            .filter_map(|timer| timer.deadline.monotonic_target(now))
            .min()
    }

    pub fn expire_next_due(&mut self, now: TimeSnapshot) -> Option<ProviderTimerExpiration> {
        let slot = self
            .timers
            .iter()
            .enumerate()
            .filter(|(_, timer)| timer.live && !timer.delete_pending && timer.deadline.is_due(now))
            .min_by_key(|(_, timer)| timer.deadline.ordering_key(now))
            .map(|(slot, _)| slot)?;
        let id = ProviderTimerId::new(slot, self.timers[slot].generation).ok()?;
        let timer = &mut self.timers[slot];
        timer.signaled = true;
        timer.deadline = if timer.period_100ns == 0 {
            Deadline::Infinite
        } else {
            Deadline::Relative {
                monotonic_100ns: now.monotonic_100ns.saturating_add(timer.period_100ns),
            }
        };
        Some(ProviderTimerExpiration {
            id,
            local_identity: timer.local_identity,
        })
    }

    fn ready_retirement(&self, slot: usize) -> Option<ProviderTimerRetirement> {
        let timer = self.timers.get(slot)?;
        (timer.live && timer.delete_pending && timer.wait_leases == 0).then(|| {
            ProviderTimerRetirement {
                id: ProviderTimerId::new(slot, timer.generation).unwrap(),
                local_identity: timer.local_identity,
            }
        })
    }

    fn slot(&self, id: ProviderTimerId) -> Result<usize, ProviderTimerError> {
        let (slot, generation) = id.parts().ok_or(ProviderTimerError::StaleIdentity)?;
        self.timers
            .get(slot)
            .filter(|timer| timer.live && timer.generation == generation)
            .map(|_| slot)
            .ok_or(ProviderTimerError::StaleIdentity)
    }

    fn timer_for_lease(
        &self,
        lease: ProviderTimerLeaseId,
    ) -> Result<ProviderTimerId, ProviderTimerError> {
        let (slot, generation) = lease.parts().ok_or(ProviderTimerError::WrongLease)?;
        self.leases
            .get(slot)
            .filter(|record| record.live && record.generation == generation)
            .map(|record| record.timer)
            .ok_or(ProviderTimerError::WrongLease)
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

    fn owner() -> ProviderWaitOwner {
        ProviderWaitOwner {
            provider_domain: 7,
            provider_generation: 3,
            client_pi: 2,
            client_generation: 4,
            client_tid: 24,
            client_badge: 9,
            dispatch_id: 11,
        }
    }

    fn now(monotonic_100ns: u64) -> TimeSnapshot {
        TimeSnapshot {
            monotonic_100ns,
            system_time_100ns: 1_000_000 + monotonic_100ns,
            clock_generation: 0,
        }
    }

    #[test]
    fn local_catalog_keeps_provider_addresses_out_of_canonical_identity() {
        let mut catalog = ProviderLocalTimerCatalog::new(provider()).unwrap();
        let id = catalog
            .initialize_static(0x1000, 0x80, ProviderTimerKind::Notification)
            .unwrap();
        assert_eq!(
            catalog.resolve_body(0x1000),
            Err(ProviderTimerError::NotPublished)
        );
        let canonical = ProviderWaitObject::new(ProviderWaitObjectType::Timer, 9, 2);
        catalog.bind_canonical(id, canonical).unwrap();
        let snapshot = catalog.resolve_body(0x1000).unwrap();
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.canonical, Some(canonical));
        assert_ne!(snapshot.body, canonical.object_id);
    }

    #[test]
    fn local_retirement_is_generation_exact() {
        let mut catalog = ProviderLocalTimerCatalog::new(provider()).unwrap();
        let first = catalog
            .initialize_static(0x1000, 0x80, ProviderTimerKind::Notification)
            .unwrap();
        let canonical = ProviderWaitObject::new(ProviderWaitObjectType::Timer, 1, 1);
        catalog.bind_canonical(first, canonical).unwrap();
        let retirement = catalog.begin_retire(first).unwrap();
        catalog.ack_retirement(retirement).unwrap();
        let second = catalog
            .initialize_static(0x1000, 0x80, ProviderTimerKind::Synchronization)
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            catalog.bind_canonical(first, canonical),
            Err(ProviderTimerError::StaleIdentity)
        );
    }

    #[test]
    fn notification_and_synchronization_timers_consume_correctly() {
        let mut table = ProviderTimerTable::new(provider()).unwrap();
        let notification = table.publish(1, ProviderTimerKind::Notification).unwrap();
        let synchronization = table
            .publish(2, ProviderTimerKind::Synchronization)
            .unwrap();
        table.set_local(1, -100, 0, now(10)).unwrap();
        table.set_local(2, -100, 0, now(10)).unwrap();
        assert_eq!(table.next_deadline(now(10)), Some(110));
        assert_eq!(table.expire_next_due(now(110)).unwrap().id, notification);
        assert_eq!(table.expire_next_due(now(110)).unwrap().id, synchronization);

        let notification_lease = table
            .acquire_wait(owner(), notification.wait_object())
            .unwrap();
        let synchronization_lease = table
            .acquire_wait(owner(), synchronization.wait_object())
            .unwrap();
        table.consume_ready(notification_lease).unwrap();
        table.consume_ready(synchronization_lease).unwrap();
        assert!(table.read_state(notification).unwrap());
        assert!(!table.read_state(synchronization).unwrap());
    }

    #[test]
    fn periodic_timer_rearms_from_the_expiration_snapshot() {
        let mut table = ProviderTimerTable::new(provider()).unwrap();
        let id = table.publish(1, ProviderTimerKind::Notification).unwrap();
        assert!(!table.set_local(1, -50, 2, now(100)).unwrap());
        assert!(table.set_local(1, -50, 2, now(100)).unwrap());
        assert_eq!(table.expire_next_due(now(150)).unwrap().id, id);
        assert_eq!(table.next_deadline(now(150)), Some(20_150));
        assert!(table.cancel_local(1).unwrap());
        assert_eq!(table.next_deadline(now(105)), None);
    }

    #[test]
    fn active_wait_lease_defers_exact_retirement() {
        let mut table = ProviderTimerTable::new(provider()).unwrap();
        let id = table.publish(1, ProviderTimerKind::Notification).unwrap();
        let lease = table.acquire_wait(owner(), id.wait_object()).unwrap();
        assert_eq!(table.request_retire_local(1).unwrap(), None);
        let retirement = table.release_wait(lease).unwrap().unwrap();
        assert_eq!(retirement.id, id);
        table.ack_retirement(retirement).unwrap();
        assert_eq!(table.read_state(id), Err(ProviderTimerError::StaleIdentity));
    }

    #[test]
    fn wrong_provider_and_stale_lease_fail_closed() {
        let mut table = ProviderTimerTable::new(provider()).unwrap();
        let id = table.publish(1, ProviderTimerKind::Notification).unwrap();
        let mut wrong = owner();
        wrong.provider_generation += 1;
        assert_eq!(
            table.acquire_wait(wrong, id.wait_object()),
            Err(ProviderTimerError::InvalidProvider)
        );
        let lease = table.acquire_wait(owner(), id.wait_object()).unwrap();
        table.release_wait(lease).unwrap();
        assert_eq!(
            table.release_wait(lease),
            Err(ProviderTimerError::WrongLease)
        );
    }
}
