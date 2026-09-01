//! Generation-fenced ownership for executive Event objects projected into a kernel provider.
//!
//! An NT Event has one canonical executive identity. Process handles, provider object pointers,
//! native waits, GUI waits, and queued cross-component signals are independent references to that
//! identity. Raw provider pointers are projection data only: they are never used as object ids.

use alloc::vec::Vec;

use nt_types::{Generation, ObjectId};

/// Canonical identity of one executive Event object.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EventObjectId(pub ObjectId);

impl EventObjectId {
    pub const NULL: Self = Self(ObjectId::NULL);

    pub const fn is_null(self) -> bool {
        self.0.is_null()
    }
}

/// Unique ownership token for one parked wait. Releasing a stale or already-released token fails.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EventLeaseId(pub ObjectId);

impl EventLeaseId {
    pub const NULL: Self = Self(ObjectId::NULL);

    pub const fn is_null(self) -> bool {
        self.0.is_null()
    }
}

/// Process generation that created the object. Handles may subsequently be duplicated elsewhere;
/// this remains immutable provenance and prevents a recycled process slot from claiming the object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventObjectOwner {
    pub process_id: u64,
    pub process_generation: u64,
}

impl EventObjectOwner {
    pub const fn new(process_id: u64, process_generation: u64) -> Self {
        Self {
            process_id,
            process_generation,
        }
    }

    const fn is_valid(self) -> bool {
        self.process_id != 0 && self.process_generation != 0
    }
}

/// Wait references need unique lease tokens so timeout, cancellation, wake, and publication
/// rollback can each prove they release exactly the reference they acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLeaseKind {
    NativeWait,
    GuiWait,
}

/// Why a registry operation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventObjectError {
    InvalidOwner,
    InvalidNativeIdentity,
    InvalidProviderBody,
    StaleObject,
    StaleLease,
    WrongLeaseKind,
    ProviderBodyInUse,
    NativeIdentityInUse,
    ReferenceOverflow,
    OutOfMemory,
    SignalNotDelivering,
}

/// State useful to the executive's lifetime diagnostics and acceptance gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventObjectSnapshot {
    pub id: EventObjectId,
    pub owner: EventObjectOwner,
    pub native_identity: u64,
    pub provider_body: Option<u64>,
    pub delete_pending: bool,
    pub handle_leases: u32,
    pub pointer_leases: u32,
    pub native_wait_leases: u32,
    pub gui_wait_leases: u32,
    pub signal_leases: u32,
}

/// Resources returned to the executive only after deletion is requested and every lease drains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredEventObject {
    pub id: EventObjectId,
    pub owner: EventObjectOwner,
    pub native_identity: u64,
    pub provider_body: Option<u64>,
}

/// Result of the non-allocating signal enqueue operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalQueueResult {
    Queued,
    Coalesced,
}

/// One signal selected for delivery. The signal lease remains held until
/// [`EventObjectRegistry::complete_signal`] succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingEventSignal {
    pub id: EventObjectId,
    pub native_identity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalState {
    None,
    Queued(u64),
    Delivering(u64),
}

#[derive(Clone, Copy, Debug)]
struct EventRecord {
    generation: Generation,
    live: bool,
    owner: EventObjectOwner,
    native_identity: u64,
    provider_body: Option<u64>,
    delete_pending: bool,
    handle_leases: u32,
    pointer_leases: u32,
    native_wait_leases: u32,
    gui_wait_leases: u32,
    signal: SignalState,
}

impl EventRecord {
    const EMPTY: Self = Self {
        generation: Generation(0),
        live: false,
        owner: EventObjectOwner::new(0, 0),
        native_identity: 0,
        provider_body: None,
        delete_pending: false,
        handle_leases: 0,
        pointer_leases: 0,
        native_wait_leases: 0,
        gui_wait_leases: 0,
        signal: SignalState::None,
    };

    fn total_leases(self) -> u64 {
        u64::from(self.handle_leases)
            + u64::from(self.pointer_leases)
            + u64::from(self.native_wait_leases)
            + u64::from(self.gui_wait_leases)
            + u64::from(!matches!(self.signal, SignalState::None))
    }

    fn snapshot(self, slot: usize) -> EventObjectSnapshot {
        EventObjectSnapshot {
            id: EventObjectId(ObjectId::new(self.generation, slot as u64)),
            owner: self.owner,
            native_identity: self.native_identity,
            provider_body: self.provider_body,
            delete_pending: self.delete_pending,
            handle_leases: self.handle_leases,
            pointer_leases: self.pointer_leases,
            native_wait_leases: self.native_wait_leases,
            gui_wait_leases: self.gui_wait_leases,
            signal_leases: u32::from(!matches!(self.signal, SignalState::None)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LeaseRecord {
    generation: Generation,
    live: bool,
    event: EventObjectId,
    kind: EventLeaseKind,
}

impl LeaseRecord {
    const EMPTY: Self = Self {
        generation: Generation(0),
        live: false,
        event: EventObjectId::NULL,
        kind: EventLeaseKind::NativeWait,
    };
}

/// Growable Event object registry with generation-exact wait leases.
#[derive(Default)]
pub struct EventObjectRegistry {
    events: Vec<EventRecord>,
    leases: Vec<LeaseRecord>,
    next_signal_sequence: u64,
}

impl EventObjectRegistry {
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            leases: Vec::new(),
            next_signal_sequence: 1,
        }
    }

    pub fn with_capacity(events: usize, leases: usize) -> Self {
        Self {
            events: Vec::with_capacity(events),
            leases: Vec::with_capacity(leases),
            next_signal_sequence: 1,
        }
    }

    fn event_slot(&self, id: EventObjectId) -> Result<usize, EventObjectError> {
        if id.is_null() {
            return Err(EventObjectError::StaleObject);
        }
        let slot = usize::try_from(id.0.slot()).map_err(|_| EventObjectError::StaleObject)?;
        let record = self.events.get(slot).ok_or(EventObjectError::StaleObject)?;
        if !record.live || record.generation != id.0.generation() {
            return Err(EventObjectError::StaleObject);
        }
        Ok(slot)
    }

    fn lease_slot(&self, id: EventLeaseId) -> Result<usize, EventObjectError> {
        if id.is_null() {
            return Err(EventObjectError::StaleLease);
        }
        let slot = usize::try_from(id.0.slot()).map_err(|_| EventObjectError::StaleLease)?;
        let record = self.leases.get(slot).ok_or(EventObjectError::StaleLease)?;
        if !record.live || record.generation != id.0.generation() {
            return Err(EventObjectError::StaleLease);
        }
        Ok(slot)
    }

    fn allocate_event_slot(&mut self) -> Result<(usize, Generation), EventObjectError> {
        if let Some(slot) = self.events.iter().position(|record| !record.live) {
            return Ok((slot, self.events[slot].generation.next()));
        }
        self.events
            .try_reserve(1)
            .map_err(|_| EventObjectError::OutOfMemory)?;
        let slot = self.events.len();
        self.events.push(EventRecord::EMPTY);
        Ok((slot, Generation(1)))
    }

    fn allocate_lease_slot(&mut self) -> Result<(usize, Generation), EventObjectError> {
        if let Some(slot) = self.leases.iter().position(|record| !record.live) {
            return Ok((slot, self.leases[slot].generation.next()));
        }
        self.leases
            .try_reserve(1)
            .map_err(|_| EventObjectError::OutOfMemory)?;
        let slot = self.leases.len();
        self.leases.push(LeaseRecord::EMPTY);
        Ok((slot, Generation(1)))
    }

    /// Register a canonical executive event. No lease is implied; publication acquires the handle
    /// lease explicitly so rollback can retire the unpublished object without guessing.
    pub fn create(
        &mut self,
        owner: EventObjectOwner,
        native_identity: u64,
    ) -> Result<EventObjectId, EventObjectError> {
        if !owner.is_valid() {
            return Err(EventObjectError::InvalidOwner);
        }
        if native_identity == 0 {
            return Err(EventObjectError::InvalidNativeIdentity);
        }
        if self
            .events
            .iter()
            .any(|record| record.live && record.native_identity == native_identity)
        {
            return Err(EventObjectError::NativeIdentityInUse);
        }
        let (slot, generation) = self.allocate_event_slot()?;
        self.events[slot] = EventRecord {
            generation,
            live: true,
            owner,
            native_identity,
            ..EventRecord::EMPTY
        };
        Ok(EventObjectId(ObjectId::new(generation, slot as u64)))
    }

    pub fn id_for_native(&self, native_identity: u64) -> Option<EventObjectId> {
        self.events
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.native_identity == native_identity)
            .map(|(slot, record)| EventObjectId(ObjectId::new(record.generation, slot as u64)))
    }

    pub fn id_for_provider_body(&self, body: u64) -> Option<EventObjectId> {
        self.events
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.provider_body == Some(body))
            .map(|(slot, record)| EventObjectId(ObjectId::new(record.generation, slot as u64)))
    }

    pub fn snapshot(&self, id: EventObjectId) -> Result<EventObjectSnapshot, EventObjectError> {
        let slot = self.event_slot(id)?;
        Ok(self.events[slot].snapshot(slot))
    }

    pub fn install_provider_body(
        &mut self,
        id: EventObjectId,
        body: u64,
    ) -> Result<(), EventObjectError> {
        if body == 0 {
            return Err(EventObjectError::InvalidProviderBody);
        }
        if self.events.iter().enumerate().any(|(slot, record)| {
            record.live && record.provider_body == Some(body) && self.event_slot(id) != Ok(slot)
        }) {
            return Err(EventObjectError::ProviderBodyInUse);
        }
        let slot = self.event_slot(id)?;
        match self.events[slot].provider_body {
            None => {
                self.events[slot].provider_body = Some(body);
                Ok(())
            }
            Some(existing) if existing == body => Ok(()),
            Some(_) => Err(EventObjectError::ProviderBodyInUse),
        }
    }

    pub fn provider_body(&self, id: EventObjectId) -> Result<Option<u64>, EventObjectError> {
        Ok(self.events[self.event_slot(id)?].provider_body)
    }

    fn increment(value: &mut u32) -> Result<(), EventObjectError> {
        *value = value
            .checked_add(1)
            .ok_or(EventObjectError::ReferenceOverflow)?;
        Ok(())
    }

    pub fn retain_handle(&mut self, id: EventObjectId) -> Result<(), EventObjectError> {
        let slot = self.event_slot(id)?;
        Self::increment(&mut self.events[slot].handle_leases)
    }

    pub fn release_handle(
        &mut self,
        id: EventObjectId,
    ) -> Result<Option<RetiredEventObject>, EventObjectError> {
        let slot = self.event_slot(id)?;
        let count = &mut self.events[slot].handle_leases;
        if *count == 0 {
            return Err(EventObjectError::StaleLease);
        }
        *count -= 1;
        Ok(self.try_retire(slot))
    }

    pub fn retain_pointer(&mut self, id: EventObjectId) -> Result<u64, EventObjectError> {
        let slot = self.event_slot(id)?;
        let body = self.events[slot]
            .provider_body
            .ok_or(EventObjectError::InvalidProviderBody)?;
        Self::increment(&mut self.events[slot].pointer_leases)?;
        Ok(body)
    }

    pub fn release_pointer_by_body(
        &mut self,
        body: u64,
    ) -> Result<Option<RetiredEventObject>, EventObjectError> {
        let id = self
            .id_for_provider_body(body)
            .ok_or(EventObjectError::InvalidProviderBody)?;
        let slot = self.event_slot(id)?;
        if self.events[slot].pointer_leases == 0 {
            return Err(EventObjectError::StaleLease);
        }
        self.events[slot].pointer_leases -= 1;
        Ok(self.try_retire(slot))
    }

    pub fn acquire_wait(
        &mut self,
        id: EventObjectId,
        kind: EventLeaseKind,
    ) -> Result<EventLeaseId, EventObjectError> {
        let event_slot = self.event_slot(id)?;
        let (lease_slot, generation) = self.allocate_lease_slot()?;
        match kind {
            EventLeaseKind::NativeWait => {
                if let Err(error) = Self::increment(&mut self.events[event_slot].native_wait_leases)
                {
                    self.leases[lease_slot].generation = generation;
                    return Err(error);
                }
            }
            EventLeaseKind::GuiWait => {
                if let Err(error) = Self::increment(&mut self.events[event_slot].gui_wait_leases) {
                    self.leases[lease_slot].generation = generation;
                    return Err(error);
                }
            }
        }
        self.leases[lease_slot] = LeaseRecord {
            generation,
            live: true,
            event: id,
            kind,
        };
        Ok(EventLeaseId(ObjectId::new(generation, lease_slot as u64)))
    }

    pub fn event_for_lease(
        &self,
        lease: EventLeaseId,
        expected: EventLeaseKind,
    ) -> Result<EventObjectId, EventObjectError> {
        let slot = self.lease_slot(lease)?;
        let record = self.leases[slot];
        if record.kind != expected {
            return Err(EventObjectError::WrongLeaseKind);
        }
        self.event_slot(record.event)?;
        Ok(record.event)
    }

    pub fn release_wait(
        &mut self,
        lease: EventLeaseId,
        expected: EventLeaseKind,
    ) -> Result<Option<RetiredEventObject>, EventObjectError> {
        let lease_slot = self.lease_slot(lease)?;
        let lease_record = self.leases[lease_slot];
        if lease_record.kind != expected {
            return Err(EventObjectError::WrongLeaseKind);
        }
        let event_slot = self.event_slot(lease_record.event)?;
        let count = match expected {
            EventLeaseKind::NativeWait => &mut self.events[event_slot].native_wait_leases,
            EventLeaseKind::GuiWait => &mut self.events[event_slot].gui_wait_leases,
        };
        if *count == 0 {
            return Err(EventObjectError::StaleLease);
        }
        *count -= 1;
        self.leases[lease_slot].live = false;
        Ok(self.try_retire(event_slot))
    }

    /// Non-allocating, coalescing signal enqueue. The embedded signal lease prevents object reuse
    /// until delivery completes or teardown explicitly cancels it.
    pub fn queue_signal(
        &mut self,
        id: EventObjectId,
    ) -> Result<SignalQueueResult, EventObjectError> {
        let slot = self.event_slot(id)?;
        if !matches!(self.events[slot].signal, SignalState::None) {
            return Ok(SignalQueueResult::Coalesced);
        }
        let sequence = self.next_signal_sequence.max(1);
        self.next_signal_sequence = sequence.wrapping_add(1).max(1);
        self.events[slot].signal = SignalState::Queued(sequence);
        Ok(SignalQueueResult::Queued)
    }

    /// Select the oldest queued signal without releasing its lease.
    pub fn take_next_signal(&mut self) -> Option<PendingEventSignal> {
        let (slot, sequence) = self
            .events
            .iter()
            .enumerate()
            .filter_map(|(slot, record)| match record.signal {
                SignalState::Queued(sequence) if record.live => Some((slot, sequence)),
                _ => None,
            })
            .min_by_key(|(_, sequence)| *sequence)?;
        self.events[slot].signal = SignalState::Delivering(sequence);
        Some(PendingEventSignal {
            id: EventObjectId(ObjectId::new(self.events[slot].generation, slot as u64)),
            native_identity: self.events[slot].native_identity,
        })
    }

    /// Finish one selected delivery and release its signal lease.
    pub fn complete_signal(
        &mut self,
        id: EventObjectId,
    ) -> Result<Option<RetiredEventObject>, EventObjectError> {
        let slot = self.event_slot(id)?;
        if !matches!(self.events[slot].signal, SignalState::Delivering(_)) {
            return Err(EventObjectError::SignalNotDelivering);
        }
        self.events[slot].signal = SignalState::None;
        Ok(self.try_retire(slot))
    }

    /// Cancel a queued or selected delivery during owner teardown.
    pub fn cancel_signal(
        &mut self,
        id: EventObjectId,
    ) -> Result<Option<RetiredEventObject>, EventObjectError> {
        let slot = self.event_slot(id)?;
        self.events[slot].signal = SignalState::None;
        Ok(self.try_retire(slot))
    }

    pub fn request_delete(
        &mut self,
        id: EventObjectId,
    ) -> Result<Option<RetiredEventObject>, EventObjectError> {
        let slot = self.event_slot(id)?;
        self.events[slot].delete_pending = true;
        Ok(self.try_retire(slot))
    }

    fn try_retire(&mut self, slot: usize) -> Option<RetiredEventObject> {
        let record = self.events[slot];
        if !record.live || !record.delete_pending || record.total_leases() != 0 {
            return None;
        }
        let id = EventObjectId(ObjectId::new(record.generation, slot as u64));
        self.events[slot].live = false;
        Some(RetiredEventObject {
            id,
            owner: record.owner,
            native_identity: record.native_identity,
            provider_body: record.provider_body,
        })
    }

    pub fn live_count(&self) -> usize {
        self.events.iter().filter(|record| record.live).count()
    }

    pub fn live_lease_count(&self) -> usize {
        self.leases.iter().filter(|record| record.live).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(generation: u64) -> EventObjectOwner {
        EventObjectOwner::new(42, generation)
    }

    fn create(registry: &mut EventObjectRegistry, native: u64) -> EventObjectId {
        registry.create(owner(7), native).unwrap()
    }

    #[test]
    fn grows_beyond_old_event_and_gui_wait_limits() {
        let mut registry = EventObjectRegistry::with_capacity(1, 1);
        let mut ids = Vec::new();
        for native in 1..=64 {
            let id = create(&mut registry, native);
            registry.retain_handle(id).unwrap();
            ids.push(id);
        }
        let mut leases = Vec::new();
        for id in ids.iter().copied().take(32) {
            leases.push(registry.acquire_wait(id, EventLeaseKind::GuiWait).unwrap());
        }
        assert_eq!(registry.live_count(), 64);
        assert_eq!(registry.live_lease_count(), 32);
        for (id, lease) in ids.iter().copied().zip(leases) {
            assert_eq!(
                registry
                    .event_for_lease(lease, EventLeaseKind::GuiWait)
                    .unwrap(),
                id
            );
        }
    }

    #[test]
    fn stale_object_and_lease_ids_fail_after_slot_reuse() {
        let mut registry = EventObjectRegistry::new();
        let old = create(&mut registry, 1);
        let old_lease = registry
            .acquire_wait(old, EventLeaseKind::NativeWait)
            .unwrap();
        registry.request_delete(old).unwrap();
        assert!(registry
            .release_wait(old_lease, EventLeaseKind::NativeWait)
            .unwrap()
            .is_some());

        let new = create(&mut registry, 2);
        assert_ne!(old, new);
        assert_eq!(registry.snapshot(old), Err(EventObjectError::StaleObject));
        assert_eq!(
            registry.event_for_lease(old_lease, EventLeaseKind::NativeWait),
            Err(EventObjectError::StaleLease)
        );
    }

    #[test]
    fn every_lease_class_independently_defers_reclamation() {
        let mut registry = EventObjectRegistry::new();
        let id = create(&mut registry, 9);
        registry.install_provider_body(id, 0x9000).unwrap();
        registry.retain_handle(id).unwrap();
        registry.retain_pointer(id).unwrap();
        let native = registry
            .acquire_wait(id, EventLeaseKind::NativeWait)
            .unwrap();
        let gui = registry.acquire_wait(id, EventLeaseKind::GuiWait).unwrap();
        registry.queue_signal(id).unwrap();
        registry.request_delete(id).unwrap();

        assert!(registry.release_handle(id).unwrap().is_none());
        assert!(registry.release_pointer_by_body(0x9000).unwrap().is_none());
        assert!(registry
            .release_wait(native, EventLeaseKind::NativeWait)
            .unwrap()
            .is_none());
        assert!(registry
            .release_wait(gui, EventLeaseKind::GuiWait)
            .unwrap()
            .is_none());
        let pending = registry.take_next_signal().unwrap();
        assert_eq!(pending.id, id);
        let retired = registry.complete_signal(id).unwrap().unwrap();
        assert_eq!(retired.provider_body, Some(0x9000));
        assert_eq!(retired.native_identity, 9);
    }

    #[test]
    fn duplicate_release_and_wrong_kind_are_rejected() {
        let mut registry = EventObjectRegistry::new();
        let id = create(&mut registry, 10);
        let lease = registry.acquire_wait(id, EventLeaseKind::GuiWait).unwrap();
        assert_eq!(
            registry.release_wait(lease, EventLeaseKind::NativeWait),
            Err(EventObjectError::WrongLeaseKind)
        );
        registry
            .release_wait(lease, EventLeaseKind::GuiWait)
            .unwrap();
        assert_eq!(
            registry.release_wait(lease, EventLeaseKind::GuiWait),
            Err(EventObjectError::StaleLease)
        );
        assert_eq!(
            registry.release_handle(id),
            Err(EventObjectError::StaleLease)
        );
    }

    #[test]
    fn provider_body_is_unique_and_reverse_resolves() {
        let mut registry = EventObjectRegistry::new();
        let a = create(&mut registry, 11);
        let b = create(&mut registry, 12);
        registry.install_provider_body(a, 0xA000).unwrap();
        assert_eq!(registry.id_for_provider_body(0xA000), Some(a));
        assert_eq!(
            registry.install_provider_body(b, 0xA000),
            Err(EventObjectError::ProviderBodyInUse)
        );
        assert_eq!(registry.provider_body(a), Ok(Some(0xA000)));
    }

    #[test]
    fn signals_coalesce_preserve_fifo_and_hold_lifetime_through_delivery() {
        let mut registry = EventObjectRegistry::new();
        let first = create(&mut registry, 20);
        let second = create(&mut registry, 21);
        assert_eq!(registry.queue_signal(first), Ok(SignalQueueResult::Queued));
        assert_eq!(
            registry.queue_signal(first),
            Ok(SignalQueueResult::Coalesced)
        );
        registry.queue_signal(second).unwrap();
        registry.request_delete(first).unwrap();

        assert_eq!(registry.take_next_signal().unwrap().id, first);
        assert_eq!(registry.snapshot(first).unwrap().signal_leases, 1);
        assert!(registry.complete_signal(first).unwrap().is_some());
        assert_eq!(registry.take_next_signal().unwrap().id, second);
        registry.complete_signal(second).unwrap();
    }

    #[test]
    fn owner_generation_and_native_identity_are_immutable() {
        let mut registry = EventObjectRegistry::new();
        let id = registry.create(owner(99), 0x55).unwrap();
        let snapshot = registry.snapshot(id).unwrap();
        assert_eq!(snapshot.owner, owner(99));
        assert_eq!(snapshot.native_identity, 0x55);
        assert_eq!(registry.id_for_native(0x55), Some(id));
        assert_eq!(
            registry.create(owner(100), 0x55),
            Err(EventObjectError::NativeIdentityInUse)
        );
    }

    #[test]
    fn invalid_creation_and_signal_completion_fail_closed() {
        let mut registry = EventObjectRegistry::new();
        assert_eq!(
            registry.create(EventObjectOwner::new(0, 1), 1),
            Err(EventObjectError::InvalidOwner)
        );
        assert_eq!(
            registry.create(owner(1), 0),
            Err(EventObjectError::InvalidNativeIdentity)
        );
        let id = create(&mut registry, 30);
        assert_eq!(
            registry.complete_signal(id),
            Err(EventObjectError::SignalNotDelivering)
        );
    }

    #[test]
    fn process_local_handles_hold_independent_registry_leases() {
        let mut processes = nt_process::ProcessManager::new();
        let owner_pid = processes.create_process("owner.exe", None, None);
        let duplicate_pid = processes.create_process("duplicate.exe", Some(owner_pid), None);
        let mut registry = EventObjectRegistry::new();
        let id = registry
            .create(EventObjectOwner::new(owner_pid as u64, 1), 81)
            .unwrap();

        registry.retain_handle(id).unwrap();
        let owner_handle = processes
            .insert_handle(owner_pid, nt_process::HandleObject::Event(id.0), 0x1f0003)
            .unwrap();
        let object = processes.lookup_handle(owner_pid, owner_handle).unwrap();
        registry.retain_handle(id).unwrap();
        let duplicate_handle = processes
            .insert_handle(duplicate_pid, object, 0x100000)
            .unwrap();
        assert_eq!(registry.snapshot(id).unwrap().handle_leases, 2);

        let closed = processes
            .take_handle_for_close(owner_pid, owner_handle)
            .unwrap();
        assert_eq!(closed, nt_process::HandleObject::Event(id.0));
        assert!(registry.release_handle(id).unwrap().is_none());
        assert_eq!(registry.snapshot(id).unwrap().handle_leases, 1);

        let closed = processes
            .take_handle_for_close(duplicate_pid, duplicate_handle)
            .unwrap();
        assert_eq!(closed, nt_process::HandleObject::Event(id.0));
        assert!(registry.release_handle(id).unwrap().is_none());
        assert_eq!(registry.snapshot(id).unwrap().handle_leases, 0);
        assert_eq!(
            registry
                .request_delete(id)
                .unwrap()
                .unwrap()
                .native_identity,
            81
        );
    }
}
