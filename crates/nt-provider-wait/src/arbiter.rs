use alloc::vec::Vec;

use nt_time::{Deadline, TimeSnapshot};

use crate::{
    ProviderWaitAbiError, ProviderWaitObject, ProviderWaitObjectType, ProviderWaitOwner,
    ProviderWaitRequest, ProviderWaitTimeoutKind, ProviderWaitType,
};

pub const STATUS_WAIT_0: i32 = 0;
pub const STATUS_TIMEOUT: i32 = 0x0000_0102;

/// Executive operations required by the typed dispatcher-object provider-wait arbiter.
///
/// A successful acquisition creates an exact canonical `ProviderWait` lease. The remaining
/// operations are infallible until release: losing a previously acquired lease is a kernel
/// invariant failure, not a recoverable wait result.
pub trait ProviderDispatcherWaitBackend {
    type Lease: Copy;
    type Error;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<Self::Lease, Self::Error>;

    fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool;
    fn consume_ready_dispatcher(&mut self, lease: Self::Lease);
    fn release_dispatcher_wait(&mut self, lease: Self::Lease);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDispatcherWaitError<E> {
    InvalidRequest(ProviderWaitAbiError),
    OwnerMismatch,
    UnsupportedAlertableWait,
    UnsupportedObjectType,
    InvalidAdmissionSequence,
    DuplicateWait,
    NoCapacity,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDispatcherWaitAdmission {
    Satisfied { wait_id: u64, status: i32 },
    TimedOut { wait_id: u64 },
    Parked { wait_id: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDispatcherWaitCompletion {
    pub wait_id: u64,
    pub owner: ProviderWaitOwner,
    pub admission_sequence: u64,
    pub status: i32,
    pub cancelled: bool,
}

struct ProviderDispatcherWaitRecord<L> {
    wait_id: u64,
    owner: ProviderWaitOwner,
    admission_sequence: u64,
    wait_type: ProviderWaitType,
    objects: Vec<ProviderWaitObject>,
    leases: Vec<L>,
    deadline: Deadline,
}

/// Dispatcher-object arbiter for calls made by isolated kernel providers.
///
/// The shared request is copied before validation, provider and client ownership are checked as one
/// tuple, and every canonical lease is acquired before a waiter becomes visible. Selection uses the
/// executive-supplied global admission sequence rather than backing-vector position.
pub struct ProviderDispatcherWaitArbiter<L> {
    waiters: Vec<ProviderDispatcherWaitRecord<L>>,
}

impl<L: Copy> ProviderDispatcherWaitArbiter<L> {
    pub const fn new() -> Self {
        Self {
            waiters: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.waiters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    pub fn lease_count(&self) -> usize {
        self.waiters
            .iter()
            .map(|waiter| waiter.leases.len())
            .sum()
    }

    pub fn contains(&self, wait_id: u64) -> bool {
        self.waiters.iter().any(|waiter| waiter.wait_id == wait_id)
    }

    pub fn admit<B>(
        &mut self,
        backend: &mut B,
        shared_request: &ProviderWaitRequest,
        expected_owner: ProviderWaitOwner,
        admission_sequence: u64,
        now: TimeSnapshot,
    ) -> Result<ProviderDispatcherWaitAdmission, ProviderDispatcherWaitError<B::Error>>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        // Never retain a borrow into a page the provider can overwrite on a nested dispatch.
        let captured = *shared_request;
        let request = captured
            .validate()
            .map_err(ProviderDispatcherWaitError::InvalidRequest)?;
        if request.owner != expected_owner {
            return Err(ProviderDispatcherWaitError::OwnerMismatch);
        }
        if request.alertable {
            return Err(ProviderDispatcherWaitError::UnsupportedAlertableWait);
        }
        if request.objects.iter().any(|object| {
            !matches!(
                object.typed(),
                Some(ProviderWaitObjectType::Event | ProviderWaitObjectType::Timer)
            )
        }) {
            return Err(ProviderDispatcherWaitError::UnsupportedObjectType);
        }
        if admission_sequence == 0 {
            return Err(ProviderDispatcherWaitError::InvalidAdmissionSequence);
        }
        if self.waiters.iter().any(|waiter| {
            waiter.wait_id == request.wait_id
                || (waiter.owner.provider_domain == request.owner.provider_domain
                    && waiter.owner.provider_generation == request.owner.provider_generation
                    && waiter.owner.dispatch_id == request.owner.dispatch_id)
        }) {
            return Err(ProviderDispatcherWaitError::DuplicateWait);
        }

        let mut objects = Vec::new();
        objects
            .try_reserve_exact(request.objects.len())
            .map_err(|_| ProviderDispatcherWaitError::NoCapacity)?;
        objects.extend_from_slice(request.objects);
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(objects.len())
            .map_err(|_| ProviderDispatcherWaitError::NoCapacity)?;
        if self.waiters.len() == self.waiters.capacity() {
            self.waiters
                .try_reserve(1)
                .map_err(|_| ProviderDispatcherWaitError::NoCapacity)?;
        }

        for object in objects.iter().copied() {
            match backend.acquire_dispatcher_wait(request.owner, object) {
                Ok(lease) => leases.push(lease),
                Err(error) => {
                    Self::release_leases(backend, &leases);
                    return Err(ProviderDispatcherWaitError::Backend(error));
                }
            }
        }

        if let Some(index) = Self::ready_selection(backend, request.wait_type, &leases) {
            Self::consume_selection(backend, request.wait_type, &leases, index);
            Self::release_leases(backend, &leases);
            return Ok(ProviderDispatcherWaitAdmission::Satisfied {
                wait_id: request.wait_id,
                status: STATUS_WAIT_0 + index as i32,
            });
        }

        let deadline = match request.timeout_kind {
            ProviderWaitTimeoutKind::Infinite | ProviderWaitTimeoutKind::Poll => Deadline::Infinite,
            ProviderWaitTimeoutKind::Relative | ProviderWaitTimeoutKind::Absolute => {
                Deadline::from_nt_timeout(Some(request.timeout_100ns), now)
            }
        };
        if request.timeout_kind == ProviderWaitTimeoutKind::Poll || deadline.is_due(now) {
            Self::release_leases(backend, &leases);
            return Ok(ProviderDispatcherWaitAdmission::TimedOut {
                wait_id: request.wait_id,
            });
        }

        self.waiters.push(ProviderDispatcherWaitRecord {
            wait_id: request.wait_id,
            owner: request.owner,
            admission_sequence,
            wait_type: request.wait_type,
            objects,
            leases,
            deadline,
        });
        Ok(ProviderDispatcherWaitAdmission::Parked {
            wait_id: request.wait_id,
        })
    }

    pub fn oldest_event_consumer_sequence<B>(
        &self,
        backend: &B,
        object: ProviderWaitObject,
    ) -> Option<u64>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        self.waiters
            .iter()
            .filter_map(|waiter| {
                let selected = Self::ready_selection(backend, waiter.wait_type, &waiter.leases)?;
                let consumes = match waiter.wait_type {
                    ProviderWaitType::All => waiter.objects.contains(&object),
                    ProviderWaitType::Any => waiter.objects[selected] == object,
                };
                consumes.then_some(waiter.admission_sequence)
            })
            .min()
    }

    pub fn pop_ready<B>(&mut self, backend: &mut B) -> Option<ProviderDispatcherWaitCompletion>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let (slot, selected) = self
            .waiters
            .iter()
            .enumerate()
            .filter_map(|(slot, waiter)| {
                Self::ready_selection(backend, waiter.wait_type, &waiter.leases)
                    .map(|selected| (slot, selected, waiter.admission_sequence))
            })
            .min_by_key(|(_, _, sequence)| *sequence)
            .map(|(slot, selected, _)| (slot, selected))?;
        let waiter = self.waiters.remove(slot);
        Self::consume_selection(backend, waiter.wait_type, &waiter.leases, selected);
        Self::release_leases(backend, &waiter.leases);
        Some(ProviderDispatcherWaitCompletion {
            wait_id: waiter.wait_id,
            owner: waiter.owner,
            admission_sequence: waiter.admission_sequence,
            status: STATUS_WAIT_0 + selected as i32,
            cancelled: false,
        })
    }

    pub fn next_deadline(&self, now: TimeSnapshot) -> Option<u64> {
        self.waiters
            .iter()
            .filter_map(|waiter| waiter.deadline.monotonic_target(now))
            .min()
    }

    pub fn pop_due<B>(
        &mut self,
        backend: &mut B,
        now: TimeSnapshot,
    ) -> Option<ProviderDispatcherWaitCompletion>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let slot = self
            .waiters
            .iter()
            .enumerate()
            .filter(|(_, waiter)| waiter.deadline.is_due(now))
            .min_by_key(|(_, waiter)| {
                (waiter.deadline.ordering_key(now), waiter.admission_sequence)
            })
            .map(|(slot, _)| slot)?;
        Some(self.remove(backend, slot, STATUS_TIMEOUT, false))
    }

    pub fn cancel<B>(
        &mut self,
        backend: &mut B,
        wait_id: u64,
        status: i32,
    ) -> Option<ProviderDispatcherWaitCompletion>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let slot = self
            .waiters
            .iter()
            .position(|waiter| waiter.wait_id == wait_id)?;
        Some(self.remove(backend, slot, status, true))
    }

    fn remove<B>(
        &mut self,
        backend: &mut B,
        slot: usize,
        status: i32,
        cancelled: bool,
    ) -> ProviderDispatcherWaitCompletion
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let waiter = self.waiters.remove(slot);
        Self::release_leases(backend, &waiter.leases);
        ProviderDispatcherWaitCompletion {
            wait_id: waiter.wait_id,
            owner: waiter.owner,
            admission_sequence: waiter.admission_sequence,
            status,
            cancelled,
        }
    }

    fn ready_selection<B>(backend: &B, wait_type: ProviderWaitType, leases: &[L]) -> Option<usize>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        match wait_type {
            ProviderWaitType::All => leases
                .iter()
                .copied()
                .all(|lease| backend.dispatcher_is_ready(lease))
                .then_some(0),
            ProviderWaitType::Any => leases
                .iter()
                .copied()
                .position(|lease| backend.dispatcher_is_ready(lease)),
        }
    }

    fn consume_selection<B>(
        backend: &mut B,
        wait_type: ProviderWaitType,
        leases: &[L],
        index: usize,
    ) where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        match wait_type {
            ProviderWaitType::All => {
                for lease in leases.iter().copied() {
                    backend.consume_ready_dispatcher(lease);
                }
            }
            ProviderWaitType::Any => backend.consume_ready_dispatcher(leases[index]),
        }
    }

    fn release_leases<B>(backend: &mut B, leases: &[L])
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        for lease in leases.iter().copied().rev() {
            backend.release_dispatcher_wait(lease);
        }
    }
}

impl<L: Copy> Default for ProviderDispatcherWaitArbiter<L> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    #[derive(Clone, Copy)]
    struct Event {
        provider: (u64, u64),
        notification: bool,
        signaled: bool,
        leases: u32,
    }

    #[derive(Default)]
    struct Backend {
        events: BTreeMap<(u64, u64), Event>,
        leases: BTreeMap<u64, (u64, u64)>,
        next_lease: u64,
        fail_object: Option<(u64, u64)>,
    }

    impl Backend {
        fn insert(
            &mut self,
            owner: ProviderWaitOwner,
            object: ProviderWaitObject,
            notification: bool,
            signaled: bool,
        ) {
            self.events.insert(
                (object.object_id, object.object_generation),
                Event {
                    provider: (owner.provider_domain, owner.provider_generation),
                    notification,
                    signaled,
                    leases: 0,
                },
            );
        }

        fn set(&mut self, object: ProviderWaitObject) {
            self.events
                .get_mut(&(object.object_id, object.object_generation))
                .unwrap()
                .signaled = true;
        }

        fn lease_count(&self) -> u32 {
            self.events.values().map(|event| event.leases).sum()
        }
    }

    impl ProviderDispatcherWaitBackend for Backend {
        type Lease = u64;
        type Error = &'static str;

        fn acquire_dispatcher_wait(
            &mut self,
            owner: ProviderWaitOwner,
            object: ProviderWaitObject,
        ) -> Result<Self::Lease, Self::Error> {
            let key = (object.object_id, object.object_generation);
            if self.fail_object == Some(key) {
                return Err("injected");
            }
            let event = self.events.get_mut(&key).ok_or("missing")?;
            if event.provider != (owner.provider_domain, owner.provider_generation) {
                return Err("owner");
            }
            self.next_lease += 1;
            event.leases += 1;
            self.leases.insert(self.next_lease, key);
            Ok(self.next_lease)
        }

        fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool {
            self.events[&self.leases[&lease]].signaled
        }

        fn consume_ready_dispatcher(&mut self, lease: Self::Lease) {
            let key = self.leases[&lease];
            let event = self.events.get_mut(&key).unwrap();
            assert!(event.signaled);
            if !event.notification {
                event.signaled = false;
            }
        }

        fn release_dispatcher_wait(&mut self, lease: Self::Lease) {
            let key = self.leases.remove(&lease).unwrap();
            self.events.get_mut(&key).unwrap().leases -= 1;
        }
    }

    fn owner(dispatch_id: u64) -> ProviderWaitOwner {
        ProviderWaitOwner {
            provider_domain: 7,
            provider_generation: 2,
            client_pi: 3,
            client_generation: 5,
            client_tid: 11,
            client_badge: 13,
            dispatch_id,
        }
    }

    fn event(slot: u64) -> ProviderWaitObject {
        ProviderWaitObject::new(ProviderWaitObjectType::Event, slot, 1)
    }

    fn timer(slot: u64) -> ProviderWaitObject {
        ProviderWaitObject::new(ProviderWaitObjectType::Timer, slot, 1)
    }

    fn request(
        owner: ProviderWaitOwner,
        wait_id: u64,
        wait_type: ProviderWaitType,
        timeout_kind: ProviderWaitTimeoutKind,
        timeout_100ns: i64,
        objects: &[ProviderWaitObject],
    ) -> ProviderWaitRequest {
        let mut request = ProviderWaitRequest::empty();
        request
            .begin(
                crate::ProviderWaitRequestMetadata {
                    wait_id,
                    owner,
                    wait_type,
                    wait_mode: crate::ProviderWaitMode::Kernel,
                    alertable: false,
                    timeout_kind,
                    timeout_100ns,
                },
                objects,
            )
            .unwrap();
        request
    }

    fn now(monotonic_100ns: u64, system_time_100ns: u64) -> TimeSnapshot {
        TimeSnapshot {
            monotonic_100ns,
            system_time_100ns,
            clock_generation: 0,
        }
    }

    #[test]
    fn immediate_wait_any_consumes_lowest_ready_index_and_releases_every_lease() {
        let identity = owner(1);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        backend.insert(identity, event(2), false, true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let result = arbiter.admit(
            &mut backend,
            &request(
                identity,
                10,
                ProviderWaitType::Any,
                ProviderWaitTimeoutKind::Infinite,
                0,
                &[event(1), event(2)],
            ),
            identity,
            1,
            now(0, 0),
        );
        assert_eq!(
            result,
            Ok(ProviderDispatcherWaitAdmission::Satisfied {
                wait_id: 10,
                status: 1
            })
        );
        assert!(!backend.events[&(2, 1)].signaled);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn wait_any_accepts_mixed_event_and_timer_leases() {
        let identity = owner(15);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        backend.insert(identity, timer(2), true, true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();

        assert_eq!(
            arbiter.admit(
                &mut backend,
                &request(
                    identity,
                    24,
                    ProviderWaitType::Any,
                    ProviderWaitTimeoutKind::Infinite,
                    0,
                    &[event(1), timer(2)],
                ),
                identity,
                15,
                now(0, 0),
            ),
            Ok(ProviderDispatcherWaitAdmission::Satisfied {
                wait_id: 24,
                status: 1,
            })
        );
        assert!(backend.events[&(2, 1)].signaled);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn wait_all_is_atomic_and_notification_state_remains_set() {
        let identity = owner(2);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, true);
        backend.insert(identity, event(2), true, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let admission = arbiter.admit(
            &mut backend,
            &request(
                identity,
                11,
                ProviderWaitType::All,
                ProviderWaitTimeoutKind::Infinite,
                0,
                &[event(1), event(2)],
            ),
            identity,
            3,
            now(0, 0),
        );
        assert_eq!(
            admission,
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 11 })
        );
        assert!(backend.events[&(1, 1)].signaled);
        backend.set(event(2));
        assert_eq!(
            arbiter.pop_ready(&mut backend).unwrap().status,
            STATUS_WAIT_0
        );
        assert!(!backend.events[&(1, 1)].signaled);
        assert!(backend.events[&(2, 1)].signaled);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn partial_acquisition_failure_rolls_back() {
        let identity = owner(3);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        backend.insert(identity, event(2), false, false);
        backend.fail_object = Some((2, 1));
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let result = arbiter.admit(
            &mut backend,
            &request(
                identity,
                12,
                ProviderWaitType::Any,
                ProviderWaitTimeoutKind::Infinite,
                0,
                &[event(1), event(2)],
            ),
            identity,
            4,
            now(0, 0),
        );
        assert_eq!(result, Err(ProviderDispatcherWaitError::Backend("injected")));
        assert_eq!(backend.lease_count(), 0);
        assert!(arbiter.is_empty());
    }

    #[test]
    fn unsupported_requests_fail_before_acquisition() {
        let identity = owner(4);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let base = request(
            identity,
            13,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        assert_eq!(
            arbiter.admit(&mut backend, &base, owner(99), 5, now(0, 0)),
            Err(ProviderDispatcherWaitError::OwnerMismatch)
        );
        let mut invalid = base;
        invalid.header.alertable = 1;
        assert_eq!(
            arbiter.admit(&mut backend, &invalid, identity, 5, now(0, 0)),
            Err(ProviderDispatcherWaitError::UnsupportedAlertableWait)
        );
        let semaphore = ProviderWaitObject::new(ProviderWaitObjectType::Semaphore, 1, 1);
        let unsupported = request(
            identity,
            13,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[semaphore],
        );
        assert_eq!(
            arbiter.admit(&mut backend, &unsupported, identity, 5, now(0, 0)),
            Err(ProviderDispatcherWaitError::UnsupportedObjectType)
        );
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn non_alertable_user_mode_wait_owns_and_releases_its_event_lease() {
        let identity = owner(14);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut user_wait = request(
            identity,
            23,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        user_wait.header.wait_mode = crate::ProviderWaitMode::User as u32;

        assert_eq!(
            arbiter.admit(&mut backend, &user_wait, identity, 14, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 23 })
        );
        assert_eq!(arbiter.lease_count(), 1);
        assert_eq!(backend.lease_count(), 1);

        let completion = arbiter
            .cancel(&mut backend, 23, 0xC000_0120u32 as i32)
            .unwrap();
        assert!(completion.cancelled);
        assert_eq!(arbiter.lease_count(), 0);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn poll_and_due_deadlines_release_without_parking() {
        let identity = owner(5);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        for (wait_id, kind, timeout) in [
            (14, ProviderWaitTimeoutKind::Poll, 0),
            (15, ProviderWaitTimeoutKind::Absolute, 100),
        ] {
            let admission = arbiter.admit(
                &mut backend,
                &request(
                    identity,
                    wait_id,
                    ProviderWaitType::Any,
                    kind,
                    timeout,
                    &[event(1)],
                ),
                identity,
                wait_id,
                now(10, 100),
            );
            assert_eq!(
                admission,
                Ok(ProviderDispatcherWaitAdmission::TimedOut { wait_id })
            );
        }
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn deadlines_and_cancel_release_exact_waits() {
        let identity = owner(6);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let timed = request(
            identity,
            16,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Relative,
            -25,
            &[event(1)],
        );
        assert_eq!(
            arbiter.admit(&mut backend, &timed, identity, 8, now(10, 100)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 16 })
        );
        assert_eq!(arbiter.next_deadline(now(10, 100)), Some(35));
        assert!(arbiter.pop_due(&mut backend, now(34, 124)).is_none());
        assert_eq!(
            arbiter.pop_due(&mut backend, now(35, 125)).unwrap().status,
            STATUS_TIMEOUT
        );
        let infinite = request(
            identity,
            17,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        assert_eq!(
            arbiter.admit(&mut backend, &infinite, identity, 9, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 17 })
        );
        let cancelled = arbiter
            .cancel(&mut backend, 17, 0xC000_0120u32 as i32)
            .unwrap();
        assert!(cancelled.cancelled);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn ready_selection_uses_global_admission_order() {
        let first = owner(7);
        let second = owner(8);
        let mut backend = Backend::default();
        backend.insert(first, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        for (identity, wait_id, sequence) in [(first, 18, 20), (second, 19, 10)] {
            let wait = request(
                identity,
                wait_id,
                ProviderWaitType::Any,
                ProviderWaitTimeoutKind::Infinite,
                0,
                &[event(1)],
            );
            assert_eq!(
                arbiter.admit(&mut backend, &wait, identity, sequence, now(0, 0)),
                Ok(ProviderDispatcherWaitAdmission::Parked { wait_id })
            );
        }
        backend.set(event(1));
        assert_eq!(
            arbiter.oldest_event_consumer_sequence(&backend, event(1)),
            Some(10)
        );
        assert_eq!(arbiter.pop_ready(&mut backend).unwrap().wait_id, 19);
        assert!(!backend.events[&(1, 1)].signaled);
        assert_eq!(
            arbiter
                .cancel(&mut backend, 18, 0xC000_0120u32 as i32)
                .unwrap()
                .wait_id,
            18
        );
    }
}
