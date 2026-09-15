use alloc::vec::Vec;

use nt_time::{Deadline, TimeSnapshot};

use crate::{
    ProviderWaitAbiError, ProviderWaitObject, ProviderWaitObjectType, ProviderWaitOwner,
    ProviderWaitRequest, ProviderWaitTimeoutKind, ProviderWaitType, ValidatedProviderWait,
    PROVIDER_WAIT_MAX_OBJECTS,
};

pub const STATUS_WAIT_0: i32 = 0;
pub const STATUS_TIMEOUT: i32 = 0x0000_0102;
pub const STATUS_ALERTED: i32 = 0x0000_0101;
pub const STATUS_USER_APC: i32 = 0x0000_00C0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitInterrupt {
    Alerted,
    UserApc,
}

impl ProviderWaitInterrupt {
    const fn status(self) -> i32 {
        match self {
            Self::Alerted => STATUS_ALERTED,
            Self::UserApc => STATUS_USER_APC,
        }
    }
}

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
    UnsupportedObjectType,
    InvalidAdmissionSequence,
    DuplicateWait,
    NotPoll,
    NoCapacity,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDispatcherWaitPublicationError<W, P> {
    Wait(ProviderDispatcherWaitError<W>),
    Publication(P),
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
    wait_mode: crate::ProviderWaitMode,
    alertable: bool,
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
        self.waiters.iter().map(|waiter| waiter.leases.len()).sum()
    }

    pub fn contains(&self, wait_id: u64) -> bool {
        self.waiters.iter().any(|waiter| waiter.wait_id == wait_id)
    }

    /// Complete a zero-timeout wait synchronously without allocating or registering a waiter.
    /// The backend owns lease acquisition; every acquired lease is released before returning.
    pub fn poll<B>(
        &self,
        backend: &mut B,
        shared_request: &ProviderWaitRequest,
        expected_owner: ProviderWaitOwner,
    ) -> Result<i32, ProviderDispatcherWaitError<B::Error>>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let captured = *shared_request;
        let request = Self::validate_request(&captured, expected_owner)?;
        if request.timeout_kind != ProviderWaitTimeoutKind::Poll {
            return Err(ProviderDispatcherWaitError::NotPoll);
        }
        self.validate_unique(&request)?;

        // Validated requests contain 1..=MAX objects. Seed the bounded array from the first real
        // lease so no default, sentinel lease, unsafe initialization or heap storage is needed.
        let first = backend
            .acquire_dispatcher_wait(request.owner, request.objects[0])
            .map_err(ProviderDispatcherWaitError::Backend)?;
        let mut leases = [first; PROVIDER_WAIT_MAX_OBJECTS];
        let mut count = 1;
        for object in request.objects[1..].iter().copied() {
            match backend.acquire_dispatcher_wait(request.owner, object) {
                Ok(lease) => {
                    leases[count] = lease;
                    count += 1;
                }
                Err(error) => {
                    Self::release_leases(backend, &leases[..count]);
                    return Err(ProviderDispatcherWaitError::Backend(error));
                }
            }
        }
        let leases = &leases[..count];
        let status = match Self::ready_selection(backend, request.wait_type, leases) {
            Some(index) => {
                Self::consume_selection(backend, request.wait_type, leases, index);
                STATUS_WAIT_0 + index as i32
            }
            None => STATUS_TIMEOUT,
        };
        Self::release_leases(backend, leases);
        Ok(status)
    }

    fn validate_request<E>(
        captured: &ProviderWaitRequest,
        expected_owner: ProviderWaitOwner,
    ) -> Result<ValidatedProviderWait<'_>, ProviderDispatcherWaitError<E>> {
        let request = captured
            .validate()
            .map_err(ProviderDispatcherWaitError::InvalidRequest)?;
        if request.owner != expected_owner {
            return Err(ProviderDispatcherWaitError::OwnerMismatch);
        }
        if request.objects.iter().any(|object| {
            !matches!(
                object.typed(),
                Some(ProviderWaitObjectType::Event | ProviderWaitObjectType::Timer)
            )
        }) {
            return Err(ProviderDispatcherWaitError::UnsupportedObjectType);
        }
        Ok(request)
    }

    fn validate_unique<E>(
        &self,
        request: &ValidatedProviderWait<'_>,
    ) -> Result<(), ProviderDispatcherWaitError<E>> {
        if self.waiters.iter().any(|waiter| {
            waiter.wait_id == request.wait_id || waiter.owner.same_dispatch(request.owner)
        }) {
            return Err(ProviderDispatcherWaitError::DuplicateWait);
        }
        Ok(())
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
        self.admit_owned(
            backend,
            shared_request,
            expected_owner,
            admission_sequence,
            now,
            (),
            |()| Ok::<(), (core::convert::Infallible, ())>(()),
        )
        .map(|(admission, ())| admission)
        .map_err(|(error, ())| match error {
            ProviderDispatcherWaitPublicationError::Wait(error) => error,
            ProviderDispatcherWaitPublicationError::Publication(error) => match error {},
        })
    }

    /// Acquire all leases and reserve waiter storage before publishing the continuation.
    /// Every rejection returns the offered continuation and releases any acquired leases;
    /// successful publication is followed only by infallible selection or waiter insertion.
    ///
    /// `publish` must perform only local canonical ownership changes. It must not invoke IPC,
    /// schedule execution, reenter this arbiter/backend, or invalidate the acquired leases.
    /// The caller must retain dispatcher serialization until the admission is committed and
    /// any immediate result is selected on the published continuation. On rejection, `publish`
    /// must leave existing continuation ownership unchanged and return the offered value.
    pub fn admit_owned<B, C, O, E>(
        &mut self,
        backend: &mut B,
        shared_request: &ProviderWaitRequest,
        expected_owner: ProviderWaitOwner,
        admission_sequence: u64,
        now: TimeSnapshot,
        continuation: C,
        publish: impl FnOnce(C) -> Result<O, (E, C)>,
    ) -> Result<
        (ProviderDispatcherWaitAdmission, O),
        (ProviderDispatcherWaitPublicationError<B::Error, E>, C),
    >
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        self.admit_owned_at(
            backend,
            shared_request,
            expected_owner,
            admission_sequence,
            now,
            now,
            continuation,
            publish,
        )
    }

    /// Admit an owned continuation without restarting its timeout after deferred publication.
    ///
    /// `origin` is the retained snapshot from the original wait request; retries must reuse it.
    /// Relative deadlines use its monotonic time, while absolute deadlines retain their original
    /// system-time target. `now` determines whether that deadline has expired at admission.
    /// Both snapshots must come from the same canonical, non-regressing monotonic clock.
    /// Readiness still takes precedence over an expired deadline. The ownership and serialization
    /// contract of `admit_owned` applies unchanged.
    pub fn admit_owned_at<B, C, O, E>(
        &mut self,
        backend: &mut B,
        shared_request: &ProviderWaitRequest,
        expected_owner: ProviderWaitOwner,
        admission_sequence: u64,
        origin: TimeSnapshot,
        now: TimeSnapshot,
        continuation: C,
        publish: impl FnOnce(C) -> Result<O, (E, C)>,
    ) -> Result<
        (ProviderDispatcherWaitAdmission, O),
        (ProviderDispatcherWaitPublicationError<B::Error, E>, C),
    >
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let (waiter, poll) = match self.prepare_admission(
            backend,
            shared_request,
            expected_owner,
            admission_sequence,
            origin,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err((
                    ProviderDispatcherWaitPublicationError::Wait(error),
                    continuation,
                ));
            }
        };
        let published = match publish(continuation) {
            Ok(published) => published,
            Err((error, continuation)) => {
                Self::release_leases(backend, &waiter.leases);
                return Err((
                    ProviderDispatcherWaitPublicationError::Publication(error),
                    continuation,
                ));
            }
        };

        let wait_id = waiter.wait_id;
        let admission = if let Some(index) =
            Self::ready_selection(backend, waiter.wait_type, &waiter.leases)
        {
            Self::consume_selection(backend, waiter.wait_type, &waiter.leases, index);
            Self::release_leases(backend, &waiter.leases);
            ProviderDispatcherWaitAdmission::Satisfied {
                wait_id,
                status: STATUS_WAIT_0 + index as i32,
            }
        } else if poll || waiter.deadline.is_due(now) {
            Self::release_leases(backend, &waiter.leases);
            ProviderDispatcherWaitAdmission::TimedOut { wait_id }
        } else {
            self.waiters.push(waiter);
            ProviderDispatcherWaitAdmission::Parked { wait_id }
        };
        Ok((admission, published))
    }

    fn prepare_admission<B>(
        &mut self,
        backend: &mut B,
        shared_request: &ProviderWaitRequest,
        expected_owner: ProviderWaitOwner,
        admission_sequence: u64,
        origin: TimeSnapshot,
    ) -> Result<(ProviderDispatcherWaitRecord<L>, bool), ProviderDispatcherWaitError<B::Error>>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        // Never retain a borrow into a page the provider can overwrite on a nested dispatch.
        let captured = *shared_request;
        let request = Self::validate_request(&captured, expected_owner)?;
        if admission_sequence == 0 {
            return Err(ProviderDispatcherWaitError::InvalidAdmissionSequence);
        }
        self.validate_unique(&request)?;

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

        let deadline = match request.timeout_kind {
            ProviderWaitTimeoutKind::Infinite | ProviderWaitTimeoutKind::Poll => Deadline::Infinite,
            ProviderWaitTimeoutKind::Relative | ProviderWaitTimeoutKind::Absolute => {
                Deadline::from_nt_timeout(Some(request.timeout_100ns), origin)
            }
        };
        Ok((
            ProviderDispatcherWaitRecord {
                wait_id: request.wait_id,
                owner: request.owner,
                admission_sequence,
                wait_type: request.wait_type,
                wait_mode: request.wait_mode,
                alertable: request.alertable,
                objects,
                leases,
                deadline,
            },
            request.timeout_kind == ProviderWaitTimeoutKind::Poll,
        ))
    }

    pub fn oldest_event_consumer_sequence<B>(
        &self,
        backend: &B,
        object: ProviderWaitObject,
    ) -> Option<u64>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        self.oldest_event_consumer(backend, object)
            .map(|(slot, _)| self.waiters[slot].admission_sequence)
    }

    fn oldest_event_consumer<B>(
        &self,
        backend: &B,
        object: ProviderWaitObject,
    ) -> Option<(usize, usize)>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        self.waiters
            .iter()
            .enumerate()
            .filter_map(|(slot, waiter)| {
                let selected = Self::ready_selection(backend, waiter.wait_type, &waiter.leases)?;
                let consumes = match waiter.wait_type {
                    ProviderWaitType::All => waiter.objects.contains(&object),
                    ProviderWaitType::Any => waiter.objects[selected] == object,
                };
                consumes.then_some((slot, selected, waiter.admission_sequence))
            })
            .min_by_key(|(_, _, sequence)| *sequence)
            .map(|(slot, selected, _)| (slot, selected))
    }

    /// Complete exactly the oldest ready waiter that consumes `object`, after rechecking the
    /// admission sequence selected by cross-domain Event arbitration. A stale selection has no
    /// effects: it cannot consume another ready object or release any retained leases.
    pub fn pop_event_ready<B>(
        &mut self,
        backend: &mut B,
        object: ProviderWaitObject,
        expected_sequence: u64,
    ) -> Option<ProviderDispatcherWaitCompletion>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        match self.pop_event_ready_with(backend, object, expected_sequence, |_| {
            Ok::<_, core::convert::Infallible>(())
        }) {
            Ok(completion) => completion.map(|(completion, ())| completion),
            Err(error) => match error {},
        }
    }

    /// Publish the exact Event completion before consuming readiness or releasing its leases.
    /// A stale sequence does not invoke publication. See `pop_ready_with` for its contract.
    pub fn pop_event_ready_with<B, O, E>(
        &mut self,
        backend: &mut B,
        object: ProviderWaitObject,
        expected_sequence: u64,
        publish: impl FnOnce(ProviderDispatcherWaitCompletion) -> Result<O, E>,
    ) -> Result<Option<(ProviderDispatcherWaitCompletion, O)>, E>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let Some((slot, selected)) = self.oldest_event_consumer(backend, object) else {
            return Ok(None);
        };
        if self.waiters[slot].admission_sequence != expected_sequence {
            return Ok(None);
        }
        let output = publish(self.completion(slot, STATUS_WAIT_0 + selected as i32, false))?;
        Ok(Some((self.complete_ready(backend, slot, selected), output)))
    }

    pub fn pop_ready<B>(&mut self, backend: &mut B) -> Option<ProviderDispatcherWaitCompletion>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        match self.pop_ready_with(backend, |_| Ok::<_, core::convert::Infallible>(())) {
            Ok(completion) => completion.map(|(completion, ())| completion),
            Err(error) => match error {},
        }
    }

    /// Publish the oldest ready completion before any destructive dispatcher operation.
    /// Rejection retains this waiter, its readiness and all leases; it never skips to a younger
    /// candidate. Publication must be memory-local and serialized with this arbiter/backend,
    /// with no IPC, scheduling, reentry or backend mutation. Failure must have no side effects;
    /// success must leave only the infallible readiness consumption and lease retirement here.
    pub fn pop_ready_with<B, O, E>(
        &mut self,
        backend: &mut B,
        publish: impl FnOnce(ProviderDispatcherWaitCompletion) -> Result<O, E>,
    ) -> Result<Option<(ProviderDispatcherWaitCompletion, O)>, E>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let Some((slot, selected)) = self
            .waiters
            .iter()
            .enumerate()
            .filter_map(|(slot, waiter)| {
                Self::ready_selection(backend, waiter.wait_type, &waiter.leases)
                    .map(|selected| (slot, selected, waiter.admission_sequence))
            })
            .min_by_key(|(_, _, sequence)| *sequence)
            .map(|(slot, selected, _)| (slot, selected))
        else {
            return Ok(None);
        };
        let output = publish(self.completion(slot, STATUS_WAIT_0 + selected as i32, false))?;
        Ok(Some((self.complete_ready(backend, slot, selected), output)))
    }

    fn complete_ready<B>(
        &mut self,
        backend: &mut B,
        slot: usize,
        selected: usize,
    ) -> ProviderDispatcherWaitCompletion
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let completion = self.completion(slot, STATUS_WAIT_0 + selected as i32, false);
        let waiter = self.waiters.remove(slot);
        Self::consume_selection(backend, waiter.wait_type, &waiter.leases, selected);
        Self::release_leases(backend, &waiter.leases);
        completion
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
        match self.pop_due_with(backend, now, |_| Ok::<_, core::convert::Infallible>(())) {
            Ok(completion) => completion.map(|(completion, ())| completion),
            Err(error) => match error {},
        }
    }

    /// Publish the oldest due timeout before removing its waiter or releasing its leases.
    /// Rejection preserves deadline ordering. See `pop_ready_with` for the publication contract.
    pub fn pop_due_with<B, O, E>(
        &mut self,
        backend: &mut B,
        now: TimeSnapshot,
        publish: impl FnOnce(ProviderDispatcherWaitCompletion) -> Result<O, E>,
    ) -> Result<Option<(ProviderDispatcherWaitCompletion, O)>, E>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let Some(slot) = self
            .waiters
            .iter()
            .enumerate()
            .filter(|(_, waiter)| waiter.deadline.is_due(now))
            .min_by_key(|(_, waiter)| {
                (waiter.deadline.ordering_key(now), waiter.admission_sequence)
            })
            .map(|(slot, _)| slot)
        else {
            return Ok(None);
        };
        let output = publish(self.completion(slot, STATUS_TIMEOUT, false))?;
        Ok(Some((self.remove(backend, slot, STATUS_TIMEOUT, false), output)))
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

    /// Interrupt one exact alertable provider wait without weakening its dispatcher ownership.
    ///
    /// NT alerts may interrupt either wait mode. A user APC may terminate only an alertable
    /// `UserMode` wait; kernel-mode waits remain parked while user APCs are pending. The caller
    /// must supply the complete generation-owned dispatch tuple so a recycled wait ID cannot be
    /// interrupted by an obsolete producer.
    pub fn interrupt_alertable<B>(
        &mut self,
        backend: &mut B,
        wait_id: u64,
        owner: ProviderWaitOwner,
        interrupt: ProviderWaitInterrupt,
    ) -> Option<ProviderDispatcherWaitCompletion>
    where
        B: ProviderDispatcherWaitBackend<Lease = L>,
    {
        let slot = self.waiters.iter().position(|waiter| {
            waiter.wait_id == wait_id
                && waiter.owner == owner
                && waiter.alertable
                && (interrupt != ProviderWaitInterrupt::UserApc
                    || waiter.wait_mode == crate::ProviderWaitMode::User)
        })?;
        Some(self.remove(backend, slot, interrupt.status(), false))
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
        let completion = self.completion(slot, status, cancelled);
        let waiter = self.waiters.remove(slot);
        Self::release_leases(backend, &waiter.leases);
        completion
    }

    fn completion(
        &self,
        slot: usize,
        status: i32,
        cancelled: bool,
    ) -> ProviderDispatcherWaitCompletion {
        let waiter = &self.waiters[slot];
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
            caller: crate::SuspensionCaller::Hosted(crate::SuspensionHostedClient {
                client_pi: 3,
                client_generation: 5,
                client_tid: 11,
                client_badge: 13,
            }),
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
    fn synchronous_poll_completes_or_times_out_without_persistent_storage() {
        let identity = owner(1);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        backend.insert(identity, event(2), false, true);
        let arbiter = ProviderDispatcherWaitArbiter::new();
        let poll = request(
            identity,
            10,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Poll,
            0,
            &[event(1), event(2)],
        );
        assert_eq!(arbiter.poll(&mut backend, &poll, identity), Ok(1));
        assert!(!backend.events[&(2, 1)].signaled);
        assert_eq!(
            arbiter.poll(&mut backend, &poll, identity),
            Ok(STATUS_TIMEOUT)
        );
        assert_eq!(backend.lease_count(), 0);
        assert!(backend.leases.is_empty());
        assert!(arbiter.is_empty());
        assert_eq!(arbiter.waiters.capacity(), 0);
    }

    #[test]
    fn synchronous_poll_rejects_nonpoll_and_wrong_owner_before_acquiring() {
        let identity = owner(2);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, true);
        let arbiter = ProviderDispatcherWaitArbiter::new();
        for (kind, timeout) in [
            (ProviderWaitTimeoutKind::Infinite, 0),
            (ProviderWaitTimeoutKind::Relative, -1),
            (ProviderWaitTimeoutKind::Absolute, 1),
        ] {
            let blocking = request(
                identity,
                11,
                ProviderWaitType::Any,
                kind,
                timeout,
                &[event(1)],
            );
            assert_eq!(
                arbiter.poll(&mut backend, &blocking, identity),
                Err(ProviderDispatcherWaitError::NotPoll)
            );
        }
        let poll = request(
            identity,
            11,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Poll,
            0,
            &[event(1)],
        );
        assert_eq!(
            arbiter.poll(&mut backend, &poll, owner(3)),
            Err(ProviderDispatcherWaitError::OwnerMismatch)
        );
        assert_eq!(backend.next_lease, 0);
        assert!(backend.events[&(1, 1)].signaled);
        assert_eq!(arbiter.waiters.capacity(), 0);
    }

    #[test]
    fn synchronous_poll_acquires_all_before_consumption_and_wait_all_is_atomic() {
        let identity = owner(4);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, true);
        backend.insert(identity, event(2), true, false);
        let arbiter = ProviderDispatcherWaitArbiter::new();
        let stale = ProviderWaitObject::new(ProviderWaitObjectType::Event, 2, 2);
        for wait_type in [ProviderWaitType::Any, ProviderWaitType::All] {
            let poll = request(
                identity,
                12,
                wait_type,
                ProviderWaitTimeoutKind::Poll,
                0,
                &[event(1), stale],
            );
            assert_eq!(
                arbiter.poll(&mut backend, &poll, identity),
                Err(ProviderDispatcherWaitError::Backend("missing"))
            );
            assert!(backend.events[&(1, 1)].signaled);
            assert_eq!(backend.lease_count(), 0);
            assert!(backend.leases.is_empty());
        }
        let all = request(
            identity,
            12,
            ProviderWaitType::All,
            ProviderWaitTimeoutKind::Poll,
            0,
            &[event(1), event(2)],
        );
        assert_eq!(
            arbiter.poll(&mut backend, &all, identity),
            Ok(STATUS_TIMEOUT)
        );
        assert!(backend.events[&(1, 1)].signaled);
        assert_eq!(backend.lease_count(), 0);
        backend.set(event(2));
        assert_eq!(
            arbiter.poll(&mut backend, &all, identity),
            Ok(STATUS_WAIT_0)
        );
        assert!(!backend.events[&(1, 1)].signaled);
        assert!(backend.events[&(2, 1)].signaled);
        assert_eq!(backend.lease_count(), 0);
        assert_eq!(arbiter.waiters.capacity(), 0);
    }

    #[test]
    fn synchronous_poll_does_not_replace_parked_wait_or_duplicate_its_dispatch() {
        let identity = owner(5);
        let polling = owner(6);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        backend.insert(identity, event(2), false, true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let blocking = request(
            identity,
            13,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        assert_eq!(
            arbiter.admit(&mut backend, &blocking, identity, 1, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 13 })
        );
        let capacity = arbiter.waiters.capacity();
        let old_leases = backend.leases.clone();
        let acquired = backend.next_lease;
        for (claim, wait_id) in [(identity, 14), (polling, 13)] {
            let duplicate = request(
                claim,
                wait_id,
                ProviderWaitType::Any,
                ProviderWaitTimeoutKind::Poll,
                0,
                &[event(2)],
            );
            assert_eq!(
                arbiter.poll(&mut backend, &duplicate, claim),
                Err(ProviderDispatcherWaitError::DuplicateWait)
            );
        }
        assert_eq!(backend.next_lease, acquired);
        assert!(backend.events[&(2, 1)].signaled);
        let poll = request(
            polling,
            14,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Poll,
            0,
            &[event(2)],
        );
        assert_eq!(
            arbiter.poll(&mut backend, &poll, polling),
            Ok(STATUS_WAIT_0)
        );
        assert_eq!(backend.leases, old_leases);
        assert_eq!(arbiter.waiters.capacity(), capacity);
        assert_eq!(arbiter.len(), 1);
        assert_eq!(arbiter.lease_count(), 1);
        backend.set(event(1));
        let completion = arbiter.pop_ready(&mut backend).unwrap();
        assert_eq!(completion.owner, identity);
        assert_eq!(completion.wait_id, 13);
        assert_eq!(completion.admission_sequence, 1);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn synchronous_poll_supports_the_complete_bounded_object_set() {
        let identity = owner(7);
        let mut backend = Backend::default();
        let mut objects = [ProviderWaitObject::EMPTY; PROVIDER_WAIT_MAX_OBJECTS];
        for (index, object) in objects.iter_mut().enumerate() {
            *object = event(index as u64 + 1);
            backend.insert(identity, *object, false, true);
        }
        let arbiter = ProviderDispatcherWaitArbiter::new();
        let all = request(
            identity,
            15,
            ProviderWaitType::All,
            ProviderWaitTimeoutKind::Poll,
            0,
            &objects,
        );
        assert_eq!(
            arbiter.poll(&mut backend, &all, identity),
            Ok(STATUS_WAIT_0)
        );
        assert!(backend
            .events
            .values()
            .all(|event| !event.signaled && event.leases == 0));
        assert_eq!(backend.next_lease, PROVIDER_WAIT_MAX_OBJECTS as u64);
        assert!(backend.leases.is_empty());
        assert_eq!(arbiter.waiters.capacity(), 0);
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
    fn kernel_wait_requires_exact_lane_generation_and_caller_kind_before_leasing() {
        let hosted = owner(1);
        let identity = ProviderWaitOwner {
            caller: crate::SuspensionCaller::Kernel {
                lane: crate::LaneHandle {
                    index: 0,
                    generation: 4,
                },
            },
            ..hosted
        };
        let wait = request(
            identity,
            40,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        for expected in [
            hosted,
            ProviderWaitOwner {
                provider_generation: 3,
                ..identity
            },
            ProviderWaitOwner {
                caller: crate::SuspensionCaller::Kernel {
                    lane: crate::LaneHandle {
                        index: 0,
                        generation: 5,
                    },
                },
                ..identity
            },
            ProviderWaitOwner {
                caller: crate::SuspensionCaller::Kernel {
                    lane: crate::LaneHandle {
                        index: 1,
                        generation: 4,
                    },
                },
                ..identity
            },
        ] {
            assert_eq!(
                arbiter.admit(&mut backend, &wait, expected, 1, now(0, 0)),
                Err(ProviderDispatcherWaitError::OwnerMismatch),
            );
            assert_eq!(backend.lease_count(), 0);
            assert!(arbiter.is_empty());
        }
        assert_eq!(
            arbiter.admit(&mut backend, &wait, identity, 1, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 40 }),
        );
        let duplicate = request(
            identity,
            41,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        assert_eq!(
            arbiter.admit(&mut backend, &duplicate, identity, 2, now(0, 0)),
            Err(ProviderDispatcherWaitError::DuplicateWait),
        );
        assert_eq!(backend.lease_count(), 1);
        arbiter
            .cancel(&mut backend, 40, 0xC000_0120u32 as i32)
            .unwrap();
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
        assert_eq!(
            result,
            Err(ProviderDispatcherWaitError::Backend("injected"))
        );
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
    fn alertable_kernel_wait_ignores_user_apc_but_accepts_alert() {
        let identity = owner(16);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut wait = request(
            identity,
            25,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        wait.header.alertable = 1;

        assert_eq!(
            arbiter.admit(&mut backend, &wait, identity, 16, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 25 })
        );
        assert!(arbiter
            .interrupt_alertable(&mut backend, 25, identity, ProviderWaitInterrupt::UserApc,)
            .is_none());
        assert_eq!(backend.lease_count(), 1);

        let completion = arbiter
            .interrupt_alertable(&mut backend, 25, identity, ProviderWaitInterrupt::Alerted)
            .unwrap();
        assert_eq!(completion.status, STATUS_ALERTED);
        assert!(!completion.cancelled);
        assert_eq!(backend.lease_count(), 0);
    }

    #[test]
    fn alertable_user_wait_accepts_only_exact_owner_user_apc() {
        let identity = owner(17);
        let mut backend = Backend::default();
        backend.insert(identity, event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut wait = request(
            identity,
            26,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
            &[event(1)],
        );
        wait.header.wait_mode = crate::ProviderWaitMode::User as u32;
        wait.header.alertable = 1;

        assert_eq!(
            arbiter.admit(&mut backend, &wait, identity, 17, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 26 })
        );
        assert!(arbiter
            .interrupt_alertable(
                &mut backend,
                26,
                owner(identity.dispatch_id + 1),
                ProviderWaitInterrupt::UserApc,
            )
            .is_none());
        let completion = arbiter
            .interrupt_alertable(&mut backend, 26, identity, ProviderWaitInterrupt::UserApc)
            .unwrap();
        assert_eq!(completion.status, STATUS_USER_APC);
        assert!(!completion.cancelled);
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

    fn park(
        arbiter: &mut ProviderDispatcherWaitArbiter<u64>,
        backend: &mut Backend,
        sequence: u64,
        wait_type: ProviderWaitType,
        objects: &[ProviderWaitObject],
    ) {
        let identity = owner(sequence);
        let wait = request(
            identity,
            sequence,
            wait_type,
            ProviderWaitTimeoutKind::Infinite,
            0,
            objects,
        );
        assert_eq!(
            arbiter.admit(backend, &wait, identity, sequence, now(0, 0)),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: sequence })
        );
    }

    #[test]
    fn targeted_ready_filters_unrelated_waits_and_unselected_wait_any_objects() {
        let mut backend = Backend::default();
        for id in 1..=3 {
            backend.insert(owner(1), event(id), false, false);
        }
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        park(
            &mut arbiter,
            &mut backend,
            1,
            ProviderWaitType::Any,
            &[event(1)],
        );
        park(
            &mut arbiter,
            &mut backend,
            2,
            ProviderWaitType::Any,
            &[event(1), event(2)],
        );
        park(
            &mut arbiter,
            &mut backend,
            3,
            ProviderWaitType::Any,
            &[event(3), event(2)],
        );
        backend.set(event(1));
        backend.set(event(2));
        assert_eq!(
            arbiter.oldest_event_consumer_sequence(&backend, event(2)),
            Some(3)
        );
        assert_eq!(arbiter.pop_event_ready(&mut backend, event(3), 3), None);
        let completion = arbiter.pop_event_ready(&mut backend, event(2), 3).unwrap();
        assert_eq!(completion.wait_id, 3);
        assert_eq!(completion.owner, owner(3));
        assert_eq!(completion.status, STATUS_WAIT_0 + 1);
        assert!(!completion.cancelled);
        assert!(backend.events[&(1, 1)].signaled);
        assert!(!backend.events[&(2, 1)].signaled);
        assert_eq!(arbiter.len(), 2);
        assert_eq!(backend.lease_count(), 3);
        assert_eq!(arbiter.pop_ready(&mut backend).unwrap().wait_id, 1);
        assert!(arbiter.contains(2));
    }

    #[test]
    fn targeted_stale_sequence_preserves_waiters_signals_and_exact_leases() {
        let mut backend = Backend::default();
        backend.insert(owner(1), event(1), true, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        for sequence in [20, 10] {
            park(
                &mut arbiter,
                &mut backend,
                sequence,
                ProviderWaitType::Any,
                &[event(1)],
            );
        }
        backend.set(event(1));
        let leases = backend.leases.clone();
        for stale in [0, 20, u64::MAX] {
            assert_eq!(arbiter.pop_event_ready(&mut backend, event(1), stale), None);
            assert_eq!(backend.leases, leases);
            assert_eq!(backend.lease_count(), 2);
            assert_eq!(arbiter.len(), 2);
            assert!(arbiter.contains(10) && arbiter.contains(20));
            assert!(backend.events[&(1, 1)].signaled);
        }
        assert_eq!(
            arbiter
                .pop_event_ready(&mut backend, event(1), 10)
                .unwrap()
                .wait_id,
            10
        );
        let remaining_leases = backend.leases.clone();
        assert_eq!(arbiter.pop_event_ready(&mut backend, event(1), 10), None);
        assert_eq!(backend.leases, remaining_leases);
        assert_eq!(arbiter.len(), 1);
        assert!(backend.events[&(1, 1)].signaled);
        assert_eq!(
            arbiter
                .pop_event_ready(&mut backend, event(1), 20)
                .unwrap()
                .wait_id,
            20
        );
        assert!(backend.leases.is_empty());
    }

    #[test]
    fn targeted_wait_all_rechecks_competing_resource_before_consuming_anything() {
        let mut backend = Backend::default();
        for id in 1..=2 {
            backend.insert(owner(1), event(id), false, false);
        }
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        park(
            &mut arbiter,
            &mut backend,
            10,
            ProviderWaitType::All,
            &[event(2), event(1)],
        );
        park(
            &mut arbiter,
            &mut backend,
            5,
            ProviderWaitType::Any,
            &[event(2)],
        );
        backend.set(event(1));
        assert_eq!(
            arbiter.oldest_event_consumer_sequence(&backend, event(1)),
            None
        );
        assert_eq!(arbiter.pop_event_ready(&mut backend, event(1), 10), None);
        assert!(backend.events[&(1, 1)].signaled);
        backend.set(event(2));
        assert_eq!(
            arbiter.oldest_event_consumer_sequence(&backend, event(1)),
            Some(10)
        );
        assert_eq!(
            arbiter
                .pop_event_ready(&mut backend, event(2), 5)
                .unwrap()
                .wait_id,
            5
        );
        let leases = backend.leases.clone();
        assert_eq!(arbiter.pop_event_ready(&mut backend, event(1), 10), None);
        assert_eq!(backend.leases, leases);
        assert!(backend.events[&(1, 1)].signaled);
        backend.set(event(2));
        let completion = arbiter.pop_event_ready(&mut backend, event(1), 10).unwrap();
        assert_eq!(completion.wait_id, 10);
        assert_eq!(completion.status, STATUS_WAIT_0);
        assert!(backend
            .events
            .values()
            .all(|event| !event.signaled && event.leases == 0));
        assert!(arbiter.is_empty());
    }

    #[test]
    fn targeted_synchronization_event_completes_only_one_waiter_per_signal() {
        let mut backend = Backend::default();
        backend.insert(owner(1), event(1), false, false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        for sequence in [20, 10] {
            park(
                &mut arbiter,
                &mut backend,
                sequence,
                ProviderWaitType::Any,
                &[event(1)],
            );
        }
        backend.set(event(1));
        assert_eq!(
            arbiter
                .pop_event_ready(&mut backend, event(1), 10)
                .unwrap()
                .wait_id,
            10
        );
        assert_eq!(
            arbiter.oldest_event_consumer_sequence(&backend, event(1)),
            None
        );
        let leases = backend.leases.clone();
        assert_eq!(arbiter.pop_event_ready(&mut backend, event(1), 20), None);
        assert_eq!(backend.leases, leases);
        assert_eq!(backend.lease_count(), 1);
        assert!(arbiter.contains(20));
        backend.set(event(1));
        assert_eq!(
            arbiter
                .pop_event_ready(&mut backend, event(1), 20)
                .unwrap()
                .wait_id,
            20
        );
        assert!(!backend.events[&(1, 1)].signaled);
        assert!(backend.leases.is_empty());
        assert!(arbiter.is_empty());
    }
}
