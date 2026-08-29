//! Kernel-owned continuation state for blocking NT LPC services.
//!
//! The broker owns ports, messages, and connection identity. This crate owns the small piece of
//! kernel policy needed between a broker `STATUS_PENDING` result and the eventual syscall resume:
//! reserve storage before the broker transition, publish exactly one typed wait, and take it
//! exactly once when completion, refusal, disconnect, cancellation, or copyout ends the wait.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

const DEFAULT_INITIAL_RESERVE: usize = 16;

/// Native service operation represented by a blocked receive continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveOperation {
    Listen,
    ReplyWaitReceive,
}

/// Broker endpoint and native output addresses retained while a receive is blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveRequest {
    pub port_handle: u64,
    pub receive_message: u64,
    pub port_context: u64,
    pub operation: ReceiveOperation,
}

impl ReceiveRequest {
    pub const fn is_valid(self) -> bool {
        self.port_handle != 0
            && self.receive_message != 0
            && (matches!(self.operation, ReceiveOperation::ReplyWaitReceive)
                || self.port_context == 0)
    }
}

/// One typed blocked receive plus the executive-specific continuation needed to resume it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingReceive<C> {
    pub request: ReceiveRequest,
    pub continuation: C,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    Full,
    InvalidRequest,
    StaleReservation,
}

enum Slot<T> {
    Empty,
    Reserved { generation: u64 },
    Occupied { generation: u64, value: T },
}

struct GenerationTable<T> {
    slots: Vec<Slot<T>>,
    initial_reserve: usize,
    next_generation: u64,
}

impl<T> GenerationTable<T> {
    const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            initial_reserve,
            next_generation: 1,
        }
    }

    fn reset(&mut self) -> Result<(), TableError> {
        self.slots.clear();
        if self.slots.capacity() < self.initial_reserve {
            self.slots
                .try_reserve(self.initial_reserve - self.slots.capacity())
                .map_err(|_| TableError::Full)?;
        }
        for _ in 0..self.initial_reserve {
            self.slots.push(Slot::Empty);
        }
        Ok(())
    }

    fn reserve(&mut self) -> Result<Reservation, TableError> {
        let available = self
            .slots
            .iter()
            .position(|entry| matches!(entry, Slot::Empty));
        let slot = if let Some(slot) = available {
            slot
        } else {
            self.slots.try_reserve(1).map_err(|_| TableError::Full)?;
            let slot = self.slots.len();
            self.slots.push(Slot::Empty);
            slot
        };
        let generation = self.next_generation.max(1);
        self.next_generation = generation.wrapping_add(1).max(1);
        self.slots[slot] = Slot::Reserved { generation };
        Ok(Reservation { slot, generation })
    }

    fn cancel(&mut self, reservation: Reservation) -> Result<(), TableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Empty;
                Ok(())
            }
            _ => Err(TableError::StaleReservation),
        }
    }

    fn publish(&mut self, reservation: Reservation, value: T) -> Result<usize, TableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Occupied {
                    generation: reservation.generation,
                    value,
                };
                Ok(reservation.slot)
            }
            _ => Err(TableError::StaleReservation),
        }
    }

    fn get(&self, slot: usize) -> Option<&T> {
        match self.slots.get(slot) {
            Some(Slot::Occupied { value, .. }) => Some(value),
            _ => None,
        }
    }

    fn occupied_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| matches!(entry, Slot::Occupied { .. }).then_some(slot))
    }

    fn next_occupied_after(&self, generation: u64) -> Option<(usize, u64, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| match entry {
                Slot::Occupied {
                    generation: current,
                    value,
                } if *current > generation => Some((slot, *current, value)),
                _ => None,
            })
            .min_by_key(|(_, current, _)| *current)
    }

    fn take(&mut self, slot: usize) -> Option<T> {
        let entry = self.slots.get_mut(slot)?;
        if !matches!(entry, Slot::Occupied { .. }) {
            return None;
        }
        let old = core::mem::replace(entry, Slot::Empty);
        match old {
            Slot::Occupied { value, .. } => Some(value),
            _ => unreachable!(),
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(|slot| matches!(slot, Slot::Empty))
    }

    fn slot_count(&self) -> usize {
        self.slots.len()
    }

    fn allocation_capacity(&self) -> usize {
        self.slots.capacity()
    }
}

/// Growable, generation-exact ownership table for pending LPC receives.
///
/// Allocation happens only in [`Self::reserve`], before the broker is allowed to commit the reply
/// half of `NtReplyWaitReceivePort`. Publishing and completing a wait cannot allocate.
pub struct ReceiveWaitTable<C> {
    inner: GenerationTable<PendingReceive<C>>,
}

impl<C> Default for ReceiveWaitTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> ReceiveWaitTable<C> {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            inner: GenerationTable::with_initial_reserve(initial_reserve),
        }
    }

    pub fn reset(&mut self) -> Result<(), TableError> {
        self.inner.reset()
    }

    pub fn reserve(&mut self) -> Result<Reservation, TableError> {
        self.inner.reserve()
    }

    pub fn cancel(&mut self, reservation: Reservation) -> Result<(), TableError> {
        self.inner.cancel(reservation)
    }

    pub fn publish(
        &mut self,
        reservation: Reservation,
        value: PendingReceive<C>,
    ) -> Result<usize, TableError> {
        if !value.request.is_valid() {
            return Err(TableError::InvalidRequest);
        }
        self.inner.publish(reservation, value)
    }

    pub fn get(&self, slot: usize) -> Option<&PendingReceive<C>> {
        self.inner.get(slot)
    }

    pub fn occupied_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.occupied_slots()
    }

    /// Return the next occupied slot in reservation order. This keeps receive polling FIFO even
    /// after a low-numbered slot has been freed and reused by a newer waiter.
    pub fn next_occupied_after(&self, generation: u64) -> Option<(usize, u64, &PendingReceive<C>)> {
        self.inner.next_occupied_after(generation)
    }

    pub fn take(&mut self, slot: usize) -> Option<PendingReceive<C>> {
        self.inner.take(slot)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn slot_count(&self) -> usize {
        self.inner.slot_count()
    }

    pub fn allocation_capacity(&self) -> usize {
        self.inner.allocation_capacity()
    }
}

/// Native connect operation represented by a blocked continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOperation {
    Connect,
    SecureConnect,
}

/// Broker connection identity and caller output addresses retained while a connect is blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    pub connection_id: u64,
    pub port_handle: u64,
    pub connection_information: u64,
    pub connection_information_length: u64,
    pub connection_information_capacity: u32,
    pub operation: ConnectOperation,
}

impl ConnectRequest {
    pub const fn is_valid(self) -> bool {
        self.connection_id != 0 && self.port_handle != 0
    }
}

/// One typed blocked connect plus the executive-specific continuation needed to resume it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingConnect<C> {
    pub request: ConnectRequest,
    pub continuation: C,
}

/// Broker identity and native reply address retained while `NtRequestWaitReplyPort` is blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestWaitRequest {
    pub port_handle: u64,
    pub reply_message: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub message_id: u32,
}

impl RequestWaitRequest {
    pub const fn is_valid(self) -> bool {
        self.port_handle != 0
            && self.reply_message != 0
            && self.client_process != 0
            && self.client_thread != 0
            && self.message_id != 0
    }
}

/// One typed blocked synchronous request plus the executive continuation needed to resume it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRequestWait<C> {
    pub request: RequestWaitRequest,
    pub continuation: C,
}

/// Growable, generation-exact ownership table for synchronous LPC request waiters.
pub struct RequestWaitTable<C> {
    inner: GenerationTable<PendingRequestWait<C>>,
}

impl<C> Default for RequestWaitTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> RequestWaitTable<C> {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            inner: GenerationTable::with_initial_reserve(initial_reserve),
        }
    }

    pub fn reset(&mut self) -> Result<(), TableError> {
        self.inner.reset()
    }

    pub fn reserve(&mut self) -> Result<Reservation, TableError> {
        self.inner.reserve()
    }

    pub fn cancel(&mut self, reservation: Reservation) -> Result<(), TableError> {
        self.inner.cancel(reservation)
    }

    pub fn publish(
        &mut self,
        reservation: Reservation,
        value: PendingRequestWait<C>,
    ) -> Result<usize, TableError> {
        if !value.request.is_valid() {
            return Err(TableError::InvalidRequest);
        }
        if self.inner.occupied_slots().any(|slot| {
            self.inner.get(slot).is_some_and(|wait| {
                wait.request.port_handle == value.request.port_handle
                    && wait.request.client_process == value.request.client_process
                    && wait.request.client_thread == value.request.client_thread
                    && wait.request.message_id == value.request.message_id
            })
        }) {
            return Err(TableError::InvalidRequest);
        }
        self.inner.publish(reservation, value)
    }

    pub fn get(&self, slot: usize) -> Option<&PendingRequestWait<C>> {
        self.inner.get(slot)
    }

    pub fn occupied_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.occupied_slots()
    }

    pub fn next_occupied_after(
        &self,
        generation: u64,
    ) -> Option<(usize, u64, &PendingRequestWait<C>)> {
        self.inner.next_occupied_after(generation)
    }

    pub fn take(&mut self, slot: usize) -> Option<PendingRequestWait<C>> {
        self.inner.take(slot)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn slot_count(&self) -> usize {
        self.inner.slot_count()
    }

    pub fn allocation_capacity(&self) -> usize {
        self.inner.allocation_capacity()
    }
}

/// Growable, generation-exact ownership table for pending LPC connects.
pub struct ConnectWaitTable<C> {
    inner: GenerationTable<PendingConnect<C>>,
}

impl<C> Default for ConnectWaitTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> ConnectWaitTable<C> {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            inner: GenerationTable::with_initial_reserve(initial_reserve),
        }
    }

    pub fn reset(&mut self) -> Result<(), TableError> {
        self.inner.reset()
    }

    pub fn reserve(&mut self) -> Result<Reservation, TableError> {
        self.inner.reserve()
    }

    pub fn cancel(&mut self, reservation: Reservation) -> Result<(), TableError> {
        self.inner.cancel(reservation)
    }

    pub fn publish(
        &mut self,
        reservation: Reservation,
        value: PendingConnect<C>,
    ) -> Result<usize, TableError> {
        if !value.request.is_valid() {
            return Err(TableError::InvalidRequest);
        }
        if self.inner.occupied_slots().any(|slot| {
            self.inner
                .get(slot)
                .is_some_and(|wait| wait.request.connection_id == value.request.connection_id)
        }) {
            return Err(TableError::InvalidRequest);
        }
        self.inner.publish(reservation, value)
    }

    pub fn get(&self, slot: usize) -> Option<&PendingConnect<C>> {
        self.inner.get(slot)
    }

    pub fn occupied_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.occupied_slots()
    }

    pub fn find_connection(&self, connection_id: u64) -> Option<(usize, &PendingConnect<C>)> {
        self.inner.occupied_slots().find_map(|slot| {
            let wait = self.inner.get(slot)?;
            (wait.request.connection_id == connection_id).then_some((slot, wait))
        })
    }

    pub fn take(&mut self, slot: usize) -> Option<PendingConnect<C>> {
        self.inner.take(slot)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn slot_count(&self) -> usize {
        self.inner.slot_count()
    }

    pub fn allocation_capacity(&self) -> usize {
        self.inner.allocation_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive(port_handle: u64, token: u64) -> PendingReceive<u64> {
        PendingReceive {
            request: ReceiveRequest {
                port_handle,
                receive_message: 0x1000 + token,
                port_context: 0x2000 + token,
                operation: ReceiveOperation::ReplyWaitReceive,
            },
            continuation: token,
        }
    }

    #[test]
    fn reservation_is_generation_exact() {
        let mut table = ReceiveWaitTable::with_initial_reserve(1);
        table.reset().unwrap();
        let stale = table.reserve().unwrap();
        table.cancel(stale).unwrap();
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        assert_eq!(
            table.publish(stale, receive(1, 10)),
            Err(TableError::StaleReservation)
        );
        assert_eq!(table.publish(current, receive(1, 11)), Ok(0));
        assert_eq!(table.take(0).unwrap().continuation, 11);
        assert!(table.is_empty());
    }

    #[test]
    fn multiple_receivers_may_wait_on_one_endpoint() {
        let mut table = ReceiveWaitTable::new();
        for token in 1..=3 {
            let reservation = table.reserve().unwrap();
            table.publish(reservation, receive(7, token)).unwrap();
        }
        let slots: alloc::vec::Vec<_> = table.occupied_slots().collect();
        assert_eq!(slots, [0, 1, 2]);
        assert_eq!(table.take(1).unwrap().continuation, 2);
        assert_eq!(table.get(0).unwrap().continuation, 1);
        assert_eq!(table.get(2).unwrap().continuation, 3);
    }

    #[test]
    fn invalid_native_output_state_is_rejected_without_consuming_reservation() {
        let mut table = ReceiveWaitTable::new();
        let reservation = table.reserve().unwrap();
        let invalid = PendingReceive {
            request: ReceiveRequest {
                port_handle: 1,
                receive_message: 0,
                port_context: 0,
                operation: ReceiveOperation::Listen,
            },
            continuation: 9,
        };
        assert_eq!(
            table.publish(reservation, invalid),
            Err(TableError::InvalidRequest)
        );
        table.cancel(reservation).unwrap();
    }

    #[test]
    fn reset_preserves_reserve_and_invalidates_old_tokens() {
        let mut table = ReceiveWaitTable::with_initial_reserve(4);
        let stale = table.reserve().unwrap();
        table.reset().unwrap();
        assert!(table.allocation_capacity() >= 4);
        assert_eq!(table.slot_count(), 4);
        assert_eq!(table.cancel(stale), Err(TableError::StaleReservation));
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        table.publish(current, receive(2, 4)).unwrap();
    }

    #[test]
    fn occupied_iteration_preserves_wait_order_after_slot_reuse() {
        let mut table = ReceiveWaitTable::new();
        for token in 1..=3 {
            let reservation = table.reserve().unwrap();
            table.publish(reservation, receive(7, token)).unwrap();
        }
        table.take(0).unwrap();
        let reused = table.reserve().unwrap();
        table.publish(reused, receive(7, 4)).unwrap();

        let mut generation = 0;
        let mut tokens = alloc::vec::Vec::new();
        while let Some((_, current, wait)) = table.next_occupied_after(generation) {
            generation = current;
            tokens.push(wait.continuation);
        }
        assert_eq!(tokens, [2, 3, 4]);
    }

    fn connect(connection_id: u64, token: u64) -> PendingConnect<u64> {
        PendingConnect {
            request: ConnectRequest {
                connection_id,
                port_handle: 0x4000 + token,
                connection_information: 0x5000 + token,
                connection_information_length: 0x6000 + token,
                connection_information_capacity: 32,
                operation: ConnectOperation::Connect,
            },
            continuation: token,
        }
    }

    #[test]
    fn connect_reservation_is_generation_exact() {
        let mut table = ConnectWaitTable::with_initial_reserve(1);
        table.reset().unwrap();
        let stale = table.reserve().unwrap();
        table.cancel(stale).unwrap();
        let current = table.reserve().unwrap();
        assert_eq!(
            table.publish(stale, connect(7, 10)),
            Err(TableError::StaleReservation)
        );
        assert_eq!(table.publish(current, connect(7, 11)), Ok(0));
        assert_eq!(table.find_connection(7).unwrap().1.continuation, 11);
    }

    #[test]
    fn connect_completion_is_selected_by_broker_identity() {
        let mut table = ConnectWaitTable::new();
        for (connection_id, token) in [(41, 1), (43, 2), (42, 3)] {
            let reservation = table.reserve().unwrap();
            table
                .publish(reservation, connect(connection_id, token))
                .unwrap();
        }
        let (slot, wait) = table.find_connection(42).unwrap();
        assert_eq!(wait.continuation, 3);
        assert_eq!(table.take(slot).unwrap().request.connection_id, 42);
        assert!(table.find_connection(42).is_none());
        assert!(table.find_connection(41).is_some());
        assert!(table.find_connection(43).is_some());
    }

    #[test]
    fn duplicate_or_invalid_connect_identity_is_rejected() {
        let mut table = ConnectWaitTable::new();
        let first = table.reserve().unwrap();
        table.publish(first, connect(9, 1)).unwrap();

        let duplicate = table.reserve().unwrap();
        assert_eq!(
            table.publish(duplicate, connect(9, 2)),
            Err(TableError::InvalidRequest)
        );
        table.cancel(duplicate).unwrap();

        let invalid = table.reserve().unwrap();
        assert_eq!(
            table.publish(invalid, connect(0, 3)),
            Err(TableError::InvalidRequest)
        );
        table.cancel(invalid).unwrap();
    }

    fn request_wait(message_id: u32, token: u64) -> PendingRequestWait<u64> {
        PendingRequestWait {
            request: RequestWaitRequest {
                port_handle: 0x7000,
                reply_message: 0x8000 + token,
                client_process: 4,
                client_thread: 8 + token,
                message_id,
            },
            continuation: token,
        }
    }

    #[test]
    fn request_waiters_preserve_broker_identity_and_fifo_order() {
        let mut table = RequestWaitTable::with_initial_reserve(2);
        table.reset().unwrap();
        for (message_id, token) in [(7, 1), (8, 2), (9, 3)] {
            let reservation = table.reserve().unwrap();
            table
                .publish(reservation, request_wait(message_id, token))
                .unwrap();
        }
        let mut generation = 0;
        let mut identities = alloc::vec::Vec::new();
        while let Some((_, current, wait)) = table.next_occupied_after(generation) {
            generation = current;
            identities.push(wait.request.message_id);
        }
        assert_eq!(identities, [7, 8, 9]);
        assert!(table.allocation_capacity() >= 3);
    }

    #[test]
    fn duplicate_or_invalid_request_wait_identity_is_rejected() {
        let mut table = RequestWaitTable::new();
        let first = table.reserve().unwrap();
        table.publish(first, request_wait(7, 1)).unwrap();

        let duplicate = table.reserve().unwrap();
        let mut same_identity = request_wait(7, 2);
        same_identity.request.client_thread = 9;
        assert_eq!(
            table.publish(duplicate, same_identity),
            Err(TableError::InvalidRequest)
        );
        table.cancel(duplicate).unwrap();

        let invalid = table.reserve().unwrap();
        let mut missing_reply = request_wait(8, 3);
        missing_reply.request.reply_message = 0;
        assert_eq!(
            table.publish(invalid, missing_reply),
            Err(TableError::InvalidRequest)
        );
        table.cancel(invalid).unwrap();
    }
}
