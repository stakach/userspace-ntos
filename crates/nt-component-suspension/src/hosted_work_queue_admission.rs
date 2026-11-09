//! Fixed-capacity ownership of shared work-item ring slots.
//!
//! A producer reserves a distinct slot before writing its payload and publishes only after
//! the write. The consumer claims published entries in order. A claimed slot remains owned
//! until its exact acknowledgement, so an uncertain callback cannot permit reuse.

use core::sync::atomic::{AtomicU64, Ordering};

const VACANT: u64 = 0;
const RESERVED: u64 = 1;
const PUBLISHED: u64 = 2;
const CLAIMED: u64 = 3;
const PHASE_BITS: u32 = 2;
const LAST_SEQUENCE: u64 = u64::MAX >> PHASE_BITS;

static NEXT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedWorkQueueAdmissionError {
    Full,
    SequenceExhausted,
    WrongReservation,
    WrongClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedWorkQueueReservation {
    queue_id: u64,
    sequence: u64,
    slot: usize,
}

impl HostedWorkQueueReservation {
    pub fn sequence(self) -> u64 { self.sequence }
    pub fn slot(self) -> usize { self.slot }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedWorkQueueReady {
    queue_id: u64,
    sequence: u64,
    slot: usize,
}

impl HostedWorkQueueReady {
    pub fn sequence(self) -> u64 { self.sequence }
    pub fn slot(self) -> usize { self.slot }
}

/// Admission metadata only; the native adapter owns payload storage and writes it between
/// `reserve` and `publish`. All methods are safe to call from multiple producer threads.
pub struct HostedWorkQueueAdmission<const N: usize> {
    id: u64,
    next: AtomicU64,
    head: AtomicU64,
    slots: [AtomicU64; N],
}

impl<const N: usize> HostedWorkQueueAdmission<N> {
    pub fn new() -> Self {
        assert!(N > 0, "work queue capacity must be nonzero");
        let id = NEXT_QUEUE_ID.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |current| current.checked_add(1)).expect("work queue identity exhausted");
        Self { id, next: AtomicU64::new(0), head: AtomicU64::new(0),
            slots: core::array::from_fn(|_| AtomicU64::new(VACANT)) }
    }

    /// Claim a free slot without exposing its payload to the consumer. A full queue retains
    /// every existing owner and leaves the next sequence unchanged.
    pub fn reserve(&self) -> Result<HostedWorkQueueReservation, HostedWorkQueueAdmissionError> {
        loop {
            let sequence = self.next.load(Ordering::Acquire);
            if sequence > LAST_SEQUENCE {
                return Err(HostedWorkQueueAdmissionError::SequenceExhausted);
            }
            let head = self.head.load(Ordering::Acquire);
            if sequence.saturating_sub(head) >= N as u64 {
                return Err(HostedWorkQueueAdmissionError::Full);
            }
            if self.next.compare_exchange_weak(sequence, sequence + 1,
                Ordering::AcqRel, Ordering::Acquire).is_err() {
                continue;
            }
            let slot = (sequence % N as u64) as usize;
            // Acknowledgement clears the old generation before it advances `head`.
            self.slots[slot].store(phase(sequence, RESERVED), Ordering::Release);
            return Ok(HostedWorkQueueReservation { queue_id: self.id, sequence, slot });
        }
    }

    /// Publish the payload after its native writes have completed. Reusing a copied ticket,
    /// or a ticket from another queue, never publishes a later slot generation.
    pub fn publish(&self, reservation: HostedWorkQueueReservation)
        -> Result<(), HostedWorkQueueAdmissionError>
    {
        if reservation.queue_id != self.id || reservation.slot != self.slot(reservation.sequence) {
            return Err(HostedWorkQueueAdmissionError::WrongReservation);
        }
        self.slots[reservation.slot].compare_exchange(
            phase(reservation.sequence, RESERVED), phase(reservation.sequence, PUBLISHED),
            Ordering::AcqRel, Ordering::Acquire,
        ).map(|_| ()).map_err(|_| HostedWorkQueueAdmissionError::WrongReservation)
    }

    /// Return the oldest published entry exactly once. A reserved head fences younger
    /// published entries; a claimed head fences duplicate consumption until ACK.
    pub fn claim_ready(&self) -> Option<HostedWorkQueueReady> {
        let sequence = self.head.load(Ordering::Acquire);
        if sequence == self.next.load(Ordering::Acquire) { return None; }
        let slot = self.slot(sequence);
        self.slots[slot].compare_exchange(
            phase(sequence, PUBLISHED), phase(sequence, CLAIMED),
            Ordering::AcqRel, Ordering::Acquire,
        ).ok()?;
        Some(HostedWorkQueueReady { queue_id: self.id, sequence, slot })
    }

    /// Release a consumed slot only for its exact one-use claim. A failed ACK preserves
    /// the head, so a different claim cannot retire this payload.
    pub fn acknowledge(&self, ready: HostedWorkQueueReady)
        -> Result<(), HostedWorkQueueAdmissionError>
    {
        if ready.queue_id != self.id || ready.slot != self.slot(ready.sequence)
            || self.head.load(Ordering::Acquire) != ready.sequence
        {
            return Err(HostedWorkQueueAdmissionError::WrongClaim);
        }
        self.slots[ready.slot].compare_exchange(
            phase(ready.sequence, CLAIMED), VACANT, Ordering::AcqRel, Ordering::Acquire,
        ).map_err(|_| HostedWorkQueueAdmissionError::WrongClaim)?;
        self.head.store(ready.sequence + 1, Ordering::Release);
        Ok(())
    }

    fn slot(&self, sequence: u64) -> usize { (sequence % N as u64) as usize }
}

impl<const N: usize> Default for HostedWorkQueueAdmission<N> {
    fn default() -> Self { Self::new() }
}

fn phase(sequence: u64, state: u64) -> u64 { (sequence << PHASE_BITS) | state }
