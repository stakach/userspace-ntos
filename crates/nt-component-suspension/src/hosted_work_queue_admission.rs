//! Fixed-capacity ownership of shared work-item ring slots.
//!
//! A producer reserves a distinct slot before writing its payload and publishes only after
//! the write. Consumers claim published entries in order, even while earlier callbacks remain
//! parked. Slot reuse waits for every earlier exact acknowledgement, so an uncertain callback
//! cannot permit reuse.

use core::sync::atomic::{AtomicU64, Ordering};

const VACANT: u64 = 0;
const RESERVED: u64 = 1;
const PUBLISHED: u64 = 2;
const CLAIMED: u64 = 3;
const ACKNOWLEDGED: u64 = 4;
const PHASE_BITS: u32 = 3;
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

/// Read-only observation of the oldest published entry. This is not a claim and
/// cannot acknowledge or authorize a callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedWorkQueuePending {
    sequence: u64,
    slot: usize,
}

/// Read-only cursor sample for diagnostics. Concurrent movement can make the
/// three loads non-atomic as a group; admission decisions use the slot phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedWorkQueueCursors {
    reserved: u64,
    dequeued: u64,
    retired: u64,
}

impl HostedWorkQueueCursors {
    pub fn reserved(self) -> u64 { self.reserved }
    pub fn dequeued(self) -> u64 { self.dequeued }
    pub fn retired(self) -> u64 { self.retired }
}

impl HostedWorkQueuePending {
    pub fn sequence(self) -> u64 { self.sequence }
    pub fn slot(self) -> usize { self.slot }
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
    dequeue: AtomicU64,
    retired: AtomicU64,
    slots: [AtomicU64; N],
}

impl<const N: usize> HostedWorkQueueAdmission<N> {
    pub fn new() -> Self {
        assert!(N > 0, "work queue capacity must be nonzero");
        let id = NEXT_QUEUE_ID.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |current| current.checked_add(1)).expect("work queue identity exhausted");
        Self { id, next: AtomicU64::new(0), dequeue: AtomicU64::new(0),
            retired: AtomicU64::new(0),
            slots: core::array::from_fn(|_| AtomicU64::new(VACANT)) }
    }

    pub fn cursors(&self) -> HostedWorkQueueCursors {
        HostedWorkQueueCursors {
            reserved: self.next.load(Ordering::Acquire),
            dequeued: self.dequeue.load(Ordering::Acquire),
            retired: self.retired.load(Ordering::Acquire),
        }
    }

    /// Claim a free slot without exposing its payload to the consumer. A full queue retains
    /// every existing owner and leaves the next sequence unchanged.
    pub fn reserve(&self) -> Result<HostedWorkQueueReservation, HostedWorkQueueAdmissionError> {
        loop {
            let sequence = self.next.load(Ordering::Acquire);
            if sequence > LAST_SEQUENCE {
                return Err(HostedWorkQueueAdmissionError::SequenceExhausted);
            }
            let retired = self.retired.load(Ordering::Acquire);
            if sequence.saturating_sub(retired) >= N as u64 {
                return Err(HostedWorkQueueAdmissionError::Full);
            }
            if self.next.compare_exchange_weak(sequence, sequence + 1,
                Ordering::AcqRel, Ordering::Acquire).is_err() {
                continue;
            }
            let slot = (sequence % N as u64) as usize;
            // The retirement frontier prevents reuse until the previous generation's
            // exact ACK. Its stamped phase is replaced only after reserving this slot.
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

    /// Inspect the next published payload without consuming it. A reserved head
    /// fences younger entries, including when producers publish out of order.
    pub fn peek_ready(&self) -> Option<HostedWorkQueuePending> {
        let sequence = self.dequeue.load(Ordering::Acquire);
        if sequence == self.next.load(Ordering::Acquire)
            || self.slots[self.slot(sequence)].load(Ordering::Acquire)
                != phase(sequence, PUBLISHED)
        {
            return None;
        }
        Some(HostedWorkQueuePending { sequence, slot: self.slot(sequence) })
    }

    /// Return the oldest unclaimed published entry exactly once. A reserved entry fences
    /// younger publication. A claimed entry advances the dequeue cursor independently
    /// of its terminal ACK, allowing another physical worker to run the next callback.
    pub fn claim_ready(&self) -> Option<HostedWorkQueueReady> {
        let sequence = self.dequeue.load(Ordering::Acquire);
        if sequence == self.next.load(Ordering::Acquire) { return None; }
        let slot = self.slot(sequence);
        self.slots[slot].compare_exchange(
            phase(sequence, PUBLISHED), phase(sequence, CLAIMED),
            Ordering::AcqRel, Ordering::Acquire,
        ).ok()?;
        // This claimant alone changed the slot's published phase. Other claimants may
        // briefly observe CLAIMED and return None, but cannot advance the cursor or
        // duplicate this claim.
        self.dequeue.compare_exchange(sequence, sequence + 1,
            Ordering::AcqRel, Ordering::Acquire).ok()?;
        Some(HostedWorkQueueReady { queue_id: self.id, sequence, slot })
    }

    /// ACK one entered callback by its exact one-use claim. Out-of-order ACKs are
    /// retained, but capacity advances only across a contiguous acknowledged prefix.
    pub fn acknowledge(&self, ready: HostedWorkQueueReady)
        -> Result<(), HostedWorkQueueAdmissionError>
    {
        if ready.queue_id != self.id || ready.slot != self.slot(ready.sequence)
            || ready.sequence >= self.dequeue.load(Ordering::Acquire)
        {
            return Err(HostedWorkQueueAdmissionError::WrongClaim);
        }
        self.slots[ready.slot].compare_exchange(
            phase(ready.sequence, CLAIMED), phase(ready.sequence, ACKNOWLEDGED),
            Ordering::AcqRel, Ordering::Acquire,
        ).map_err(|_| HostedWorkQueueAdmissionError::WrongClaim)?;
        self.advance_retired();
        Ok(())
    }

    fn advance_retired(&self) {
        loop {
            let sequence = self.retired.load(Ordering::Acquire);
            if sequence == self.dequeue.load(Ordering::Acquire)
                || self.slots[self.slot(sequence)].load(Ordering::Acquire)
                    != phase(sequence, ACKNOWLEDGED)
            {
                return;
            }
            let _ = self.retired.compare_exchange_weak(sequence, sequence + 1,
                Ordering::AcqRel, Ordering::Acquire);
        }
    }

    fn slot(&self, sequence: u64) -> usize { (sequence % N as u64) as usize }
}

impl<const N: usize> Default for HostedWorkQueueAdmission<N> {
    fn default() -> Self { Self::new() }
}

fn phase(sequence: u64, state: u64) -> u64 { (sequence << PHASE_BITS) | state }
