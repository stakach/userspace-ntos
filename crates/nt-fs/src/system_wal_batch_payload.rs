//! A bounded, move-only payload for several published SYSTEM mutations in one WAL frame.
//!
//! The executive validates the exact CM receipt before calling `append_committed`. This crate
//! owns the journal bytes, capacity reservation, and HLR1 sequence rule; it does not decide
//! whether CM has published a mutation or whether the physical WAL marker is durable.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_hive_core::{complete_log_sequence_span_from, HiveLogReplayError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemWalBatchError {
    InvalidGeneration,
    GenerationGap,
    InvalidJournal,
    SequenceGap,
    InvalidGeometry,
    OutOfSpace,
    OutOfMemory,
    Busy,
    ReservationMismatch,
}

/// The exact journal and preflight proof for the sole mutation entering CM COMMIT.
/// An uncertain COMMIT keeps this value with its caller until the exact result is known.
#[derive(Debug)]
#[must_use = "retain the reservation until its CM COMMIT or exact abort is resolved"]
pub struct SystemWalBatchReservation {
    batch_id: u64,
    id: u64,
    generation: u64,
    last_log_sequence: u64,
    journal: Vec<u8>,
}

/// The first live SYSTEM writer owns this together with the exact physical WAL reserve.
/// Other writers cannot bypass the outstanding reservation or append past the bounded frame.
#[derive(Debug)]
#[must_use = "retain published SYSTEM journals until their physical WAL barrier settles"]
pub struct SystemWalBatchPayload {
    batch_id: u64,
    durable_floor: u64,
    published_generation: u64,
    max_frame_bytes: usize,
    payload: Vec<u8>,
    last_log_sequence: u64,
    pending: Option<u64>,
    next_id: u64,
}

static NEXT_BATCH_ID: AtomicU64 = AtomicU64::new(1);

/// One sealed physical WAL payload and the CM generation reached when its marker settles.
/// Empty-only generations need no WAL frame and already advance the in-process durable floor.
#[derive(Debug)]
#[must_use = "retain the sealed payload until its exact physical barrier settles"]
pub struct SealedSystemWalBatch {
    durable_floor: u64,
    target_generation: u64,
    payload: Vec<u8>,
}

impl SystemWalBatchPayload {
    /// `previous_hive_sequence` is the exact semantic sequence of the preceding durable
    /// SYSTEM WAL prefix. `remaining_frame_sectors` includes the future PREPARE and COMMIT
    /// sectors, from the same leased WAL instance that will receive the sealed payload.
    pub fn new(
        durable_floor: u64,
        previous_hive_sequence: u64,
        remaining_frame_sectors: u64,
        sector_bytes: usize,
    ) -> Result<Self, SystemWalBatchError> {
        if durable_floor == 0 {
            return Err(SystemWalBatchError::InvalidGeneration);
        }
        if sector_bytes == 0 {
            return Err(SystemWalBatchError::InvalidGeometry);
        }
        let payload_sectors = remaining_frame_sectors.checked_sub(2).unwrap_or(0);
        let max_frame_bytes = u128::from(payload_sectors)
            .checked_mul(sector_bytes as u128)
            .ok_or(SystemWalBatchError::InvalidGeometry)?
            .min(u128::from(u32::MAX))
            .min(usize::MAX as u128) as usize;
        let batch_id = NEXT_BATCH_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| SystemWalBatchError::InvalidGeneration)?;
        Ok(Self {
            batch_id,
            durable_floor,
            published_generation: durable_floor,
            max_frame_bytes,
            payload: Vec::new(),
            last_log_sequence: previous_hive_sequence,
            pending: None,
            next_id: 1,
        })
    }

    pub const fn durable_floor(&self) -> u64 {
        self.durable_floor
    }
    pub const fn published_generation(&self) -> u64 {
        self.published_generation
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Validate and preallocate before CM COMMIT. Failure returns the caller's exact bytes.
    /// At most one reservation may be in flight because CM has one SYSTEM mutation slot.
    pub fn reserve(
        &mut self,
        generation: u64,
        journal: Vec<u8>,
    ) -> Result<SystemWalBatchReservation, (SystemWalBatchError, Vec<u8>)> {
        let checked = (|| {
            if self.pending.is_some() {
                return Err(SystemWalBatchError::Busy);
            }
            if self.published_generation.checked_add(1) != Some(generation) {
                return Err(SystemWalBatchError::GenerationGap);
            }
            let next_len = self
                .payload
                .len()
                .checked_add(journal.len())
                .ok_or(SystemWalBatchError::OutOfSpace)?;
            if next_len > self.max_frame_bytes || u32::try_from(next_len).is_err() {
                return Err(SystemWalBatchError::OutOfSpace);
            }
            let last_log_sequence = if journal.is_empty() {
                self.last_log_sequence
            } else {
                complete_log_sequence_span_from(&journal, self.last_log_sequence)
                    .map_err(|error| match error {
                        HiveLogReplayError::SequenceGap
                        | HiveLogReplayError::NonAdvancingSequence => {
                            SystemWalBatchError::SequenceGap
                        }
                        _ => SystemWalBatchError::InvalidJournal,
                    })?
                    .1
            };
            let next_id = self
                .next_id
                .checked_add(1)
                .ok_or(SystemWalBatchError::InvalidGeneration)?;
            self.payload
                .try_reserve_exact(journal.len())
                .map_err(|_| SystemWalBatchError::OutOfMemory)?;
            Ok((last_log_sequence, next_id))
        })();
        let (last_log_sequence, next_id) = match checked {
            Ok(checked) => checked,
            Err(error) => return Err((error, journal)),
        };
        let id = self.next_id;
        self.next_id = next_id;
        self.pending = Some(id);
        Ok(SystemWalBatchReservation {
            batch_id: self.batch_id,
            id,
            generation,
            last_log_sequence,
            journal,
        })
    }

    /// The executive calls this only after a positive receipt matches the prepared CM binding.
    /// Every fallible allocation and frame-size check was completed by `reserve`.
    pub fn append_committed(
        &mut self,
        reservation: SystemWalBatchReservation,
    ) -> Result<(), (SystemWalBatchError, SystemWalBatchReservation)> {
        if self.batch_id != reservation.batch_id
            || self.pending != Some(reservation.id)
            || self.published_generation.checked_add(1) != Some(reservation.generation)
            || self
                .payload
                .len()
                .checked_add(reservation.journal.len())
                .is_none_or(|len| len > self.max_frame_bytes || len > self.payload.capacity())
        {
            return Err((SystemWalBatchError::ReservationMismatch, reservation));
        }
        self.payload.extend_from_slice(&reservation.journal);
        self.published_generation = reservation.generation;
        self.last_log_sequence = reservation.last_log_sequence;
        self.pending = None;
        if self.payload.is_empty() {
            // A no-storage COMMIT is immediately covered only when no older bytes wait.
            self.durable_floor = self.published_generation;
        }
        Ok(())
    }

    /// Return an uncommitted journal to its caller after exact pre-COMMIT cancellation.
    pub fn cancel(
        &mut self,
        reservation: SystemWalBatchReservation,
    ) -> Result<Vec<u8>, (SystemWalBatchError, SystemWalBatchReservation)> {
        if self.batch_id != reservation.batch_id || self.pending != Some(reservation.id) {
            return Err((SystemWalBatchError::ReservationMismatch, reservation));
        }
        self.pending = None;
        Ok(reservation.journal)
    }

    /// Seal only when no CM COMMIT is in flight. A refusal returns the exact owner unchanged.
    pub fn seal(self) -> Result<SealedSystemWalBatch, (SystemWalBatchError, Self)> {
        if self.pending.is_some() {
            return Err((SystemWalBatchError::Busy, self));
        }
        Ok(SealedSystemWalBatch {
            durable_floor: self.durable_floor,
            target_generation: self.published_generation,
            payload: self.payload,
        })
    }
}

impl SealedSystemWalBatch {
    pub const fn durable_floor(&self) -> u64 {
        self.durable_floor
    }
    pub const fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn wal_payload(&self) -> Option<&[u8]> {
        (!self.payload.is_empty()).then_some(&self.payload)
    }

    /// Transfer the owned bytes into one `RegistryWal::begin` without cloning them.
    pub fn into_parts(self) -> (u64, u64, Option<Vec<u8>>) {
        let payload = if self.payload.is_empty() {
            None
        } else {
            Some(self.payload)
        };
        (self.durable_floor, self.target_generation, payload)
    }
}
