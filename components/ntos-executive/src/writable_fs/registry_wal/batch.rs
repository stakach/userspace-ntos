//! One move-only SYSTEM mutation batch over an exact physical WAL owner.
//!
//! CM mutation slots and their receipts are checked here. The physical owner retains the
//! exclusive mount lease, continuation, paired-header proof, and every uncertain native effect.

use super::*;
use nt_fs::{
    RegistryWalContinuation, SystemWalBatchError, SystemWalBatchPayload, SystemWalBatchReservation,
};

#[derive(Debug)]
#[must_use = "retain the exact reservation through CM COMMIT or confirmed cancellation"]
pub(crate) struct BatchReservation {
    payload: SystemWalBatchReservation,
    binding: nt_config_client::SystemHiveMutationStorageBinding,
    generation: u64,
}

enum Phase {
    Collecting(SystemWalBatchPayload),
    Empty { target: u64 },
    Frame { target: u64, bytes: Vec<u8> },
    Preparing { target: u64 },
    Marking { target: u64, entered: bool },
    Anchoring { target: u64 },
    Releasing { target: u64 },
    Done { target: u64 },
}

/// The sole live owner of a bounded batch and its physical SYSTEM WAL reserve.
#[must_use = "retain the batch through its exact marker and paired snapshot anchors"]
pub(crate) struct BatchOwner {
    physical: PhysicalWalOwner,
    cm_mount: nt_config_client::SystemHiveMount,
    phase: Phase,
}

fn status(error: SystemWalBatchError) -> u32 {
    match error {
        SystemWalBatchError::OutOfSpace | SystemWalBatchError::OutOfMemory => {
            nt_fs::STATUS_INSUFFICIENT_RESOURCES
        }
        SystemWalBatchError::Busy => snapshot_storage::BUSY,
        SystemWalBatchError::InvalidGeometry
        | SystemWalBatchError::InvalidJournal
        | SystemWalBatchError::SequenceGap => nt_fs::STATUS_DATA_ERROR,
        SystemWalBatchError::InvalidGeneration
        | SystemWalBatchError::GenerationGap
        | SystemWalBatchError::ReservationMismatch => nt_fs::STATUS_INVALID_DEVICE_REQUEST,
    }
}

impl BatchOwner {
    /// Admit only the exact native recheck and the published CM generation named by the
    /// caller. The CM sequence query is observational; the paired WAL proof independently
    /// establishes the durable storage authority under the retained physical lease.
    ///
    /// # Safety
    /// The lease, continuation, and rechecked proof must all belong to the same mounted
    /// physical reserve. No other writer may own or reuse them during this call.
    pub(crate) unsafe fn admit_rechecked(
        prepared: &nt_config_client::PreparedSystemHiveMutation,
        lease: snapshot_storage::Lease,
        continuation: RegistryWalContinuation,
        rechecked: nt_fs::RecheckedPairedWalSnapshot,
        durable_generation: u64,
    ) -> Result<Self, u32> {
        let preflight = prepared.expected_generation() == durable_generation
            && durable_generation != 0
            && crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT == Some(prepared.mount())
            && crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire)
                == durable_generation
            && crate::LIVE_CONFIG_MANAGER_SYSTEM_PUBLISHED_GENERATION.load(Ordering::Acquire)
                == durable_generation
            && Some(*lease.identity()) == crate::fs_loader::exec_fs_mount_identity()
            && ensure_mounted().is_ok()
            && !legacy_snapshot_writes_allowed();
        if !preflight {
            restore_continuation(lease, continuation, rechecked.into_pair())?;
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }

        // This read does not authorize storage or enter native I/O. Bind it to precisely
        // the preparation's mount and preceding published generation.
        let previous_hive_sequence = unsafe { crate::CONFIG_CLIENT_PTR.as_mut() }
            .ok_or(crate::CONFIG_STATUS_DEVICE_NOT_READY as u32)
            .and_then(|client| {
                client
                    .query_system_hive_sequence_at_mount(
                        prepared.mount(),
                        prepared.expected_generation(),
                    )
                    .map_err(|error| error as u32)
            });
        let previous_hive_sequence = match previous_hive_sequence {
            Ok(sequence) => sequence,
            Err(refusal) => {
                restore_continuation(lease, continuation, rechecked.into_pair())?;
                return Err(refusal);
            }
        };

        let manifest = rechecked.manifest();
        // SAFETY: admission checked the mounted reserve identity; the recheck minted the
        // exact paired proof while this exclusive lease remained held.
        let mut physical = unsafe {
            PhysicalWalOwner::resume_authority(
                lease,
                continuation,
                PairAuthority::Rechecked(rechecked),
                manifest,
            )?
        };
        let payload = physical.frame_room().and_then(|room| {
            SystemWalBatchPayload::new(
                durable_generation,
                previous_hive_sequence,
                room.remaining_sectors,
                room.sector_bytes,
            )
            .map_err(status)
        });
        let payload = match payload {
            Ok(payload) => payload,
            Err(error) => {
                // Neither BEGIN nor a native effect has occurred. Never drop an owner
                // whose exact continuation could not be restored.
                if let Err(release_error) = physical.release_aborted() {
                    core::mem::forget(physical);
                    return Err(release_error);
                }
                return Err(error);
            }
        };
        Ok(Self {
            physical,
            cm_mount: prepared.mount(),
            phase: Phase::Collecting(payload),
        })
    }

    pub(crate) fn mount(&self) -> nt_memory_manager::SectionMountId {
        self.physical.mount()
    }

    pub(crate) fn cm_mount(&self) -> nt_config_client::SystemHiveMount {
        self.cm_mount
    }

    pub(crate) fn published_generation(&self) -> u64 {
        match &self.phase {
            Phase::Collecting(payload) => payload.published_generation(),
            Phase::Empty { target }
            | Phase::Frame { target, .. }
            | Phase::Preparing { target }
            | Phase::Marking { target, .. }
            | Phase::Anchoring { target }
            | Phase::Releasing { target }
            | Phase::Done { target } => *target,
        }
    }

    /// A prior nonempty journal can be drained before a later journal asks for frame room.
    /// Empty-only publications cannot make an oversized journal fit this physical frame.
    pub(crate) fn has_collected_payload(&self) -> bool {
        matches!(&self.phase, Phase::Collecting(payload) if !payload.payload().is_empty())
    }

    /// Reserve the prepared journal before entering CM COMMIT. Every refusal returns the
    /// caller's exact Vec, and no second reservation can pass the payload's sole slot.
    pub(crate) fn reserve(
        &mut self,
        prepared: &nt_config_client::PreparedSystemHiveMutation,
        bytes: Vec<u8>,
    ) -> Result<BatchReservation, (SystemWalBatchError, Vec<u8>)> {
        let Phase::Collecting(payload) = &mut self.phase else {
            return Err((SystemWalBatchError::Busy, bytes));
        };
        if self.cm_mount != prepared.mount()
            || prepared.expected_generation() != payload.published_generation()
            || unsafe { crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT } != Some(prepared.mount())
            || crate::LIVE_CONFIG_MANAGER_SYSTEM_PUBLISHED_GENERATION.load(Ordering::Acquire)
                != payload.published_generation()
            || bytes.as_slice() != prepared.durable_journal()
        {
            return Err((SystemWalBatchError::ReservationMismatch, bytes));
        }
        let generation = prepared.next_generation();
        let payload = payload.reserve(generation, bytes)?;
        Ok(BatchReservation {
            payload,
            binding: prepared.storage_binding(),
            generation,
        })
    }

    /// A validated positive CM receipt moves this exact journal into the sealed frame.
    /// The reservation remains with the caller on every mismatch.
    pub(crate) fn append_committed(
        &mut self,
        reservation: BatchReservation,
        receipt: nt_config_client::SystemHiveMutationCommitReceipt,
    ) -> Result<(), (SystemWalBatchError, BatchReservation)> {
        let Phase::Collecting(payload) = &mut self.phase else {
            return Err((SystemWalBatchError::Busy, reservation));
        };
        if !receipt.matches_storage_binding(reservation.binding)
            || receipt.outcome().generation != reservation.generation
        {
            return Err((SystemWalBatchError::ReservationMismatch, reservation));
        }
        match payload.append_committed(reservation.payload) {
            Ok(()) => Ok(()),
            Err((error, retained)) => Err((
                error,
                BatchReservation {
                    payload: retained,
                    binding: reservation.binding,
                    generation: reservation.generation,
                },
            )),
        }
    }

    /// Call only after exact pre-COMMIT no-effect confirmation or matching CM abort.
    pub(crate) fn cancel(
        &mut self,
        reservation: BatchReservation,
    ) -> Result<Vec<u8>, (SystemWalBatchError, BatchReservation)> {
        let Phase::Collecting(payload) = &mut self.phase else {
            return Err((SystemWalBatchError::Busy, reservation));
        };
        match payload.cancel(reservation.payload) {
            Ok(bytes) => Ok(bytes),
            Err((error, retained)) => Err((
                error,
                BatchReservation {
                    payload: retained,
                    binding: reservation.binding,
                    generation: reservation.generation,
                },
            )),
        }
    }

    /// Freeze the batch only when no CM COMMIT reservation remains in flight.
    pub(crate) fn request_drain(&mut self) -> Result<(), SystemWalBatchError> {
        let Phase::Collecting(payload) = &self.phase else {
            return Ok(());
        };
        if unsafe { crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT } != Some(self.cm_mount)
            || crate::LIVE_CONFIG_MANAGER_SYSTEM_PUBLISHED_GENERATION.load(Ordering::Acquire)
                != payload.published_generation()
        {
            return Err(SystemWalBatchError::Busy);
        }
        let old = core::mem::replace(&mut self.phase, Phase::Done { target: 0 });
        let Phase::Collecting(payload) = old else {
            self.phase = old;
            return Ok(());
        };
        match payload.seal() {
            Ok(sealed) => {
                let (_, target, bytes) = sealed.into_parts();
                self.phase = match bytes {
                    Some(bytes) => Phase::Frame { target, bytes },
                    None => Phase::Empty { target },
                };
                Ok(())
            }
            Err((error, payload)) => {
                self.phase = Phase::Collecting(payload);
                Err(error)
            }
        }
    }

    /// Drive one retained physical batch. Busy or uncertain outcomes leave this owner and
    /// phase intact for the exact native completion path. The target is returned only after
    /// the marker and both anchors, or after an empty batch's unchanged proof is restored.
    pub(crate) fn advance_drain(&mut self) -> Result<u64, u32> {
        loop {
            match &mut self.phase {
                Phase::Collecting(_) => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
                Phase::Empty { target } => {
                    let target = *target;
                    self.physical.release_aborted()?;
                    self.phase = Phase::Done { target };
                }
                Phase::Frame { target, bytes } => {
                    let target = *target;
                    let owned = core::mem::take(bytes);
                    match self.physical.begin_payload_owned(owned) {
                        Ok(()) => self.phase = Phase::Preparing { target },
                        Err((error, retained)) => {
                            *bytes = retained;
                            return Err(error);
                        }
                    }
                }
                Phase::Preparing { target } => {
                    let target = *target;
                    self.physical.prepare()?;
                    self.phase = Phase::Marking {
                        target,
                        entered: false,
                    };
                }
                Phase::Marking { target, entered } => {
                    let target = *target;
                    if !*entered {
                        self.physical.can_commit_marker(false)?;
                        // Retain this before the marker can enter native I/O. A retry after
                        // asynchronous completion must not demand Prepared again.
                        *entered = true;
                    }
                    self.physical.commit_marker()?;
                    self.phase = Phase::Anchoring { target };
                }
                Phase::Anchoring { target } => {
                    let target = *target;
                    self.physical.anchor()?;
                    self.phase = Phase::Releasing { target };
                }
                Phase::Releasing { target } => {
                    let target = *target;
                    self.physical.release_anchored()?;
                    self.phase = Phase::Done { target };
                }
                Phase::Done { target } => return Ok(*target),
            }
        }
    }

    pub(crate) fn native_io_active(&self) -> bool {
        self.physical.native_io_active()
    }

    pub(crate) fn claim_native_io(
        &mut self,
    ) -> Result<Option<(nt_fs::AsyncWalIoRequest, nt_fs::BlockOperation, Vec<u8>)>, u32> {
        self.physical.claim_native_io()
    }

    pub(crate) fn mark_native_io_entered(
        &mut self,
        request: nt_fs::AsyncWalIoRequest,
    ) -> Result<(), u32> {
        self.physical.mark_native_io_entered(request)
    }

    pub(crate) fn release_unentered_native_io(
        &mut self,
        request: nt_fs::AsyncWalIoRequest,
    ) -> Result<(), u32> {
        self.physical.release_unentered_native_io(request)
    }

    pub(crate) fn refuse_unentered_native_io(
        &mut self,
        request: nt_fs::AsyncWalIoRequest,
    ) -> Result<nt_fs::AsyncWalRefusal, u32> {
        let (refusal, bytes) = self.physical.refuse_unentered_native_io_owned(request)?;
        match (refusal, bytes) {
            (nt_fs::AsyncWalRefusal::NoEffect, Some(bytes)) => {
                let Phase::Preparing { target } = self.phase else {
                    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                    core::mem::forget(bytes);
                    return Err(nt_fs::STATUS_DATA_ERROR);
                };
                self.phase = Phase::Frame { target, bytes };
                Ok(refusal)
            }
            (nt_fs::AsyncWalRefusal::RetainedEffects, None) => Ok(refusal),
            (_, Some(bytes)) => {
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                core::mem::forget(bytes);
                Err(nt_fs::STATUS_DATA_ERROR)
            }
            _ => {
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                Err(nt_fs::STATUS_DATA_ERROR)
            }
        }
    }

    pub(crate) fn complete_native_io(
        &mut self,
        request: nt_fs::AsyncWalIoRequest,
        result: Result<&[u8], nt_status::NtStatus>,
    ) -> Result<super::super::native_snapshot_io::SnapshotCompletion, u32> {
        self.physical.complete_native_io(request, result)
    }
}
