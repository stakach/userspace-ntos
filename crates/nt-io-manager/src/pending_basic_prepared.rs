//! Move-only FileBasic preparation beside the Copy pending File I/O delivery row.
//!
//! This sidecar owns the captured semantic input, prepared MemFs mutation and a move-only native
//! Overlay File lifetime token supplied by its adapter. The native route transfers its retained
//! local reference into this owner until an exact terminal returns it to the delivery row.
//! Neither a claim nor an observed baseline grants
//! snapshot/WAL authority or publishes the caller's IOSB and Reply.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{PendingFileIo, PendingFileIoIdentity, PendingFileIoOperation,
    PendingBasicPrimaryReservation, PendingFileIoParkError, PendingFileIoReservation,
    PendingFileIoTable};

static NEXT_TABLE_ID: AtomicU64 = AtomicU64::new(1);

/// The Overlay File lifetime owner is supplied by the native adapter and is never copied here.
/// The adapter must provide a dedicated retained reference or transfer the pending row's owned
/// local reference with a single release authority; a syscall-local handler borrow is insufficient.
#[must_use = "retain or explicitly release the native Overlay File reference"]
pub struct PendingBasicPreparedOwner<FileReference> {
    input: [u8; 40],
    stable_file_id: u64,
    prepared: Option<nt_fs::PreparedBasicInformation>,
    applied: Option<(u32, bool)>,
    file: FileReference,
}

impl<FileReference> PendingBasicPreparedOwner<FileReference> {
    /// Freeze the exact 40-byte semantic input and its resolved mutation together. A failed
    /// preparation returns the native File reference without dropping or replacing it.
    pub fn prepare(fs: &nt_fs::FileSystem, handle: u64, input: [u8; 40],
        file: FileReference) -> Result<Self, (u32, FileReference)> {
        match fs.prepare_basic_information(handle, &input) {
            Ok(prepared) => Ok(Self {
                input, stable_file_id: prepared.resolved_metadata().file_id,
                prepared: Some(prepared), applied: None, file,
            }),
            Err(status) => Err((status, file)),
        }
    }

    pub fn input(&self) -> &[u8; 40] { &self.input }
    /// The node's identity survives closing and reopening the same path with a new handle.
    pub fn stable_file_id(&self) -> u64 { self.stable_file_id }
    pub fn prepared(&self) -> Option<&nt_fs::PreparedBasicInformation> { self.prepared.as_ref() }
    pub fn file(&self) -> &FileReference { &self.file }

    /// Apply the frozen in-memory plan once. The terminal receipt stays beside the File owner
    /// if exact row settlement needs another turn; a retry cannot execute the mutation again.
    pub fn apply_snapshot_once(&mut self, fs: &mut nt_fs::FileSystem) -> (u32, bool) {
        if let Some(applied) = self.applied { return applied; }
        let Some(prepared) = self.prepared.take() else {
            return (nt_fs::STATUS_DATA_ERROR, false);
        };
        let result = prepared.rebase_snapshot(fs, &self.input).and_then(|fresh| {
            let changed = fresh.changes_volume();
            fs.apply_prepared_basic_information(fresh).map(|_| changed)
        });
        let applied = match result {
            Ok(changed) => (nt_fs::STATUS_SUCCESS, changed),
            Err(status) => (status, false),
        };
        self.applied = Some(applied);
        applied
    }

    pub fn refuse_snapshot_once(&mut self, status: u32) -> (u32, bool) {
        if let Some(applied) = self.applied { return applied; }
        self.prepared = None;
        self.applied = Some((status, false));
        (status, false)
    }

    pub fn into_file(self) -> FileReference { self.file }

    /// Transfer the remaining plan (if unentered) and File after a known terminal or no-effect
    /// cancellation. An applied plan is represented by the retained terminal receipt instead.
    pub fn into_parts(self) -> ([u8; 40], Option<nt_fs::PreparedBasicInformation>, FileReference) {
        (self.input, self.prepared, self.file)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Ready, Claimed, Uncertain }

struct Entry<FileReference> {
    identity: PendingFileIoIdentity,
    irp_id: u64,
    phase: Phase,
    owner: PendingBasicPreparedOwner<FileReference>,
}

/// Exact claim token. Losing it leaves the sidecar owned; it never releases an entered effect.
#[must_use = "retain through native terminal or uncertain continuation"]
pub struct PendingBasicPreparedClaim {
    table_id: u64,
    identity: PendingFileIoIdentity,
    irp_id: u64,
}

/// A generation-exact sidecar slot reserved before retaining the native File. It is move-only;
/// admission or explicit pre-effect cancellation consumes the slot claim.
#[must_use = "commit the Basic owner or cancel the unused sidecar slot"]
pub struct PendingBasicPreparedReservation {
    table_id: u64,
    slot: usize,
    generation: u64,
}

/// Bounded sidecar for parked FileBasic owners. A pending row remains the sole delivery owner.
pub struct PendingBasicPreparedTable<FileReference> {
    entries: Vec<Option<Entry<FileReference>>>,
    reservations: Vec<u64>,
    table_id: u64,
    limit: usize,
    next_reservation_generation: u64,
}

/// Admission refusal before any Basic effect. A row-shape failure preserves the pending table's
/// exact reason; the caller also receives its original delivery row and move-only File owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingBasicPreparedAdmissionError {
    SidecarUnavailable,
    PendingRow(PendingFileIoParkError),
}

impl<FileReference> Default for PendingBasicPreparedTable<FileReference> {
    fn default() -> Self { Self::new() }
}

impl<FileReference> PendingBasicPreparedTable<FileReference> {
    const DEFAULT_LIMIT: usize = 16;

    pub const fn new() -> Self { Self::with_limit(Self::DEFAULT_LIMIT) }

    pub const fn with_limit(limit: usize) -> Self {
        Self { entries: Vec::new(), reservations: Vec::new(), table_id: 0, limit,
            next_reservation_generation: 1 }
    }

    pub fn len(&self) -> usize { self.entries.iter().filter(|entry| entry.is_some()).count() }

    fn exact_row(pending: &PendingFileIoTable, identity: PendingFileIoIdentity,
        irp_id: u64, allow_abandoned: bool) -> bool {
        let Some(row) = pending.get_exact(identity) else { return false; };
        row.irp_id == irp_id && row.delivery_state == 0
            && (allow_abandoned || !row.consumer_abandoned)
            && matches!(row.operation, PendingFileIoOperation::OwnedBasicPreflight(_))
    }

    fn admission_slot(&mut self, identity: Option<PendingFileIoIdentity>) -> Option<usize> {
        if self.len() + self.reservations.iter().filter(|&&generation| generation != 0).count()
            >= self.limit
            || identity.is_some_and(|identity| self.entries.iter().flatten().any(|entry| {
                entry.identity.table() == identity.table()
                    && entry.identity.slot() == identity.slot()
            }))
        { return None; }
        let slot = if let Some(slot) = self.entries.iter().zip(self.reservations.iter())
            .position(|(entry, generation)| entry.is_none() && *generation == 0) {
            slot
        } else {
            if self.entries.try_reserve(1).is_err()
                || self.reservations.try_reserve(1).is_err() { return None; }
            self.entries.push(None);
            self.reservations.push(0);
            self.entries.len() - 1
        };
        if self.table_id == 0 {
            self.table_id = match NEXT_TABLE_ID.try_update(Ordering::Relaxed,
                Ordering::Relaxed, |id| id.checked_add(1)) {
                Ok(id) => id,
                Err(_) => return None,
            };
        }
        Some(slot)
    }

    pub fn reserve_admission(&mut self) -> Option<PendingBasicPreparedReservation> {
        let generation = self.next_reservation_generation;
        if generation == 0 { return None; }
        let slot = self.admission_slot(None)?;
        self.next_reservation_generation = generation.checked_add(1).unwrap_or(0);
        self.reservations[slot] = generation;
        Some(PendingBasicPreparedReservation { table_id: self.table_id, slot, generation })
    }

    pub fn admission_live(&self, reservation: &PendingBasicPreparedReservation) -> bool {
        reservation.table_id != 0 && reservation.table_id == self.table_id
            && self.reservations.get(reservation.slot).copied() == Some(reservation.generation)
            && self.entries[reservation.slot].is_none()
    }

    pub fn cancel_admission(&mut self, reservation: PendingBasicPreparedReservation) -> bool {
        if !self.admission_live(&reservation) { return false; }
        self.reservations[reservation.slot] = 0;
        true
    }

    /// Commit a preallocated sidecar and its move-only primary File row in one table-bound
    /// transition. No callback or allocation occurs between the final checks and publication.
    /// A refusal returns every original owner unchanged so the primary can become a no-effect
    /// inline terminal without borrowing a second File row.
    pub fn try_admit_pre_reserved_exact(&mut self, pending: &mut PendingFileIoTable,
        sidecar: PendingBasicPreparedReservation,
        primary: PendingBasicPrimaryReservation, row: PendingFileIo,
        owner: PendingBasicPreparedOwner<FileReference>,
    ) -> Result<PendingFileIoIdentity,
        (PendingBasicPreparedAdmissionError, PendingFileIo,
            PendingBasicPreparedOwner<FileReference>, PendingBasicPrimaryReservation,
            PendingBasicPreparedReservation)> {
        let identity = primary.identity();
        if !self.admission_live(&sidecar) {
            return Err((PendingBasicPreparedAdmissionError::SidecarUnavailable,
                row, owner, primary, sidecar));
        }
        if !matches!(row.operation, PendingFileIoOperation::OwnedBasicPreflight(_)) {
            return Err((PendingBasicPreparedAdmissionError::PendingRow(
                PendingFileIoParkError::InvalidRecord), row, owner, primary, sidecar));
        }
        let irp_id = row.irp_id;
        if let Err((error, row, primary)) = pending.try_park_basic_primary(primary, row) {
            return Err((PendingBasicPreparedAdmissionError::PendingRow(error),
                row, owner, primary, sidecar));
        }
        self.entries[sidecar.slot] = Some(Entry {
            identity, irp_id, phase: Phase::Ready, owner,
        });
        self.reservations[sidecar.slot] = 0;
        Ok(identity)
    }

    /// Publish the exact Basic delivery row and its move-only prepared owner as one admission.
    /// All fallible sidecar work finishes before the pending row can be observed. A refusal
    /// cancels only the exact still-live unoccupied reservation and returns both the delivery
    /// row and File reference without physical entry.
    pub fn admit_reserved_exact(&mut self, pending: &mut PendingFileIoTable,
        reservation: PendingFileIoReservation, row: PendingFileIo,
        owner: PendingBasicPreparedOwner<FileReference>,
    ) -> Result<PendingFileIoIdentity,
        (PendingBasicPreparedAdmissionError, PendingFileIo,
            PendingBasicPreparedOwner<FileReference>)> {
        let admitted = self.try_admit_reserved_exact(pending, reservation, row, owner);
        if admitted.is_err() { pending.cancel_reservation(reservation); }
        admitted
    }

    /// Legacy caller-supplied reservation admission used by host model tests. Native Basic SET
    /// uses the pre-reserved sidecar and move-only primary claim above.
    pub fn try_admit_reserved_exact(&mut self, pending: &mut PendingFileIoTable,
        reservation: PendingFileIoReservation, row: PendingFileIo,
        owner: PendingBasicPreparedOwner<FileReference>,
    ) -> Result<PendingFileIoIdentity,
        (PendingBasicPreparedAdmissionError, PendingFileIo,
            PendingBasicPreparedOwner<FileReference>)> {
        let identity = reservation.identity();
        if !matches!(row.operation, PendingFileIoOperation::OwnedBasicPreflight(_)) {
            return Err((PendingBasicPreparedAdmissionError::PendingRow(
                PendingFileIoParkError::InvalidRecord), row, owner));
        }
        let Some(slot) = self.admission_slot(Some(identity)) else {
            return Err((PendingBasicPreparedAdmissionError::SidecarUnavailable, row, owner));
        };
        if let Err(error) = pending.park_reserved(reservation, row) {
            return Err((PendingBasicPreparedAdmissionError::PendingRow(error), row, owner));
        }
        self.entries[slot] = Some(Entry {
            identity, irp_id: row.irp_id, phase: Phase::Ready, owner,
        });
        Ok(identity)
    }

    /// Claim once against the exact still-parked row. This is not permission for a WAL effect.
    pub fn claim_exact(&mut self, pending: &PendingFileIoTable,
        identity: PendingFileIoIdentity, irp_id: u64) -> Option<PendingBasicPreparedClaim> {
        if !Self::exact_row(pending, identity, irp_id, false) { return None; }
        let entry = self.entries.iter_mut().flatten().find(|entry| {
            entry.identity == identity && entry.irp_id == irp_id && entry.phase == Phase::Ready
        })?;
        entry.phase = Phase::Claimed;
        Some(PendingBasicPreparedClaim { table_id: self.table_id, identity, irp_id })
    }

    /// Recreate only a known in-memory terminal claim after a settlement refusal. Its stored
    /// receipt makes a second apply impossible, including after the original claim was lost.
    pub fn reclaim_applied_exact(&self, pending: &PendingFileIoTable,
        identity: PendingFileIoIdentity, irp_id: u64) -> Option<PendingBasicPreparedClaim> {
        if !Self::exact_row(pending, identity, irp_id, true) { return None; }
        self.entries.iter().flatten().find(|entry| {
            entry.identity == identity && entry.irp_id == irp_id
                && entry.phase == Phase::Claimed && entry.owner.applied.is_some()
        })?;
        Some(PendingBasicPreparedClaim { table_id: self.table_id, identity, irp_id })
    }

    fn claimed_slot(&self, pending: &PendingFileIoTable,
        claim: &PendingBasicPreparedClaim) -> Option<usize> {
        if claim.table_id == 0 || claim.table_id != self.table_id
            || !Self::exact_row(pending, claim.identity, claim.irp_id, true)
        { return None; }
        self.entries.iter().position(|slot| matches!(slot,
            Some(entry) if entry.identity == claim.identity && entry.irp_id == claim.irp_id
                && matches!(entry.phase, Phase::Claimed | Phase::Uncertain)))
    }

    /// Borrow the captured input and prepared metadata while the exact claim remains live.
    pub fn claimed_exact(&self, pending: &PendingFileIoTable,
        claim: &PendingBasicPreparedClaim) -> Option<&PendingBasicPreparedOwner<FileReference>> {
        let slot = self.claimed_slot(pending, claim)?;
        Some(&self.entries[slot].as_ref()?.owner)
    }

    pub fn apply_snapshot_claimed_exact(&mut self, pending: &PendingFileIoTable,
        claim: &PendingBasicPreparedClaim, fs: &mut nt_fs::FileSystem,
    ) -> Option<(u32, bool, bool)> {
        let slot = self.claimed_slot(pending, claim)?;
        let entry = self.entries[slot].as_mut()?;
        if entry.phase != Phase::Claimed { return None; }
        let fresh = entry.owner.applied.is_none();
        let (status, changed) = entry.owner.apply_snapshot_once(fs);
        Some((status, changed, fresh))
    }

    pub fn refuse_snapshot_claimed_exact(&mut self, pending: &PendingFileIoTable,
        claim: &PendingBasicPreparedClaim, status: u32) -> Option<u32> {
        let slot = self.claimed_slot(pending, claim)?;
        let entry = self.entries[slot].as_mut()?;
        if entry.phase != Phase::Claimed { return None; }
        Some(entry.owner.refuse_snapshot_once(status).0)
    }

    /// A definite refusal before entering the in-memory apply may return to Ready. An applied
    /// or uncertain owner cannot be released for another attempt.
    pub fn release_unentered_claim_exact(&mut self, pending: &PendingFileIoTable,
        claim: &PendingBasicPreparedClaim) -> Option<()> {
        let slot = self.claimed_slot(pending, claim)?;
        let entry = self.entries[slot].as_mut()?;
        if entry.phase != Phase::Claimed || entry.owner.applied.is_some() { return None; }
        entry.phase = Phase::Ready;
        Some(())
    }

    /// An entered effect with no known terminal keeps all three values in the sidecar.
    /// The exact claim remains usable if a later provider terminal resolves the uncertainty.
    pub fn mark_uncertain_exact(&mut self, pending: &PendingFileIoTable,
        claim: &PendingBasicPreparedClaim) -> Option<()> {
        let slot = self.claimed_slot(pending, claim)?;
        let entry = self.entries[slot].as_mut()?;
        if entry.phase != Phase::Claimed { return None; }
        entry.phase = Phase::Uncertain;
        Some(())
    }

    /// Settle the exact delivery row and transfer its prepared owner together after a known
    /// native terminal. The caller must prove the physical terminal and any durable WAL result;
    /// a sidecar claim alone grants neither. Refusal retains the row and owner unchanged.
    pub fn commit_owned_basic_exact(&mut self, pending: &mut PendingFileIoTable,
        claim: PendingBasicPreparedClaim, status: u32,
    ) -> Result<PendingBasicPreparedOwner<FileReference>, PendingBasicPreparedClaim> {
        let Some(slot) = self.claimed_slot(pending, &claim) else { return Err(claim); };
        if pending.commit_owned_basic_terminal_exact(claim.identity, claim.irp_id, status).is_none() {
            return Err(claim);
        }
        let entry = self.entries[slot].take().expect("settled Basic row lost its prepared owner");
        Ok(entry.owner)
    }

    /// Cancel only before a claim or baseline effect. The pending row becomes a real CANCELLED
    /// local terminal; any still-live delivery surfaces remain owned by that row.
    pub fn cancel_unentered_exact(&mut self, pending: &mut PendingFileIoTable,
        identity: PendingFileIoIdentity, irp_id: u64,
    ) -> Option<PendingBasicPreparedOwner<FileReference>> {
        let slot = self.entries.iter().position(|slot| matches!(slot,
            Some(entry) if entry.identity == identity && entry.irp_id == irp_id
                && entry.phase == Phase::Ready))?;
        pending.cancel_unentered_owned_basic_exact(identity, irp_id)?;
        Some(self.entries[slot].take()?.owner)
    }
}
