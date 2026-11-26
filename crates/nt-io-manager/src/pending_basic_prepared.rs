//! Move-only FileBasic preparation beside the Copy pending File I/O delivery row.
//!
//! This sidecar owns the captured semantic input, prepared MemFs mutation and a move-only native
//! Overlay File lifetime token supplied by its adapter. The current native route's local retain
//! and release calls are not yet transferred into this sidecar. It is row correlation only:
//! neither a claim nor an observed baseline grants
//! snapshot/WAL authority or publishes the caller's IOSB and Reply.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{PendingFileIoIdentity, PendingFileIoOperation, PendingFileIoTable};

static NEXT_TABLE_ID: AtomicU64 = AtomicU64::new(1);

/// The Overlay File lifetime owner is supplied by the native adapter and is never copied here.
/// The adapter must provide a dedicated retained reference or transfer the pending row's owned
/// local reference with a single release authority; a syscall-local handler borrow is insufficient.
#[must_use = "retain or explicitly release the native Overlay File reference"]
pub struct PendingBasicPreparedOwner<FileReference> {
    input: [u8; 40],
    prepared: nt_fs::PreparedBasicInformation,
    file: FileReference,
}

impl<FileReference> PendingBasicPreparedOwner<FileReference> {
    /// Freeze the exact 40-byte semantic input and its resolved mutation together. A failed
    /// preparation returns the native File reference without dropping or replacing it.
    pub fn prepare(fs: &nt_fs::FileSystem, handle: u64, input: [u8; 40],
        file: FileReference) -> Result<Self, (u32, FileReference)> {
        match fs.prepare_basic_information(handle, &input) {
            Ok(prepared) => Ok(Self { input, prepared, file }),
            Err(status) => Err((status, file)),
        }
    }

    pub fn input(&self) -> &[u8; 40] { &self.input }
    pub fn prepared(&self) -> &nt_fs::PreparedBasicInformation { &self.prepared }

    /// Transfer all three values after a known terminal or before-entry no-effect cancellation.
    pub fn into_parts(self) -> ([u8; 40], nt_fs::PreparedBasicInformation, FileReference) {
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

/// Bounded sidecar for parked FileBasic owners. A pending row remains the sole delivery owner.
pub struct PendingBasicPreparedTable<FileReference> {
    entries: Vec<Option<Entry<FileReference>>>,
    table_id: u64,
    limit: usize,
}

impl<FileReference> Default for PendingBasicPreparedTable<FileReference> {
    fn default() -> Self { Self::new() }
}

impl<FileReference> PendingBasicPreparedTable<FileReference> {
    const DEFAULT_LIMIT: usize = 16;

    pub const fn new() -> Self { Self::with_limit(Self::DEFAULT_LIMIT) }

    pub const fn with_limit(limit: usize) -> Self {
        Self { entries: Vec::new(), table_id: 0, limit }
    }

    pub fn len(&self) -> usize { self.entries.iter().filter(|entry| entry.is_some()).count() }

    fn exact_row(pending: &PendingFileIoTable, identity: PendingFileIoIdentity,
        irp_id: u64, allow_abandoned: bool) -> bool {
        let Some(row) = pending.get_exact(identity) else { return false; };
        row.irp_id == irp_id && row.delivery_state == 0
            && (allow_abandoned || !row.consumer_abandoned)
            && matches!(row.operation, PendingFileIoOperation::OwnedBasicPreflight(_))
    }

    /// Attach before physical entry. Refusal returns every move-only value to the caller.
    /// The same pending table/slot cannot be reused while an older generation is retained.
    pub fn park_exact(&mut self, pending: &PendingFileIoTable,
        identity: PendingFileIoIdentity, irp_id: u64,
        owner: PendingBasicPreparedOwner<FileReference>,
    ) -> Result<(), PendingBasicPreparedOwner<FileReference>> {
        if !Self::exact_row(pending, identity, irp_id, false)
            || self.len() >= self.limit
            || self.entries.iter().flatten().any(|entry| {
                entry.identity.table() == identity.table()
                    && entry.identity.slot() == identity.slot()
            })
        { return Err(owner); }
        let slot = if let Some(slot) = self.entries.iter().position(Option::is_none) {
            slot
        } else {
            if self.entries.try_reserve(1).is_err() { return Err(owner); }
            self.entries.push(None);
            self.entries.len() - 1
        };
        if self.table_id == 0 {
            self.table_id = match NEXT_TABLE_ID.fetch_update(Ordering::Relaxed,
                Ordering::Relaxed, |id| id.checked_add(1)) {
                Ok(id) => id,
                Err(_) => return Err(owner),
            };
        }
        self.entries[slot] = Some(Entry { identity, irp_id, phase: Phase::Ready, owner });
        Ok(())
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
