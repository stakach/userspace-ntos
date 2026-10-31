//! Block-backed snapshot store for durable filesystem images.
//!
//! This is intentionally below the executive writable-overlay policy: it persists an opaque snapshot
//! byte string to a fixed block range using two commit slots. Payload sectors are written first and
//! the header sector is written last, with device-cache barriers separating publication from data.
//! A failed/torn update preserves the previous payload-valid slot.

use alloc::vec::Vec;
use nt_config_store::codec::{crc32c, Crc32c};

#[path = "snapshot_payload_writer.rs"]
mod payload_writer;
pub use payload_writer::PayloadSectorWriter;

#[path = "snapshot_async_commit.rs"]
mod async_commit;
pub use async_commit::{AsyncSnapshotCommit, AsyncSnapshotCommitError, AsyncSnapshotIoKind, AsyncSnapshotRequest};

#[path = "snapshot_async_header_recheck.rs"]
mod async_header_recheck;
pub use async_header_recheck::{AsyncSnapshotHeaderRecheck, RecheckedPairedWalSnapshot};

#[path = "snapshot_async_wal_anchor.rs"]
mod async_wal_anchor;
pub use async_wal_anchor::{AnchoredWalPublication, AsyncWalSnapshotAnchorUpdate};

#[path = "snapshot_wal_anchor.rs"]
mod wal_anchor;
pub use wal_anchor::WalSnapshotAnchorUpdate;

#[path = "snapshot_epoch_rollover.rs"]
mod epoch_rollover;
pub use epoch_rollover::WalSnapshotEpochRollover;

#[path = "snapshot_async_epoch_rollover.rs"]
mod async_epoch_rollover;
pub use async_epoch_rollover::AsyncWalEpochRollover;


#[cfg(test)]
#[path = "snapshot_store_tests.rs"]
mod tests;

const STORE_MAGIC: [u8; 8] = *b"USNTSNP\0";
const STORE_VERSION: u16 = 1;
const HEADER_LEN: usize = 48;
const WAL_STORE_VERSION: u16 = 2;
const WAL_HEADER_LEN: usize = 80;
const WAL_RESET_VERSION: u16 = 3;
const WAL_RESET_HEADER_LEN: usize = 84;

/// Errors reported by the snapshot block store.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotBlockStoreError {
    InvalidGeometry,
    OutOfSpace,
    Io,
    Corrupt,
    OutOfMemory,
}

/// Minimal sector I/O contract required by [`SnapshotBlockStore`].
pub trait SnapshotBlockDevice {
    fn sector_size(&self) -> usize;
    fn sector_count(&self) -> u64;
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError>;

    /// Read a whole-sector range. Success means every requested byte was read; an error may
    /// leave partially filled output and must not be treated as a complete payload. The default
    /// validates the entire range before composing single-sector operations.
    fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let size = self.sector_size();
        if size == 0 || out.len() % size != 0 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        let count = u64::try_from(out.len() / size)
            .map_err(|_| SnapshotBlockStoreError::InvalidGeometry)?;
        let end = lba
            .checked_add(count)
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        if end > self.sector_count() {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        for (index, sector) in out.chunks_exact_mut(size).enumerate() {
            self.read_sector(lba + index as u64, sector)?;
        }
        Ok(())
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError>;

    /// Complete all preceding writes to stable storage before returning success. Implementations
    /// must propagate unsupported barriers and device failures; cached write completion is not enough.
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError>;

    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let sector_size = self.sector_size();
        if sector_size == 0 || data.len() % sector_size != 0 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        let mut next_lba = lba;
        for sector in data.chunks_exact(sector_size) {
            self.write_sector(next_lba, sector)?;
            next_lba = next_lba
                .checked_add(1)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        }
        Ok(())
    }
}

/// Byte sink used by streaming snapshot encoders.
pub trait SnapshotPayloadSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError>;
}

/// Sequential byte reader used by streaming snapshot decoders.
pub trait SnapshotPayloadReader {
    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError>;
    fn remaining(&self) -> usize;
}

const READ_BATCH_SECTORS: usize = 4;

/// Sector-buffered payload reader for [`SnapshotBlockStore::read_latest_streaming`].
pub struct PayloadSectorReader<'a, D: SnapshotBlockDevice> {
    dev: &'a mut D,
    batch: Vec<u8>,
    sector_size: usize,
    slot_base: u64,
    payload_len: usize,
    payload_crc: u32,
    read: usize,
    sector_index: u64,
    batch_offset: usize,
    batch_valid: usize,
    crc: Crc32c,
}

/// A two-slot commit area over a fixed block range.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBlockStore {
    start_lba: u64,
    sector_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSnapshot {
    pub generation: u64,
    pub payload: Vec<u8>,
}

#[derive(Copy, Clone)]
struct SlotHeader {
    slot: u32,
    generation: u64,
    payload_len: u64,
    payload_crc: u32,
    payload_sectors: u32,
    wal: Option<WalSnapshotManifest>,
    resetting: bool,
}

#[derive(Clone)]
struct SlotSnapshot {
    generation: u64,
    payload: Vec<u8>,
    wal: Option<WalSnapshotManifest>,
    resetting: bool,
}

#[derive(Copy, Clone)]
struct SlotSummary {
    slot: u32,
    generation: u64,
    wal: Option<WalSnapshotManifest>,
    resetting: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SlotReadPlan {
    slot: u32,
    generation: u64,
    payload_len: usize,
    payload_crc: u32,
    payload_sectors: u32,
    wal: Option<WalSnapshotManifest>,
    resetting: bool,
}

/// In-process proof that both WAL snapshot payloads passed CRC validation on one exclusive
/// reserve. It must travel with that reserve's physical owner; boot recovery must mint a fresh
/// proof and an uncertain write must never return one to a new writer.
#[must_use = "retain with the exact snapshot reserve until a settled update or recovery"]
pub struct VerifiedPairedWalSnapshot {
    store: SnapshotBlockStore,
    plans: [SlotReadPlan; 2],
    manifest: WalSnapshotManifest,
}

impl VerifiedPairedWalSnapshot {
    /// In-memory durability fence for a pair retained from settled header/flush ACKs.
    /// The caller must also hold the exact exclusive physical reserve lease.
    pub fn matches_cached_fence(&self, store: SnapshotBlockStore, anchor: WalSnapshotAnchor) -> bool {
        self.store == store && anchor.incarnation != 0
            && self.manifest.anchor() == anchor
    }

    pub fn manifest(&self) -> WalSnapshotManifest {
        self.manifest
    }

    pub fn anchor(&self) -> WalSnapshotAnchor {
        self.manifest.anchor()
    }
}

/// V2 snapshot-header metadata. End LBA is relative to the disjoint WAL view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalSnapshotManifest {
    pub incarnation: u64,
    pub base_serial: u64,
    pub high_water_serial: u64,
    pub high_water_end_lba: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalSnapshotAnchor {
    pub incarnation: u64,
    pub serial: u64,
    pub end_lba: u64,
}

impl WalSnapshotManifest {
    fn anchor(self) -> WalSnapshotAnchor {
        WalSnapshotAnchor {
            incarnation: self.incarnation,
            serial: self.high_water_serial,
            end_lba: self.high_water_end_lba,
        }
    }

    fn valid(self) -> bool {
        self.incarnation != 0
            && self.base_serial <= self.high_water_serial
            && ((self.high_water_serial == 0 && self.high_water_end_lba == 0)
                || (self.high_water_serial != 0 && self.high_water_end_lba != 0))
    }
}

fn wal_recovery_floor(
    selected: WalSnapshotManifest,
    other: Option<WalSnapshotManifest>,
) -> Result<WalSnapshotAnchor, SnapshotBlockStoreError> {
    let mut anchor = selected.anchor();
    if let Some(other) = other {
        let candidate = other.anchor();
        if selected.base_serial < other.base_serial
            || candidate.incarnation != anchor.incarnation
            || (candidate.serial == anchor.serial && candidate.end_lba != anchor.end_lba)
            || (candidate.serial > anchor.serial && candidate.end_lba < anchor.end_lba)
            || (candidate.serial < anchor.serial && candidate.end_lba > anchor.end_lba)
        {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        if candidate.serial > anchor.serial {
            anchor = candidate;
        }
    }
    if selected.base_serial > anchor.serial {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    Ok(anchor)
}

/// A torn payload may be replaced only when its still-valid v2 header cannot carry
/// a higher recovery floor than the surviving payload. A damaged or unknown header
/// has no such proof and remains a hard refusal.
fn same_anchor_wal_companion(
    selected_generation: u64,
    selected: WalSnapshotManifest,
    companion_generation: u64,
    companion: WalSnapshotManifest,
) -> Result<(), SnapshotBlockStoreError> {
    if selected_generation == companion_generation
        || selected.anchor() != companion.anchor()
        || selected.base_serial < companion.base_serial
    {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredWalSnapshot {
    pub snapshot: StoredSnapshot,
    pub selected_base_serial: u64,
    pub anchor: WalSnapshotAnchor,
}

/// Format and WAL recovery floor for the payload selected by the streaming reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotReadFormat {
    Legacy,
    Wal {
        selected_base_serial: u64,
        anchor: WalSnapshotAnchor,
    },
}

/// Recovery required before the native boot reader may decode or publish a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootSnapshotRecovery {
    Ready,
    InterruptedEmptyBaseline { incarnation: u64 },
    Resetting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredSnapshotMetadata {
    pub generation: u64,
    pub payload_len: usize,
    pub format: SnapshotReadFormat,
}

fn verify_recovered_wal_anchor<D: SnapshotBlockDevice>(
    selected_base_serial: u64,
    anchor: WalSnapshotAnchor,
    wal: &crate::RegistryWal<D>,
) -> Result<(), SnapshotBlockStoreError> {
    let Some((incarnation, recovered_serial, _)) = wal.verified_prefix() else {
        return Err(SnapshotBlockStoreError::Corrupt);
    };
    if incarnation != anchor.incarnation
        || recovered_serial < anchor.serial
        || wal.verified_record_end_lba(anchor.serial) != Some(anchor.end_lba)
        || recovered_serial < selected_base_serial
    {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    Ok(())
}

fn verified_boot_system_log_suffix<D: SnapshotBlockDevice>(
    selected_base_serial: u64,
    anchor: WalSnapshotAnchor,
    snapshot_log: &[u8],
    wal: &crate::RegistryWal<D>,
) -> Result<Vec<u8>, SnapshotBlockStoreError> {
    verify_recovered_wal_anchor(selected_base_serial, anchor, wal)?;
    let base = usize::try_from(selected_base_serial).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
    let suffix = wal.records().get(base..).ok_or(SnapshotBlockStoreError::Corrupt)?;
    let total = suffix
        .iter()
        .try_fold(snapshot_log.len(), |length, record| {
            length.checked_add(record.payload.len())
        })
        .ok_or(SnapshotBlockStoreError::Corrupt)?;
    let mut log = Vec::new();
    log.try_reserve_exact(total)
        .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
    log.extend_from_slice(snapshot_log);
    for record in suffix {
        log.extend_from_slice(&record.payload);
    }
    Ok(log)
}

impl StoredWalSnapshot {
    /// Reject a WAL whose recovered committed prefix is shorter than either snapshot's
    /// acknowledged high-water. Later marked records may represent a pre-reply crash.
    pub fn verify_recovered_wal<D: SnapshotBlockDevice>(
        &self,
        wal: &crate::RegistryWal<D>,
    ) -> Result<(), SnapshotBlockStoreError> {
        verify_recovered_wal_anchor(self.selected_base_serial, self.anchor, wal)
    }

    /// Assemble the exact SYSTEM sidecar log to replay before CM imports the boot hive.
    pub fn verified_boot_system_log<D: SnapshotBlockDevice>(
        &self,
        snapshot_log: &[u8],
        wal: &crate::RegistryWal<D>,
    ) -> Result<Vec<u8>, SnapshotBlockStoreError> {
        verified_boot_system_log_suffix(self.selected_base_serial, self.anchor, snapshot_log, wal)
    }
}

impl StoredSnapshotMetadata {
    /// Verify the selected streamed snapshot's WAL floor and return its exact unapplied SYSTEM
    /// journal suffix. A legacy snapshot has no WAL anchor and cannot use this path.
    pub fn verified_boot_system_log<D: SnapshotBlockDevice>(
        &self,
        snapshot_log: &[u8],
        wal: &crate::RegistryWal<D>,
    ) -> Result<Vec<u8>, SnapshotBlockStoreError> {
        let SnapshotReadFormat::Wal { selected_base_serial, anchor } = self.format else {
            return Err(SnapshotBlockStoreError::Corrupt);
        };
        verified_boot_system_log_suffix(selected_base_serial, anchor, snapshot_log, wal)
    }
}

impl SnapshotBlockStore {
    pub fn sector_count(&self) -> u64 { self.sector_count }

    pub fn new(start_lba: u64, sector_count: u64) -> Self {
        Self {
            start_lba,
            sector_count,
        }
    }

    pub fn payload_capacity<D: SnapshotBlockDevice>(
        &self,
        dev: &D,
    ) -> Result<usize, SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let payload_sectors = slot_sectors
            .checked_sub(1)
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        usize::try_from(payload_sectors)
            .ok()
            .and_then(|sectors| sectors.checked_mul(sector_size))
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)
    }

    /// Classify states requiring an exact-lease repair before the boot payload is decoded.
    /// This probe performs no writes and never guesses an incarnation from a torn header.
    pub fn boot_recovery_state<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<BootSnapshotRecovery, SnapshotBlockStoreError> {
        let first = self.read_slot_plan(dev, 0);
        let second = self.read_slot_plan(dev, 1);
        for slot in [&first, &second] {
            if let Err(error) = slot {
                if *error != SnapshotBlockStoreError::Corrupt {
                    return Err(*error);
                }
            }
        }
        if first.as_ref().ok().and_then(|slot| *slot).is_some_and(|slot| slot.resetting)
            || second.as_ref().ok().and_then(|slot| *slot).is_some_and(|slot| slot.resetting)
        {
            return Ok(BootSnapshotRecovery::Resetting);
        }
        // Only a genuinely empty companion proves first-boot initialization. A torn header
        // could hide a newer WAL floor and must not be overwritten by this repair.
        let single = match (&first, &second) {
            (Ok(Some(v2)), Ok(None)) | (Ok(None), Ok(Some(v2))) => Some(*v2),
            _ => None,
        };
        if let Some(v2) = single {
            if let Some(wal) = v2.wal {
                if wal.incarnation == 0 || wal.base_serial != 0
                    || wal.high_water_serial != 0 || wal.high_water_end_lba != 0
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                self.validate_slot_payload_crc(dev, v2)?;
                return Ok(BootSnapshotRecovery::InterruptedEmptyBaseline {
                    incarnation: wal.incarnation,
                });
            }
        }
        let (Some(a), Some(b)) = (first.ok().flatten(), second.ok().flatten()) else {
            // A torn companion remains the normal reader's responsibility. It will only
            // select a surviving payload under the existing same-anchor rules.
            return Ok(BootSnapshotRecovery::Ready);
        };
        let (v2, legacy) = match (a.wal, b.wal) {
            (Some(_), None) => (a, b),
            (None, Some(_)) => (b, a),
            _ => return Ok(BootSnapshotRecovery::Ready),
        };
        let wal = v2.wal.expect("identified WAL header");
        if v2.generation <= legacy.generation || wal.incarnation == 0
            || wal.base_serial != 0 || wal.high_water_serial != 0
            || wal.high_water_end_lba != 0
        {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        self.validate_slot_payload_crc(dev, v2)?;
        self.validate_slot_payload_crc(dev, legacy)?;
        Ok(BootSnapshotRecovery::InterruptedEmptyBaseline {
            incarnation: wal.incarnation,
        })
    }

    pub fn read_latest<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<StoredSnapshot>, SnapshotBlockStoreError> {
        let slot0 = self.read_slot(dev, 0);
        let slot1 = self.read_slot(dev, 1);
        match (slot0, slot1) {
            (Ok(Some(a)), Ok(Some(b))) => {
                let latest = if b.generation > a.generation { b } else { a };
                Ok(Some(StoredSnapshot {
                    generation: latest.generation,
                    payload: latest.payload,
                }))
            }
            (Ok(Some(a)), _) => Ok(Some(StoredSnapshot {
                generation: a.generation,
                payload: a.payload,
            })),
            (_, Ok(Some(b))) => Ok(Some(StoredSnapshot {
                generation: b.generation,
                payload: b.payload,
            })),
            (Ok(None), Ok(None)) => Ok(None),
            (Err(err), Ok(None)) | (Ok(None), Err(err)) => Err(err),
            (Err(_), Err(_)) => Err(SnapshotBlockStoreError::Corrupt),
        }
    }

    /// Read the latest valid payload through a sector-buffered reader without allocating it whole.
    pub fn read_latest_streaming<D, F, R>(
        &self,
        dev: &mut D,
        read_payload: F,
    ) -> Result<Option<(u64, usize, R)>, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorReader<'_, D>) -> Result<R, SnapshotBlockStoreError>,
    {
        let Some(plan) = self.latest_valid_slot(dev)? else {
            return Ok(None);
        };
        self.read_selected_streaming(dev, plan, read_payload)
            .map(Some)
    }

    /// Inspect the format of the same payload selected by the streaming reader without
    /// allocating that payload. A mixed or damaged companion slot is ambiguous at a
    /// legacy-to-WAL boundary and must not silently select the legacy image.
    pub fn read_latest_metadata<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<StoredSnapshotMetadata>, SnapshotBlockStoreError> {
        let Some(plan) = self.latest_valid_slot(dev)? else {
            return Ok(None);
        };
        self.metadata_for_selected(dev, plan).map(Some)
    }

    /// Read the selected payload and its format under the same device borrow. Native boot
    /// can use the metadata for WAL recovery before publishing the decoded filesystem.
    pub fn read_latest_streaming_with_metadata<D, F, R>(
        &self,
        dev: &mut D,
        read_payload: F,
    ) -> Result<Option<(StoredSnapshotMetadata, R)>, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorReader<'_, D>) -> Result<R, SnapshotBlockStoreError>,
    {
        let Some(plan) = self.latest_valid_slot(dev)? else {
            return Ok(None);
        };
        let metadata = self.metadata_for_selected(dev, plan)?;
        let (_, _, payload) = self.read_selected_streaming(dev, plan, read_payload)?;
        Ok(Some((metadata, payload)))
    }

    /// Restore before WAL replay is wired into the caller. Legacy snapshots remain readable,
    /// but v2 is usable only when both slots contain a validated, identical zero-serial
    /// baseline. A partial migration or an acknowledged WAL suffix needs explicit recovery.
    pub fn read_latest_streaming_before_wal_replay<D, F, R>(
        &self,
        dev: &mut D,
        read_payload: F,
    ) -> Result<Option<(StoredSnapshotMetadata, R)>, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorReader<'_, D>) -> Result<R, SnapshotBlockStoreError>,
    {
        let Some(plan) = self.latest_valid_slot(dev)? else {
            return Ok(None);
        };
        let metadata = self.metadata_for_selected(dev, plan)?;
        if let SnapshotReadFormat::Wal {
            selected_base_serial,
            anchor,
        } = metadata.format
        {
            if selected_base_serial != 0 || anchor.serial != 0 || anchor.end_lba != 0 {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            let first = self
                .read_valid_slot_plan(dev, 0)?
                .and_then(|plan| plan.wal)
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
            let second = self
                .read_valid_slot_plan(dev, 1)?
                .and_then(|plan| plan.wal)
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
            if first != second || first.incarnation != anchor.incarnation {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
        }
        let (_, _, payload) = self.read_selected_streaming(dev, plan, read_payload)?;
        Ok(Some((metadata, payload)))
    }

    fn read_selected_streaming<D, F, R>(
        &self,
        dev: &mut D,
        plan: SlotReadPlan,
        read_payload: F,
    ) -> Result<(u64, usize, R), SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorReader<'_, D>) -> Result<R, SnapshotBlockStoreError>,
    {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let slot_base = self.slot_lba(slot_sectors, plan.slot)?;
        let batch_size = sector_size
            .checked_mul(READ_BATCH_SECTORS)
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(batch_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        batch.resize(batch_size, 0);
        let generation = plan.generation;
        let payload_len = plan.payload_len;
        let mut reader = PayloadSectorReader::new(dev, batch, sector_size, slot_base, plan);
        let result = read_payload(&mut reader)?;
        reader.finish()?;
        Ok((generation, payload_len, result))
    }

    fn metadata_for_selected<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        selected: SlotReadPlan,
    ) -> Result<StoredSnapshotMetadata, SnapshotBlockStoreError> {
        let other_slot = 1 - selected.slot;
        let other_header = self.read_slot_plan(dev, other_slot)?;
        if selected.resetting || other_header.is_some_and(|header| header.resetting) {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let format = match (selected.wal, other_header) {
            // A legacy payload may fall back from a companion legacy payload whose CRC is bad.
            // A damaged header remains ambiguous because its format cannot be trusted.
            (None, None | Some(SlotReadPlan { wal: None, .. })) => SnapshotReadFormat::Legacy,
            (None, Some(_)) => return Err(SnapshotBlockStoreError::Corrupt),
            (Some(selected_manifest), other_header) => {
                let other_manifest = match other_header {
                    None => None,
                    Some(SlotReadPlan { wal: None, .. }) => {
                        return Err(SnapshotBlockStoreError::Corrupt)
                    }
                    Some(other_plan) => {
                        let manifest = other_plan.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                        match self.validate_slot_payload_crc(dev, other_plan) {
                            Ok(()) => {}
                            Err(SnapshotBlockStoreError::Corrupt) => {
                                same_anchor_wal_companion(
                                    selected.generation,
                                    selected_manifest,
                                    other_plan.generation,
                                    manifest,
                                )?;
                            }
                            Err(error) => return Err(error),
                        }
                        Some(manifest)
                    }
                };
                SnapshotReadFormat::Wal {
                    selected_base_serial: selected_manifest.base_serial,
                    anchor: wal_recovery_floor(selected_manifest, other_manifest)?,
                }
            }
        };
        Ok(StoredSnapshotMetadata {
            generation: selected.generation,
            payload_len: selected.payload_len,
            format,
        })
    }

    /// Commit a new payload to the alternate slot and return its generation.
    pub fn commit_next<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        payload: &[u8],
    ) -> Result<u64, SnapshotBlockStoreError> {
        self.commit_next_streaming(dev, payload.len(), crc32c(payload), |writer| {
            writer.write_all(payload)
        })
    }

    /// Enter WAL-capable snapshot format while retaining the existing payload barriers.
    /// Native activation must write a baseline to both slots before any WAL acknowledgement.
    pub fn commit_next_with_wal_manifest<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        payload: &[u8],
        manifest: WalSnapshotManifest,
    ) -> Result<u64, SnapshotBlockStoreError> {
        AsyncSnapshotCommit::new(*self, payload, manifest, dev.sector_size(), dev.sector_count())?
            .run_sync(dev)
    }

    /// Finish an interrupted v1-to-v2 baseline migration before any WAL record is admitted.
    /// The caller must have verified that the disjoint WAL region is empty for `incarnation`.
    /// A complete legacy pair returns `None` so its owner can begin migration explicitly.
    /// A mixed pair is repairable only when its newer, payload-valid slot is an empty-WAL v2
    /// checkpoint. The older legacy slot is replaced with the exact durable v2 payload.
    pub(crate) fn repair_empty_wal_baseline<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        incarnation: u64,
    ) -> Result<Option<u64>, SnapshotBlockStoreError> {
        if incarnation == 0 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        // Stabilize any completed header before selecting a slot to overwrite.
        dev.flush()?;
        let a = self.read_slot(dev, 0);
        let b = self.read_slot(dev, 1);
        if a.as_ref().ok().and_then(Option::as_ref).is_some_and(|slot| slot.resetting)
            || b.as_ref().ok().and_then(Option::as_ref).is_some_and(|slot| slot.resetting)
        {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let empty = WalSnapshotManifest {
            incarnation,
            base_serial: 0,
            high_water_serial: 0,
            high_water_end_lba: 0,
        };
        let repair = match (a, b) {
            (Ok(Some(a)), Ok(Some(b))) if a.wal.is_none() && b.wal.is_none() => return Ok(None),
            (Ok(Some(legacy)), Ok(None) | Err(SnapshotBlockStoreError::Corrupt))
            | (Ok(None) | Err(SnapshotBlockStoreError::Corrupt), Ok(Some(legacy)))
                if legacy.wal.is_none() => return Ok(None),
            (Ok(Some(a)), Ok(Some(b))) if a.wal == Some(empty) && b.wal == Some(empty) => {
                if a.generation == b.generation {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                return Ok(Some(a.generation.max(b.generation)));
            }
            (Ok(Some(a)), Ok(Some(b))) => {
                let (v2, legacy) = if a.wal == Some(empty) && b.wal.is_none() {
                    (a, b)
                } else if b.wal == Some(empty) && a.wal.is_none() {
                    (b, a)
                } else {
                    return Err(SnapshotBlockStoreError::Corrupt);
                };
                if v2.generation <= legacy.generation {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                Ok(Some(v2))
            }
            (Ok(Some(v2)), Err(SnapshotBlockStoreError::Corrupt) | Ok(None))
            | (Err(SnapshotBlockStoreError::Corrupt) | Ok(None), Ok(Some(v2)))
                if v2.wal == Some(empty) =>
            {
                Ok(Some(v2))
            }
            (Err(error), _) | (_, Err(error)) if error != SnapshotBlockStoreError::Corrupt => {
                Err(error)
            }
            _ => Err(SnapshotBlockStoreError::Corrupt),
        }?;
        let Some(v2) = repair else {
            return Ok(None);
        };
        // The selected v2 payload was CRC checked before the companion is touched. This
        // dedicated path may overwrite a torn companion that the normal v2 writer rejects.
        self.commit_next_streaming_inner(
            dev,
            v2.payload.len(),
            crc32c(&v2.payload),
            Some(empty),
            true,
            |writer| writer.write_all(&v2.payload),
        )
        .map(Some)
    }

    /// Select the valid payload by snapshot generation, but retain the highest durability
    /// floor from both valid v2 headers. A mixed v1/v2 pair cannot enter WAL recovery.
    pub fn read_latest_wal<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<StoredWalSnapshot>, SnapshotBlockStoreError> {
        let Some((metadata, payload)) = self.read_latest_streaming_with_metadata(dev, |reader| {
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(reader.remaining())
                .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
            payload.resize(reader.remaining(), 0);
            reader.read_exact(&mut payload)?;
            Ok(payload)
        })? else {
            return Ok(None);
        };
        let SnapshotReadFormat::Wal {
            selected_base_serial,
            anchor,
        } = metadata.format
        else {
            return Err(SnapshotBlockStoreError::Corrupt);
        };
        Ok(Some(StoredWalSnapshot {
            snapshot: StoredSnapshot {
                generation: metadata.generation,
                payload,
            },
            selected_base_serial,
            anchor,
        }))
    }

    /// Commit a payload produced incrementally by `write_payload`.
    ///
    /// The caller supplies the exact length and CRC of the byte stream. Payload sectors are written
    /// first and the slot header is written last, preserving the same torn-write behavior as
    /// [`Self::commit_next`] without requiring the whole payload in memory.
    pub fn commit_next_streaming<D, F>(
        &self,
        dev: &mut D,
        payload_len: usize,
        payload_crc: u32,
        write_payload: F,
    ) -> Result<u64, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorWriter<'_, D>) -> Result<(), SnapshotBlockStoreError>,
    {
        self.commit_next_streaming_inner(dev, payload_len, payload_crc, None, false, write_payload)
    }

    /// Stream a volume checkpoint with the WAL incarnation, included serial, and exact
    /// acknowledged high-water recorded in the slot header. The ordinary v1 entry point
    /// remains unchanged for volumes that have not entered WAL mode.
    pub fn commit_next_streaming_with_wal_manifest<D, F>(
        &self,
        dev: &mut D,
        payload_len: usize,
        payload_crc: u32,
        manifest: WalSnapshotManifest,
        write_payload: F,
    ) -> Result<u64, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorWriter<'_, D>) -> Result<(), SnapshotBlockStoreError>,
    {
        if !manifest.valid() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        if dev.sector_size() < WAL_HEADER_LEN {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        self.commit_next_streaming_inner(
            dev,
            payload_len,
            payload_crc,
            Some(manifest),
            false,
            write_payload,
        )
    }

    pub(crate) fn commit_next_streaming_for_empty_wal_migration<D, F>(
        &self,
        dev: &mut D,
        payload_len: usize,
        payload_crc: u32,
        manifest: WalSnapshotManifest,
        write_payload: F,
    ) -> Result<u64, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorWriter<'_, D>) -> Result<(), SnapshotBlockStoreError>,
    {
        if !manifest.valid() || manifest.base_serial != 0
            || manifest.high_water_serial != 0 || manifest.high_water_end_lba != 0
            || dev.sector_size() < WAL_HEADER_LEN
        {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        // Admission and empty-WAL proof belong to WalSnapshotBaselineRepair. This path may
        // recycle a torn legacy companion after a previous first-slot migration cut.
        self.commit_next_streaming_inner(
            dev, payload_len, payload_crc, Some(manifest), true, write_payload,
        )
    }

    /// Admit a journal checkpoint only after both payload-valid slots name the same WAL
    /// anchor. A mixed migration or half-advanced anchor needs recovery under this device
    /// owner before a new journal effect can begin.
    pub fn validate_wal_journal_manifest<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        manifest: WalSnapshotManifest,
    ) -> Result<(), SnapshotBlockStoreError> {
        if !manifest.valid() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let first = self
            .read_valid_slot_plan(dev, 0)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        let second = self
            .read_valid_slot_plan(dev, 1)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        if first.generation == second.generation {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        for previous in [first, second] {
            if previous.resetting {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            let previous = previous.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
            if previous.anchor() != manifest.anchor()
                || previous.base_serial > manifest.base_serial
            {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
        }
        Ok(())
    }

    /// Select a journal admission manifest while validating each snapshot payload once.
    /// Both slots must be intact before a WAL marker can advance their shared anchor.
    pub fn current_paired_wal_journal_manifest<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<WalSnapshotManifest, SnapshotBlockStoreError> {
        let first = self.read_valid_slot_plan(dev, 0)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        let second = self.read_valid_slot_plan(dev, 1)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        Self::paired_manifest([first, second])
    }

    /// Mint a move-only paired-slot proof after fully validating both payload CRCs. This is a
    /// boot/recovery boundary; steady-state callers carry the resulting proof with the reserve.
    pub fn verify_paired_wal_snapshot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<VerifiedPairedWalSnapshot, SnapshotBlockStoreError> {
        let first = self.read_valid_slot_plan(dev, 0)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        let second = self.read_valid_slot_plan(dev, 1)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        let plans = [first, second];
        let manifest = Self::paired_manifest(plans)?;
        Ok(VerifiedPairedWalSnapshot { store: *self, plans, manifest })
    }

    /// Check exact slot headers under the proof's original exclusive reserve. Payload bytes
    /// remain certified only while no other writer can change that reserve; native callers bind
    /// the proof to their physical mount and move it through every possible write owner.
    pub fn recheck_verified_paired_wal_snapshot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        proof: &VerifiedPairedWalSnapshot,
    ) -> Result<WalSnapshotManifest, SnapshotBlockStoreError> {
        if proof.store != *self
            || self.read_slot_plan(dev, 0)? != Some(proof.plans[0])
            || self.read_slot_plan(dev, 1)? != Some(proof.plans[1])
        {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(proof.manifest)
    }

    fn paired_manifest(plans: [SlotReadPlan; 2]) -> Result<WalSnapshotManifest, SnapshotBlockStoreError> {
        let [first, second] = plans;
        if first.resetting || second.resetting {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let (selected, companion) = if first.generation > second.generation {
            (first, second)
        } else {
            (second, first)
        };
        let manifest = selected.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
        let other = companion.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
        if !manifest.valid() || !other.valid() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        same_anchor_wal_companion(selected.generation, manifest, companion.generation, other)?;
        Ok(manifest)
    }

    /// Select the manifest for an unrelated mounted-volume checkpoint. The new payload
    /// has not folded any additional SYSTEM records, so it inherits the selected payload's
    /// base serial and the exact anchor present in both valid v2 headers. One companion
    /// payload may be torn, but a half-advanced anchor must be repaired from the WAL
    /// before either slot can be recycled.
    pub fn current_wal_checkpoint_manifest<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<WalSnapshotManifest, SnapshotBlockStoreError> {
        let first = self.read_valid_slot_plan(dev, 0);
        let second = self.read_valid_slot_plan(dev, 1);
        let selected = match (first, second) {
            (Ok(Some(first)), Ok(Some(second))) => {
                if first.generation > second.generation { first } else { second }
            }
            (Ok(Some(first)), Err(SnapshotBlockStoreError::Corrupt)) => first,
            (Err(SnapshotBlockStoreError::Corrupt), Ok(Some(second))) => second,
            (Err(error), _) if error != SnapshotBlockStoreError::Corrupt => return Err(error),
            (_, Err(error)) if error != SnapshotBlockStoreError::Corrupt => return Err(error),
            _ => return Err(SnapshotBlockStoreError::Corrupt),
        };
        let companion = self
            .read_slot_plan(dev, 1 - selected.slot)?
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        if selected.resetting || companion.resetting {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let selected_manifest = selected.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
        let companion_manifest = companion.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
        same_anchor_wal_companion(
            selected.generation,
            selected_manifest,
            companion.generation,
            companion_manifest,
        )?;
        Ok(selected_manifest)
    }

    /// Check only the two headers before a legacy journal append. The writer will validate
    /// payloads at its barrier; admission must cheaply reject a v2 or ambiguous slot without
    /// reading an entire volume image for every current v1 mutation.
    pub(crate) fn validate_legacy_journal_format<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<(), SnapshotBlockStoreError> {
        for slot in 0..2 {
            if self.read_slot_plan(dev, slot)?.is_some_and(|plan| plan.wal.is_some()) {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
        }
        Ok(())
    }

    fn commit_next_streaming_inner<D, F>(
        &self,
        dev: &mut D,
        payload_len: usize,
        payload_crc: u32,
        wal: Option<WalSnapshotManifest>,
        repair_empty_baseline: bool,
        write_payload: F,
    ) -> Result<u64, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorWriter<'_, D>) -> Result<(), SnapshotBlockStoreError>,
    {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let batch_size = sector_size
            .checked_mul(payload_writer::WRITE_BATCH_SECTORS)
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        let max_payload_len = usize::try_from(
            slot_sectors
                .checked_sub(1)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?,
        )
        .ok()
        .and_then(|sectors| sectors.checked_mul(sector_size))
        .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        if payload_len > max_payload_len {
            return Err(SnapshotBlockStoreError::OutOfSpace);
        }
        // A failed earlier commit may have left a read-visible but volatile header. Stabilize it
        // before deciding which slot is safe to reuse.
        dev.flush()?;
        let latest = self.latest_commit_slot(dev)?;
        if latest.is_some_and(|slot| slot.resetting) {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let (target_slot, generation) = match latest {
            Some(latest) => (
                1 - latest.slot,
                latest
                    .generation
                    .checked_add(1)
                    .ok_or(SnapshotBlockStoreError::OutOfSpace)?,
            ),
            None => (0, 1),
        };
        if let Some(current) = wal {
            // A partially advanced two-slot anchor may live only in the older generation.
            // Inspect both valid payloads before either can be recycled by a v2 commit.
            for slot in 0..2 {
                let plan = match self.read_valid_slot_plan(dev, slot) {
                    Ok(plan) => plan,
                    Err(SnapshotBlockStoreError::Corrupt)
                        if repair_empty_baseline && slot == target_slot =>
                    {
                        continue
                    }
                    Err(SnapshotBlockStoreError::Corrupt) if slot == target_slot => {
                        // The selected payload is still complete. Recycle its torn companion
                        // only if that companion's valid v2 header names the same WAL floor;
                        // a newer or different floor cannot be discarded by this checkpoint.
                        let selected = latest.ok_or(SnapshotBlockStoreError::Corrupt)?;
                        let selected_manifest =
                            selected.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                        let companion = self
                            .read_slot_plan(dev, slot)?
                            .ok_or(SnapshotBlockStoreError::Corrupt)?;
                        let companion_manifest =
                            companion.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                        same_anchor_wal_companion(
                            selected.generation,
                            selected_manifest,
                            companion.generation,
                            companion_manifest,
                        )?;
                        if current.anchor() != selected_manifest.anchor()
                            || current.base_serial < selected_manifest.base_serial
                        {
                            return Err(SnapshotBlockStoreError::Corrupt);
                        }
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if plan.is_some_and(|plan| plan.resetting) {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                if let Some(previous) = plan.and_then(|plan| plan.wal) {
                    // A newer checkpoint may fold more of the WAL into its payload, but
                    // must never make recovery depend on records an earlier checkpoint
                    // had already applied and may have reclaimed.
                    if current.anchor() != previous.anchor()
                        || current.base_serial < previous.base_serial
                    {
                        return Err(SnapshotBlockStoreError::Corrupt);
                    }
                }
            }
        } else if latest.is_some_and(|previous| previous.wal.is_some()) {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let payload_sectors = payload_len.div_ceil(sector_size);
        let payload_sectors_u32 =
            u32::try_from(payload_sectors).map_err(|_| SnapshotBlockStoreError::OutOfSpace)?;
        if payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::OutOfSpace);
        }

        let slot_base = self.slot_lba(slot_sectors, target_slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(batch_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(batch_size, 0);
        let mut writer = PayloadSectorWriter::new(dev, sector, sector_size, slot_base, payload_len);
        write_payload(&mut writer)?;
        let (mut sector, written, actual_crc) = writer.finish()?;
        if written != payload_len || actual_crc != payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        dev.flush()?;

        sector.fill(0);
        encode_header(
            &mut sector,
            SlotHeader {
                slot: target_slot,
                generation,
                payload_len: payload_len as u64,
                payload_crc,
                payload_sectors: payload_sectors_u32,
                wal,
                resetting: false,
            },
        );
        dev.write_sector(slot_base, &sector)?;
        dev.flush()?;
        Ok(generation)
    }

    fn geometry<D: SnapshotBlockDevice>(
        &self,
        dev: &D,
    ) -> Result<(usize, u64), SnapshotBlockStoreError> {
        let sector_size = dev.sector_size();
        if sector_size < HEADER_LEN || self.sector_count < 4 || self.sector_count % 2 != 0 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        if self
            .start_lba
            .checked_add(self.sector_count)
            .is_none_or(|end| end > dev.sector_count())
        {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        Ok((sector_size, self.sector_count / 2))
    }

    fn slot_lba(&self, slot_sectors: u64, slot: u32) -> Result<u64, SnapshotBlockStoreError> {
        if slot > 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        self.start_lba
            .checked_add(slot_sectors.saturating_mul(slot as u64))
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)
    }

    fn read_slot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotSnapshot>, SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let slot_base = self.slot_lba(slot_sectors, slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(sector_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(sector_size, 0);
        dev.read_sector(slot_base, &mut sector)?;
        let Some(header) = decode_header(&sector)? else {
            return Ok(None);
        };
        if header.slot != slot || header.payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let payload_len =
            usize::try_from(header.payload_len).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
        let payload_capacity = usize::try_from(header.payload_sectors)
            .ok()
            .and_then(|sectors| sectors.checked_mul(sector_size))
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        if payload_len > payload_capacity {
            return Err(SnapshotBlockStoreError::Corrupt);
        }

        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_len)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        let mut remaining = payload_len;
        for index in 0..header.payload_sectors {
            sector.fill(0);
            dev.read_sector(slot_base + 1 + index as u64, &mut sector)?;
            let copy = remaining.min(sector_size);
            payload.extend_from_slice(&sector[..copy]);
            remaining -= copy;
        }
        if crc32c(&payload) != header.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(Some(SlotSnapshot {
            generation: header.generation,
            payload,
            wal: header.wal,
            resetting: header.resetting,
        }))
    }

    fn read_slot_plan<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let slot_base = self.slot_lba(slot_sectors, slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(sector_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(sector_size, 0);
        dev.read_sector(slot_base, &mut sector)?;
        Self::slot_plan_from_sector(slot, sector_size, slot_sectors, &sector)
    }

    fn slot_plan_from_sector(
        slot: u32,
        sector_size: usize,
        slot_sectors: u64,
        sector: &[u8],
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
        let Some(header) = decode_header(&sector)? else {
            return Ok(None);
        };
        if header.slot != slot || header.payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let payload_len =
            usize::try_from(header.payload_len).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
        let payload_capacity = usize::try_from(header.payload_sectors)
            .ok()
            .and_then(|sectors| sectors.checked_mul(sector_size))
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        if payload_len > payload_capacity {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(Some(SlotReadPlan {
            slot,
            generation: header.generation,
            payload_len,
            payload_crc: header.payload_crc,
            payload_sectors: header.payload_sectors,
            wal: header.wal,
            resetting: header.resetting,
        }))
    }

    fn read_valid_slot_plan<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
        let Some(plan) = self.read_slot_plan(dev, slot)? else {
            return Ok(None);
        };
        self.validate_slot_payload_crc(dev, plan)?;
        Ok(Some(plan))
    }

    fn validate_slot_payload_crc<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        plan: SlotReadPlan,
    ) -> Result<(), SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        if plan.payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let slot_base = self.slot_lba(slot_sectors, plan.slot)?;
        let batch_size = sector_size
            .checked_mul(READ_BATCH_SECTORS)
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(batch_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        batch.resize(batch_size, 0);
        let mut remaining = plan.payload_len;
        let mut crc = Crc32c::new();
        let mut index = 0;
        while index < plan.payload_sectors {
            let sectors = (plan.payload_sectors - index).min(READ_BATCH_SECTORS as u32);
            let bytes = sectors as usize * sector_size;
            let output = &mut batch[..bytes];
            output.fill(0);
            dev.read_sectors(slot_base + 1 + index as u64, output)?;
            let copy = remaining.min(bytes);
            crc.update(&output[..copy]);
            remaining -= copy;
            index += sectors;
        }
        if remaining != 0 || crc.finish() != plan.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(())
    }

    fn latest_commit_slot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<SlotSummary>, SnapshotBlockStoreError> {
        let mut corrupt = false;
        let mut candidates = [None, None];
        for (slot, candidate) in candidates.iter_mut().enumerate() {
            match self.read_slot_plan(dev, slot as u32) {
                Ok(plan) => *candidate = plan,
                Err(SnapshotBlockStoreError::Corrupt) => corrupt = true,
                Err(err) => return Err(err),
            }
        }
        candidates.sort_unstable_by_key(|plan| core::cmp::Reverse(plan.map(|p| p.generation)));
        for plan in candidates.into_iter().flatten() {
            match self.validate_slot_payload_crc(dev, plan) {
                Ok(()) => {
                    return Ok(Some(SlotSummary {
                        slot: plan.slot,
                        generation: plan.generation,
                        wal: plan.wal,
                        resetting: plan.resetting,
                    }))
                }
                Err(SnapshotBlockStoreError::Corrupt) => corrupt = true,
                Err(err) => return Err(err),
            }
        }
        if corrupt {
            Err(SnapshotBlockStoreError::Corrupt)
        } else {
            Ok(None)
        }
    }

    fn latest_valid_slot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
        let slot0 = self.read_valid_slot_plan(dev, 0);
        let slot1 = self.read_valid_slot_plan(dev, 1);
        match (slot0, slot1) {
            (Ok(Some(a)), Ok(Some(b))) => Ok(Some(if b.generation > a.generation { b } else { a })),
            (Ok(Some(a)), _) => Ok(Some(a)),
            (_, Ok(Some(b))) => Ok(Some(b)),
            (Ok(None), Ok(None)) => Ok(None),
            (Err(err), Ok(None)) | (Ok(None), Err(err)) => Err(err),
            (Err(_), Err(_)) => Err(SnapshotBlockStoreError::Corrupt),
        }
    }
}

impl<'a, D: SnapshotBlockDevice> PayloadSectorReader<'a, D> {
    fn new(
        dev: &'a mut D,
        batch: Vec<u8>,
        sector_size: usize,
        slot_base: u64,
        plan: SlotReadPlan,
    ) -> Self {
        Self {
            dev,
            batch,
            sector_size,
            slot_base,
            payload_len: plan.payload_len,
            payload_crc: plan.payload_crc,
            read: 0,
            sector_index: 0,
            batch_offset: 0,
            batch_valid: 0,
            crc: Crc32c::new(),
        }
    }

    fn fill_batch(&mut self) -> Result<(), SnapshotBlockStoreError> {
        if self.read >= self.payload_len {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let remaining = self.payload_len - self.read;
        let sectors = remaining.div_ceil(self.sector_size).min(READ_BATCH_SECTORS);
        let bytes = sectors * self.sector_size;
        self.batch[..bytes].fill(0);
        self.dev
            .read_sectors(self.slot_base + 1 + self.sector_index, &mut self.batch[..bytes])?;
        self.sector_index += sectors as u64;
        self.batch_offset = 0;
        self.batch_valid = remaining.min(bytes);
        Ok(())
    }

    fn finish(self) -> Result<(), SnapshotBlockStoreError> {
        if self.read != self.payload_len || self.crc.finish() != self.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(())
    }
}

impl<D: SnapshotBlockDevice> SnapshotPayloadReader for PayloadSectorReader<'_, D> {
    fn read_exact(&mut self, mut out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        if out.len() > self.remaining() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        while !out.is_empty() {
            if self.batch_offset == self.batch_valid {
                self.fill_batch()?;
            }
            let copy = out.len().min(self.batch_valid - self.batch_offset);
            let bytes = &self.batch[self.batch_offset..self.batch_offset + copy];
            self.crc.update(bytes);
            out[..copy].copy_from_slice(bytes);
            self.batch_offset += copy;
            self.read += copy;
            out = &mut out[copy..];
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.payload_len - self.read
    }
}

fn encode_header(out: &mut [u8], header: SlotHeader) {
    let len = if header.resetting {
        WAL_RESET_HEADER_LEN
    } else if header.wal.is_some() {
        WAL_HEADER_LEN
    } else {
        HEADER_LEN
    };
    out[..len].fill(0);
    out[0..8].copy_from_slice(&STORE_MAGIC);
    put_u16(&mut out[8..10], len as u16);
    put_u16(
        &mut out[10..12],
        if header.resetting {
            WAL_RESET_VERSION
        } else if header.wal.is_some() {
            WAL_STORE_VERSION
        } else {
            STORE_VERSION
        },
    );
    put_u32(&mut out[12..16], 0);
    put_u64(&mut out[16..24], header.generation);
    put_u64(&mut out[24..32], header.payload_len);
    put_u32(&mut out[32..36], header.payload_crc);
    put_u32(&mut out[36..40], header.payload_sectors);
    put_u32(&mut out[40..44], header.slot);
    if let Some(wal) = header.wal {
        put_u64(&mut out[44..52], wal.incarnation);
        put_u64(&mut out[52..60], wal.base_serial);
        put_u64(&mut out[60..68], wal.high_water_serial);
        put_u64(&mut out[68..76], wal.high_water_end_lba);
    }
    if header.resetting {
        put_u32(&mut out[76..80], 1);
    }
    let crc = crc32c(&out[..len - 4]);
    put_u32(&mut out[len - 4..len], crc);
}

fn decode_header(bytes: &[u8]) -> Result<Option<SlotHeader>, SnapshotBlockStoreError> {
    if bytes.len() < HEADER_LEN {
        return Err(SnapshotBlockStoreError::InvalidGeometry);
    }
    if bytes[..HEADER_LEN].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if bytes[0..8] != STORE_MAGIC {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    let header_len = read_u16(&bytes[8..10]);
    let version = read_u16(&bytes[10..12]);
    let len = match (version, header_len as usize) {
        (STORE_VERSION, HEADER_LEN) => HEADER_LEN,
        (WAL_STORE_VERSION, WAL_HEADER_LEN) if bytes.len() >= WAL_HEADER_LEN => WAL_HEADER_LEN,
        (WAL_RESET_VERSION, WAL_RESET_HEADER_LEN) if bytes.len() >= WAL_RESET_HEADER_LEN => {
            WAL_RESET_HEADER_LEN
        }
        _ => return Err(SnapshotBlockStoreError::Corrupt),
    };
    if bytes.len() < len {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    let header_crc = read_u32(&bytes[len - 4..len]);
    if crc32c(&bytes[..len - 4]) != header_crc {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    let resetting = version == WAL_RESET_VERSION;
    if resetting && read_u32(&bytes[76..80]) != 1 {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    let wal = if version == WAL_STORE_VERSION || resetting {
        let manifest = WalSnapshotManifest {
            incarnation: read_u64(&bytes[44..52]),
            base_serial: read_u64(&bytes[52..60]),
            high_water_serial: read_u64(&bytes[60..68]),
            high_water_end_lba: read_u64(&bytes[68..76]),
        };
        if !manifest.valid() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Some(manifest)
    } else {
        None
    };
    Ok(Some(SlotHeader {
        generation: read_u64(&bytes[16..24]),
        payload_len: read_u64(&bytes[24..32]),
        payload_crc: read_u32(&bytes[32..36]),
        payload_sectors: read_u32(&bytes[36..40]),
        slot: read_u32(&bytes[40..44]),
        wal,
        resetting,
    }))
}

fn put_u16(out: &mut [u8], value: u16) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], value: u64) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().unwrap())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}
