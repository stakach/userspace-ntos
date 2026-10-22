//! The single owned backend for the executable mount's physical snapshot reserve.

use super::*;
use nt_fs::{BoundedBlockRange, OwnedBoundedBlockRange, SnapshotBlockDevice, SnapshotReserve, SnapshotReserveLease};
use nt_memory_manager::SectionMountId;

#[path = "snapshot_storage/native_header_recheck.rs"]
mod native_header_recheck;
pub(crate) use native_header_recheck::*;

type Reserve = SnapshotReserve<AhciSnapshotDevice, SectionMountId>;
pub(crate) type Lease = SnapshotReserveLease<'static, AhciSnapshotDevice, SectionMountId>;
static mut RESERVE: Option<Reserve> = None;
static mut PHYSICAL_RANGE: Option<(SectionMountId, u64, u64)> = None;

struct MountedWalContinuation {
    mount: SectionMountId,
    token: nt_fs::RegistryWalContinuation,
    pair: nt_fs::VerifiedPairedWalSnapshot,
}

// These move-only in-process proofs are never boot recovery authority. Boot scans the physical
// WAL and validates both snapshot payloads before installing a fresh mounted pair.
static mut WAL_CONTINUATION: Option<MountedWalContinuation> = None;
pub(super) const BUSY: u32 = 0x8000_0011;
const SNAPSHOT_SECTORS: u64 = crate::fs_loader::WRITABLE_SNAPSHOT_RESERVE_SECTORS as u64;
const WAL_SECTORS: u64 = SNAPSHOT_SECTORS;

pub(super) fn wal_bounds(lease: &Lease) -> Result<(u64, u64), u32> {
    if lease.sector_count() < SNAPSHOT_SECTORS + WAL_SECTORS {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok((SNAPSHOT_SECTORS, WAL_SECTORS))
}

/// Boot-only publication, before the executable filesystem identity becomes visible. This slot
/// cannot be replaced; copied Fat32 values elsewhere never grant snapshot device access.
pub(crate) unsafe fn publish(fat: Fat32, mount: SectionMountId, physical_sectors: u64) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(RESERVE);
    if slot.is_some() {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if let Some(device) = AhciSnapshotDevice::from_backing(fat, physical_sectors)? {
        let physical_range = (mount, device.start_lba, u64::from(device.sectors));
        let store = nt_fs::SnapshotBlockStore::new(0, SNAPSHOT_SECTORS);
        *slot = Some(SnapshotReserve::new(device, mount, store));
        *core::ptr::addr_of_mut!(PHYSICAL_RANGE) = Some(physical_range);
    }
    Ok(())
}

/// A disjoint tail view under the snapshot backend's existing exclusive mount lease.
/// No registry write path uses this region until append/recovery ownership is implemented.
#[allow(dead_code)]
pub(super) fn wal_region(lease: &mut Lease) -> Result<Option<BoundedBlockRange<'_, Lease>>, u32> {
    if lease.sector_count() < SNAPSHOT_SECTORS + WAL_SECTORS {
        return Ok(None);
    }
    BoundedBlockRange::new(lease, SNAPSHOT_SECTORS, WAL_SECTORS)
        .map(Some)
        .map_err(|_| nt_fs::STATUS_INVALID_PARAMETER)
}

/// Move the exact reserve lease into a bounded WAL owner. Once a record write begins,
/// uncertainty must retain this owner so the reserve cannot be reused by a new writer.
#[allow(dead_code)]
pub(super) fn owned_wal_region(
    lease: Lease,
) -> Result<OwnedBoundedBlockRange<Lease>, (u32, Lease)> {
    OwnedBoundedBlockRange::new(lease, SNAPSHOT_SECTORS, WAL_SECTORS)
        .map_err(|(_, lease)| (nt_fs::STATUS_INVALID_PARAMETER, lease))
}

pub(super) unsafe fn acquire() -> Result<Lease, u32> {
    let reserve = (&*core::ptr::addr_of!(RESERVE))
        .as_ref()
        .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    let lease = reserve.try_acquire().ok_or(BUSY)?;
    if Some(*lease.identity()) != crate::fs_loader::exec_fs_mount_identity() {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    Ok(lease)
}

fn checked_mount(lease: &Lease) -> Result<SectionMountId, u32> {
    let mount = *lease.identity();
    if Some(mount) != unsafe { crate::fs_loader::exec_fs_mount_identity() } {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    Ok(mount)
}

/// Convert one reserve-relative sector under the exact mounted lease, including WAL tail sectors.
/// The native executor still validates the resulting absolute request against its disk route.
pub(super) fn physical_lba(lease: &Lease, relative_lba: u64) -> Result<u64, u32> {
    let mount = checked_mount(lease)?;
    let (range_mount, start, sectors) = unsafe { *core::ptr::addr_of!(PHYSICAL_RANGE) }
        .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    if mount != range_mount || relative_lba >= sectors || relative_lba >= lease.sector_count() {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    start.checked_add(relative_lba).ok_or(nt_fs::STATUS_INVALID_PARAMETER)
}

/// Publish the WAL continuation and verified snapshot pair under their physical mount lease.
/// Refusal returns both move-only proofs so the caller can retain them with the lease.
pub(crate) fn install_wal_continuation(
    lease: &Lease,
    token: nt_fs::RegistryWalContinuation,
    pair: nt_fs::VerifiedPairedWalSnapshot,
) -> Result<(), (u32, nt_fs::RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot)> {
    let mount = match checked_mount(lease) {
        Ok(mount) => mount,
        Err(status) => return Err((status, token, pair)),
    };
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(WAL_CONTINUATION) };
    if slot.is_some() || token.anchor().incarnation == 0 || token.anchor() != pair.anchor() {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, token, pair));
    }
    *slot = Some(MountedWalContinuation { mount, token, pair });
    Ok(())
}

/// Transfer both proofs only under the exact mount lease and unchanged paired headers.
/// Absence or mismatch refuses admission without changing the cached authority.
pub(super) fn take_wal_continuation(
    lease: &mut Lease,
) -> Result<(nt_fs::RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot, nt_fs::WalSnapshotManifest), u32> {
    let mount = checked_mount(lease)?;
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(WAL_CONTINUATION) };
    let Some(cached) = slot.as_ref() else {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    };
    if cached.mount != mount || cached.token.anchor() != cached.pair.anchor() {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    let manifest = lease.store()
        .recheck_verified_paired_wal_snapshot(lease, &cached.pair)
        .map_err(super::snapshot_store_error_status)?;
    if cached.token.anchor() != manifest_anchor(manifest) {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    let cached = slot.take().expect("checked continuation");
    Ok((cached.token, cached.pair, manifest))
}

/// NtFlushKey and fold admission recheck both exact headers while holding the mount lease.
pub(super) fn peek_wal_continuation(
    lease: &mut Lease,
) -> Result<nt_fs::WalSnapshotManifest, u32> {
    let mount = checked_mount(lease)?;
    let slot = unsafe { &*core::ptr::addr_of!(WAL_CONTINUATION) };
    let Some(cached) = slot.as_ref() else {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    };
    if cached.mount != mount || cached.token.anchor() != cached.pair.anchor() {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    let manifest = lease.store()
        .recheck_verified_paired_wal_snapshot(lease, &cached.pair)
        .map_err(super::snapshot_store_error_status)?;
    if cached.token.anchor() != manifest_anchor(manifest) {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    Ok(manifest)
}

/// The native flush fence uses only authority already published after the exact marker and
/// paired anchor ACKs. The acquired singleton lease excludes every pending WAL, recheck,
/// checkpoint, and fold owner; no provider I/O is needed to prove a completed durability fence.
pub(super) fn check_cached_wal_fence(lease: &Lease) -> Result<(), u32> {
    let mount = checked_mount(lease)?;
    let cached = unsafe { &*core::ptr::addr_of!(WAL_CONTINUATION) }
        .as_ref().ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    let anchor = cached.token.anchor();
    if cached.mount != mount
        || !cached.pair.matches_cached_fence(lease.store(), anchor)
        || anchor != manifest_anchor(cached.pair.manifest())
    {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    // Reject an obsolete lease geometry if a mount publication was ever contradicted.
    physical_lba(lease, 0)?;
    Ok(())
}

pub(super) fn cached_wal_manifest(lease: &Lease) -> Result<nt_fs::WalSnapshotManifest, u32> {
    check_cached_wal_fence(lease)?;
    Ok(unsafe { &*core::ptr::addr_of!(WAL_CONTINUATION) }
        .as_ref().expect("checked cached continuation").pair.manifest())
}

fn manifest_anchor(manifest: nt_fs::WalSnapshotManifest) -> nt_fs::WalSnapshotAnchor {
    nt_fs::WalSnapshotAnchor {
        incarnation: manifest.incarnation,
        serial: manifest.high_water_serial,
        end_lba: manifest.high_water_end_lba,
    }
}

pub(crate) struct AhciSnapshotDevice {
    fat: Fat32,
    start_lba: u64,
    sectors: u32,
    flush_command: Option<nt_ahci::FlushCommand>,
}

impl AhciSnapshotDevice {
    fn from_backing(fat: Fat32, physical_sectors: u64) -> Result<Option<Self>, u32> {
        let Some((start_lba, snapshot_sectors)) = crate::fs_loader::writable_snapshot_reserve(&fat) else {
            return Ok(None);
        };
        let snapshot_end = start_lba
            .checked_add(u64::from(snapshot_sectors))
            .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
        if snapshot_end > physical_sectors {
            return Ok(None);
        }
        let wal_end = snapshot_end.checked_add(WAL_SECTORS)
            .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
        let sectors = if wal_end <= physical_sectors {
            snapshot_sectors + WAL_SECTORS as u32
        } else {
            snapshot_sectors
        };
        Ok(Some(Self {
            fat,
            start_lba,
            sectors,
            flush_command: None,
        }))
    }

    fn absolute_lba(&self, lba: u64) -> Result<u64, nt_fs::SnapshotBlockStoreError> {
        if lba >= u64::from(self.sectors) {
            return Err(nt_fs::SnapshotBlockStoreError::InvalidGeometry);
        }
        self.start_lba
            .checked_add(lba)
            .ok_or(nt_fs::SnapshotBlockStoreError::InvalidGeometry)
    }
}

impl nt_fs::SnapshotBlockDevice for AhciSnapshotDevice {
    fn flush(&mut self) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        if !crate::fs_loader::admit_exec_mount_boot_io(nt_fs::BlockSource::Snapshot, nt_fs::BlockOperation::Flush) {
            return Err(nt_fs::SnapshotBlockStoreError::Io);
        }
        unsafe { crate::ahci_maintenance::flush(&self.fat, &mut self.flush_command) }
            .map_err(|_| nt_fs::SnapshotBlockStoreError::Io)
    }

    fn sector_size(&self) -> usize {
        512
    }

    fn sector_count(&self) -> u64 {
        self.sectors as u64
    }

    fn read_sector(
        &mut self,
        lba: u64,
        out: &mut [u8],
    ) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        if out.len() != self.sector_size() {
            return Err(nt_fs::SnapshotBlockStoreError::InvalidGeometry);
        }
        self.read_sectors(lba, out)
    }

    fn read_sectors(
        &mut self,
        lba: u64,
        out: &mut [u8],
    ) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        let sector_size = self.sector_size();
        if sector_size == 0 || out.len() % sector_size != 0 {
            return Err(nt_fs::SnapshotBlockStoreError::InvalidGeometry);
        }
        let total_sectors = u64::try_from(out.len() / sector_size)
            .map_err(|_| nt_fs::SnapshotBlockStoreError::InvalidGeometry)?;
        let end = lba
            .checked_add(total_sectors)
            .ok_or(nt_fs::SnapshotBlockStoreError::InvalidGeometry)?;
        if end > u64::from(self.sectors) {
            return Err(nt_fs::SnapshotBlockStoreError::InvalidGeometry);
        }

        let max_chunk = AHCI_MAX_SECTORS_PER_READ as usize;
        let mut sector_index = 0usize;
        while sector_index < total_sectors as usize {
            let chunk_sectors = (total_sectors as usize - sector_index).min(max_chunk);
            let absolute = self.absolute_lba(lba + sector_index as u64)?;
            if !crate::fs_loader::admit_exec_mount_boot_io(
                nt_fs::BlockSource::Snapshot,
                nt_fs::BlockOperation::Read { lba: absolute, sectors: chunk_sectors as u32 },
            ) {
                return Err(nt_fs::SnapshotBlockStoreError::Io);
            }
            let byte_start = sector_index * sector_size;
            let byte_end = byte_start + chunk_sectors * sector_size;
            let started = self.fat.census.then(disk_census_ticks);
            let tfd = unsafe {
                ahci_read_sectors(
                    self.fat.ahci_vaddr,
                    self.fat.dma_vaddr,
                    self.fat.dma_paddr,
                    absolute,
                    chunk_sectors as u32,
                )
            };
            crate::fs_loader::disk_census_record(
                nt_ahci::IoOperation::Read,
                started,
                chunk_sectors as u64,
                tfd & nt_ahci::TASK_FILE_FAILURE != 0,
            );
            if tfd & nt_ahci::TASK_FILE_FAILURE != 0 {
                return Err(nt_fs::SnapshotBlockStoreError::Io);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.fat.dma_vaddr + AHCI_DMA_DATA_OFFSET) as *const u8,
                    out[byte_start..byte_end].as_mut_ptr(),
                    byte_end - byte_start,
                );
            }
            sector_index += chunk_sectors;
        }
        Ok(())
    }

    fn write_sector(
        &mut self,
        lba: u64,
        data: &[u8],
    ) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        self.write_sectors(lba, data)
    }

    fn write_sectors(
        &mut self,
        lba: u64,
        data: &[u8],
    ) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        let sector_size = self.sector_size();
        if sector_size == 0 || data.is_empty() || data.len() % sector_size != 0 {
            return Err(nt_fs::SnapshotBlockStoreError::InvalidGeometry);
        }
        let total_sectors = u64::try_from(data.len() / sector_size)
            .map_err(|_| nt_fs::SnapshotBlockStoreError::InvalidGeometry)?;
        let end = lba
            .checked_add(total_sectors)
            .ok_or(nt_fs::SnapshotBlockStoreError::InvalidGeometry)?;
        if end > self.sectors as u64 {
            return Err(nt_fs::SnapshotBlockStoreError::InvalidGeometry);
        }

        let max_chunk = AHCI_MAX_SECTORS_PER_WRITE as usize;
        let mut sector_index = 0usize;
        while sector_index < total_sectors as usize {
            let chunk_sectors = (total_sectors as usize - sector_index).min(max_chunk);
            let relative_lba = lba + sector_index as u64;
            let absolute = self.absolute_lba(relative_lba)?;
            if !crate::fs_loader::admit_exec_mount_boot_io(
                nt_fs::BlockSource::Snapshot,
                nt_fs::BlockOperation::Write { lba: absolute, sectors: chunk_sectors as u32 },
            ) {
                return Err(nt_fs::SnapshotBlockStoreError::Io);
            }
            let byte_start = sector_index * sector_size;
            let byte_end = byte_start + chunk_sectors * sector_size;
            let started = self.fat.census.then(disk_census_ticks);
            let tfd = unsafe {
                ahci_write_sectors(
                    self.fat.ahci_vaddr,
                    self.fat.dma_vaddr,
                    self.fat.dma_paddr,
                    absolute,
                    &data[byte_start..byte_end],
                )
            };
            crate::fs_loader::disk_census_record(
                nt_ahci::IoOperation::Write,
                started,
                chunk_sectors as u64,
                tfd & nt_ahci::TASK_FILE_FAILURE != 0,
            );
            if tfd & nt_ahci::TASK_FILE_FAILURE != 0 {
                return Err(nt_fs::SnapshotBlockStoreError::Io);
            }
            let n = WRITABLE_FS_SNAPSHOT_WRITE_SECTORS
                .fetch_add(chunk_sectors as u64, Ordering::Relaxed);
            if n < 8 || (n / 2048) != ((n + chunk_sectors as u64) / 2048) {
                print_str(b"[writable-fs-snapshot] write-sector #");
                print_u64(n.saturating_add(chunk_sectors as u64));
                print_str(b" rel-lba=");
                print_u64(relative_lba);
                print_str(b" abs-lba=");
                print_u64(absolute as u64);
                print_str(b" count=");
                print_u64(chunk_sectors as u64);
                print_str(b"\n");
            }
            sector_index += chunk_sectors;
        }
        Ok(())
    }
}
