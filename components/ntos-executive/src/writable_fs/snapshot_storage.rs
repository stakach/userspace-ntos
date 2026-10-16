//! The single owned backend for the executable mount's physical snapshot reserve.

use super::*;
use nt_fs::{BoundedBlockRange, OwnedBoundedBlockRange, SnapshotBlockDevice, SnapshotReserve, SnapshotReserveLease};
use nt_memory_manager::SectionMountId;

type Reserve = SnapshotReserve<AhciSnapshotDevice, SectionMountId>;
pub(super) type Lease = SnapshotReserveLease<'static, AhciSnapshotDevice, SectionMountId>;
static mut RESERVE: Option<Reserve> = None;

struct MountedWalContinuation {
    mount: SectionMountId,
    token: nt_fs::RegistryWalContinuation,
}

// This is an in-process accelerator, never a boot recovery authority. Boot always scans the
// physical WAL and proves paired snapshot headers before installing a fresh continuation.
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
pub(crate) unsafe fn publish(fat: Fat32, mount: SectionMountId) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(RESERVE);
    if slot.is_some() {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if let Some(device) = AhciSnapshotDevice::from_backing(fat)? {
        let store = nt_fs::SnapshotBlockStore::new(0, SNAPSHOT_SECTORS);
        *slot = Some(SnapshotReserve::new(device, mount, store));
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

/// Publish a typed post-anchor continuation under the same physical mount lease that produced
/// it. The nt-fs token can only be minted by a completed paired-header anchor update or
/// completed two-slot empty baseline repair, so its private anchor is the durable header proof;
/// this cache adds the immutable physical mount binding. Refusal returns the move-only token.
pub(super) fn install_wal_continuation(
    lease: &Lease,
    token: nt_fs::RegistryWalContinuation,
) -> Result<(), (u32, nt_fs::RegistryWalContinuation)> {
    let mount = match checked_mount(lease) {
        Ok(mount) => mount,
        Err(status) => return Err((status, token)),
    };
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(WAL_CONTINUATION) };
    if slot.is_some() || token.anchor().incarnation == 0 {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, token));
    }
    *slot = Some(MountedWalContinuation { mount, token });
    Ok(())
}

/// Transfer the continuation only to an owner holding the exact mount lease and paired-header
/// anchor. Absence or mismatch refuses admission without changing the cached authority.
pub(super) fn take_wal_continuation(
    lease: &Lease,
    expected_anchor: nt_fs::WalSnapshotAnchor,
) -> Result<nt_fs::RegistryWalContinuation, u32> {
    let mount = checked_mount(lease)?;
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(WAL_CONTINUATION) };
    let Some(cached) = slot.as_ref() else {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    };
    if cached.mount != mount || cached.token.anchor() != expected_anchor {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    Ok(slot.take().expect("checked continuation").token)
}

/// NtFlushKey can prove the current anchored prefix without scanning the WAL again. The caller
/// must have read and validated the paired-header anchor while holding this lease.
pub(super) fn peek_wal_continuation(
    lease: &Lease,
    expected_anchor: nt_fs::WalSnapshotAnchor,
) -> Result<(), u32> {
    let mount = checked_mount(lease)?;
    let slot = unsafe { &*core::ptr::addr_of!(WAL_CONTINUATION) };
    let Some(cached) = slot.as_ref() else {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    };
    if cached.mount != mount || cached.token.anchor() != expected_anchor {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    Ok(())
}

pub(super) struct AhciSnapshotDevice {
    fat: Fat32,
    start_lba: u64,
    sectors: u32,
    flush_command: Option<nt_ahci::FlushCommand>,
}

impl AhciSnapshotDevice {
    fn from_backing(fat: Fat32) -> Result<Option<Self>, u32> {
        let Some((start_lba, snapshot_sectors)) = crate::fs_loader::writable_snapshot_reserve(&fat) else {
            return Ok(None);
        };
        let physical_sectors = unsafe { crate::ahci_maintenance::physical_sector_count(&fat) }
            .map_err(|_| nt_fs::STATUS_DEVICE_NOT_READY)?;
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
