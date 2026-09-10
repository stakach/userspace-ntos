//! The single owned backend for the executable mount's physical snapshot reserve.

use super::*;
use nt_fs::{SnapshotReserve, SnapshotReserveLease};
use nt_memory_manager::SectionMountId;

type Reserve = SnapshotReserve<AhciSnapshotDevice, SectionMountId>;
pub(super) type Lease = SnapshotReserveLease<'static, AhciSnapshotDevice, SectionMountId>;
static mut RESERVE: Option<Reserve> = None;
pub(super) const BUSY: u32 = 0x8000_0011;

/// Boot-only publication, before the executable filesystem identity becomes visible. This slot
/// cannot be replaced; copied Fat32 values elsewhere never grant snapshot device access.
pub(crate) unsafe fn publish(fat: Fat32, mount: SectionMountId) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(RESERVE);
    if slot.is_some() {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if let Some(device) = AhciSnapshotDevice::from_backing(fat)? {
        let store = nt_fs::SnapshotBlockStore::new(0, u64::from(device.sectors));
        *slot = Some(SnapshotReserve::new(device, mount, store));
    }
    Ok(())
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

pub(super) struct AhciSnapshotDevice {
    fat: Fat32,
    start_lba: u64,
    sectors: u32,
    flush_command: Option<nt_ahci::FlushCommand>,
}

impl AhciSnapshotDevice {
    fn from_backing(fat: Fat32) -> Result<Option<Self>, u32> {
        let Some((start_lba, sectors)) = crate::fs_loader::writable_snapshot_reserve(&fat) else {
            return Ok(None);
        };
        start_lba
            .checked_add(u64::from(sectors))
            .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
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
        let absolute = self.absolute_lba(lba)?;
        let tfd = unsafe {
            ahci_read_sector(
                self.fat.ahci_vaddr,
                self.fat.dma_vaddr,
                self.fat.dma_paddr,
                absolute,
            )
        };
        if tfd & nt_ahci::TASK_FILE_FAILURE != 0 {
            return Err(nt_fs::SnapshotBlockStoreError::Io);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.fat.dma_vaddr + 0x800) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
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
            let tfd = unsafe {
                ahci_write_sectors(
                    self.fat.ahci_vaddr,
                    self.fat.dma_vaddr,
                    self.fat.dma_paddr,
                    absolute,
                    &data[byte_start..byte_end],
                )
            };
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
