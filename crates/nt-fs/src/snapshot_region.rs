//! Checked borrowed and owned sector views for a disjoint area of one leased disk.

use crate::{SnapshotBlockDevice, SnapshotBlockStoreError};

pub struct BoundedBlockRange<'a, D> {
    device: &'a mut D,
    start: u64,
    sectors: u64,
}

/// An exact device owner limited to one subrange. A WAL can retain this value across
/// uncertain writes without releasing the underlying reserve lease by dropping a borrow.
#[must_use = "retain the device owner until the bounded storage effect is settled"]
pub struct OwnedBoundedBlockRange<D> {
    device: D,
    start: u64,
    sectors: u64,
}

fn valid_range<D: SnapshotBlockDevice>(device: &D, start: u64, sectors: u64) -> bool {
    sectors != 0 && start.checked_add(sectors).is_some_and(|end| end <= device.sector_count())
}

fn absolute<D: SnapshotBlockDevice>(
    device: &D,
    start: u64,
    sectors: u64,
    lba: u64,
    bytes: usize,
) -> Result<u64, SnapshotBlockStoreError> {
    let sector_size = device.sector_size();
    if sector_size == 0 || bytes == 0 || bytes % sector_size != 0 {
        return Err(SnapshotBlockStoreError::InvalidGeometry);
    }
    let count = u64::try_from(bytes / sector_size).map_err(|_| SnapshotBlockStoreError::InvalidGeometry)?;
    if lba.checked_add(count).is_none_or(|end| end > sectors) {
        return Err(SnapshotBlockStoreError::InvalidGeometry);
    }
    start.checked_add(lba).ok_or(SnapshotBlockStoreError::InvalidGeometry)
}

impl<D: SnapshotBlockDevice> OwnedBoundedBlockRange<D> {
    /// Invalid geometry returns the original owner so the caller can release or retain it.
    pub fn new(device: D, start: u64, sectors: u64) -> Result<Self, (SnapshotBlockStoreError, D)> {
        if !valid_range(&device, start, sectors) {
            return Err((SnapshotBlockStoreError::InvalidGeometry, device));
        }
        Ok(Self { device, start, sectors })
    }

    pub fn into_device(self) -> D { self.device }

    /// Physical start of this exact owned subrange in its parent device.
    pub fn start_lba(&self) -> u64 { self.start }

    pub(crate) fn parent_device_mut(&mut self) -> &mut D { &mut self.device }

    fn absolute(&self, lba: u64, bytes: usize) -> Result<u64, SnapshotBlockStoreError> {
        absolute(&self.device, self.start, self.sectors, lba, bytes)
    }
}

impl<'a, D: SnapshotBlockDevice> BoundedBlockRange<'a, D> {
    pub fn new(device: &'a mut D, start: u64, sectors: u64) -> Result<Self, SnapshotBlockStoreError> {
        if !valid_range(device, start, sectors) {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        Ok(Self { device, start, sectors })
    }

    fn absolute(&self, lba: u64, bytes: usize) -> Result<u64, SnapshotBlockStoreError> {
        absolute(self.device, self.start, self.sectors, lba, bytes)
    }
}

impl<D: SnapshotBlockDevice> SnapshotBlockDevice for OwnedBoundedBlockRange<D> {
    fn sector_size(&self) -> usize { self.device.sector_size() }
    fn sector_count(&self) -> u64 { self.sectors }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, out.len())?;
        if out.len() != self.sector_size() { return Err(SnapshotBlockStoreError::InvalidGeometry); }
        self.device.read_sector(absolute, out)
    }
    fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, out.len())?;
        self.device.read_sectors(absolute, out)
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, data.len())?;
        if data.len() != self.sector_size() { return Err(SnapshotBlockStoreError::InvalidGeometry); }
        self.device.write_sector(absolute, data)
    }
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, data.len())?;
        self.device.write_sectors(absolute, data)
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> { self.device.flush() }
}

impl<D: SnapshotBlockDevice> SnapshotBlockDevice for BoundedBlockRange<'_, D> {
    fn sector_size(&self) -> usize { self.device.sector_size() }
    fn sector_count(&self) -> u64 { self.sectors }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, out.len())?;
        if out.len() != self.sector_size() { return Err(SnapshotBlockStoreError::InvalidGeometry); }
        self.device.read_sector(absolute, out)
    }
    fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, out.len())?;
        self.device.read_sectors(absolute, out)
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, data.len())?;
        if data.len() != self.sector_size() { return Err(SnapshotBlockStoreError::InvalidGeometry); }
        self.device.write_sector(absolute, data)
    }
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let absolute = self.absolute(lba, data.len())?;
        self.device.write_sectors(absolute, data)
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> { self.device.flush() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SnapshotBlockStore, SnapshotReserve};
    use crate::snapshot_test_device::CachedDisk;

    #[test]
    fn old_snapshot_slots_and_new_tail_remain_disjoint() {
        let reserve = SnapshotReserve::new(CachedDisk::with_sectors(48), 7, SnapshotBlockStore::new(0, 32));
        let mut lease = reserve.try_acquire().unwrap();
        let store = lease.store();
        store.commit_next(&mut lease, b"old").unwrap();
        store.commit_next(&mut lease, b"new").unwrap();
        {
            let mut wal = BoundedBlockRange::new(&mut lease, 32, 16).unwrap();
            wal.write_sector(0, &[0xa5; 512]).unwrap();
            assert_eq!(wal.write_sector(16, &[0; 512]), Err(SnapshotBlockStoreError::InvalidGeometry));
        }
        store.commit_next(&mut lease, b"latest").unwrap();
        lease.flush().unwrap();
        let mut sentinel = [0; 512];
        BoundedBlockRange::new(&mut lease, 32, 16).unwrap().read_sector(0, &mut sentinel).unwrap();
        assert_eq!(sentinel, [0xa5; 512]);
        assert_eq!(store.read_latest(&mut lease).unwrap().unwrap().payload, b"latest");
        // Simulate reboot from stable media: append bytes and the latest snapshot survive.
        drop(lease);
        let mut lease = reserve.try_acquire().unwrap();
        lease.test_device_mut().power_cut();
        BoundedBlockRange::new(&mut lease, 32, 16).unwrap().read_sector(0, &mut sentinel).unwrap();
        assert_eq!(sentinel, [0xa5; 512]);
        assert_eq!(store.read_latest(&mut lease).unwrap().unwrap().payload, b"latest");
        drop(lease);

        let old = SnapshotReserve::new(CachedDisk::with_sectors(32), 8, SnapshotBlockStore::new(0, 32));
        let mut old_lease = old.try_acquire().unwrap();
        assert!(matches!(BoundedBlockRange::new(&mut old_lease, 32, 16), Err(SnapshotBlockStoreError::InvalidGeometry)));
        assert_eq!(old_lease.store().commit_next(&mut old_lease, b"legacy"), Ok(1));
    }

    #[test]
    fn range_rejects_crossing_and_overflow_at_both_ends() {
        let reserve = SnapshotReserve::new(CachedDisk::with_sectors(48), 9, SnapshotBlockStore::new(0, 32));
        let mut lease = reserve.try_acquire().unwrap();
        assert!(matches!(BoundedBlockRange::new(&mut lease, u64::MAX, 2), Err(SnapshotBlockStoreError::InvalidGeometry)));
        let mut wal = BoundedBlockRange::new(&mut lease, 32, 16).unwrap();
        let mut one = [0; 512];
        let mut two = [0; 1024];
        assert!(wal.read_sector(0, &mut one).is_ok());
        assert!(wal.read_sector(15, &mut one).is_ok());
        assert_eq!(wal.read_sector(16, &mut one), Err(SnapshotBlockStoreError::InvalidGeometry));
        assert!(wal.read_sectors(14, &mut two).is_ok());
        assert_eq!(wal.read_sectors(15, &mut two), Err(SnapshotBlockStoreError::InvalidGeometry));
        assert_eq!(wal.write_sectors(u64::MAX, &two), Err(SnapshotBlockStoreError::InvalidGeometry));
    }

    #[test]
    fn owned_range_retains_and_returns_the_exact_reserve_lease() {
        let reserve = SnapshotReserve::new(CachedDisk::with_sectors(48), 11, SnapshotBlockStore::new(0, 32));
        let lease = reserve.try_acquire().unwrap();
        let mut wal = match OwnedBoundedBlockRange::new(lease, 32, 16) {
            Ok(wal) => wal,
            Err((error, _)) => panic!("valid owned WAL range: {error:?}"),
        };
        assert!(reserve.try_acquire().is_none());
        wal.write_sector(0, &[0x5a; 512]).unwrap();
        assert_eq!(wal.write_sector(16, &[0; 512]), Err(SnapshotBlockStoreError::InvalidGeometry));
        let mut lease = wal.into_device();
        assert_eq!(*lease.identity(), 11);
        assert!(reserve.try_acquire().is_none());
        let mut sector = [0; 512];
        lease.read_sector(32, &mut sector).unwrap();
        assert_eq!(sector, [0x5a; 512]);
        drop(lease);
        assert!(reserve.try_acquire().is_some());
    }

    #[test]
    fn invalid_owned_range_returns_unmodified_lease() {
        let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 12, SnapshotBlockStore::new(0, 32));
        let lease = reserve.try_acquire().unwrap();
        let (error, lease) = match OwnedBoundedBlockRange::new(lease, 32, 16) {
            Ok(_) => panic!("legacy reserve must reject WAL tail"),
            Err(error) => error,
        };
        assert_eq!(error, SnapshotBlockStoreError::InvalidGeometry);
        assert_eq!(*lease.identity(), 12);
        assert!(reserve.try_acquire().is_none());
        drop(lease);
        assert!(reserve.try_acquire().is_some());
    }
}
