use super::*;

struct WideDisk {
    bytes: Vec<u8>,
    reads: Vec<usize>,
    writes: Vec<usize>,
    fail_batch: bool,
}

impl WideDisk {
    fn new() -> Self {
        Self {
            bytes: alloc::vec![0; 128 * 512],
            reads: Vec::new(),
            writes: Vec::new(),
            fail_batch: false,
        }
    }
}

impl SnapshotBlockDevice for WideDisk {
    fn sector_size(&self) -> usize { 512 }
    fn sector_count(&self) -> u64 { 128 }
    fn max_transfer_sectors(&self) -> usize { 32 }

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let start = lba as usize * 512;
        out.copy_from_slice(&self.bytes[start..start + 512]);
        Ok(())
    }
    fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let count = out.len() / 512;
        assert!(count > 0 && count <= 32 && out.len() % 512 == 0);
        self.reads.push(count);
        let start = lba as usize * 512;
        out.copy_from_slice(&self.bytes[start..start + out.len()]);
        Ok(())
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let start = lba as usize * 512;
        self.bytes[start..start + 512].copy_from_slice(data);
        Ok(())
    }
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let count = data.len() / 512;
        assert!(count > 0 && count <= 32 && data.len() % 512 == 0);
        self.writes.push(count);
        let start = lba as usize * 512;
        if self.fail_batch {
            self.bytes[start..start + 512].copy_from_slice(&data[..512]);
            return Err(SnapshotBlockStoreError::Io);
        }
        self.bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> { Ok(()) }
}

#[test]
fn wide_device_batches_thirty_two_sectors_and_keeps_partial_write_unpublished() {
    let store = SnapshotBlockStore::new(0, 128);
    let payload = alloc::vec![0xa5; 40 * 512 - 1];
    let mut disk = WideDisk::new();
    assert_eq!(store.commit_next(&mut disk, b"previous"), Ok(1));
    disk.writes.clear();
    assert_eq!(store.commit_next(&mut disk, &payload), Ok(2));
    assert_eq!(disk.writes, [32, 8]);
    disk.reads.clear();
    let selected = store.read_latest_streaming(&mut disk, |reader| {
        let mut bytes = alloc::vec![0; reader.remaining()];
        reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }).unwrap().unwrap();
    assert_eq!(selected, (2, payload.len(), payload.clone()));
    assert!(disk.reads.windows(2).any(|batch| batch == [32, 8]));

    disk.writes.clear();
    disk.fail_batch = true;
    assert_eq!(store.commit_next(&mut disk, &payload), Err(SnapshotBlockStoreError::Io));
    assert_eq!(disk.writes, [32]);
    disk.fail_batch = false;
    assert_eq!(store.read_latest(&mut disk).unwrap().unwrap().generation, 2);
}
