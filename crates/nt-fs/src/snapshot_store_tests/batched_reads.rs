use super::*;
use crate::snapshot_reserve::SnapshotReserve;
use alloc::rc::Rc;
use core::cell::Cell;

struct PrimitiveDisk {
    inner: CachedDisk,
    reads: Vec<u64>,
    size: usize,
}

impl PrimitiveDisk {
    fn new() -> Self {
        Self {
            inner: CachedDisk::new(),
            reads: Vec::new(),
            size: 512,
        }
    }
}

impl SnapshotBlockDevice for PrimitiveDisk {
    fn sector_size(&self) -> usize {
        self.size
    }
    fn sector_count(&self) -> u64 {
        16
    }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.reads.push(lba);
        self.inner.read_sector(lba, out)
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.inner.write_sector(lba, data)
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        self.inner.flush()
    }
}

#[test]
fn default_range_read_composes_real_reads_and_validates_before_effects() {
    let mut disk = PrimitiveDisk::new();
    disk.inner.cache[2 * 512..4 * 512].fill(0x73);
    let mut bytes = [0; 1024];
    disk.read_sectors(2, &mut bytes).unwrap();
    assert_eq!(bytes, [0x73; 1024]);
    assert_eq!(disk.reads, [2, 3]);
    disk.reads.clear();
    for (lba, len) in [(0, 513), (15, 1024), (u64::MAX, 512), (17, 0)] {
        assert_eq!(
            disk.read_sectors(lba, &mut alloc::vec![0; len]),
            Err(SnapshotBlockStoreError::InvalidGeometry)
        );
        assert!(disk.reads.is_empty());
    }
    disk.read_sectors(16, &mut []).unwrap();
    assert!(disk.reads.is_empty());
    disk.size = 0;
    assert_eq!(
        disk.read_sectors(0, &mut []),
        Err(SnapshotBlockStoreError::InvalidGeometry)
    );
}

#[test]
fn default_range_read_propagates_incomplete_primitive_read() {
    let mut disk = PrimitiveDisk::new();
    disk.inner.cache[512..1024].fill(0x45);
    disk.inner.fail_read = Some(2);
    let mut bytes = [0; 1536];
    assert_eq!(
        disk.read_sectors(1, &mut bytes),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(disk.reads, [1, 2]);
    assert_eq!(&bytes[..512], &[0x45; 512]);
    assert_eq!(&bytes[512..], &[0; 1024]);
}

struct CommandDisk {
    inner: CachedDisk,
    singles: Vec<u64>,
    batches: Vec<(u64, usize)>,
    partial_failure: Option<u64>,
    fail_batch_number: Option<usize>,
    corrupt_batch_number: Option<usize>,
    command_count: Rc<Cell<usize>>,
}

impl CommandDisk {
    fn new(inner: CachedDisk) -> Self {
        Self {
            inner,
            singles: Vec::new(),
            batches: Vec::new(),
            partial_failure: None,
            fail_batch_number: None,
            corrupt_batch_number: None,
            command_count: Rc::new(Cell::new(0)),
        }
    }
    fn copy_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        if self.partial_failure == Some(lba) {
            out[..256]
                .copy_from_slice(&self.inner.cache[lba as usize * 512..lba as usize * 512 + 256]);
            return Err(SnapshotBlockStoreError::Io);
        }
        self.inner.read_sector(lba, out)
    }
}

impl SnapshotBlockDevice for CommandDisk {
    fn sector_size(&self) -> usize {
        512
    }
    fn sector_count(&self) -> u64 {
        16
    }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.singles.push(lba);
        self.command_count.set(self.command_count.get() + 1);
        self.copy_sector(lba, out)
    }
    fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        let count = out.len() / 512;
        if out.len() % 512 != 0
            || count > 4
            || lba.checked_add(count as u64).is_none_or(|end| end > 16)
        {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        self.batches.push((lba, count));
        self.command_count.set(self.command_count.get() + 1);
        if self.fail_batch_number == Some(self.batches.len()) {
            self.copy_sector(lba, &mut out[..512])?;
            return Err(SnapshotBlockStoreError::Io);
        }
        for (index, sector) in out.chunks_exact_mut(512).enumerate() {
            self.copy_sector(lba + index as u64, sector)?;
        }
        if self.corrupt_batch_number == Some(self.batches.len()) {
            out[0] ^= 0x55;
        }
        Ok(())
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.inner.write_sector(lba, data)
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        self.inner.flush()
    }
}

fn populated(len: usize) -> (SnapshotBlockStore, CommandDisk, Vec<u8>) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut inner = CachedDisk::new();
    store
        .commit_next(&mut inner, b"older valid snapshot")
        .unwrap();
    let payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
    assert_eq!(store.commit_next(&mut inner, &payload), Ok(2));
    inner.events.clear();
    (store, CommandDisk::new(inner), payload)
}

#[test]
fn streaming_payload_batches_reads_across_fragmented_decoder_requests() {
    for len in [511, 512, 513, 2047, 2048, 2049, 3584] {
        let (store, mut disk, payload) = populated(len);
        let restored = store.read_latest_streaming(&mut disk, |reader| {
            let mut bytes = alloc::vec![0; reader.remaining()];
            let mut offset = 0;
            let chunks = [1, 510, 2, 713];
            let mut next = 0;
            while offset < bytes.len() {
                let end = (offset + chunks[next % chunks.len()]).min(bytes.len());
                reader.read_exact(&mut bytes[offset..end])?;
                assert_eq!(reader.remaining(), bytes.len() - end);
                offset = end;
                next += 1;
            }
            Ok(bytes)
        }).unwrap().unwrap();
        assert_eq!(restored, (2, len, payload));
        let sectors = len.div_ceil(512);
        let latest_batches: Vec<_> = (0..sectors)
            .step_by(4)
            .map(|index| (9 + index as u64, (sectors - index).min(4)))
            .collect();
        let mut expected = alloc::vec![(1, 1)]; // Validate the older slot.
        expected.extend_from_slice(&latest_batches); // Validate the selected slot.
        expected.extend_from_slice(&latest_batches); // Decode the selected slot.
        assert_eq!(disk.batches, expected, "payload length {len}");
        assert_eq!(disk.singles, [0, 8], "only headers need primitive reads");
    }
}

#[test]
fn streaming_payload_rejects_partial_batch_failure_and_changed_crc() {
    for failure_is_io in [true, false] {
        let (store, mut disk, _) = populated(3584);
        // Three CRC batches validate both slots. The fifth is the final decode batch.
        if failure_is_io {
            disk.fail_batch_number = Some(5);
        } else {
            disk.corrupt_batch_number = Some(5);
        }
        let result = store.read_latest_streaming(&mut disk, |reader| {
            let mut bytes = alloc::vec![0; reader.remaining()];
            reader.read_exact(&mut bytes)?;
            Ok(bytes)
        });
        assert!(matches!(result, Err(error) if error == if failure_is_io {
            SnapshotBlockStoreError::Io
        } else {
            SnapshotBlockStoreError::Corrupt
        }));
        assert_eq!(disk.batches.last(), Some(&(13, 3)));
        assert!(disk.inner.events.is_empty(), "a read cannot publish a snapshot");
    }
}

#[test]
fn prior_payload_crc_uses_four_sector_commands_at_logical_boundaries() {
    for len in [0, 1, 511, 512, 513, 2047, 2048, 2049, 3583, 3584] {
        let (store, mut disk, _) = populated(len);
        assert_eq!(store.commit_next(&mut disk, b"replacement"), Ok(3));
        let sectors = len.div_ceil(512);
        let expected: Vec<_> = (0..sectors)
            .step_by(4)
            .map(|i| (9 + i as u64, (sectors - i).min(4)))
            .collect();
        assert_eq!(disk.batches, expected, "logical payload length {len}");
        assert_eq!(
            disk.singles,
            [0, 8],
            "payload sectors must not become separate commands"
        );
        disk.inner.power_cut();
        assert_eq!(
            store.read_latest(&mut disk.inner).unwrap().unwrap().payload,
            b"replacement"
        );
    }
}

#[test]
fn crc_ignores_padding_but_not_logical_bytes_in_final_batch() {
    for len in [513, 2049, 3583] {
        let (store, mut disk, _) = populated(len);
        let padding = 9 * 512 + len;
        disk.inner.cache[padding] ^= 0x55;
        disk.inner.stable[padding] ^= 0x55;
        assert_eq!(store.commit_next(&mut disk, b"replacement"), Ok(3));
    }
}

#[test]
fn corrupt_each_batch_position_preserves_the_older_valid_slot() {
    for lba in 9..16 {
        let (store, mut disk, _) = populated(3584);
        disk.inner.corrupt(lba);
        assert_eq!(store.commit_next(&mut disk, b"replacement"), Ok(2));
        assert!(disk
            .inner
            .events
            .iter()
            .all(|event| !matches!(event, Event::Write(0..=7))));
        disk.inner.power_cut();
        assert_eq!(
            store.read_latest(&mut disk.inner).unwrap().unwrap().payload,
            b"replacement"
        );
    }
}

#[test]
fn failed_or_partial_read_at_each_batch_position_prohibits_target_writes() {
    for lba in 9..16 {
        for partial in [false, true] {
            let (store, mut disk, _) = populated(3584);
            if partial {
                disk.partial_failure = Some(lba);
            } else {
                disk.inner.fail_read = Some(lba);
            }
            assert_eq!(
                store.commit_next(&mut disk, b"replacement"),
                Err(SnapshotBlockStoreError::Io)
            );
            assert_eq!(disk.inner.events, [Event::Flush]);
            disk.inner.fail_read = None;
            disk.partial_failure = None;
            disk.inner.power_cut();
            assert_eq!(
                store
                    .read_latest(&mut disk.inner)
                    .unwrap()
                    .unwrap()
                    .generation,
                2
            );
        }
    }
}

#[test]
fn reserve_lease_forwards_batch_override_without_relaxing_exclusion() {
    let (store, disk, _) = populated(2049);
    let commands = Rc::clone(&disk.command_count);
    let reserve = SnapshotReserve::new(disk, 73u64, store);
    let mut lease = reserve.try_acquire().unwrap();
    assert!(reserve.try_acquire().is_none());
    lease.read_sectors(9, &mut [0; 2048]).unwrap();
    assert_eq!(commands.get(), 1);
    assert!(reserve.try_acquire().is_none());
    drop(lease);
    let mut lease = reserve.try_acquire().unwrap();
    // Invalid input must be rejected by the forwarded backend before any command.
    assert_eq!(
        lease.read_sectors(9, &mut [0; 513]),
        Err(SnapshotBlockStoreError::InvalidGeometry)
    );
    assert_eq!(commands.get(), 1);
    assert!(reserve.try_acquire().is_none());
}
