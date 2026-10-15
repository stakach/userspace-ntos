use super::*;

struct CommandDisk {
    inner: CachedDisk,
    batches: Vec<(u64, usize)>,
    singles: Vec<u64>,
    fail_batch: Option<(usize, u8)>,
}

impl CommandDisk {
    fn new() -> Self {
        Self {
            inner: CachedDisk::new(),
            batches: Vec::new(),
            singles: Vec::new(),
            fail_batch: None,
        }
    }

    fn with_generations() -> (SnapshotBlockStore, Self) {
        let (store, inner) = two_generations();
        (
            store,
            Self {
                inner,
                ..Self::new()
            },
        )
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
        self.inner.read_sector(lba, out)
    }
    fn write_sector(&mut self, lba: u64, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        assert_eq!(
            bytes.len(),
            512,
            "publication header must remain one sector"
        );
        self.singles.push(lba);
        self.inner.write_sector(lba, bytes)
    }
    fn write_sectors(&mut self, lba: u64, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len() % 512, 0);
        assert!(
            bytes.len() <= 4 * 512,
            "payload staging must remain bounded"
        );
        let batch = self.batches.len();
        self.batches.push((lba, bytes.len() / 512));
        if let Some((failed, mask)) = self.fail_batch {
            if batch == failed {
                // A failed command may already have persisted an arbitrary subset of sectors.
                for (index, sector) in bytes.chunks_exact(512).enumerate() {
                    if mask & (1 << index) != 0 {
                        self.inner.write_sector(lba + index as u64, sector)?;
                        let start = (lba as usize + index) * 512;
                        self.inner.stable[start..start + 512].copy_from_slice(sector);
                    }
                }
                return Err(SnapshotBlockStoreError::Io);
            }
        }
        for (index, sector) in bytes.chunks_exact(512).enumerate() {
            self.inner.write_sector(lba + index as u64, sector)?;
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        self.inner.flush()
    }
}

#[test]
fn fragmented_encoder_uses_bounded_payload_batches() {
    for len in [0usize, 1, 511, 512, 513, 2047, 2048, 2049, 3583, 3584] {
        for fragment in [1, 9, 127, 511] {
            let mut disk = CommandDisk::new();
            let store = SnapshotBlockStore::new(0, 16);
            let payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                store.commit_next_streaming(&mut disk, len, crc32c(&payload), |writer| {
                    for bytes in payload.chunks(fragment) {
                        writer.write_all(bytes)?;
                    }
                    Ok(())
                }),
                Ok(1)
            );
            let sectors = len.div_ceil(512);
            let expected: Vec<_> = (0..sectors)
                .step_by(4)
                .map(|i| (1 + i as u64, (sectors - i).min(4)))
                .collect();
            assert_eq!(disk.batches, expected, "length={len} fragment={fragment}");
            assert_eq!(disk.singles, [0]);
            assert_eq!(
                disk.inner
                    .events
                    .iter()
                    .filter(|e| **e == Event::Flush)
                    .count(),
                3
            );
            let padded_len = sectors * 512;
            assert!(disk.inner.cache[512 + len..512 + padded_len]
                .iter()
                .all(|b| *b == 0));
            disk.inner.power_cut();
            assert_eq!(
                store.read_latest(&mut disk.inner).unwrap().unwrap().payload,
                payload
            );
        }
    }
}

#[test]
fn partial_batch_failures_never_publish_or_displace_previous_snapshot() {
    let payload = alloc::vec![0xa5; 3500];
    for failed in 0..2 {
        for mask in [0, 1, 3, 5, 15] {
            let (store, mut disk) = CommandDisk::with_generations();
            disk.fail_batch = Some((failed, mask));
            assert_eq!(
                store.commit_next_streaming(&mut disk, payload.len(), crc32c(&payload), |writer| {
                    for fragment in payload.chunks(9) {
                        writer.write_all(fragment)?;
                    }
                    Ok(())
                }),
                Err(SnapshotBlockStoreError::Io)
            );
            assert!(disk.singles.is_empty());
            assert_eq!(disk.batches.len(), failed + 1);
            disk.inner.power_cut();
            let snapshot = store.read_latest(&mut disk.inner).unwrap().unwrap();
            assert_eq!(snapshot.generation, 2);
            assert_eq!(snapshot.payload, b"second");
        }
    }
}

#[test]
fn ignored_uncertain_write_error_is_sticky_and_never_replayed() {
    let (store, mut disk) = CommandDisk::with_generations();
    let payload = alloc::vec![0x5a; 2048];
    disk.fail_batch = Some((0, 5));
    assert_eq!(
        store.commit_next_streaming(&mut disk, payload.len(), crc32c(&payload), |writer| {
            assert_eq!(writer.write_all(&payload), Err(SnapshotBlockStoreError::Io));
            assert_eq!(writer.write_all(&[]), Err(SnapshotBlockStoreError::Io));
            Ok(())
        }),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(disk.batches, [(1, 4)]);
    assert!(disk.singles.is_empty());
    assert_eq!(
        disk.inner
            .events
            .iter()
            .filter(|event| **event == Event::Flush)
            .count(),
        1
    );
    disk.inner.power_cut();
    assert_eq!(
        store.read_latest(&mut disk.inner).unwrap().unwrap().payload,
        b"second"
    );
}

#[test]
fn encoder_length_and_crc_failures_do_not_publish_headers() {
    for failure in 0..4 {
        let (store, mut disk) = CommandDisk::with_generations();
        let crc = if failure == 3 {
            crc32c(b"bad")
        } else {
            crc32c(b"new")
        };
        let expected = if failure == 0 {
            SnapshotBlockStoreError::Io
        } else {
            SnapshotBlockStoreError::Corrupt
        };
        assert_eq!(
            store.commit_next_streaming(&mut disk, 3, crc, |writer| {
                match failure {
                    0 => {
                        writer.write_all(b"n")?;
                        Err(SnapshotBlockStoreError::Io)
                    }
                    1 => writer.write_all(b"ne"),
                    2 => {
                        assert_eq!(
                            writer.write_all(b"extra"),
                            Err(SnapshotBlockStoreError::Corrupt)
                        );
                        assert_eq!(
                            writer.write_all(b"new"),
                            Err(SnapshotBlockStoreError::Corrupt)
                        );
                        Ok(())
                    }
                    _ => writer.write_all(b"new"),
                }
            }),
            Err(expected)
        );
        assert!(disk.singles.is_empty());
        disk.inner.power_cut();
        assert_eq!(
            store.read_latest(&mut disk.inner).unwrap().unwrap().payload,
            b"second"
        );
    }
}

#[test]
fn batched_payload_preserves_all_write_and_barrier_failures() {
    let payload = alloc::vec![0xa5; 3500];
    for partial_flush in [false, true] {
        // Three barriers, seven payload sectors, and one publication header.
        for fail_event in 0..11 {
            let (store, mut disk) = CommandDisk::with_generations();
            disk.inner.fail_event = Some(fail_event);
            disk.inner.partial_flush = partial_flush;
            assert_eq!(
                store.commit_next(&mut disk, &payload),
                Err(SnapshotBlockStoreError::Io)
            );
            if fail_event <= 8 {
                assert!(disk.singles.is_empty());
            }
            disk.inner.power_cut();
            let snapshot = store.read_latest(&mut disk.inner).unwrap().unwrap();
            assert!(snapshot.generation == 2 || snapshot.generation == 3);
            assert_eq!(
                snapshot.payload,
                if snapshot.generation == 2 {
                    b"second".to_vec()
                } else {
                    payload.clone()
                }
            );
        }
    }
}

#[test]
fn batch_publication_keeps_header_between_second_and_third_barriers() {
    let (store, mut disk) = CommandDisk::with_generations();
    let payload = alloc::vec![0xa5; 3500];
    assert_eq!(store.commit_next(&mut disk, &payload), Ok(3));
    assert_eq!(disk.batches, [(1, 4), (5, 3)]);
    assert_eq!(disk.singles, [0]);
    let mut expected = alloc::vec![Event::Flush];
    expected.extend((1..8).map(Event::Write));
    expected.extend([Event::Flush, Event::Write(0), Event::Flush]);
    assert_eq!(disk.inner.events, expected);
}

#[test]
fn overflowing_staging_geometry_is_rejected_before_device_or_encoder_work() {
    struct OversizedDisk;
    impl SnapshotBlockDevice for OversizedDisk {
        fn sector_size(&self) -> usize {
            usize::MAX / 4 + 1
        }
        fn sector_count(&self) -> u64 {
            4
        }
        fn read_sector(&mut self, _: u64, _: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
            panic!("invalid geometry read")
        }
        fn write_sector(&mut self, _: u64, _: &[u8]) -> Result<(), SnapshotBlockStoreError> {
            panic!("invalid geometry write")
        }
        fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
            panic!("invalid geometry flush")
        }
    }
    assert_eq!(
        SnapshotBlockStore::new(0, 4).commit_next_streaming(
            &mut OversizedDisk,
            0,
            crc32c(&[]),
            |_| { panic!("invalid geometry encoder") }
        ),
        Err(SnapshotBlockStoreError::InvalidGeometry)
    );
}

#[test]
fn staging_uses_device_sector_geometry_without_power_of_two_assumptions() {
    struct SizedDisk {
        size: usize,
        bytes: Vec<u8>,
        batches: Vec<usize>,
    }
    impl SnapshotBlockDevice for SizedDisk {
        fn sector_size(&self) -> usize {
            self.size
        }
        fn sector_count(&self) -> u64 {
            16
        }
        fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
            let start = lba as usize * self.size;
            out.copy_from_slice(&self.bytes[start..start + self.size]);
            Ok(())
        }
        fn write_sector(&mut self, lba: u64, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
            assert_eq!(bytes.len(), self.size);
            let start = lba as usize * self.size;
            self.bytes[start..start + self.size].copy_from_slice(bytes);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
            assert!(!bytes.is_empty() && bytes.len() % self.size == 0);
            assert!(bytes.len() <= 4 * self.size);
            self.batches.push(bytes.len() / self.size);
            let start = lba as usize * self.size;
            self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
            Ok(())
        }
    }
    for size in [48, 513, 4096] {
        let store = SnapshotBlockStore::new(0, 16);
        let mut disk = SizedDisk {
            size,
            bytes: alloc::vec![0; size * 16],
            batches: Vec::new(),
        };
        let payload = alloc::vec![0x5a; size * 7 - 1];
        assert_eq!(
            store.commit_next_streaming(&mut disk, payload.len(), crc32c(&payload), |writer| {
                for fragment in payload.chunks(7) {
                    writer.write_all(fragment)?;
                }
                Ok(())
            }),
            Ok(1)
        );
        assert_eq!(disk.batches, [4, 3]);
        assert_eq!(disk.bytes[size * 8 - 1], 0);
        assert_eq!(
            store.read_latest(&mut disk).unwrap().unwrap().payload,
            payload
        );
    }
}
