use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Write(u64),
    Flush,
}

struct CachedDisk {
    stable: Vec<u8>,
    cache: Vec<u8>,
    pending: Vec<(u64, Vec<u8>)>,
    events: Vec<Event>,
    fail_event: Option<usize>,
    fail_read: Option<u64>,
    partial_flush: bool,
}

impl CachedDisk {
    fn new() -> Self {
        Self {
            stable: alloc::vec![0; 16 * 512],
            cache: alloc::vec![0; 16 * 512],
            pending: Vec::new(),
            events: Vec::new(),
            fail_event: None,
            fail_read: None,
            partial_flush: false,
        }
    }

    fn event(&mut self, event: Event) -> bool {
        let fail = self.fail_event == Some(self.events.len());
        self.events.push(event);
        fail
    }

    fn power_cut(&mut self) {
        self.cache.copy_from_slice(&self.stable);
        self.pending.clear();
        self.fail_event = None;
    }

    fn corrupt(&mut self, lba: usize) {
        self.stable[lba * 512] ^= 0x55;
        self.cache[lba * 512] ^= 0x55;
    }
}

impl SnapshotBlockDevice for CachedDisk {
    fn sector_size(&self) -> usize {
        512
    }
    fn sector_count(&self) -> u64 {
        16
    }

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        if self.fail_read == Some(lba) {
            return Err(SnapshotBlockStoreError::Io);
        }
        out.copy_from_slice(&self.cache[lba as usize * 512..(lba as usize + 1) * 512]);
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        if self.event(Event::Write(lba)) {
            return Err(SnapshotBlockStoreError::Io);
        }
        self.cache[lba as usize * 512..(lba as usize + 1) * 512].copy_from_slice(data);
        self.pending.push((lba, data.to_vec()));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        if self.event(Event::Flush) {
            if self.partial_flush {
                // A failed barrier may persist any subset, not necessarily an ordered prefix.
                if let Some((lba, data)) = self.pending.pop() {
                    self.stable[lba as usize * 512..(lba as usize + 1) * 512]
                        .copy_from_slice(&data);
                }
            }
            return Err(SnapshotBlockStoreError::Io);
        }
        for (lba, data) in self.pending.drain(..) {
            self.stable[lba as usize * 512..(lba as usize + 1) * 512].copy_from_slice(&data);
        }
        Ok(())
    }
}

fn two_generations() -> (SnapshotBlockStore, CachedDisk) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut dev = CachedDisk::new();
    assert_eq!(store.commit_next(&mut dev, b"first"), Ok(1));
    assert_eq!(store.commit_next(&mut dev, b"second"), Ok(2));
    dev.events.clear();
    (store, dev)
}

#[test]
fn commit_orders_three_barriers_and_survives_power_loss() {
    let (store, mut dev) = two_generations();
    assert_eq!(store.commit_next(&mut dev, b"third"), Ok(3));
    assert_eq!(
        dev.events,
        [
            Event::Flush,
            Event::Write(1),
            Event::Flush,
            Event::Write(0),
            Event::Flush
        ]
    );
    dev.power_cut();
    let snapshot = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(snapshot.generation, 3);
    assert_eq!(snapshot.payload, b"third");
}

#[test]
fn every_write_and_barrier_failure_preserves_a_complete_snapshot() {
    let payload = alloc::vec![0xa5; 1300];
    for partial_flush in [false, true] {
        for fail_event in 0..7 {
            let (store, mut dev) = two_generations();
            dev.fail_event = Some(fail_event);
            dev.partial_flush = partial_flush;
            assert_eq!(
                store.commit_next(&mut dev, &payload),
                Err(SnapshotBlockStoreError::Io)
            );
            if fail_event <= 4 {
                assert!(
                    !dev.events.contains(&Event::Write(0)),
                    "payload failure must not publish a header"
                );
            }
            dev.power_cut();
            let snapshot = store.read_latest(&mut dev).unwrap().unwrap();
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
fn retry_stabilizes_uncertain_header_before_reusing_previous_slot() {
    let (store, mut dev) = two_generations();
    dev.fail_event = Some(4);
    assert_eq!(
        store.commit_next(&mut dev, b"third"),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().generation,
        3,
        "new header is only cached"
    );
    dev.events.clear();
    dev.fail_event = Some(0);
    assert_eq!(
        store.commit_next(&mut dev, b"fourth"),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(dev.events, [Event::Flush]);
    dev.fail_event = None;
    assert_eq!(store.commit_next(&mut dev, b"fourth"), Ok(4));
    dev.power_cut();
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().payload,
        b"fourth"
    );
}

#[test]
fn corrupt_latest_payload_does_not_make_previous_valid_slot_reusable() {
    let (store, mut dev) = two_generations();
    dev.corrupt(9);
    dev.fail_event = Some(2); // Fail payload barrier after writing the corrupt slot.
    assert_eq!(
        store.commit_next(&mut dev, b"replacement"),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(dev.events, [Event::Flush, Event::Write(9), Event::Flush]);
    dev.power_cut();
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().payload,
        b"first"
    );
    assert_eq!(store.commit_next(&mut dev, b"replacement"), Ok(2));
}

#[test]
fn ambiguous_header_or_payload_io_prevents_slot_reuse() {
    for lba in [0, 8, 9] {
        let (store, mut dev) = two_generations();
        dev.fail_read = Some(lba);
        assert_eq!(
            store.commit_next(&mut dev, b"third"),
            Err(SnapshotBlockStoreError::Io)
        );
        assert_eq!(dev.events, [Event::Flush]);
    }
}

#[test]
fn corrupt_only_snapshot_is_not_silently_reinitialized() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut dev = CachedDisk::new();
    store.commit_next(&mut dev, b"first").unwrap();
    dev.corrupt(1);
    dev.events.clear();
    assert_eq!(
        store.commit_next(&mut dev, b"replacement"),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(dev.events, [Event::Flush]);
}

#[test]
fn generation_exhaustion_cannot_report_invisible_success() {
    let (store, mut dev) = two_generations();
    let header = SlotHeader {
        slot: 1,
        generation: u64::MAX,
        payload_len: 6,
        payload_crc: crc32c(b"second"),
        payload_sectors: 1,
    };
    encode_header(&mut dev.cache[8 * 512..9 * 512], header);
    dev.stable.copy_from_slice(&dev.cache);
    assert_eq!(
        store.commit_next(&mut dev, b"third"),
        Err(SnapshotBlockStoreError::OutOfSpace)
    );
    assert_eq!(dev.events, [Event::Flush]);
}

#[test]
fn streaming_crc_mismatch_never_publishes_a_header() {
    let (store, mut dev) = two_generations();
    assert_eq!(
        store.commit_next_streaming(&mut dev, 3, crc32c(b"bad"), |writer| writer
            .write_all(b"new")),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(dev.events, [Event::Flush, Event::Write(1)]);
    dev.power_cut();
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().payload,
        b"second"
    );
}

#[test]
fn empty_payload_still_persists_its_commit_header() {
    let (store, mut dev) = two_generations();
    assert_eq!(store.commit_next(&mut dev, b""), Ok(3));
    assert_eq!(
        dev.events,
        [Event::Flush, Event::Flush, Event::Write(0), Event::Flush]
    );
    dev.power_cut();
    assert!(store
        .read_latest(&mut dev)
        .unwrap()
        .unwrap()
        .payload
        .is_empty());
}
