use crate::snapshot_store::*;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    Write(u64),
    Flush,
}

pub(crate) struct CachedDisk {
    pub(crate) stable: Vec<u8>,
    pub(crate) cache: Vec<u8>,
    pub(crate) pending: Vec<(u64, Vec<u8>)>,
    pub(crate) events: Vec<Event>,
    pub(crate) fail_event: Option<usize>,
    pub(crate) fail_read: Option<u64>,
    pub(crate) partial_flush: bool,
}

impl CachedDisk {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn power_cut(&mut self) {
        self.cache.copy_from_slice(&self.stable);
        self.pending.clear();
        self.fail_event = None;
    }

    pub(crate) fn corrupt(&mut self, lba: usize) {
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
