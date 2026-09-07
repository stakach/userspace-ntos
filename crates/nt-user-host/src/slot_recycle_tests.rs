use super::*;
use crate::sched_context::{SchedContextConstruction, SchedContextIo, Stage};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Storage {
    start: u64,
    end: u64,
    live: [u64; 2],
    pinned: [u64; 2],
    bytes: [u32; 128],
    free: [u64; 3],
    live_len: usize,
    pinned_len: usize,
    bytes_len: usize,
    free_len: usize,
    count: u64,
    live_bytes: u64,
    released_bytes: u64,
}

impl Storage {
    fn new() -> Self {
        let mut bytes = [0; 128];
        bytes[6] = 4096;
        Self {
            start: 64,
            end: 192,
            live: [1 << 6, 0],
            pinned: [0; 2],
            bytes,
            free: [65, 0, 0],
            live_len: 2,
            pinned_len: 2,
            bytes_len: 128,
            free_len: 3,
            count: 1,
            live_bytes: 4096,
            released_bytes: 7,
        }
    }

    fn publish(&mut self, slot: u64) -> Result<(), RecycleError> {
        let mut view = SlotRecycleState {
            start: self.start,
            end: self.end,
            live: &mut self.live[..self.live_len],
            pinned: &self.pinned[..self.pinned_len],
            retype_bytes: &mut self.bytes[..self.bytes_len],
            free: &mut self.free[..self.free_len],
            count: self.count,
            live_bytes: self.live_bytes,
            released_bytes: self.released_bytes,
        };
        let result = view.publish_empty(slot);
        self.count = view.count;
        self.live_bytes = view.live_bytes;
        self.released_bytes = view.released_bytes;
        result
    }

    fn rejects_unchanged(&mut self, slot: u64, error: RecycleError) {
        let before = self.clone();
        for _ in 0..3 {
            assert_eq!(self.publish(slot), Err(error));
            assert_eq!(*self, before);
        }
    }
}

#[test]
fn successful_publication_clears_only_selected_ownership_and_accounts_once() {
    let mut storage = Storage::new();
    storage.live[1] = 1 << 6;
    storage.bytes[70] = 8192;
    storage.live_bytes += 8192;
    storage.publish(134).unwrap();
    assert_eq!(storage.live, [1 << 6, 0]);
    assert_eq!(storage.bytes[6], 4096);
    assert_eq!(storage.bytes[70], 0);
    assert_eq!(storage.free, [65, 134, 0]);
    assert_eq!(storage.count, 2);
    assert_eq!(storage.live_bytes, 4096);
    assert_eq!(storage.released_bytes, 8199);
    storage.rejects_unchanged(134, RecycleError::NotOwned);
}

#[test]
fn allocated_empty_slot_does_not_release_retype_bytes() {
    let mut storage = Storage::new();
    storage.bytes[6] = 0;
    storage.publish(70).unwrap();
    assert_eq!(storage.live_bytes, 4096);
    assert_eq!(storage.released_bytes, 7);
    assert_eq!(storage.count, 2);
    assert_eq!(storage.live[0], 0);
}

#[test]
fn invalid_range_and_reserved_slots_leave_storage_unchanged() {
    for slot in [0, 1, 63, 192, u64::MAX] {
        Storage::new().rejects_unchanged(slot, RecycleError::InvalidSlot);
    }
    let mut storage = Storage::new();
    storage.end = storage.start;
    storage.rejects_unchanged(70, RecycleError::InvalidSlot);
    storage.start = 0;
    storage.end = 192;
    storage.rejects_unchanged(1, RecycleError::InvalidSlot);
}

#[test]
fn every_tracker_must_cover_the_selected_slot() {
    for missing in 0..3 {
        let mut storage = Storage::new();
        match missing {
            0 => storage.live_len = 0,
            1 => storage.pinned_len = 0,
            _ => storage.bytes_len = 6,
        }
        storage.rejects_unchanged(70, RecycleError::UntrackedSlot);
    }
    let mut storage = Storage::new();
    storage.end = u64::MAX;
    storage.rejects_unchanged(u64::MAX - 1, RecycleError::UntrackedSlot);
}

#[test]
fn pinned_or_unowned_slots_cannot_be_published() {
    let mut storage = Storage::new();
    storage.pinned[0] = 1 << 6;
    storage.rejects_unchanged(70, RecycleError::Pinned);
    storage.pinned[0] = 0;
    storage.live[0] = 0;
    storage.rejects_unchanged(70, RecycleError::NotOwned);
}

#[test]
fn full_and_corrupt_counts_do_not_discard_ownership_or_clamp_count() {
    for count in [3, 4, u64::MAX] {
        let mut storage = Storage::new();
        storage.count = count;
        storage.rejects_unchanged(
            70,
            if count == 3 {
                RecycleError::Full
            } else {
                RecycleError::CorruptCount
            },
        );
    }
    let mut storage = Storage::new();
    storage.free_len = 0;
    storage.count = 0;
    storage.rejects_unchanged(70, RecycleError::Full);
}

#[test]
fn only_active_prefix_participates_in_duplicate_detection() {
    let mut storage = Storage::new();
    storage.free[0] = 70;
    storage.rejects_unchanged(70, RecycleError::AlreadyPublished);
    storage.free = [65, 70, 70];
    storage.publish(70).unwrap();
    assert_eq!(storage.count, 2);
    assert_eq!(&storage.free[..2], &[65, 70]);
}

#[test]
fn accounting_failure_preserves_per_slot_and_aggregate_values() {
    let mut storage = Storage::new();
    storage.live_bytes = 4095;
    storage.rejects_unchanged(70, RecycleError::AccountingUnderflow);
    storage.live_bytes = 4096;
    storage.released_bytes = u64::MAX - 4095;
    storage.rejects_unchanged(70, RecycleError::AccountingOverflow);
    storage.released_bytes = u64::MAX - 4096;
    storage.publish(70).unwrap();
    assert_eq!(storage.released_bytes, u64::MAX);
    assert_eq!(storage.live_bytes, 0);
}

struct ScBackend {
    storage: Storage,
    fail_retype: bool,
    deletes: usize,
}

impl SchedContextIo for ScBackend {
    fn allocate_slot(&mut self) -> Result<u64, u64> {
        Ok(70)
    }
    fn retype(&mut self, _: u64) -> Result<(), u64> {
        if self.fail_retype {
            Err(10)
        } else {
            Ok(())
        }
    }
    fn configure(&mut self, _: u64, _: u64, _: u64) -> Result<(), u64> {
        Err(11)
    }
    fn bind(&mut self, _: u64, _: u64) -> Result<(), u64> {
        panic!("configuration failed")
    }
    fn delete(&mut self, slot: u64) -> Result<(), u64> {
        assert_eq!(slot, 70);
        assert!(!self.fail_retype);
        self.deletes += 1;
        Ok(())
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u64> {
        self.storage.publish(slot).map_err(|_| 12)
    }
}

#[test]
fn checked_publication_failure_retains_sc_phase_until_capacity_returns() {
    for fail_retype in [false, true] {
        let mut backend = ScBackend {
            storage: Storage::new(),
            fail_retype,
            deletes: 0,
        };
        backend.storage.count = 3;
        backend.storage.free = [65, 66, 67];
        if fail_retype {
            backend.storage.bytes[6] = 0;
            backend.storage.live_bytes = 0;
        }
        let before = backend.storage.clone();
        let mut owner = SchedContextConstruction::new(400, 10, 10).unwrap();
        assert!(owner.construct(&mut backend).is_err());
        for _ in 0..3 {
            assert!(owner.retire(&mut backend).is_err());
            assert_eq!(owner.stage(), Stage::Recycle);
            assert_eq!(owner.slot(), Some(70));
            assert_eq!(backend.storage, before);
            assert_eq!(backend.deletes, usize::from(!fail_retype));
        }
        // Model allocation popping the last free slot; its inactive cell intentionally stays set.
        backend.storage.count = 2;
        owner.retire(&mut backend).unwrap();
        owner.retire(&mut backend).unwrap();
        assert_eq!(owner.stage(), Stage::Retired);
        assert_eq!(owner.slot(), None);
        assert_eq!(backend.storage.free, [65, 66, 70]);
        assert_eq!(backend.storage.live[0], 0);
        assert_eq!(backend.storage.bytes[6], 0);
        assert_eq!(
            backend.storage.released_bytes,
            if fail_retype { 7 } else { 4103 }
        );
        assert_eq!(backend.deletes, usize::from(!fail_retype));
    }
}
