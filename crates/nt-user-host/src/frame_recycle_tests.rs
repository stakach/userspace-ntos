use super::*;
use nt_memory_manager::{
    ClientFrameRegistry, GenericSectionBacking, PendingSectionFrames, SectionRetirementIo,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Storage {
    live: [u64; 2],
    pinned: [u64; 2],
    bytes: [u32; 128],
    slots: [u64; 3],
    count: u64,
    total: u64,
}
impl Storage {
    fn new() -> Self {
        let mut bytes = [0; 128];
        bytes[6] = 4096;
        Self {
            live: [1 << 6, 0],
            pinned: [0; 2],
            bytes,
            slots: [65, 70, 0],
            count: 1,
            total: 4096,
        }
    }
    fn view(&self) -> FrameRecycleState<'_> {
        FrameRecycleState {
            start: 64,
            end: 192,
            live: &self.live,
            pinned: &self.pinned,
            retype_bytes: &self.bytes,
            free_slots: &self.slots,
            free_slot_count: self.count,
            live_bytes: self.total,
        }
    }
    fn rejects(&self, frame: u64, error: FrameRecycleError) {
        let before = self.clone();
        let mut pool = RecycledFramePool::new();
        assert!(pool.reserve(1));
        let pool_before = pool.stats();
        for _ in 0..3 {
            assert_eq!(self.view().check_reserved(frame, &pool), Err(error));
            assert_eq!(self.view().publish_reserved(frame, &mut pool), Err(error));
            assert_eq!(pool.stats(), pool_before);
            assert_eq!(*self, before);
        }
    }
}

#[test]
fn publication_keeps_live_cap_and_physical_accounting_and_ignores_inactive_slot_cells() {
    let storage = Storage::new();
    let before = storage.clone();
    let mut pool = RecycledFramePool::new();
    assert!(pool.reserve(1));
    storage.view().publish_reserved(70, &mut pool).unwrap();
    assert_eq!(storage, before);
    assert_eq!(pool.acquire(), Some(70));
    storage.view().publish_reserved(70, &mut pool).unwrap();
    assert_eq!(storage, before);
    assert_eq!(pool.stats().live, 1);
}

#[test]
fn invalid_range_and_reserved_slots_are_refused() {
    for frame in [0, 1, 63, 192, u64::MAX] {
        Storage::new().rejects(frame, FrameRecycleError::InvalidSlot);
    }
}

#[test]
fn every_allocator_array_must_cover_the_frame_slot() {
    let storage = Storage::new();
    for missing in 0..3 {
        let mut view = storage.view();
        match missing {
            0 => view.live = &[],
            1 => view.pinned = &[],
            _ => view.retype_bytes = &[],
        }
        assert_eq!(
            view.validate_owner(70),
            Err(FrameRecycleError::UntrackedSlot)
        );
    }
    let mut view = storage.view();
    view.end = u64::MAX;
    assert_eq!(
        view.validate_owner(u64::MAX - 1),
        Err(FrameRecycleError::UntrackedSlot)
    );
}

#[test]
fn pinned_unowned_empty_alias_and_wrong_size_slots_cannot_become_free_frames() {
    let mut storage = Storage::new();
    storage.pinned[0] = 1 << 6;
    storage.rejects(70, FrameRecycleError::Pinned);
    storage.pinned[0] = 0;
    storage.live[0] = 0;
    storage.rejects(70, FrameRecycleError::NotOwned);
    storage.live[0] = 1 << 6;
    for bytes in [0, 16, 2048, 8192] {
        storage.bytes[6] = bytes;
        storage.rejects(70, FrameRecycleError::WrongRetypeSize);
    }
}

#[test]
fn contradictory_root_slot_publication_and_accounting_are_not_repaired() {
    let mut storage = Storage::new();
    storage.total = 4095;
    storage.rejects(70, FrameRecycleError::AccountingUnderflow);
    storage.total = 4096;
    storage.count = 2;
    storage.rejects(70, FrameRecycleError::EmptySlotPublished);
    for count in [4, u64::MAX] {
        storage.count = count;
        storage.rejects(70, FrameRecycleError::CorruptSlotCount);
    }
}

#[test]
fn absent_capacity_and_duplicate_frame_publication_preserve_the_existing_owner() {
    let storage = Storage::new();
    let mut pool = RecycledFramePool::new();
    assert_eq!(
        storage.view().publish_reserved(70, &mut pool),
        Err(FrameRecycleError::Pool(FramePoolError::Full))
    );
    assert!(pool.reserve(1));
    storage.view().publish_reserved(70, &mut pool).unwrap();
    let before = pool.stats();
    assert_eq!(
        storage.view().publish_reserved(70, &mut pool),
        Err(FrameRecycleError::Pool(FramePoolError::AlreadyPublished))
    );
    assert_eq!(pool.stats(), before);
    assert_eq!(pool.acquire(), Some(70));
    assert_eq!(pool.acquire(), None);
}

#[test]
fn publication_revalidates_allocator_changes_after_preflight() {
    let mut storage = Storage::new();
    let mut pool = RecycledFramePool::new();
    assert!(pool.reserve(1));
    storage.view().check_reserved(70, &pool).unwrap();
    storage.bytes[6] = 0;
    assert_eq!(
        storage.view().publish_reserved(70, &mut pool),
        Err(FrameRecycleError::WrongRetypeSize)
    );
    assert_eq!(pool.stats().live, 0);
}

#[test]
fn registry_owner_survives_publication_failure_with_unmap_acknowledged() {
    let mut storage = Storage::new();
    let mut pool = RecycledFramePool::new();
    assert!(pool.reserve(1));
    let mut registry = ClientFrameRegistry::new();
    registry.insert(2, 0x1000, 70, 0, 0, 0, true).unwrap();
    storage.view().check_reserved(70, &pool).unwrap();
    let record = registry.get(2, 0x1000).unwrap();
    let record = registry.begin_reclaim_exact(record).unwrap();
    let record = registry.mark_frame_unmapped_exact(record).unwrap();
    storage.pinned[0] = 1 << 6;
    assert_eq!(
        storage.view().publish_reserved(record.frame, &mut pool),
        Err(FrameRecycleError::Pinned)
    );
    assert_eq!(registry.get(2, 0x1000), Some(record));
    assert!(record.frame_unmapped);
    storage.pinned[0] = 0;
    storage
        .view()
        .publish_reserved(record.frame, &mut pool)
        .unwrap();
    assert_eq!(registry.take_exact(record), Some(record));
    assert!(registry.get(2, 0x1000).is_none());
    assert_eq!(pool.acquire(), Some(70));
}

struct SectionIo {
    storage: Storage,
    pool: RecycledFramePool,
    effects: usize,
    fail_after_unmap: bool,
}
impl SectionRetirementIo for SectionIo {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        self.storage
            .view()
            .check_reserved(frame, &self.pool)
            .map_err(|_| 1u32)?;
        self.effects += 2; // Revoke/unmap are safe to retry while the owner remains retained.
        if self.fail_after_unmap {
            return Err(2);
        }
        self.storage
            .view()
            .publish_reserved(frame, &mut self.pool)
            .map_err(|_| 3u32)
    }
    fn release_backing(&mut self, _: GenericSectionBacking) -> Result<(), u32> {
        panic!("frame only")
    }
}

#[test]
fn section_cleanup_retains_failures_and_never_deletes_a_duplicate_pool_owner() {
    let mut pending = PendingSectionFrames::new();
    assert!(pending.reserve());
    let mut io = SectionIo {
        storage: Storage::new(),
        pool: RecycledFramePool::new(),
        effects: 0,
        fail_after_unmap: true,
    };
    assert!(io.pool.reserve(1));
    pending.release_or_defer(70, &mut io);
    assert_eq!(pending.drain(&mut io), Err(2));
    assert_eq!(io.pool.stats().live, 0);
    io.fail_after_unmap = false;
    pending.drain(&mut io).unwrap();
    let effects = io.effects;
    pending.drain(&mut io).unwrap();
    assert_eq!(io.release_frame(70), Err(1));
    assert_eq!(io.effects, effects);
    assert_eq!(io.pool.acquire(), Some(70));
    assert_eq!(io.pool.acquire(), None);
}
