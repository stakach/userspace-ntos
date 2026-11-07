use nt_fs::{SnapshotBlockDevice, SnapshotBlockStore, SnapshotBlockStoreError, WalSnapshotManifest};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: This wrapper forwards every allocation operation to System with unchanged arguments.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies the GlobalAlloc layout contract unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The allocation and layout are forwarded unchanged to their original owner.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The allocation, layout, and requested size retain System's contract.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct AllocationCheckedDisk {
    bytes: Vec<u8>,
    entered_at: Option<usize>,
    reads: usize,
}

impl AllocationCheckedDisk {
    fn new() -> Self {
        Self { bytes: vec![0; 16 * 512], entered_at: None, reads: 0 }
    }

    fn check_no_allocation_after_entry(&mut self) {
        let now = ALLOCATIONS.load(Ordering::Relaxed);
        match self.entered_at {
            Some(entered_at) => assert_eq!(now, entered_at, "snapshot sync I/O allocated after entry"),
            None => self.entered_at = Some(now),
        }
    }
}

impl SnapshotBlockDevice for AllocationCheckedDisk {
    fn sector_size(&self) -> usize { 512 }
    fn sector_count(&self) -> u64 { 16 }

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.check_no_allocation_after_entry();
        self.reads += 1;
        let start = lba as usize * 512;
        out.copy_from_slice(&self.bytes[start..start + 512]);
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.check_no_allocation_after_entry();
        let start = lba as usize * 512;
        self.bytes[start..start + 512].copy_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        self.check_no_allocation_after_entry();
        Ok(())
    }
}

#[test]
fn synchronous_wal_checkpoint_reuses_prepared_scratch_through_reads() {
    let mut disk = AllocationCheckedDisk::new();
    let store = SnapshotBlockStore::new(0, 16);
    let manifest = WalSnapshotManifest {
        incarnation: 7,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    let payload = [0x5a; 1300];
    let generation = store.commit_next_with_wal_manifest(&mut disk, &payload, manifest).unwrap();
    assert_eq!(generation, 1);
    assert!(disk.reads >= 2, "checkpoint must exercise the synchronous read path");
}
