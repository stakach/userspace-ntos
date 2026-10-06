//! Reproduce the native fragmented-heap boundary without aborting the whole test suite.

extern crate std;

use crate::hive::Cell;
use crate::{Hive, HiveKind, RegistryValueType};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};
use std::process::Command;

const CHILD_ENV: &str = "NT_HIVE_FRAGMENTED_GROWTH_CHILD";
const TEST_NAME: &str =
    "allocation_growth_tests::set_value_growth_survives_native_fragmented_span_limit";
const OBSERVED_REFUSED_BYTES: usize = 1_172_160;
const AVAILABLE_SPAN_BYTES: usize = 584_192;

static SPAN_LIMIT: AtomicUsize = AtomicUsize::new(0);
static MAX_REQUEST: AtomicUsize = AtomicUsize::new(0);
static REFUSALS: AtomicUsize = AtomicUsize::new(0);

struct FragmentedAllocator;

fn refuse(size: usize, align: usize) -> bool {
    let limit = SPAN_LIMIT.load(Ordering::Relaxed);
    if limit == 0 {
        return false;
    }
    MAX_REQUEST.fetch_max(size, Ordering::Relaxed);
    if size <= limit {
        return false;
    }
    REFUSALS.fetch_add(1, Ordering::Relaxed);
    // Diagnostic output must not recursively inject another allocation failure.
    SPAN_LIMIT.store(0, Ordering::Relaxed);
    std::eprintln!("fragmented allocation refused size={size} align={align} limit={limit}");
    SPAN_LIMIT.store(limit, Ordering::Relaxed);
    true
}

// SAFETY: All successful allocations and deallocations preserve System's contract. Refusal
// returns null, as permitted by GlobalAlloc, and never modifies an existing allocation.
unsafe impl GlobalAlloc for FragmentedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse(layout.size(), layout.align()) {
            return core::ptr::null_mut();
        }
        // SAFETY: Forward the caller's valid layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse(layout.size(), layout.align()) {
            return core::ptr::null_mut();
        }
        // SAFETY: Forward the caller's valid layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if refuse(new_size, layout.align()) {
            return core::ptr::null_mut();
        }
        // SAFETY: The original allocation belongs to System and retains its valid layout.
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: All non-null allocations were supplied by System with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FragmentedAllocator = FragmentedAllocator;

struct SpanLimitGuard;

impl Drop for SpanLimitGuard {
    fn drop(&mut self) {
        SPAN_LIMIT.store(0, Ordering::Relaxed);
    }
}

fn isolated_child(test_name: &str) -> bool {
    if std::env::var(CHILD_ENV).as_deref() != Ok(test_name) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
            .env(CHILD_ENV, test_name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "registry allocation test must return normally: {}\nstdout: {}\nstderr: {}",
            output.status,
            std::string::String::from_utf8_lossy(&output.stdout),
            std::string::String::from_utf8_lossy(&output.stderr),
        );
        return false;
    }
    true
}

#[test]
fn set_value_growth_survives_native_fragmented_span_limit() {
    if !isolated_child(TEST_NAME) {
        return;
    }

    let cell_bytes = core::mem::size_of::<Option<Cell>>();
    let doubled_cell_bytes = cell_bytes.checked_mul(2).unwrap();
    assert_eq!(OBSERVED_REFUSED_BYTES % doubled_cell_bytes, 0);
    let imported_like_capacity = OBSERVED_REFUSED_BYTES / doubled_cell_bytes;
    let mut hive = Hive::new(HiveKind::Software);
    assert!(hive.reserve_cells(imported_like_capacity - hive.cells.len()));
    let prepared_len = imported_like_capacity;
    assert!(prepared_len < 20_000, "fixture must remain bounded");
    let root = hive.root();
    let initial_value_count = prepared_len - hive.cells.len();
    for index in 1..=initial_value_count {
        assert!(hive.set_value(
            root,
            &std::format!("V{index}"),
            RegistryValueType::Binary,
            alloc::vec![0x5a],
        ));
    }
    assert_eq!(hive.cells.len(), prepared_len);
    let first = hive.key(root).unwrap().values[0];
    let previous_sequence = hive.sequence;
    std::eprintln!(
        "registry arena fingerprint cell-bytes={cell_bytes} align={} len={} imported-like-boundary={prepared_len} former-geometric-next-bytes={} span-limit={AVAILABLE_SPAN_BYTES}",
        core::mem::align_of::<Option<Cell>>(),
        hive.cells.len(),
        prepared_len * doubled_cell_bytes,
    );

    MAX_REQUEST.store(0, Ordering::Relaxed);
    REFUSALS.store(0, Ordering::Relaxed);
    SPAN_LIMIT.store(AVAILABLE_SPAN_BYTES, Ordering::Relaxed);
    let guard = SpanLimitGuard;
    let additions = prepared_len + 1_024;
    for index in initial_value_count + 1..=initial_value_count + additions {
        assert!(hive.set_value(
            root,
            &std::format!("V{index}"),
            RegistryValueType::Binary,
            alloc::vec![0x5a],
        ));
    }
    drop(guard);

    assert_eq!(REFUSALS.load(Ordering::Relaxed), 0);
    let maximum_request = MAX_REQUEST.load(Ordering::Relaxed);
    assert!(maximum_request > 0, "growth must exercise the allocator");
    assert!(maximum_request <= AVAILABLE_SPAN_BYTES);
    assert_eq!(hive.cells.len(), prepared_len + additions);
    assert_eq!(hive.sequence, previous_sequence + additions as u64);
    assert_eq!(hive.key(root).unwrap().values[0], first);
    assert_eq!(hive.query_value(root, "V1"), Some((RegistryValueType::Binary, &[0x5a][..])));
    let last = std::format!("V{}", initial_value_count + additions);
    assert_eq!(hive.query_value(root, &last), Some((RegistryValueType::Binary, &[0x5a][..])));

    let image = crate::encode_image(&hive);
    let decoded = crate::decode_image(&image).unwrap();
    assert_eq!(decoded.cell_count(), hive.cell_count());
    assert_eq!(decoded.sequence, hive.sequence);
    assert_eq!(decoded.query_value(decoded.root(), "V1"), hive.query_value(root, "V1"));
    assert_eq!(decoded.query_value(decoded.root(), &last), hive.query_value(root, &last));

    let cells_len = hive.cells.len();
    let next_id = hive.next_id;
    let blobs_len = hive.value_blobs.len();
    let sequence = hive.sequence;
    {
        let mut transaction = hive.begin_transaction();
        assert!(transaction.set_value(
            root,
            "RolledBack",
            RegistryValueType::Binary,
            alloc::vec![0x6b],
        ));
    }
    assert_eq!(hive.cells.len(), cells_len);
    assert_eq!(hive.next_id, next_id);
    assert_eq!(hive.value_blobs.len(), blobs_len);
    assert_eq!(hive.sequence, sequence);
    assert_eq!(hive.key(root).unwrap().values[0], first);
    assert!(hive.query_value(root, "RolledBack").is_none());
    assert_eq!(crate::encode_image(&hive), image);
}

#[test]
fn refused_cell_reservation_preserves_logical_hive_state() {
    if !isolated_child("allocation_growth_tests::refused_cell_reservation_preserves_logical_hive_state") {
        return;
    }
    let mut hive = Hive::new(HiveKind::Software);
    let root = hive.root();
    assert!(hive.set_value(root, "Existing", RegistryValueType::Binary, alloc::vec![0x5a]));
    let before = crate::encode_image(&hive);
    let cells_len = hive.cells.len();
    let next_id = hive.next_id;
    let blobs_len = hive.value_blobs.len();
    let sequence = hive.sequence;
    let dirty_count = hive.dirty_count();
    let leaf_bytes = nt_page_storage::PageSequence::<Option<Cell>>::leaf_capacity()
        * core::mem::size_of::<Option<Cell>>();

    MAX_REQUEST.store(0, Ordering::Relaxed);
    REFUSALS.store(0, Ordering::Relaxed);
    SPAN_LIMIT.store(leaf_bytes - 1, Ordering::Relaxed);
    let guard = SpanLimitGuard;
    let reserved = hive.reserve_cells(1_024);
    drop(guard);

    assert!(!reserved);
    assert!(REFUSALS.load(Ordering::Relaxed) > 0, "fixture must refuse actual storage growth");
    assert_eq!(hive.cells.len(), cells_len);
    assert_eq!(hive.next_id, next_id);
    assert_eq!(hive.value_blobs.len(), blobs_len);
    assert_eq!(hive.sequence, sequence);
    assert_eq!(hive.dirty_count(), dirty_count);
    assert_eq!(crate::encode_image(&hive), before);
    assert_eq!(hive.query_value(root, "Existing"), Some((RegistryValueType::Binary, &[0x5a][..])));
}
