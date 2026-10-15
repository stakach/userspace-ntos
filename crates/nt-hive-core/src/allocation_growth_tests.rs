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

fn commit_without_allocations(prepared: crate::PreparedSetValue<'_>) -> crate::CellId {
    MAX_REQUEST.store(0, Ordering::Relaxed);
    REFUSALS.store(0, Ordering::Relaxed);
    SPAN_LIMIT.store(1, Ordering::Relaxed);
    let guard = SpanLimitGuard;
    let id = prepared.commit();
    drop(guard);
    assert_eq!(MAX_REQUEST.load(Ordering::Relaxed), 0);
    assert_eq!(REFUSALS.load(Ordering::Relaxed), 0);
    id
}

#[test]
fn prepared_new_and_replacement_commits_allocate_nothing() {
    if !isolated_child("allocation_growth_tests::prepared_new_and_replacement_commits_allocate_nothing") {
        return;
    }
    for replacement in [false, true] {
        for deduplicated in [false, true] {
            let mut hive = Hive::new(HiveKind::Software);
            let root = hive.root();
            assert!(hive.set_value(root, "Original", RegistryValueType::Binary, alloc::vec![7]));
            assert!(hive.set_value(root, "Shared", RegistryValueType::Binary, alloc::vec![9]));
            if !replacement {
                let boundary = nt_page_storage::PageSequence::<Option<Cell>>::leaf_capacity();
                while hive.cells.len() < boundary {
                    let name = std::format!("V{}", hive.cells.len());
                    assert!(hive.set_value(root, &name, RegistryValueType::Binary, alloc::vec![7]));
                }
            }
            let original = hive.key(root).unwrap().values[0];
            let shared = hive.key(root).unwrap().values[1];
            let shared_blob = hive.value(shared).unwrap().data_blob;
            let sequence = hive.sequence;
            let cells = hive.cells.len();
            let next_id = hive.next_id;
            let blobs = hive.value_blobs.len();
            let name = if replacement { "ORIGINAL" } else { "New" };
            let byte = if deduplicated { 9 } else { 11 };
            let prepared = hive
                .try_prepare_set_value(root, name, RegistryValueType::Dword, alloc::vec![byte])
                .unwrap();
            let id = commit_without_allocations(prepared);

            assert_eq!(id.0, if replacement { original.0 } else { next_id });
            assert_eq!(hive.cells.len(), cells + usize::from(!replacement));
            assert_eq!(hive.next_id, next_id + u64::from(!replacement));
            assert_eq!(hive.sequence, sequence + 1);
            assert_eq!(hive.value_blobs.len(), blobs + usize::from(!deduplicated));
            assert_eq!(hive.value(id).unwrap().name, if replacement { "Original" } else { "New" });
            assert_eq!(hive.query_value(root, name), Some((RegistryValueType::Dword, &[byte][..])));
            assert_eq!(hive.query_value(root, "Shared"), Some((RegistryValueType::Binary, &[9][..])));
            if deduplicated {
                assert_eq!(hive.value(id).unwrap().data_blob, shared_blob);
                assert_eq!(
                    hive.query_value(root, name).unwrap().1.as_ptr(),
                    hive.query_value(root, "Shared").unwrap().1.as_ptr(),
                );
            }
        }
    }
}

#[test]
fn abandoned_prepared_edits_preserve_encoded_and_logical_state() {
    if !isolated_child("allocation_growth_tests::abandoned_prepared_edits_preserve_encoded_and_logical_state") {
        return;
    }
    for replacement in [false, true] {
        for deduplicated in [false, true] {
            let mut hive = Hive::new(HiveKind::Software);
            let root = hive.root();
            assert!(hive.set_value(root, "Original", RegistryValueType::Binary, alloc::vec![7]));
            let before = crate::encode_image(&hive);
            let cells = hive.cells.len();
            let next_id = hive.next_id;
            let blobs = hive.value_blobs.len();
            let sequence = hive.sequence;
            let dirty = hive.dirty_count();
            let name = if replacement { "ORIGINAL" } else { "New" };
            let data = alloc::vec![if deduplicated { 7 } else { 11 }];
            drop(hive.try_prepare_set_value(root, name, RegistryValueType::Dword, data).unwrap());
            assert_eq!(hive.cells.len(), cells);
            assert_eq!(hive.next_id, next_id);
            assert_eq!(hive.value_blobs.len(), blobs);
            assert_eq!(hive.sequence, sequence);
            assert_eq!(hive.dirty_count(), dirty);
            assert_eq!(crate::encode_image(&hive), before);
        }
    }
}

#[test]
fn refused_prepared_growth_preserves_cells_ids_sequence_and_payloads() {
    if !isolated_child("allocation_growth_tests::refused_prepared_growth_preserves_cells_ids_sequence_and_payloads") {
        return;
    }
    // Refuse a name, a new cell page, a full value-link vector, and a full blob directory.
    for stage in 0..4 {
        let mut hive = Hive::new(HiveKind::Software);
        let root = hive.root();
        assert!(hive.set_value(root, "Original", RegistryValueType::Binary, alloc::vec![7]));
        match stage {
            1 => {
                let leaf_capacity = nt_page_storage::PageSequence::<Option<Cell>>::leaf_capacity();
                while hive.cells.len() < leaf_capacity {
                    let name = std::format!("V{}", hive.cells.len());
                    assert!(hive.set_value(root, &name, RegistryValueType::Binary, alloc::vec![7]));
                }
            }
            2 => {
                while hive.key(root).unwrap().values.len() < hive.key(root).unwrap().values.capacity() {
                    let name = std::format!("V{}", hive.key(root).unwrap().values.len());
                    assert!(hive.set_value(root, &name, RegistryValueType::Binary, alloc::vec![7]));
                }
                assert!(hive.reserve_cells(1));
            }
            3 => {
                while hive.value_blobs.len() < hive.value_blobs.capacity() {
                    let index = hive.value_blobs.len();
                    let name = std::format!("B{index}");
                    assert!(hive.set_value(
                        root, &name, RegistryValueType::Binary, alloc::vec![20 + index as u8],
                    ));
                }
            }
            _ => {}
        }
        let before = crate::encode_image(&hive);
        let cells = hive.cells.len();
        let next_id = hive.next_id;
        let blobs = hive.value_blobs.len();
        let sequence = hive.sequence;
        let dirty = hive.dirty_count();
        let ids = hive.key(root).unwrap().values.clone();
        let name = match stage {
            0 => "Refused",
            3 => "ORIGINAL",
            _ => "",
        };
        let data = alloc::vec![if stage == 3 { 99 } else { 7 }];
        MAX_REQUEST.store(0, Ordering::Relaxed);
        REFUSALS.store(0, Ordering::Relaxed);
        SPAN_LIMIT.store(1, Ordering::Relaxed);
        let guard = SpanLimitGuard;
        let result = hive.try_prepare_set_value(root, name, RegistryValueType::Dword, data);
        drop(guard);
        let refused = matches!(&result, Err(crate::SetValueError::InsufficientResources));
        drop(result);

        assert!(refused, "preparation stage {stage} must return resource failure");
        assert_eq!(REFUSALS.load(Ordering::Relaxed), 1);
        assert!(MAX_REQUEST.load(Ordering::Relaxed) > 1);
        assert_eq!(hive.cells.len(), cells);
        assert_eq!(hive.next_id, next_id);
        assert_eq!(hive.value_blobs.len(), blobs);
        assert_eq!(hive.sequence, sequence);
        assert_eq!(hive.dirty_count(), dirty);
        assert_eq!(hive.key(root).unwrap().values, ids);
        assert_eq!(crate::encode_image(&hive), before);
        assert_eq!(hive.query_value(root, "Original"), Some((RegistryValueType::Binary, &[7][..])));
    }
}
