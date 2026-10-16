//! Execute the native source-pool capture functions with recorded host memory reads.
//! The mocked ports supply bytes and mapped windows, not replacement capture policy.

use std::process::Command;

fn function_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("actual native function start");
    let length = source[start..].find(end).expect("next native function");
    let function = &source[start..start + length];
    syn::parse_str::<syn::ItemFn>(function).expect("extract a complete unchanged native function");
    function
}

fn functions_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("actual native function group start");
    let length = source[start..].find(end).expect("next native function");
    let functions = &source[start..start + length];
    syn::parse_file(functions).expect("extract complete unchanged native functions");
    functions
}

#[test]
fn actual_native_source_pool_bounds_and_fallback_behavior() {
    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let functions = [
        function_between(
            ledger,
            "unsafe fn pool_range_identity_unlocked(",
            "\npub(super) unsafe fn exact_pool_identity_unlocked(",
        ),
        function_between(
            ledger,
            "unsafe fn mapped_memory_identity_unlocked(",
            "\nunsafe fn memory_identity_matches_unlocked(",
        ),
        function_between(
            ledger,
            "unsafe fn memory_identity_matches_unlocked(",
            "\nunsafe fn mdl_identity_unlocked(",
        ),
        function_between(
            driver,
            "fn translate_component_range(",
            "\nfn component_to_exec_va_for_instance(",
        ),
        function_between(
            driver,
            "fn component_to_exec_va_for_instance(",
            "\npub(crate) unsafe fn hosted_component_stack_qword(",
        ),
        functions_between(
            driver,
            "fn component_pool_end()",
            "\nunsafe fn hosted_pool_allocation_exec_va(",
        ),
        function_between(
            driver,
            "unsafe fn hosted_pool_allocation_exec_va(",
            "\nfn component_pool_to_exec_va(",
        ),
        function_between(
            driver,
            "unsafe fn hosted_instance_pool_alloc(",
            "\nunsafe fn hosted_instance_pool_free_unlocked(",
        ),
        function_between(
            driver,
            "unsafe fn hosted_instance_pool_free_unlocked(",
            "\nunsafe fn hosted_instance_pool_free(",
        ),
        function_between(
            driver,
            "unsafe fn hosted_instance_pool_allocation_is_free_unlocked(",
            "\nunsafe fn release_hosted_instance_pool_allocation_if_live(",
        ),
        functions_between(
            driver,
            "pub(crate) unsafe fn pool_alloc(size: u64) -> u64 {",
            "\n// --- FILE_OBJECT LIFETIME:",
        ),
    ]
    .join("\n");
    let constants = [
        "FSD_CODE_VA",
        "FSD_IMAGE_FRAMES",
        "FSD_POOL_VADDR",
        "FSD_POOL_FRAMES",
        "FSD_STACK_VADDR",
        "FSD_STACK_FRAMES",
        "FSD_STACK_BYTES",
        "FSD_DATA_VADDR",
        "FSD_DATA_FRAMES",
        "FSD_SHARED_VADDR",
        "FSD_SHARED_FRAMES",
        "FSD_ARG_VADDR",
        "FSD_ARG_FRAMES",
    ]
    .map(|name| {
        driver
            .lines()
            .find(|line| line.starts_with(&format!("pub const {name}:")))
            .expect("actual native pool and translation geometry")
    })
    .join("\n");
    let data_offset = driver
        .lines()
        .find(|line| line.starts_with("const POOL_DATA_OFF:"))
        .expect("actual pool data offset");
    let walker = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../nt-io-manager/src/hosted_pool_range.rs")
        .canonicalize()
        .unwrap();
    let harness = format!(
        "mod nt_io_manager {{ #[path = {walker:?}] pub mod hosted_pool_range; }}\n{constants}\n{data_offset}\n{PORTS}\n{functions}\n{CASES}"
    );
    let directory =
        std::env::temp_dir().join(format!("nt-source-pool-bounds-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "fixture must compile before behavioral assertions:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .args(["cases::", "--nocapture"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "actual source capture regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

const POOL_FREE_LIST_MAX:u64 = 1024;
static FSD_POOL_LIST_CYCLES:AtomicU64 = AtomicU64::new(0);
static FSD_POOL_INVALID_FREES:AtomicU64 = AtomicU64::new(0);
static FSD_POOL_DOUBLE_FREES:AtomicU64 = AtomicU64::new(0);
static mut POOL_CALLS:u64 = 0;
static mut POOL_LONG_WALKS:u64 = 0;
fn component_pool_lock() {}
fn hosted_instance_pool_lock(_:u64)->Option<()> { Some(()) }
fn next_component_pool_generation(_:u64)->Option<u64> { Some(7) }
fn print_str(_: &[u8]) {}
fn print_u64(_:u64) {}
fn print_hex(_:u32) {}
fn print_hex64(_:u64) {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourcePoolAllocationIdentity { component_address:u64, capacity:u64, pool_generation:u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceMemoryIdentity {
    Pool { allocation:SourcePoolAllocationIdentity, component_address:u64, bytes:u64 },
    MappedRange { component_address:u64, bytes:u64, exec_address:u64 },
}
#[derive(Clone, Copy)]
struct DriverInstance {
    driver_id:u64, exec_pool_va:u64, image_frames:u64, exec_stack_va:u64, exec_shared_va:u64, exec_arg_va:u64,
}
#[derive(Clone, Copy)]
struct HostedDriverThreadRuntime;
struct ExecVaWindow { code_va:u64, data_va:u64 }
impl ExecVaWindow {
    fn try_for_instance(index:usize)->Option<Self> {
        MEMORY.with(|memory| memory.borrow_mut().translations += 1);
        (index == 3).then_some(Self { code_va:0x3000_0000, data_va:0x4000_0000 })
    }
}
fn hosted_worker_component_to_exec_va(_:HostedDriverThreadRuntime,_:u64,_:u64)->Option<u64> { None }
fn hosted_driver_runtime_for_worker_component_range(_:usize,_:u64,_:u64)->Option<HostedDriverThreadRuntime> { None }
#[derive(Default)]
struct Memory { words:BTreeMap<u64,u64>, reads:Vec<u64>, writes:Vec<u64>, translations:usize }
thread_local! { static MEMORY:RefCell<Memory> = RefCell::new(Memory::default()); }
unsafe fn read_volatile<T:Copy>(pointer:*const T)->T {
    assert_eq!(core::mem::size_of::<T>(), 8);
    let value = MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        memory.reads.push(pointer as u64);
        memory.words.get(&(pointer as u64)).copied().unwrap_or(0)
    });
    // Never dereference the supplied native address: record attempted reads, including OOB.
    core::mem::transmute_copy(&value)
}
unsafe fn write_volatile<T:Copy>(pointer:*mut T, value:T) {
    assert_eq!(core::mem::size_of::<T>(), 8);
    let value:u64 = core::mem::transmute_copy(&value);
    MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        memory.writes.push(pointer as u64);
        memory.words.insert(pointer as u64, value);
    });
}
unsafe fn hosted_pool_used(pool_view_base:u64)->u64 {
    read_volatile(pool_view_base as *const u64)
}
unsafe fn hosted_pool_publish_used(pool_view_base:u64, used:u64) {
    write_volatile(pool_view_base as *mut u64, used);
}
fn instance()->DriverInstance {
    DriverInstance { driver_id:3, exec_pool_va:0x2000_0000, image_frames:FSD_IMAGE_FRAMES,
        exec_stack_va:0x5000_0000, exec_shared_va:0x6000_0000, exec_arg_va:0x7000_0000 }
}
fn reset(used:u64, capacity:u64, generation:u64, free:bool) {
    MEMORY.with(|memory| {
        let mut state = Memory::default();
        state.words.insert(instance().exec_pool_va, used);
        if free { state.words.insert(instance().exec_pool_va + 8, FSD_POOL_VADDR + POOL_DATA_OFF + 16); }
        state.words.insert(instance().exec_pool_va + POOL_DATA_OFF, capacity);
        state.words.insert(instance().exec_pool_va + POOL_DATA_OFF + 8, generation);
        *memory.borrow_mut() = state;
    });
}
fn mirror_component_pool(used:u64, capacity:u64) {
    MEMORY.with(|memory| {
        let mut state = memory.borrow_mut();
        state.words.insert(FSD_POOL_VADDR, used);
        state.words.insert(FSD_POOL_VADDR + POOL_DATA_OFF, capacity);
    });
}
"#;

const CASES: &str = r#"
#[cfg(test)] mod cases {
use super::*;

#[test]
fn corrupted_component_free_list_head_is_not_read_as_a_header() {
    let used = POOL_DATA_OFF + 16 + 0x80;
    reset(used, 0x80, 7, false);
    mirror_component_pool(used, 0x80);
    let outside = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000 + 0x10;
    MEMORY.with(|memory| {
        memory.borrow_mut().words.insert(FSD_POOL_VADDR + 8, outside);
    });
    let _ = unsafe { pool_alloc(8) };
    let reads = MEMORY.with(|memory| memory.borrow().reads.clone());
    assert!(!reads.contains(&(outside - 16)) && !reads.contains(&(outside - 8)),
        "untrusted free-list head must be validated before reading its header: {reads:x?}");

    reset(used, 0x80, 7, false);
    mirror_component_pool(used, 0x80);
    let base = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    MEMORY.with(|memory| {
        memory.borrow_mut().words.insert(FSD_POOL_VADDR + 8, outside);
    });
    assert!(!unsafe { pool_free_locked(base) });
    let reads = MEMORY.with(|memory| memory.borrow().reads.clone());
    assert!(!reads.contains(&(outside - 8)),
        "free-list walk must reject an out-of-arena successor before following it: {reads:x?}");
}

#[test]
fn forged_exec_free_list_interior_cannot_be_reused_or_certified() {
    let used = POOL_DATA_OFF + 16 + 0x80;
    let first = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    let interior = first + 0x40;
    let fake_exec = instance().exec_pool_va + POOL_DATA_OFF + 16 + 0x40;
    reset(used, 0x80, 7, false);
    MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        memory.words.insert(instance().exec_pool_va + 8, interior);
        memory.words.insert(fake_exec - 16, 0x40);
        memory.words.insert(fake_exec - 8, 0);
    });
    let allocated = unsafe { hosted_instance_pool_alloc(instance(), 8) };
    assert_ne!(allocated, Some(interior),
        "a forged capacity inside live payload cannot become a new allocation");
    let reads = MEMORY.with(|memory| memory.borrow().reads.clone());
    assert!(!reads.contains(&(fake_exec - 16)) && !reads.contains(&(fake_exec - 8)),
        "interior node must be rejected before reading its fake header: {reads:x?}");

    reset(used, 0x80, 7, false);
    MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        memory.words.insert(instance().exec_pool_va + 8, interior);
        memory.words.insert(fake_exec - 8, 0);
    });
    assert_eq!(unsafe { hosted_instance_pool_allocation_is_free_unlocked(instance(), first) }, None,
        "a corrupt free list cannot certify the allocation as live");
    assert!(!unsafe { hosted_instance_pool_free_unlocked(instance(), first) },
        "a corrupt free list cannot admit another free");
    let reads = MEMORY.with(|memory| memory.borrow().reads.clone());
    assert!(!reads.contains(&(fake_exec - 8)),
        "free-list walkers must reject the interior node before following it: {reads:x?}");
}

#[test]
fn cyclic_exec_free_list_cannot_admit_another_free() {
    let first = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    let second = first + 0x80 + 16;
    let first_exec = instance().exec_pool_va + POOL_DATA_OFF + 16;
    let second_exec = first_exec + 0x80 + 16;
    reset(POOL_DATA_OFF + 16 + 0x80 + 16 + 0x40, 0x80, 7, false);
    MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        memory.words.insert(instance().exec_pool_va + 8, first);
        memory.words.insert(first_exec - 8, first);
        memory.words.insert(second_exec - 16, 0x40);
        memory.words.insert(second_exec - 8, 9);
    });

    assert!(!unsafe { hosted_instance_pool_free_unlocked(instance(), second) },
        "a cyclic free list cannot acquire another allocation");
    let (writes, head, second_generation) = MEMORY.with(|memory| {
        let memory = memory.borrow();
        (memory.writes.clone(), memory.words[&(instance().exec_pool_va + 8)],
            memory.words[&(second_exec - 8)])
    });
    assert!(writes.is_empty(), "cycle refusal must preserve all pool metadata: {writes:x?}");
    assert_eq!(head, first);
    assert_eq!(second_generation, 9);
}

#[test]
fn oversized_component_bump_cursor_cannot_allocate_or_write() {
    let oversized = FSD_POOL_FRAMES * 0x1000 + 0x20;
    reset(oversized, 0x80, 7, false);
    mirror_component_pool(oversized, 0x80);
    assert_eq!(unsafe { pool_alloc(8) }, 0);
    let (reads, writes) = MEMORY.with(|memory| {
        let memory = memory.borrow();
        (memory.reads.clone(), memory.writes.clone())
    });
    assert!(reads.iter().all(|address| *address < FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000),
        "invalid bump cursor caused an out-of-arena read: {reads:x?}");
    assert!(writes.is_empty(), "invalid bump cursor changed allocator metadata: {writes:x?}");
}

#[test]
fn forged_aligned_interior_header_cannot_establish_component_capacity() {
    let used = POOL_DATA_OFF + 16 + 0x100;
    reset(used, 0x100, 7, false);
    mirror_component_pool(used, 0x100);
    let interior = FSD_POOL_VADDR + POOL_DATA_OFF + 16 + 0x40;
    MEMORY.with(|memory| {
        memory.borrow_mut().words.insert(interior - 16, 0x40);
    });
    assert_eq!(unsafe { component_pool_allocation_capacity(interior) }, None,
        "an aligned value inside a payload is not an allocation header");
}

#[test]
fn forged_aligned_interior_header_cannot_establish_exec_capacity() {
    let used = POOL_DATA_OFF + 16 + 0x100;
    reset(used, 0x100, 7, false);
    let interior = FSD_POOL_VADDR + POOL_DATA_OFF + 16 + 0x40;
    let interior_exec = instance().exec_pool_va + POOL_DATA_OFF + 16 + 0x40;
    MEMORY.with(|memory| {
        memory.borrow_mut().words.insert(interior_exec - 16, 0x40);
    });
    assert_eq!(unsafe { hosted_pool_allocation_exec_range(instance().exec_pool_va, interior) }, None,
        "an aligned value inside a payload is not an allocation header");
}

#[test]
fn oversized_cursor_cannot_establish_component_capacity() {
    let used = FSD_POOL_FRAMES * 0x1000 + 0x20;
    reset(used, 0x80, 7, false);
    mirror_component_pool(used, 0x80);
    let base = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    assert_eq!(unsafe { component_pool_allocation_capacity(base) }, None);
    assert_eq!(MEMORY.with(|memory| memory.borrow().reads.clone()), [FSD_POOL_VADDR],
        "an invalid cursor must be rejected before reading any capacity header");
}

#[test]
fn oversized_cursor_cannot_establish_exec_capacity() {
    let used = FSD_POOL_FRAMES * 0x1000 + 0x20;
    reset(used, 0x80, 7, false);
    let base = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    assert_eq!(unsafe { hosted_pool_allocation_exec_range(instance().exec_pool_va, base) }, None);
    assert_eq!(MEMORY.with(|memory| memory.borrow().reads.clone()), [instance().exec_pool_va],
        "an invalid cursor must be rejected before reading any capacity header");
}

#[test]
fn oversized_cursor_must_not_invoke_any_capacity_reader() {
    let size = FSD_POOL_FRAMES * 0x1000;
    reset(size + 0x20, size - POOL_DATA_OFF - 16, 7, false);
    let result = unsafe { pool_range_identity_unlocked(instance(), FSD_POOL_VADDR + size + 16, 1) };
    assert_eq!(result, None);
    let reads = MEMORY.with(|memory| memory.borrow().reads.clone());
    assert_eq!(reads, [instance().exec_pool_va],
        "invalid bump must be rejected before capacity reads; out-of-arena header reached: {reads:x?}");
}

#[test]
fn oversized_cursor_cannot_validate_an_in_arena_payload_either() {
    let size = FSD_POOL_FRAMES * 0x1000;
    reset(size + 0x20, 0x80, 7, false);
    let result = unsafe { pool_range_identity_unlocked(instance(), FSD_POOL_VADDR + POOL_DATA_OFF + 16, 1) };
    assert_eq!(result, None, "corrupt cursor cannot establish an exact allocation");
    assert_eq!(MEMORY.with(|memory| memory.borrow().reads.clone()), [instance().exec_pool_va]);
}

#[test]
fn failed_pool_identity_is_not_downgraded_to_mapped_range() {
    for (capacity,generation,free,offset) in [
        (0x80,7,true,POOL_DATA_OFF + 16),
        (0x80,0,false,POOL_DATA_OFF + 16),
        (0,7,false,POOL_DATA_OFF + 16),
        (0x80,7,false,POOL_DATA_OFF + 8),
        (0x80,7,false,POOL_DATA_OFF + 0x200),
    ] {
        reset(POOL_DATA_OFF + 16 + 0x80, capacity, generation, free);
        let result = unsafe { mapped_memory_identity_unlocked(3, instance(), None, FSD_POOL_VADDR + offset, 8) };
        assert_eq!(result, None, "failed pool capture became generationless mapping for offset {offset:x}");
        assert_eq!(MEMORY.with(|memory| memory.borrow().translations), 0,
            "pool identity refusal must not consult the generic mapped-window fallback");
    }
}

#[test]
fn valid_pool_interior_retains_full_allocation_identity() {
    reset(POOL_DATA_OFF + 16 + 0x80, 0x80, 7, false);
    let address = FSD_POOL_VADDR + POOL_DATA_OFF + 16 + 4;
    let result = unsafe { mapped_memory_identity_unlocked(3, instance(), None, address, 8) };
    assert_eq!(result, Some(SourceMemoryIdentity::Pool {
        allocation:SourcePoolAllocationIdentity { component_address:address-4, capacity:0x80, pool_generation:7 },
        component_address:address, bytes:8,
    }));
    assert_eq!(MEMORY.with(|memory| memory.borrow().translations), 0);
}

#[test]
fn pool_range_crossing_into_next_allocation_is_not_captured() {
    let first = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    reset(POOL_DATA_OFF + 0x60, 0x20, 7, false);
    MEMORY.with(|memory| {
        let mut memory = memory.borrow_mut();
        memory.words.insert(instance().exec_pool_va + POOL_DATA_OFF + 0x30, 0x20);
        memory.words.insert(instance().exec_pool_va + POOL_DATA_OFF + 0x38, 8);
    });
    let result = unsafe { mapped_memory_identity_unlocked(3, instance(), None, first + 0x1c, 8) };
    assert_eq!(result, None, "a range spanning two live allocations has no single owner");
    assert_eq!(MEMORY.with(|memory| memory.borrow().translations), 0,
        "a rejected pool range cannot fall through to a mapped window");
}

#[test]
fn recycled_pool_generation_invalidates_captured_identity() {
    reset(POOL_DATA_OFF + 16 + 0x80, 0x80, 7, false);
    let address = FSD_POOL_VADDR + POOL_DATA_OFF + 16 + 4;
    let captured = unsafe { mapped_memory_identity_unlocked(3, instance(), None, address, 8) }
        .expect("initial live pool allocation");
    assert!(unsafe { memory_identity_matches_unlocked(3, instance(), captured) });

    MEMORY.with(|memory| {
        memory.borrow_mut().words.insert(instance().exec_pool_va + POOL_DATA_OFF + 8, 8);
    });
    assert!(!unsafe { memory_identity_matches_unlocked(3, instance(), captured) },
        "the same address and capacity cannot stand in for the captured generation");
    assert_eq!(MEMORY.with(|memory| memory.borrow().translations), 0);
}

#[test]
fn pool_address_cannot_revalidate_as_generationless_mapped_range() {
    reset(POOL_DATA_OFF + 16 + 0x80, 0x80, 7, false);
    let address = FSD_POOL_VADDR + POOL_DATA_OFF + 16;
    let stale = SourceMemoryIdentity::MappedRange {
        component_address:address, bytes:8,
        exec_address:instance().exec_pool_va + POOL_DATA_OFF + 16,
    };
    assert!(!unsafe { memory_identity_matches_unlocked(3, instance(), stale) });
    assert_eq!(MEMORY.with(|memory| memory.borrow().translations), 0);
}

#[test]
fn genuine_nonpool_stack_and_data_windows_remain_supported() {
    for (address, expected) in [(FSD_STACK_VADDR+0x40,instance().exec_stack_va+0x40),
        (FSD_DATA_VADDR+0x40,0x4000_0040)] {
        reset(POOL_DATA_OFF + 16 + 0x80, 0x80, 7, false);
        let result = unsafe { mapped_memory_identity_unlocked(3, instance(), None, address, 8) };
        assert_eq!(result, Some(SourceMemoryIdentity::MappedRange { component_address:address, bytes:8, exec_address:expected }));
        assert_eq!(MEMORY.with(|memory| memory.borrow().translations), 1);
    }
}
}
"#;
