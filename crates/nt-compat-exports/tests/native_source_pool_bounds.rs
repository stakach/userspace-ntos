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

#[test]
fn actual_native_source_pool_bounds_and_fallback_behavior() {
    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let functions = [
        function_between(
            ledger,
            "unsafe fn pool_range_identity_unlocked(",
            "\nunsafe fn exact_pool_identity_unlocked(",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourcePoolAllocationIdentity { component_address:u64, capacity:u64, pool_generation:u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceMemoryIdentity {
    Pool { allocation:SourcePoolAllocationIdentity, component_address:u64, bytes:u64 },
    MappedRange { component_address:u64, bytes:u64, exec_address:u64 },
}
#[derive(Clone, Copy)]
struct DriverInstance {
    exec_pool_va:u64, image_frames:u64, exec_stack_va:u64, exec_shared_va:u64, exec_arg_va:u64,
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
struct Memory { words:BTreeMap<u64,u64>, reads:Vec<u64>, free:bool, translations:usize }
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
unsafe fn hosted_instance_pool_allocation_is_free_unlocked(_:DriverInstance,_:u64)->Option<bool> {
    Some(MEMORY.with(|memory| memory.borrow().free))
}
fn instance()->DriverInstance {
    DriverInstance { exec_pool_va:0x2000_0000, image_frames:FSD_IMAGE_FRAMES,
        exec_stack_va:0x5000_0000, exec_shared_va:0x6000_0000, exec_arg_va:0x7000_0000 }
}
fn reset(used:u64, capacity:u64, generation:u64, free:bool) {
    MEMORY.with(|memory| {
        let mut state = Memory::default();
        state.words.insert(instance().exec_pool_va, used);
        state.words.insert(instance().exec_pool_va + POOL_DATA_OFF, capacity);
        state.words.insert(instance().exec_pool_va + POOL_DATA_OFF + 8, generation);
        state.free = free;
        *memory.borrow_mut() = state;
    });
}
"#;

const CASES: &str = r#"
#[cfg(test)] mod cases {
use super::*;

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
