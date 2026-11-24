//! Execute the native PutScatterGatherList body with a provider that checks lock ownership.

use std::process::Command;

#[test]
fn put_sg_never_holds_allocation_spin_guard_across_provider_effects() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("extern \"win64\" fn s_dma_put_scatter_gather_list(")
        .expect("native PutScatterGatherList");
    let end = source[start..]
        .find("\n/// `NTSTATUS IoCreateSymbolicLink")
        .expect("following native export");
    let body = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(body).expect("complete native PutScatterGatherList body");
    let host_body = body.replacen(
        "extern \"win64\" fn s_dma_put_scatter_gather_list(",
        "extern \"C\" fn s_dma_put_scatter_gather_list(",
        1,
    );
    let helpers_start = source
        .find("unsafe fn dma_reserve_sg_records(")
        .expect("short SG record transitions");
    let helpers_end = source[helpers_start..]
        .find("\nextern \"win64\" fn s_dma_allocate_adapter_channel(")
        .expect("following native export");
    let helpers = &source[helpers_start..helpers_start + helpers_end];
    syn::parse_file(helpers).expect("complete short SG record transitions");
    let fixture = format!("{PORTS}\n{helpers}\n{host_body}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-native-dma-sg-put-lock-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native DMA fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native DMA lock regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::ptr::read_unaligned;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const HOSTED_SG_CONTEXT_MDL: u64 = 0x10;
const HOSTED_SG_CONTEXT_CURRENT_VA: u64 = 0x18;
const HOSTED_SG_CONTEXT_LENGTH: u64 = 0x20;
const HOSTED_SG_CONTEXT_WRITE_TO_DEVICE: u64 = 0x28;
static LOCKED: AtomicBool = AtomicBool::new(false);
static RESERVED: AtomicBool = AtomicBool::new(false);
static RETIRE_SUCCEEDS: AtomicBool = AtomicBool::new(false);
static QUERIES: AtomicUsize = AtomicUsize::new(0);
static RETIRES: AtomicUsize = AtomicUsize::new(0);
static CLEARS: AtomicUsize = AtomicUsize::new(0);
static mut CONTEXT: [u64; 8] = [0; 8];

struct HostedDmaAllocationGuard;
impl HostedDmaAllocationGuard {
    fn acquire() -> Self {
        assert!(!LOCKED.swap(true, Ordering::AcqRel), "recursive spin guard");
        Self
    }
}
impl Drop for HostedDmaAllocationGuard {
    fn drop(&mut self) { LOCKED.store(false, Ordering::Release); }
}
unsafe fn dma_query_sg_members(adapter: u64, list: u64) -> Option<(u64, u64)> {
    assert!(!LOCKED.load(Ordering::Acquire), "provider query under spin guard");
    assert_eq!((adapter, list), (7, 11));
    QUERIES.fetch_add(1, Ordering::Relaxed);
    Some((42, core::ptr::addr_of!(CONTEXT) as u64))
}
unsafe fn s_dma_flush_adapter_buffers(
    adapter: u64, mdl: u64, map: u64, va: u64, length: u32, direction: u8,
) -> u8 {
    assert_eq!((adapter, mdl, map, va, length, direction), (7, 17, 42, 23, 31, 1));
    1
}
unsafe fn dma_reserve_records_for_map(map: u64) -> bool {
    assert!(LOCKED.load(Ordering::Acquire), "reservation needs spin guard");
    assert_eq!(map, 42);
    !RESERVED.swap(true, Ordering::AcqRel)
}
unsafe fn dma_retire_sg_list(adapter: u64, list: u64) -> bool {
    assert!(!LOCKED.load(Ordering::Acquire), "provider retirement under spin guard");
    assert!(RESERVED.load(Ordering::Acquire), "effect before reservation");
    assert_eq!((adapter, list), (7, 11));
    RETIRES.fetch_add(1, Ordering::Relaxed);
    RETIRE_SUCCEEDS.load(Ordering::Relaxed)
}
unsafe fn dma_clear_records_for_map(map: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "record clear needs spin guard");
    assert_eq!(map, 42);
    assert!(RESERVED.swap(false, Ordering::AcqRel));
    CLEARS.fetch_add(1, Ordering::Relaxed);
}
"#;

const CASES: &str = r#"
#[test]
fn uncertain_retirement_keeps_the_claim_and_success_clears_once() {
    unsafe {
        CONTEXT[2] = 17; // MDL
        CONTEXT[3] = 23; // current VA
        CONTEXT[4] = 31; // length
        CONTEXT[5] = 1;  // write to device
    }
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(QUERIES.load(Ordering::Relaxed), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(CLEARS.load(Ordering::Relaxed), 0);
    assert!(RESERVED.load(Ordering::Acquire));
    assert!(!LOCKED.load(Ordering::Acquire));

    // A second entry cannot replay the uncertain provider effect.
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    RETIRE_SUCCEEDS.store(true, Ordering::Relaxed);
    // A separate fresh list may retire successfully after its own claim.
    RESERVED.store(false, Ordering::Release);
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 2);
    assert_eq!(CLEARS.load(Ordering::Relaxed), 1);
    assert!(!RESERVED.load(Ordering::Acquire));
    assert!(!LOCKED.load(Ordering::Acquire));
}
"#;
