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
    let claim_start = source
        .find("static HOSTED_DMA_RETIRE_NEXT_EPOCH:")
        .expect("native retirement claim and exact record clear");
    let claim_end = source[claim_start..]
        .find("\nunsafe fn dma_retire_claimed_map(")
        .expect("following FreeMapRegisters retirement");
    let claim_helpers = &source[claim_start..claim_start + claim_end];
    syn::parse_file(claim_helpers).expect("complete native claim and clear bodies");
    let helpers_start = source
        .find("unsafe fn dma_reserve_sg_records(")
        .expect("short SG record transitions");
    let helpers_end = source[helpers_start..]
        .find("\nextern \"win64\" fn s_dma_allocate_adapter_channel(")
        .expect("following native export");
    let helpers = &source[helpers_start..helpers_start + helpers_end];
    syn::parse_file(helpers).expect("complete short SG record transitions");
    let fixture = format!("{PORTS}\n{claim_helpers}\n{helpers}\n{host_body}\n{CASES}");
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
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native DMA lock regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::ptr::{read_unaligned, read_volatile, write_volatile};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const HOSTED_DMA_RECORD_KIND_MAP_TRANSFER: u64 = 2;
const HOSTED_DMA_RECORD_KIND_COHERENT_MAP: u64 = 3;
const DMA_RECORD_RESERVED: u64 = u64::MAX;
const SH_DMA_ALLOC_RECORD_COUNT: u64 = 0x20;
const SH_DMA_ALLOC_RECORDS: u64 = 0x100;
const SH_DMA_ALLOC_RECORD_SIZE: u64 = 0x50;
const SH_DMA_ALLOC_RECORD_LOGICAL: u64 = 0;
const SH_DMA_ALLOC_RECORD_LEN: u64 = 8;
const SH_DMA_ALLOC_RECORD_VA: u64 = 16;
const SH_DMA_ALLOC_RECORD_KIND: u64 = 24;
const SH_DMA_ALLOC_RECORD_SOURCE_VA: u64 = 32;
const SH_DMA_ALLOC_RECORD_MAP_REGISTER: u64 = 48;
const SH_DMA_ALLOC_RECORD_ADAPTER_ID: u64 = 56;
const SH_DMA_ALLOC_RECORD_PENDING_EXTENT: u64 = 64;
const SH_DMA_ALLOC_RECORD_RETIREMENT_EPOCH: u64 = 72;
const HOSTED_SG_CONTEXT_MDL: u64 = 0x10;
const HOSTED_SG_CONTEXT_CURRENT_VA: u64 = 0x18;
const HOSTED_SG_CONTEXT_LENGTH: u64 = 0x20;
const HOSTED_SG_CONTEXT_WRITE_TO_DEVICE: u64 = 0x28;
static LOCKED: AtomicBool = AtomicBool::new(false);
static RETIRE_SUCCEEDS: AtomicBool = AtomicBool::new(false);
static INVALIDATE_ON_LAST_ALIAS: AtomicBool = AtomicBool::new(false);
static RETIRED_ALIASES: AtomicUsize = AtomicUsize::new(0);
static QUERIES: AtomicUsize = AtomicUsize::new(0);
static RETIRES: AtomicUsize = AtomicUsize::new(0);
static HOSTED_DMA_RECORD_CLEARED_COUNT: AtomicU64 = AtomicU64::new(0);
static HOSTED_DMA_PUT_SG_ENTER_COUNT: AtomicUsize = AtomicUsize::new(0);
static HOSTED_DMA_PUT_SG_QUERY_FAILED_COUNT: AtomicUsize = AtomicUsize::new(0);
static HOSTED_DMA_PUT_SG_RESERVE_FAILED_COUNT: AtomicUsize = AtomicUsize::new(0);
static mut CONTEXT: [u64; 8] = [0; 8];
static mut TOKEN: [u64; 4] = [0x4D41_5052_4547_3031, 1, 7, 0];
static mut FSD_SHARED_VADDR: u64 = 0;

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
fn token() -> u64 { core::ptr::addr_of!(TOKEN) as u64 }
unsafe fn dma_allocation_record_capacity(_: u64) -> u64 { 2 }
unsafe fn dma_allocation_record(sh: u64, index: u64) -> Option<u64> {
    (index < 2).then_some(sh + SH_DMA_ALLOC_RECORDS + index * SH_DMA_ALLOC_RECORD_SIZE)
}
unsafe fn dma_record_load(record: u64, offset: u64) -> u64 {
    read_volatile((record + offset) as *const u64)
}
unsafe fn dma_record_store(record: u64, offset: u64, value: u64) {
    write_volatile((record + offset) as *mut u64, value)
}
struct FixtureDmaRecord(u64);
impl FixtureDmaRecord {
    fn retirement_epoch(&self) -> u64 {
        unsafe { dma_record_load(self.0, SH_DMA_ALLOC_RECORD_RETIREMENT_EPOCH) }
    }
}
unsafe fn dma_shared_record(record: u64) -> FixtureDmaRecord { FixtureDmaRecord(record) }
unsafe fn begin_dma_allocation_record(record: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "begin without allocation guard");
    let previous = dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, DMA_RECORD_RESERVED);
    if previous != DMA_RECORD_RESERVED {
        dma_record_store(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT, previous);
    }
}
unsafe fn begin_dma_record_retirement(record: u64, epoch: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "retirement without allocation guard");
    assert_ne!(epoch, 0);
    assert_eq!(dma_shared_record(record).retirement_epoch(), 0);
    begin_dma_allocation_record(record);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_RETIREMENT_EPOCH, epoch);
}
unsafe fn clear_dma_allocation_record(record: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "clear without allocation guard");
    for offset in [SH_DMA_ALLOC_RECORD_LOGICAL, SH_DMA_ALLOC_RECORD_LEN,
        SH_DMA_ALLOC_RECORD_VA, SH_DMA_ALLOC_RECORD_KIND, SH_DMA_ALLOC_RECORD_SOURCE_VA,
        SH_DMA_ALLOC_RECORD_MAP_REGISTER, SH_DMA_ALLOC_RECORD_ADAPTER_ID,
        SH_DMA_ALLOC_RECORD_PENDING_EXTENT, SH_DMA_ALLOC_RECORD_RETIREMENT_EPOCH] {
        dma_record_store(record, offset, 0);
    }
}
unsafe fn first_free_dma_allocation_record(sh: u64) -> Option<u64> {
    (0..2).filter_map(|index| dma_allocation_record(sh, index))
        .find(|&record| dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN) == 0)
}
unsafe fn dma_query_sg_members(adapter: u64, list: u64) -> Option<(u64, u64)> {
    assert!(!LOCKED.load(Ordering::Acquire), "provider query under spin guard");
    assert_eq!((adapter, list), (7, 11));
    QUERIES.fetch_add(1, Ordering::Relaxed);
    Some((token(), core::ptr::addr_of!(CONTEXT) as u64))
}
unsafe fn s_dma_flush_adapter_buffers(
    adapter: u64, mdl: u64, map: u64, va: u64, length: u32, direction: u8,
) -> u8 {
    assert_eq!((adapter, mdl, map, va, length, direction), (7, 17, token(), 23, 31, 1));
    1
}
unsafe fn dma_retire_sg_list(adapter: u64, list: u64) -> bool {
    assert!(!LOCKED.load(Ordering::Acquire), "provider retirement under spin guard");
    assert_eq!((adapter, list), (7, 11));
    let old = dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap();
    assert_eq!(dma_record_load(old, SH_DMA_ALLOC_RECORD_LEN), DMA_RECORD_RESERVED,
        "effect before exact local reservation");
    assert_ne!(dma_shared_record(old).retirement_epoch(), 0);
    RETIRES.fetch_add(1, Ordering::Relaxed);
    if !RETIRE_SUCCEEDS.load(Ordering::Relaxed) { return false; }
    if INVALIDATE_ON_LAST_ALIAS.load(Ordering::Acquire)
        && RETIRED_ALIASES.fetch_add(1, Ordering::AcqRel) == 15 {
        // Fifteen aliases have already retired. The root frees this token on the
        // sixteenth success, before its reply reaches the caller.
        let _guard = HostedDmaAllocationGuard::acquire();
        TOKEN[0] = 0;
        TOKEN[2] = 8;
        let fresh = dma_allocation_record(FSD_SHARED_VADDR, 1).unwrap();
        begin_dma_allocation_record(fresh);
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_LOGICAL, 0x2000);
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_VA, 0x5000);
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_KIND, HOSTED_DMA_RECORD_KIND_MAP_TRANSFER);
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_SOURCE_VA, 0x6000);
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_MAP_REGISTER, token());
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_ADAPTER_ID, 8);
        dma_record_store(fresh, SH_DMA_ALLOC_RECORD_LEN, 64);
        write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 2);
    }
    true
}
"#;

const CASES: &str = r#"
fn reset() -> Vec<u64> {
    LOCKED.store(false, Ordering::Release);
    RETIRE_SUCCEEDS.store(false, Ordering::Release);
    INVALIDATE_ON_LAST_ALIAS.store(false, Ordering::Release);
    RETIRED_ALIASES.store(0, Ordering::Relaxed);
    QUERIES.store(0, Ordering::Relaxed);
    RETIRES.store(0, Ordering::Relaxed);
    HOSTED_DMA_RECORD_CLEARED_COUNT.store(0, Ordering::Relaxed);
    HOSTED_DMA_RETIRE_NEXT_EPOCH.store(0, Ordering::Relaxed);
    HOSTED_DMA_PUT_SG_ENTER_COUNT.store(0, Ordering::Relaxed);
    HOSTED_DMA_PUT_SG_QUERY_FAILED_COUNT.store(0, Ordering::Relaxed);
    HOSTED_DMA_PUT_SG_RESERVE_FAILED_COUNT.store(0, Ordering::Relaxed);
    let mut shared = vec![0u64; 64];
    unsafe {
        FSD_SHARED_VADDR = shared.as_mut_ptr() as u64;
        TOKEN[0] = 0x4D41_5052_4547_3031;
        TOKEN[2] = 7;
        CONTEXT[2] = 17; // MDL
        CONTEXT[3] = 23; // current VA
        CONTEXT[4] = 31; // length
        CONTEXT[5] = 1;  // write to device
        let row = dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap();
        dma_record_store(row, SH_DMA_ALLOC_RECORD_LOGICAL, 0x1000);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_LEN, 64);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_VA, 0x4000);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_KIND, HOSTED_DMA_RECORD_KIND_MAP_TRANSFER);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_SOURCE_VA, 0x5000);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_MAP_REGISTER, token());
        dma_record_store(row, SH_DMA_ALLOC_RECORD_ADAPTER_ID, 7);
        write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 1);
    }
    shared
}

#[test]
fn uncertain_retirement_keeps_the_claim_and_refuses_replay() {
    let _shared = reset();
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(QUERIES.load(Ordering::Relaxed), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_RECORD_CLEARED_COUNT.load(Ordering::Relaxed), 0);
    assert_eq!(HOSTED_DMA_PUT_SG_ENTER_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_PUT_SG_QUERY_FAILED_COUNT.load(Ordering::Relaxed), 0);
    let row = unsafe { dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap() };
    assert_eq!(unsafe { dma_record_load(row, SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
    assert_eq!(unsafe { dma_record_load(row, SH_DMA_ALLOC_RECORD_PENDING_EXTENT) }, 64);
    assert_ne!(unsafe { dma_shared_record(row).retirement_epoch() }, 0);
    assert!(!LOCKED.load(Ordering::Acquire));

    // A second entry cannot replay the uncertain provider effect.
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_PUT_SG_ENTER_COUNT.load(Ordering::Relaxed), 2);
    assert_eq!(HOSTED_DMA_PUT_SG_RESERVE_FAILED_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(row, SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
}

#[test]
fn successful_retirement_clears_its_claim_once() {
    let _shared = reset();
    RETIRE_SUCCEEDS.store(true, Ordering::Relaxed);
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(QUERIES.load(Ordering::Relaxed), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_RECORD_CLEARED_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_PUT_SG_ENTER_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_PUT_SG_RESERVE_FAILED_COUNT.load(Ordering::Relaxed), 0);
    let row = unsafe { dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap() };
    assert_eq!(unsafe { dma_record_load(row, SH_DMA_ALLOC_RECORD_LEN) }, 0);
    assert_eq!(unsafe { dma_shared_record(row).retirement_epoch() }, 0);
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn sixteenth_alias_retirement_clears_only_pre_effect_row_after_token_invalidation() {
    let _shared = reset();
    RETIRE_SUCCEEDS.store(true, Ordering::Release);
    INVALIDATE_ON_LAST_ALIAS.store(true, Ordering::Release);
    RETIRED_ALIASES.store(15, Ordering::Release);
    s_dma_put_scatter_gather_list(7, 11, 0);

    assert_eq!(RETIRED_ALIASES.load(Ordering::Acquire), 16);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    let old = unsafe { dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap() };
    let fresh = unsafe { dma_allocation_record(FSD_SHARED_VADDR, 1).unwrap() };
    assert_eq!(unsafe { dma_record_load(old, SH_DMA_ALLOC_RECORD_LEN) }, 0,
        "the authenticated claim must clear without rereading an invalidated token");
    assert_eq!(unsafe { dma_shared_record(old).retirement_epoch() }, 0);
    assert_eq!(unsafe { dma_record_load(fresh, SH_DMA_ALLOC_RECORD_LEN) }, 64,
        "a row published after the root effect must remain live");
    assert_eq!(unsafe { dma_record_load(fresh, SH_DMA_ALLOC_RECORD_ADAPTER_ID) }, 8);
    assert_eq!(HOSTED_DMA_RECORD_CLEARED_COUNT.load(Ordering::Relaxed), 1);
    assert!(!LOCKED.load(Ordering::Acquire));
}
"#;
