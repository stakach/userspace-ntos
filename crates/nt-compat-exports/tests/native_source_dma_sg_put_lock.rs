//! Execute native SG flush and PutScatterGatherList bodies with exact record ownership.

use std::process::Command;

#[test]
fn put_sg_preserves_copyback_and_releases_guard_before_provider_effects() {
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
    let copy_start = source
        .find("unsafe fn dma_copy_bytes(")
        .expect("native DMA byte copy");
    let copy_end = source[copy_start..]
        .find("\nunsafe fn dma_allocate_private_graph(")
        .expect("following private DMA graph allocation");
    let copy = &source[copy_start..copy_start + copy_end];
    syn::parse_file(copy).expect("complete native DMA byte copy");
    let flush_start = source
        .find("unsafe fn dma_find_map_record(")
        .expect("native active map lookup");
    let flush_end = source[flush_start..]
        .find("\nextern \"win64\" fn s_dma_free_map_registers(")
        .expect("following native FreeMapRegisters");
    let flush = &source[flush_start..flush_start + flush_end];
    syn::parse_file(flush).expect("complete native DMA flush and map lookup");
    let flush = flush.replacen(
        "extern \"win64\" fn s_dma_flush_adapter_buffers(",
        "fn s_dma_flush_adapter_buffers(",
        1,
    );
    let fixture = format!("{PORTS}\n{copy}\n{flush}\n{claim_helpers}\n{helpers}\n{host_body}\n{CASES}");
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
const HOSTED_DMA_MAP_REGISTER_SIGNATURE: u64 = 0x4D41_5052_4547_3031;
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
struct HostedDmaAdapterMetadata { adapter_id: u64 }
unsafe fn dma_adapter_metadata(adapter: u64) -> Option<HostedDmaAdapterMetadata> {
    (adapter == 7).then_some(HostedDmaAdapterMetadata { adapter_id: 7 })
}
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
struct FixtureMemory {
    _shared: Vec<u64>,
    source: Vec<u8>,
    bounce: Vec<u8>,
}

fn reset_with(kind: u64, write_to_device: u8) -> FixtureMemory {
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
    let source = vec![0x11u8; 64];
    let bounce = vec![0xA5u8; 64];
    let source_va = if kind == HOSTED_DMA_RECORD_KIND_COHERENT_MAP {
        bounce.as_ptr() as u64
    } else {
        source.as_ptr() as u64
    };
    unsafe {
        FSD_SHARED_VADDR = shared.as_mut_ptr() as u64;
        TOKEN[0] = 0x4D41_5052_4547_3031;
        TOKEN[2] = 7;
        CONTEXT[2] = 17; // MDL
        CONTEXT[3] = source_va; // exact current VA
        CONTEXT[4] = 31; // length
        CONTEXT[5] = write_to_device as u64;
        let row = dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap();
        dma_record_store(row, SH_DMA_ALLOC_RECORD_LOGICAL, 0x1000);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_LEN, 64);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_VA, bounce.as_ptr() as u64);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_KIND, kind);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_SOURCE_VA, source_va);
        dma_record_store(row, SH_DMA_ALLOC_RECORD_MAP_REGISTER, token());
        dma_record_store(row, SH_DMA_ALLOC_RECORD_ADAPTER_ID, 7);
        write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 1);
    }
    FixtureMemory { _shared: shared, source, bounce }
}

fn reset() -> FixtureMemory {
    reset_with(HOSTED_DMA_RECORD_KIND_MAP_TRANSFER, 1)
}

#[test]
fn uncertain_retirement_keeps_the_claim_and_refuses_replay() {
    let mut memory = reset_with(HOSTED_DMA_RECORD_KIND_MAP_TRANSFER, 0);
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
    let source_after_first = memory.source.clone();
    memory.bounce.fill(0x5A);
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_PUT_SG_ENTER_COUNT.load(Ordering::Relaxed), 2);
    assert_eq!(HOSTED_DMA_PUT_SG_RESERVE_FAILED_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(row, SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
    assert_eq!(memory.source, source_after_first,
        "duplicate PutSG must not copy bytes after an uncertain retirement");
}

#[test]
fn device_to_memory_put_copies_exact_bounce_bytes_before_retirement() {
    let mut memory = reset_with(HOSTED_DMA_RECORD_KIND_MAP_TRANSFER, 0);
    let source_va = memory.source.as_ptr() as u64;
    assert_eq!(s_dma_flush_adapter_buffers(7, 17, token(), source_va, 31, 0), 1,
        "the production flush must find a published active map");
    assert_eq!(&memory.source[..31], &memory.bounce[..31]);
    memory.source.fill(0x11);

    RETIRE_SUCCEEDS.store(true, Ordering::Release);
    s_dma_put_scatter_gather_list(7, 11, 0);

    assert_eq!(&memory.source[..31], &memory.bounce[..31],
        "PutSG must copy the completed device bytes before retiring its exact map");
    assert_eq!(memory.source[31], 0x11, "copyback must respect the requested length");
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
}

#[test]
fn write_to_device_and_coherent_maps_do_not_copy_back() {
    let write_memory = reset();
    let source_va = write_memory.source.as_ptr() as u64;
    assert_eq!(s_dma_flush_adapter_buffers(7, 17, token(), source_va, 31, 1), 1);
    RETIRE_SUCCEEDS.store(true, Ordering::Release);
    s_dma_put_scatter_gather_list(7, 11, 1);
    assert!(write_memory.source.iter().all(|byte| *byte == 0x11));
    assert!(write_memory.bounce.iter().all(|byte| *byte == 0xA5));

    let coherent_memory = reset_with(HOSTED_DMA_RECORD_KIND_COHERENT_MAP, 0);
    let coherent_va = coherent_memory.bounce.as_ptr() as u64;
    assert_eq!(s_dma_flush_adapter_buffers(7, 17, token(), coherent_va, 31, 0), 1);
    RETIRE_SUCCEEDS.store(true, Ordering::Release);
    s_dma_put_scatter_gather_list(7, 11, 0);
    assert!(coherent_memory.source.iter().all(|byte| *byte == 0x11));
    assert!(coherent_memory.bounce.iter().all(|byte| *byte == 0xA5));
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
