//! Run native map-token retirement bodies against exact pending-record ownership.

use std::process::Command;

#[test]
fn map_retirement_releases_guard_and_keeps_uncertain_claims() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let retire_start = source
        .find("#[derive(Clone, Copy, PartialEq, Eq)]\nenum DmaMapRetirement")
        .expect("native map-token retirement");
    let retire_end = source[retire_start..]
        .find("\nunsafe fn dma_retire_sg_list(")
        .expect("following SG retirement");
    let retire = &source[retire_start..retire_start + retire_end];
    syn::parse_file(retire).expect("complete map-token retirement");

    let helpers_start = source
        .find("unsafe fn dma_reserve_records_for_map(")
        .expect("native map-record reservation");
    let helpers_end = source[helpers_start..]
        .find("\nextern \"win64\" fn s_dma_free_adapter_channel(")
        .expect("following adapter export");
    let helpers = &source[helpers_start..helpers_start + helpers_end];
    syn::parse_file(helpers).expect("complete native record and action2 bodies");
    let helpers = helpers.replacen(
        "extern \"win64\" fn s_dma_allocate_adapter_channel(",
        "fn s_dma_allocate_adapter_channel(",
        1,
    );

    let free_start = source
        .find("extern \"win64\" fn s_dma_free_map_registers(")
        .expect("native FreeMapRegisters");
    let free_end = source[free_start..]
        .find("\nextern \"win64\" fn s_dma_get_dma_alignment(")
        .expect("following native DMA export");
    let free = &source[free_start..free_start + free_end];
    syn::parse_str::<syn::ItemFn>(free).expect("complete native FreeMapRegisters");
    let free = free.replacen(
        "extern \"win64\" fn s_dma_free_map_registers(",
        "fn s_dma_free_map_registers(",
        1,
    );

    let fixture = format!("{PORTS}\n{retire}\n{helpers}\n{free}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-dma-map-retirement-{}",
        std::process::id()
    ));
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
        "native map-retirement fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native map-retirement regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::ptr::{read_unaligned, read_volatile, write_volatile};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const HOSTED_DMA_RECORD_KIND_MAP_TRANSFER: u64 = 2;
const HOSTED_DMA_RECORD_KIND_COHERENT_MAP: u64 = 3;
const HOSTED_DMA_MAP_REGISTER_SIGNATURE: u64 = 0x4D41_5052_4547_3031;
const HOSTED_DMA_SERVICE_OPERATION_SHIFT: u64 = 56;
const HOSTED_DMA_SERVICE_FREE_MAP: u64 = 9;
const HOSTED_DMA_ADAPTER_LEASE_ID_OFFSET: u64 = 0x38;
const FSD_SERVICE_DMA_ADAPTER_LABEL: u64 = 9;
const DMA_RECORD_RESERVED: u64 = u64::MAX;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INVALID_HANDLE: i32 = 0xC000_0008u32 as i32;
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;
const SH_DMA_ALLOC_RECORD_COUNT: u64 = 0x20;
const SH_DMA_ALLOC_RECORDS: u64 = 0x100;
const SH_DMA_ALLOC_RECORD_SIZE: u64 = 0x48;
const SH_DMA_ALLOC_RECORD_LOGICAL: u64 = 0x00;
const SH_DMA_ALLOC_RECORD_LEN: u64 = 0x08;
const SH_DMA_ALLOC_RECORD_VA: u64 = 0x10;
const SH_DMA_ALLOC_RECORD_KIND: u64 = 0x18;
const SH_DMA_ALLOC_RECORD_SOURCE_VA: u64 = 0x20;
const SH_DMA_ALLOC_RECORD_MAP_REGISTER: u64 = 0x30;
const SH_DMA_ALLOC_RECORD_ADAPTER_ID: u64 = 0x38;
const SH_DMA_ALLOC_RECORD_PENDING_EXTENT: u64 = 0x40;

static LOCKED: AtomicBool = AtomicBool::new(false);
static RETIRE_SUCCEEDS: AtomicBool = AtomicBool::new(false);
static REPLY_VALID: AtomicBool = AtomicBool::new(true);
static ACTION: AtomicU32 = AtomicU32::new(2);
static RETIRES: AtomicUsize = AtomicUsize::new(0);
static mut FSD_SHARED_VADDR: u64 = 0;
static mut TOKEN: [u64; 4] = [HOSTED_DMA_MAP_REGISTER_SIGNATURE, 1, 7, 0];

struct HostedDmaAllocationGuard;
impl HostedDmaAllocationGuard {
    fn acquire() -> Self {
        assert!(!LOCKED.swap(true, Ordering::AcqRel), "recursive allocation guard");
        Self
    }
}
impl Drop for HostedDmaAllocationGuard {
    fn drop(&mut self) { LOCKED.store(false, Ordering::Release); }
}

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
unsafe fn begin_dma_allocation_record(record: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "reserve without guard");
    let prior = dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, DMA_RECORD_RESERVED);
    if prior != DMA_RECORD_RESERVED {
        dma_record_store(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT, prior);
    }
}
unsafe fn clear_dma_allocation_record(record: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "clear without guard");
    for offset in [SH_DMA_ALLOC_RECORD_LOGICAL, SH_DMA_ALLOC_RECORD_LEN,
        SH_DMA_ALLOC_RECORD_VA, SH_DMA_ALLOC_RECORD_KIND, SH_DMA_ALLOC_RECORD_SOURCE_VA,
        SH_DMA_ALLOC_RECORD_MAP_REGISTER, SH_DMA_ALLOC_RECORD_ADAPTER_ID,
        SH_DMA_ALLOC_RECORD_PENDING_EXTENT] {
        dma_record_store(record, offset, 0);
    }
}
unsafe fn first_free_dma_allocation_record(sh: u64) -> Option<u64> {
    (0..2).filter_map(|index| dma_allocation_record(sh, index))
        .find(|&record| dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN) == 0)
}

#[derive(Clone, Copy)]
struct Identity { domain_id: u64, domain_cookie: u64 }
fn hosted_irq_lane_context() -> Option<((), Identity, (), (), ())> { None }
fn hosted_irq_lane_protocol_fault(_: u64) -> ! { panic!("unexpected IRQ lane") }
mod nt_hosted_runtime {
    #[derive(Clone, Copy)]
    pub enum HostedIrqServiceKind { DmaFreeMapping }
    pub const HOSTED_IRQ_ARENA_ARGUMENT_CAP: usize = 8;
    pub struct HostedIrqServiceCommand {
        pub kind: HostedIrqServiceKind,
        pub service_id: u64,
        pub target_domain_id: u64,
        pub target_domain_cookie: u64,
        pub authority_cookie: u64,
        pub grant: (),
        pub argument_count: usize,
        pub arguments: [u64; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
    }
}
struct HostedIrqServiceResult { faulted: bool, value_count: usize, status: i32 }
fn hosted_irq_lane_service(_: nt_hosted_runtime::HostedIrqServiceCommand) -> HostedIrqServiceResult {
    panic!("unexpected IRQ lane")
}

unsafe fn call_on5_raw(
    _: u64, adapter: u64, operation: u64, map: u64, arg3: u64, arg4: u64,
) -> (u64, u64, u64, u64, u64) {
    assert!(!LOCKED.load(Ordering::Acquire), "provider retirement under spin guard");
    assert_eq!((adapter, operation >> HOSTED_DMA_SERVICE_OPERATION_SHIFT),
        (7, HOSTED_DMA_SERVICE_FREE_MAP));
    assert_eq!((arg3, arg4), (0, 0));
    assert_eq!(map, core::ptr::addr_of!(TOKEN) as u64);
    let count = read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *const u64);
    assert!(count > 0 && count <= 2, "pending token must be root-visible");
    assert!((0..count).filter_map(|index| dma_allocation_record(FSD_SHARED_VADDR, index))
        .any(|record| dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN) == DMA_RECORD_RESERVED
            && dma_record_load(record, SH_DMA_ALLOC_RECORD_MAP_REGISTER) == map
            && dma_record_load(record, SH_DMA_ALLOC_RECORD_ADAPTER_ID) == 7),
        "exact token must be reserved before provider retirement");
    let prior = RETIRES.fetch_add(1, Ordering::Relaxed);
    let reply = if REPLY_VALID.load(Ordering::Acquire) { 4 } else { 0 };
    let status = if prior != 0 {
        STATUS_INVALID_HANDLE
    } else if RETIRE_SUCCEEDS.load(Ordering::Acquire) {
        STATUS_SUCCESS
    } else {
        STATUS_DEVICE_BUSY
    };
    (reply, status as u32 as u64, 0, 0, 0)
}
unsafe fn dma_allocate_map_register_token(adapter: u64, count: u32) -> u64 {
    assert_eq!((adapter, count), (7, 1));
    core::ptr::addr_of!(TOKEN) as u64
}
unsafe fn call_hosted_pe(routine: u64, args: &[u64]) -> u64 {
    assert!(!LOCKED.load(Ordering::Acquire), "callback under spin guard");
    assert_eq!(routine, 19);
    assert_eq!(args, &[13, 0, core::ptr::addr_of!(TOKEN) as u64, 23]);
    ACTION.load(Ordering::Acquire) as u64
}
"#;

const CASES: &str = r#"
fn setup() -> Vec<u64> {
    LOCKED.store(false, Ordering::Release);
    RETIRE_SUCCEEDS.store(false, Ordering::Release);
    REPLY_VALID.store(true, Ordering::Release);
    ACTION.store(2, Ordering::Release);
    RETIRES.store(0, Ordering::Relaxed);
    let mut shared = vec![0u64; 64];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    shared
}
fn token() -> u64 { core::ptr::addr_of!(TOKEN) as u64 }
unsafe fn seed_active_map() {
    let record = dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap();
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LOGICAL, 0x1000);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, 64);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_VA, 0x4000);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_KIND, HOSTED_DMA_RECORD_KIND_MAP_TRANSFER);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_SOURCE_VA, 0x5000);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_MAP_REGISTER, token());
    dma_record_store(record, SH_DMA_ALLOC_RECORD_ADAPTER_ID, 7);
    write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 1);
}

#[test]
fn direct_free_with_no_mapping_claims_token_before_uncertain_retirement() {
    let _shared = setup();
    s_dma_free_map_registers(7, token(), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(
        dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap(), SH_DMA_ALLOC_RECORD_LEN) },
        DMA_RECORD_RESERVED);
    assert_eq!(unsafe { dma_record_load(
        dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap(), SH_DMA_ALLOC_RECORD_PENDING_EXTENT) },
        0, "a token-only retirement has no mapped extent");
    s_dma_free_map_registers(7, token(), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1, "uncertain effect was replayed");
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn malformed_success_does_not_clear_or_replay_claim() {
    let _shared = setup();
    unsafe { seed_active_map(); }
    RETIRE_SUCCEEDS.store(true, Ordering::Release);
    REPLY_VALID.store(false, Ordering::Release);
    s_dma_free_map_registers(7, token(), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(
        dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap(), SH_DMA_ALLOC_RECORD_LEN) },
        DMA_RECORD_RESERVED);
    assert_eq!(unsafe { dma_record_load(
        dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap(), SH_DMA_ALLOC_RECORD_PENDING_EXTENT) },
        64, "an uncertain retirement must keep its exact published extent");
    s_dma_free_map_registers(7, token(), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1, "malformed receipt replayed retirement");
}

#[test]
fn authenticated_free_clears_exact_published_mapping_once() {
    let _shared = setup();
    unsafe { seed_active_map(); }
    RETIRE_SUCCEEDS.store(true, Ordering::Release);
    s_dma_free_map_registers(7, token(), 1);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    let record = unsafe { dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap() };
    assert_eq!(unsafe { dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN) }, 0);
    assert_eq!(unsafe { dma_record_load(record, SH_DMA_ALLOC_RECORD_MAP_REGISTER) }, 0);
    assert_eq!(unsafe { dma_record_load(record, SH_DMA_ALLOC_RECORD_ADAPTER_ID) }, 0);
    assert_eq!(unsafe { dma_record_load(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT) }, 0);
    s_dma_free_map_registers(7, token(), 1);
    assert!(RETIRES.load(Ordering::Relaxed) <= 2,
        "stale token retried retirement beyond the authenticated no-effect");
    assert!((0..2).all(|index| unsafe {
        dma_record_load(dma_allocation_record(FSD_SHARED_VADDR, index).unwrap(),
            SH_DMA_ALLOC_RECORD_LEN) == 0
    }), "stale-token no-effect must not leave a reserved local slot");
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn adapter_action2_claims_token_before_uncertain_retirement() {
    let _shared = setup();
    assert_eq!(s_dma_allocate_adapter_channel(7, 13, 1, 19, 23), 0);
    assert_eq!(RETIRES.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(
        dma_allocation_record(FSD_SHARED_VADDR, 0).unwrap(), SH_DMA_ALLOC_RECORD_LEN) },
        DMA_RECORD_RESERVED);
    assert!(!LOCKED.load(Ordering::Acquire));
}
"#;
