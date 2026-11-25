//! Exercise the native MapTransfer body against an uncertain DMA provider effect.

use std::process::Command;

#[test]
fn map_transfer_releases_spin_guard_and_fences_uncertain_replay() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let decoded_start = source
        .find("pub(crate) unsafe fn call_on5(")
        .expect("production decoded five-word transport");
    let decoded_end = source[decoded_start..]
        .find("\n/// Keep the complete reply MessageInfo")
        .expect("following raw transport") + decoded_start;
    let decoded = &source[decoded_start..decoded_end];
    syn::parse_str::<syn::ItemFn>(decoded).expect("complete decoded transport");
    let start = source
        .find("extern \"win64\" fn s_dma_map_transfer(")
        .expect("native MapTransfer");
    let end = source[start..]
        .find("\nunsafe fn dma_find_map_record(")
        .expect("following native map-record helper");
    let body = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(body).expect("complete native MapTransfer body");
    // A normal Rust ABI lets the deliberately failing provider assertion unwind.
    let host_body = body.replacen(
        "extern \"win64\" fn s_dma_map_transfer(",
        "fn s_dma_map_transfer(",
        1,
    );
    let fixture = format!("{PORTS}\n{decoded}\n{host_body}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-dma-map-transfer-lock-{}",
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
        "native DMA fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native MapTransfer regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = -1;
const STATUS_INVALID_DEVICE_REQUEST: i32 = -2;
const STATUS_INSUFFICIENT_RESOURCES: i32 = -3;
const STATUS_UNCERTAIN_RESULT: i32 = -4;
const FSD_SERVICE_DMA_ADAPTER_LABEL: u64 = 9;
const HOSTED_DMA_SERVICE_OPERATION_SHIFT: u64 = 56;
const HOSTED_DMA_SERVICE_OPERATION_MASK: u64 = 0xff << HOSTED_DMA_SERVICE_OPERATION_SHIFT;
const HOSTED_DMA_SERVICE_PROBE_SCSI_SOURCE: u64 = 15;
const HOSTED_DMA_SERVICE_MAP_TRANSFER: u64 = 8;
const HOSTED_DMA_MAP_REGISTER_SIGNATURE: u64 = 0x4D41_5052_4547_3031;
const HOSTED_DMA_COMMON_ALIGNMENT: u64 = 0x1000;
const HOSTED_DMA_CONFLICT_RETRY_LIMIT: u32 = 64;
const HOSTED_DMA_RECORD_KIND_MAP_TRANSFER: u64 = 2;
const HOSTED_DMA_RECORD_KIND_COHERENT_MAP: u64 = 3;
const DMA_RECORD_RESERVED: u64 = u64::MAX;
const HOSTED_DMA_RECORD_FLAG_WRITE_TO_DEVICE: u64 = 1;
const SH_DMA_ALLOC_RECORDS: u64 = 0x100;
const SH_DMA_ALLOC_RECORD_SIZE: u64 = 0x50;
const SH_DMA_ALLOC_RECORD_COUNT: u64 = 0x20;
const SH_DMA_ALLOC_CURSOR: u64 = 0x28;
const SH_DMA_ALLOC_RECORD_LOGICAL: u64 = 0;
const SH_DMA_ALLOC_RECORD_LEN: u64 = 0x08;
const SH_DMA_ALLOC_RECORD_VA: u64 = 0x10;
const SH_DMA_ALLOC_RECORD_KIND: u64 = 0x18;
const SH_DMA_ALLOC_RECORD_SOURCE_VA: u64 = 0x20;
const SH_DMA_ALLOC_RECORD_FLAGS: u64 = 0x28;
const SH_DMA_ALLOC_RECORD_MAP_REGISTER: u64 = 0x30;
const SH_DMA_ALLOC_RECORD_ADAPTER_ID: u64 = 0x38;
const SH_DMA_ALLOC_RECORD_PENDING_EXTENT: u64 = 0x40;
const SH_DMA_ALLOC_RECORD_RETIREMENT_EPOCH: u64 = 0x48;

static LOCKED: AtomicBool = AtomicBool::new(false);
static ASSERT_PROVIDER_UNLOCKED: AtomicBool = AtomicBool::new(false);
static CONFLICT_ONCE: AtomicBool = AtomicBool::new(false);
static MAP_CALLS: AtomicUsize = AtomicUsize::new(0);
static MAP_STATUS: AtomicI32 = AtomicI32::new(STATUS_UNCERTAIN_RESULT);
static MAP_REPLY_INFO: AtomicU64 = AtomicU64::new(4);
static MAP_DETAIL0: AtomicU64 = AtomicU64::new(0);
static MAP_DETAIL1: AtomicU64 = AtomicU64::new(0);
static GRANT_VA: AtomicU64 = AtomicU64::new(0x4000_0000);
static HOSTED_DMA_MAP_PUBLISHED_COUNT: AtomicU64 = AtomicU64::new(0);
static mut FSD_SHARED_VADDR: u64 = 0;

struct HostedDmaAllocationGuard;
impl HostedDmaAllocationGuard {
    fn acquire() -> Self {
        assert!(!LOCKED.swap(true, Ordering::AcqRel), "recursive DMA spin guard");
        Self
    }
}
impl Drop for HostedDmaAllocationGuard {
    fn drop(&mut self) { LOCKED.store(false, Ordering::Release); }
}

struct HostedDmaAdapterMetadata {
    adapter_id: u64,
    grant_va: u64,
    grant_len: u64,
    grant_logical: u64,
}
unsafe fn dma_adapter_metadata(adapter: u64) -> Option<HostedDmaAdapterMetadata> {
    (adapter == 7).then_some(HostedDmaAdapterMetadata {
        adapter_id: 7, grant_va: GRANT_VA.load(Ordering::Relaxed), grant_len: 0x3000,
        grant_logical: 0x1000,
    })
}
unsafe fn dma_mdl_transfer_window(mdl: u64, current_va: u64, requested: u64) -> Option<(u64, u64)> {
    (mdl == 17 && current_va == 0x5000_0000 && requested == 64)
        .then_some((current_va, requested))
}
unsafe fn trace_hosted_dma_sg(
    _: &[u8], _: &[u8], _: i32, _: u64, _: u64, _: u64,
    _: u32, _: u64, _: u64, _: u64,
) {}
unsafe fn trace_dma_record_exhaustion(_: u64, _: u64) {
    panic!("this fixture has a free DMA record; exhaustion is unexpected");
}
unsafe fn call_on5_raw(
    _: u64, adapter: u64, operation: u64, address: u64, backing: u64, length: u64,
) -> (u64, u64, u64, u64, u64) {
    assert_eq!(read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *const u64), 1,
        "root must see pending record before provider IPC");
    if ASSERT_PROVIDER_UNLOCKED.load(Ordering::Acquire) {
        assert!(!LOCKED.load(Ordering::Acquire), "DMA provider IPC under spin guard");
    }
    match operation >> HOSTED_DMA_SERVICE_OPERATION_SHIFT {
        HOSTED_DMA_SERVICE_PROBE_SCSI_SOURCE => {
            assert_eq!(adapter, 0);
            assert_eq!((address, backing, length), (0x5000_0000, 64, 0));
            (4, STATUS_INVALID_DEVICE_REQUEST as u64, 0, 0, 0)
        }
        HOSTED_DMA_SERVICE_MAP_TRANSFER => {
            assert_eq!(adapter, 7);
            let row = FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS;
            assert_eq!(dma_record_load(row, SH_DMA_ALLOC_RECORD_LEN), DMA_RECORD_RESERVED);
            assert_eq!(dma_record_load(row, SH_DMA_ALLOC_RECORD_LOGICAL), address);
            assert_eq!(dma_record_load(row, SH_DMA_ALLOC_RECORD_PENDING_EXTENT), length,
                "the exact attempted range must precede the native map effect");
            let attempt = MAP_CALLS.fetch_add(1, Ordering::Relaxed);
            let expected_logical = if CONFLICT_ONCE.load(Ordering::Relaxed) && attempt > 0 {
                0x2000
            } else {
                0x1000
            };
            assert_eq!((address, backing, length),
                (expected_logical,
                    GRANT_VA.load(Ordering::Relaxed) + expected_logical - 0x1000, 64),
                "a conflict must advance to the next exact root candidate");
            if CONFLICT_ONCE.load(Ordering::Relaxed) && attempt == 0 {
                (MAP_REPLY_INFO.load(Ordering::Relaxed),
                    nt_status::NtStatus::CONFLICTING_ADDRESSES.raw() as u64, 0x2000, 0, 0)
            } else {
                let status = MAP_STATUS.load(Ordering::Relaxed);
                (MAP_REPLY_INFO.load(Ordering::Relaxed),
                    status as u64, if status == STATUS_SUCCESS { 71 } else { 0 },
                    MAP_DETAIL0.load(Ordering::Relaxed), MAP_DETAIL1.load(Ordering::Relaxed))
            }
        }
        other => panic!("unexpected DMA provider operation {other}"),
    }
}
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value.checked_add(alignment - 1).map(|n| n & !(alignment - 1))
}
unsafe fn dma_allocation_range_overlaps(_: u64, _: u64, _: u64, _: u64, _: u64) -> Option<u64> {
    assert!(LOCKED.load(Ordering::Acquire), "local overlap scan needs the allocation guard");
    None
}
unsafe fn dma_root_conflict_next(_: u64, _: u64, _: u64) -> Result<Option<u64>, i32> {
    if ASSERT_PROVIDER_UNLOCKED.load(Ordering::Acquire) {
        assert!(!LOCKED.load(Ordering::Acquire), "DMA conflict IPC under spin guard");
    }
    Ok(None)
}
unsafe fn first_free_dma_allocation_record(sh: u64) -> Option<u64> {
    let record = sh + SH_DMA_ALLOC_RECORDS;
    (dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN) == 0).then_some(record)
}
unsafe fn dma_allocation_record_capacity(_: u64) -> u64 { 1 }
unsafe fn dma_allocation_record(sh: u64, index: u64) -> Option<u64> {
    (index == 0).then_some(sh + SH_DMA_ALLOC_RECORDS)
}
unsafe fn dma_record_load(record: u64, offset: u64) -> u64 {
    read_volatile((record + offset) as *const u64)
}
unsafe fn clear_dma_allocation_record(record: u64) {
    for offset in [SH_DMA_ALLOC_RECORD_LOGICAL, SH_DMA_ALLOC_RECORD_VA,
        SH_DMA_ALLOC_RECORD_KIND, SH_DMA_ALLOC_RECORD_SOURCE_VA,
        SH_DMA_ALLOC_RECORD_MAP_REGISTER, SH_DMA_ALLOC_RECORD_ADAPTER_ID,
        SH_DMA_ALLOC_RECORD_PENDING_EXTENT, SH_DMA_ALLOC_RECORD_RETIREMENT_EPOCH] {
        dma_record_store(record, offset, 0);
    }
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, 0);
}
unsafe fn begin_dma_allocation_record(record: u64) {
    let prior = dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, u64::MAX);
    if prior != DMA_RECORD_RESERVED {
        dma_record_store(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT, prior);
    }
}
unsafe fn reserve_dma_allocation_pending_extent(record: u64, length: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "pending extent needs the allocation guard");
    assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN), DMA_RECORD_RESERVED);
    assert!(length != 0 && length != DMA_RECORD_RESERVED);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT, length);
}
unsafe fn dma_record_store(record: u64, offset: u64, value: u64) {
    write_volatile((record + offset) as *mut u64, value);
}
unsafe fn publish_dma_allocation_record(record: u64, length: u64, flags: u64) {
    dma_record_store(record, SH_DMA_ALLOC_RECORD_FLAGS, flags);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, length);
}
unsafe fn dma_find_map_record(_: u64, map: u64, _: u64) -> Option<u64> {
    let record = FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS;
    (dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN) != 0
        && dma_record_load(record, SH_DMA_ALLOC_RECORD_MAP_REGISTER) == map).then_some(record)
}
unsafe fn dma_copy_bytes(_: u64, _: u64, _: u64) {
    panic!("uncertain map must not copy source bytes");
}
mod nt_status {
    pub struct NtStatus(i32);
    impl NtStatus {
        pub const CONFLICTING_ADDRESSES: Self = Self(-5);
        pub const INVALID_HANDLE: Self = Self(-6);
        pub const DEVICE_BUSY: Self = Self(0x8000_0011u32 as i32);
        pub const INSUFFICIENT_RESOURCES: Self = Self(0xC000_009Au32 as i32);
        pub fn raw(self) -> i32 { self.0 }
    }
}
"#;

const CASES: &str = r#"
fn setup() -> ([u64; 48], [u64; 4]) {
    LOCKED.store(false, Ordering::Release);
    ASSERT_PROVIDER_UNLOCKED.store(false, Ordering::Release);
    CONFLICT_ONCE.store(false, Ordering::Release);
    MAP_CALLS.store(0, Ordering::Relaxed);
    MAP_STATUS.store(STATUS_UNCERTAIN_RESULT, Ordering::Relaxed);
    MAP_REPLY_INFO.store(4, Ordering::Relaxed);
    MAP_DETAIL0.store(0, Ordering::Relaxed);
    MAP_DETAIL1.store(0, Ordering::Relaxed);
    HOSTED_DMA_MAP_PUBLISHED_COUNT.store(0, Ordering::Relaxed);
    GRANT_VA.store(0x4000_0000, Ordering::Relaxed);
    let mut shared = [0u64; 48];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    let mut token = [0u64; 4];
    token[0] = HOSTED_DMA_MAP_REGISTER_SIGNATURE;
    token[2] = 7;
    (shared, token)
}

#[test]
fn provider_ipc_runs_without_allocation_spin_guard() {
    let (mut shared, token) = setup();
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    ASSERT_PROVIDER_UNLOCKED.store(true, Ordering::Release);
    let mut length = 64u32;
    assert_eq!(s_dma_map_transfer(7, 17, token.as_ptr() as u64,
        0x5000_0000, &mut length, 0), 0);
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn decoded_legacy_transport_returns_label_not_reply_length() {
    let (mut shared, _token) = setup();
    unsafe {
        FSD_SHARED_VADDR = shared.as_mut_ptr() as u64;
        write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 1);
        let (label, status, _, _, _) = call_on5(
            (FSD_SERVICE_DMA_ADAPTER_LABEL << 12) | 5,
            0,
            HOSTED_DMA_SERVICE_PROBE_SCSI_SOURCE << HOSTED_DMA_SERVICE_OPERATION_SHIFT,
            0x5000_0000, 64, 0,
        );
        assert_eq!(label, 0);
        assert_eq!(status as i32, STATUS_INVALID_DEVICE_REQUEST);
    }
}

#[test]
fn uncertain_map_keeps_token_claim_and_cannot_replay_provider_effect() {
    let (mut shared, token) = setup();
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    let mut length = 64u32;
    let map = token.as_ptr() as u64;
    assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
    assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(HOSTED_DMA_MAP_PUBLISHED_COUNT.load(Ordering::Relaxed), 0);
    assert_eq!(unsafe { dma_record_load(FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS,
        SH_DMA_ALLOC_RECORD_LEN) }, u64::MAX, "claim must precede uncertain IPC");
    assert_eq!(unsafe { dma_record_load(FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS,
        SH_DMA_ALLOC_RECORD_PENDING_EXTENT) }, 64);
    length = 64;
    assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
    assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1, "uncertain provider effect was replayed");
}

#[test]
fn authenticated_invalid_handle_clears_the_pre_effect_claim() {
    let (mut shared, token) = setup();
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    MAP_STATUS.store(nt_status::NtStatus::INVALID_HANDLE.raw(), Ordering::Relaxed);
    let mut length = 64u32;
    let map = token.as_ptr() as u64;
    assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
    assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS,
        SH_DMA_ALLOC_RECORD_LEN) }, 0, "root rejected token before mapping effect");
}

#[test]
fn malformed_success_keeps_the_pending_claim() {
    let (mut shared, token) = setup();
    let mut grant = [0xA5u8; 0x3000];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    GRANT_VA.store(grant.as_mut_ptr() as u64, Ordering::Relaxed);
    MAP_STATUS.store(STATUS_SUCCESS, Ordering::Relaxed);
    MAP_DETAIL0.store(1, Ordering::Relaxed);
    let mut length = 64u32;
    let map = token.as_ptr() as u64;
    assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
    assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS,
        SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
}

#[test]
fn malformed_raw_reply_keeps_the_pending_claim() {
    for reply_info in [0, (1 << 12) | 4] {
        let (mut shared, token) = setup();
        let mut grant = [0xA5u8; 0x3000];
        unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
        GRANT_VA.store(grant.as_mut_ptr() as u64, Ordering::Relaxed);
        MAP_STATUS.store(STATUS_SUCCESS, Ordering::Relaxed);
        MAP_REPLY_INFO.store(reply_info, Ordering::Relaxed);
        let mut length = 64u32;
        let map = token.as_ptr() as u64;
        assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
        assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(unsafe { dma_record_load(FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS,
            SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
        length = 64;
        assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
        assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn authenticated_pre_effect_pressure_releases_the_claim() {
    for status in [nt_status::NtStatus::DEVICE_BUSY.raw(),
        nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw()] {
        let (mut shared, token) = setup();
        unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
        MAP_STATUS.store(status, Ordering::Relaxed);
        let mut length = 64u32;
        let map = token.as_ptr() as u64;
        assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0);
        assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(unsafe { dma_record_load(FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS,
            SH_DMA_ALLOC_RECORD_LEN) }, 0,
            "authenticated pre-effect refusal should allow a later retry");
    }
}

fn assert_published_map(record: u64, token: u64, logical: u64, bounce_va: u64) {
    unsafe {
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN), 64);
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_LOGICAL), logical);
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_VA), bounce_va);
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_KIND),
            HOSTED_DMA_RECORD_KIND_MAP_TRANSFER);
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_SOURCE_VA), 0x5000_0000);
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_MAP_REGISTER), token);
        assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_ADAPTER_ID), 7);
        assert_eq!(read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *const u64), 1);
    }
}

#[test]
fn authenticated_mapping_publishes_exact_bounce_record() {
    let (mut shared, token) = setup();
    let mut grant = [0xA5u8; 0x3000];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    GRANT_VA.store(grant.as_mut_ptr() as u64, Ordering::Relaxed);
    MAP_STATUS.store(STATUS_SUCCESS, Ordering::Relaxed);
    ASSERT_PROVIDER_UNLOCKED.store(true, Ordering::Release);
    let mut length = 64u32;
    let map = token.as_ptr() as u64;
    assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0x1000);
    assert_eq!(length, 64);
    assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(&grant[..64], &[0u8; 64]);
    assert_eq!(HOSTED_DMA_MAP_PUBLISHED_COUNT.load(Ordering::Relaxed), 1);
    assert_published_map(unsafe { FSD_SHARED_VADDR } + SH_DMA_ALLOC_RECORDS,
        map, 0x1000, grant.as_ptr() as u64);
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn definite_conflict_advances_once_and_publishes_next_exact_mapping() {
    let (mut shared, token) = setup();
    let mut grant = [0xA5u8; 0x3000];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    GRANT_VA.store(grant.as_mut_ptr() as u64, Ordering::Relaxed);
    MAP_STATUS.store(STATUS_SUCCESS, Ordering::Relaxed);
    CONFLICT_ONCE.store(true, Ordering::Release);
    ASSERT_PROVIDER_UNLOCKED.store(true, Ordering::Release);
    let mut length = 64u32;
    let map = token.as_ptr() as u64;
    assert_eq!(s_dma_map_transfer(7, 17, map, 0x5000_0000, &mut length, 0), 0x2000);
    assert_eq!(length, 64);
    assert_eq!(MAP_CALLS.load(Ordering::Relaxed), 2,
        "the rejected candidate must be sent only once");
    assert_eq!(HOSTED_DMA_MAP_PUBLISHED_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(&grant[..64], &[0xA5u8; 64]);
    assert_eq!(&grant[0x1000..0x1040], &[0u8; 64]);
    assert_published_map(unsafe { FSD_SHARED_VADDR } + SH_DMA_ALLOC_RECORDS,
        map, 0x2000, grant.as_ptr() as u64 + 0x1000);
    assert!(!LOCKED.load(Ordering::Acquire));
}
"#;
