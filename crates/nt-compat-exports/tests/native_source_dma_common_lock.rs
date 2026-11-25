//! Execute the native common-buffer adapters against a provider that checks lock ownership.

use std::process::Command;

#[test]
fn common_buffer_provider_effects_do_not_hold_the_allocation_guard() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("extern \"win64\" fn s_dma_allocate_common_buffer(")
        .expect("native AllocateCommonBuffer");
    let end = source[start..]
        .find("\nunsafe fn dma_active_adapter_and_grant(")
        .expect("following native DMA helper");
    let body = &source[start..start + end];
    let allocate_end = body.find("\n/// `FreeCommonBuffer`").unwrap();
    let free_start = body
        .find("extern \"win64\" fn s_dma_free_common_buffer(")
        .expect("native FreeCommonBuffer");
    syn::parse_str::<syn::ItemFn>(&body[..allocate_end])
        .expect("complete native AllocateCommonBuffer body");
    // Parse the free function without its documentation header.
    let free = &body[free_start..];
    syn::parse_str::<syn::ItemFn>(free).expect("complete native FreeCommonBuffer body");
    let overlap_start = source
        .find("unsafe fn dma_allocation_range_overlaps(")
        .expect("native DMA overlap helper");
    let overlap_end = source[overlap_start..]
        .find("\nunsafe fn first_free_dma_allocation_record(")
        .expect("following native DMA helper");
    let overlap = &source[overlap_start..overlap_start + overlap_end];
    syn::parse_str::<syn::ItemFn>(overlap).expect("complete native DMA overlap helper");
    let host_body = body
        .replacen("extern \"win64\" fn s_dma_allocate_common_buffer(",
                  "extern \"C\" fn s_dma_allocate_common_buffer(", 1)
        .replacen("extern \"win64\" fn s_dma_free_common_buffer(",
                  "extern \"C\" fn s_dma_free_common_buffer(", 1);
    let fixture = format!("{PORTS}\n{overlap}\n{host_body}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-dma-common-lock-{}", std::process::id()
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
    assert!(compiled.status.success(), "native common-buffer fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "native common-buffer lock regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr));
}

const PORTS: &str = r#"
use std::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

fn print_str(_text: &[u8]) {}
fn print_hex_u64(_value: u64) {}

const HOSTED_DMA_COMMON_ALIGNMENT: u64 = 0x1000;
const HOSTED_DMA_RECORD_KIND_COMMON: u64 = 1;
const HOSTED_DMA_RECORD_KIND_MAP_TRANSFER: u64 = 2;
const HOSTED_DMA_SERVICE_REGISTER_COMMON_BUFFER: u64 = 16;
const HOSTED_DMA_SERVICE_FREE_COMMON_BUFFER: u64 = 12;
const HOSTED_DMA_SERVICE_OPERATION_SHIFT: u64 = 56;
const HOSTED_DMA_ADAPTER_LEASE_ID_OFFSET: u64 = 0x38;
const HOSTED_DMA_CONFLICT_RETRY_LIMIT: u32 = 64;
const FSD_SERVICE_DMA_ADAPTER_LABEL: u64 = 1;
const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;
const DMA_RECORD_RESERVED: u64 = u64::MAX;
const SH_DMA_REQUESTED_LEN: u64 = 0x430;
const SH_DMA_ALLOCATED_VA: u64 = 0x438;
const SH_DMA_ALLOCATED_LOGICAL: u64 = 0x440;
const SH_DMA_FREED_LOGICAL: u64 = 0x448;
const SH_DMA_ALLOC_RECORD_COUNT: u64 = 0x6A8;
const SH_DMA_ALLOC_CURSOR: u64 = 0x6A0;
// 0x1248 handoff base + 0x100 support records + 0x858 export scratch
// + 0x2820 work queue arena + 0x820 admission metadata.
const SH_DMA_ALLOC_RECORDS: u64 = 0x4BE0;
const SH_DMA_ALLOC_RECORD_SIZE: u64 = 0x48;
const SH_DMA_ALLOC_RECORD_LOGICAL: u64 = 0;
const SH_DMA_ALLOC_RECORD_LEN: u64 = 8;
const SH_DMA_ALLOC_RECORD_VA: u64 = 16;
const SH_DMA_ALLOC_RECORD_KIND: u64 = 24;
const SH_DMA_ALLOC_RECORD_SOURCE_VA: u64 = 32;
const SH_DMA_ALLOC_RECORD_MAP_REGISTER: u64 = 48;
const SH_DMA_ALLOC_RECORD_ADAPTER_ID: u64 = 56;
const SH_DMA_ALLOC_RECORD_PENDING_EXTENT: u64 = 64;

mod nt_status {
    pub struct NtStatus;
    impl NtStatus {
        pub const CONFLICTING_ADDRESSES: Self = Self;
        pub fn raw(self) -> i32 { 0xC000_0018u32 as i32 }
    }
}
mod provider_bugcheck {
    pub unsafe fn report(_code: u32, _parameters: [u64; 4]) -> ! {
        panic!("unexpected provider refusal")
    }
}

static LOCKED: AtomicBool = AtomicBool::new(false);
static REGISTER_EFFECTS: AtomicUsize = AtomicUsize::new(0);
static FREE_EFFECTS: AtomicUsize = AtomicUsize::new(0);
static REGISTER_SUCCEEDS: AtomicBool = AtomicBool::new(false);
static REGISTER_REPLY_VALID: AtomicBool = AtomicBool::new(true);
static REGISTER_FORGED_CONFLICT: AtomicBool = AtomicBool::new(false);
static mut FSD_SHARED_VADDR: u64 = 0;
static mut ADAPTER: [u64; 8] = [0; 8];
static mut FRESH_ADAPTER: [u64; 8] = [0; 8];

struct HostedDmaAllocationGuard;
impl HostedDmaAllocationGuard {
    fn acquire() -> Self {
        assert!(!LOCKED.swap(true, Ordering::AcqRel), "recursive DMA guard");
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
fn adapter_address() -> u64 { core::ptr::addr_of!(ADAPTER) as u64 }
fn fresh_adapter_address() -> u64 { core::ptr::addr_of!(FRESH_ADAPTER) as u64 }
unsafe fn dma_adapter_metadata(adapter: u64) -> Option<HostedDmaAdapterMetadata> {
    if adapter == adapter_address() {
        Some(HostedDmaAdapterMetadata {
            adapter_id: 7, grant_va: 0x4000_0000, grant_len: 0x100000, grant_logical: 0x1000,
        })
    } else if adapter == fresh_adapter_address() {
        Some(HostedDmaAdapterMetadata {
            adapter_id: 8, grant_va: 0x5000_0000, grant_len: 0x100000, grant_logical: 0x2000,
        })
    } else {
        None
    }
}
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}
fn record(index: u64) -> u64 {
    unsafe { FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORDS + index * SH_DMA_ALLOC_RECORD_SIZE }
}
unsafe fn dma_allocation_record(_sh: u64, index: u64) -> Option<u64> {
    (index < 2).then(|| record(index))
}
unsafe fn dma_allocation_record_capacity(_sh: u64) -> u64 { 2 }
unsafe fn dma_record_load(record: u64, offset: u64) -> u64 {
    read_volatile((record + offset) as *const u64)
}
unsafe fn dma_record_store(record: u64, offset: u64, value: u64) {
    write_volatile((record + offset) as *mut u64, value)
}
unsafe fn begin_dma_allocation_record(record: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "reservation needs the guard");
    let prior = dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, DMA_RECORD_RESERVED);
    if prior != DMA_RECORD_RESERVED {
        dma_record_store(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT, prior);
    }
}
unsafe fn reserve_dma_allocation_pending_extent(record: u64, length: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "pending range needs the guard");
    assert_eq!(dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN), DMA_RECORD_RESERVED);
    assert!(length != 0 && length != DMA_RECORD_RESERVED);
    dma_record_store(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT, length);
}
unsafe fn dma_allocation_record_next_overlap_locked(
    record: u64, adapter_id: u64, grant_logical: u64, offset: u64, length: u64,
) -> Option<u64> {
    assert!(LOCKED.load(Ordering::Acquire), "overlap classification needs the guard");
    if dma_record_load(record, SH_DMA_ALLOC_RECORD_ADAPTER_ID) != adapter_id { return None; }
    let logical = dma_record_load(record, SH_DMA_ALLOC_RECORD_LOGICAL);
    let published = dma_record_load(record, SH_DMA_ALLOC_RECORD_LEN);
    if logical == 0 || published == 0 { return None; }
    let extent = if published == DMA_RECORD_RESERVED {
        dma_record_load(record, SH_DMA_ALLOC_RECORD_PENDING_EXTENT)
    } else { published };
    if extent == 0 || extent == DMA_RECORD_RESERVED { return Some(u64::MAX); }
    let start = logical.checked_sub(grant_logical)?;
    let end = start.checked_add(extent)?;
    let candidate_end = offset.checked_add(length)?;
    (offset < end && start < candidate_end).then_some(end)
}
unsafe fn publish_dma_allocation_record(record: u64, length: u64, _direction: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "publication needs the guard");
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, length)
}
unsafe fn clear_dma_allocation_record(record: u64) {
    assert!(LOCKED.load(Ordering::Acquire), "clear needs the guard");
    for offset in [0, 8, 16, 24, 32, 48, 56, 64] { dma_record_store(record, offset, 0); }
}
unsafe fn first_free_dma_allocation_record(_sh: u64) -> Option<u64> {
    (0..2).map(record).find(|&r| dma_record_load(r, SH_DMA_ALLOC_RECORD_LEN) == 0)
}
unsafe fn dma_root_conflict_next(
    _adapter: u64, _logical: u64, _length: u64,
) -> Result<Option<u64>, ()> {
    assert!(!LOCKED.load(Ordering::Acquire), "read-only root query under spin guard");
    Ok(None)
}
unsafe fn call_on5_raw(
    _label: u64, adapter_or_lease: u64, operation: u64,
    logical_or_adapter: u64, va_or_logical: u64, length: u64,
) -> (u64, u64, u64, u64, u64) {
    assert!(!LOCKED.load(Ordering::Acquire), "provider effect under spin guard");
    if operation >> HOSTED_DMA_SERVICE_OPERATION_SHIFT == HOSTED_DMA_SERVICE_REGISTER_COMMON_BUFFER {
        let metadata = dma_adapter_metadata(adapter_or_lease).unwrap();
        let pending = (0..2).map(record).any(|r| {
            dma_record_load(r, SH_DMA_ALLOC_RECORD_LEN) == DMA_RECORD_RESERVED
                && dma_record_load(r, SH_DMA_ALLOC_RECORD_KIND) == HOSTED_DMA_RECORD_KIND_COMMON
                && dma_record_load(r, SH_DMA_ALLOC_RECORD_ADAPTER_ID) == metadata.adapter_id
                && dma_record_load(r, SH_DMA_ALLOC_RECORD_LOGICAL) == logical_or_adapter
                && dma_record_load(r, SH_DMA_ALLOC_RECORD_VA) == va_or_logical
                && dma_record_load(r, SH_DMA_ALLOC_RECORD_MAP_REGISTER) == 0
                && dma_record_load(r, SH_DMA_ALLOC_RECORD_PENDING_EXTENT) == length
        });
        assert!(pending, "exact local record must be reserved before root registration");
        assert!(read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *const u64) >= 1,
                "root replay high-water mark must include pending claim");
        assert_eq!(length, 4096);
        REGISTER_EFFECTS.fetch_add(1, Ordering::Relaxed);
        // This fixture models call_on5_raw: label zero and four reply words.
        let reply = if REGISTER_REPLY_VALID.load(Ordering::Acquire) { 4 } else { 0 };
        if REGISTER_FORGED_CONFLICT.swap(false, Ordering::AcqRel) {
            (reply, nt_status::NtStatus::CONFLICTING_ADDRESSES.raw() as u32 as u64,
                logical_or_adapter + length, 0, 0)
        } else if REGISTER_SUCCEEDS.load(Ordering::Acquire) {
            (reply, STATUS_SUCCESS as u64, 99, 0, 0)
        } else {
            (reply, STATUS_UNSUCCESSFUL as u32 as u64, 0, 0, 0)
        }
    } else {
        assert_eq!(operation >> HOSTED_DMA_SERVICE_OPERATION_SHIFT,
                   HOSTED_DMA_SERVICE_FREE_COMMON_BUFFER);
        assert_eq!(adapter_or_lease, 88);
        assert_eq!(operation & ((1u64 << HOSTED_DMA_SERVICE_OPERATION_SHIFT) - 1), 99);
        assert_eq!((logical_or_adapter, va_or_logical, length), (8, 0x2000, 4096));
        assert_eq!(dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN), DMA_RECORD_RESERVED);
        FREE_EFFECTS.fetch_add(1, Ordering::Relaxed);
        (4, STATUS_SUCCESS as u64, 0, 0, 0)
    }
}
"#;

const CASES: &str = r#"
unsafe fn seed_reserved_map(logical: u64, extent: u64) {
    let _guard = HostedDmaAllocationGuard::acquire();
    let row = record(0);
    begin_dma_allocation_record(row);
    dma_record_store(row, SH_DMA_ALLOC_RECORD_LOGICAL, logical);
    dma_record_store(row, SH_DMA_ALLOC_RECORD_VA, 0x4000_0000 + logical - 0x1000);
    dma_record_store(row, SH_DMA_ALLOC_RECORD_KIND, HOSTED_DMA_RECORD_KIND_MAP_TRANSFER);
    dma_record_store(row, SH_DMA_ALLOC_RECORD_SOURCE_VA, 0x5000_0000);
    dma_record_store(row, SH_DMA_ALLOC_RECORD_MAP_REGISTER, 0x7000);
    dma_record_store(row, SH_DMA_ALLOC_RECORD_ADAPTER_ID, 7);
    if extent != 0 { reserve_dma_allocation_pending_extent(row, extent); }
    write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 1);
}

#[test]
fn reserved_map_blocks_its_range_without_starving_other_common_allocations() {
    REGISTER_EFFECTS.store(0, Ordering::Relaxed);
    REGISTER_REPLY_VALID.store(true, Ordering::Release);
    REGISTER_SUCCEEDS.store(true, Ordering::Release);
    REGISTER_FORGED_CONFLICT.store(false, Ordering::Release);
    let mut shared = vec![0u64; 4096];
    unsafe {
        FSD_SHARED_VADDR = shared.as_mut_ptr() as u64;
        seed_reserved_map(0x2000, 2056);
    }
    let mut logical = 0i64;
    assert_eq!(s_dma_allocate_common_buffer(adapter_address(), 4096, &mut logical, 0),
        0x4000_0000, "a separate grant slice remains available");
    assert_eq!(logical, 0x1000);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) },
        DMA_RECORD_RESERVED, "allocation must retain the uncertain map");
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 1);

    let mut overlapping = vec![0u64; 4096];
    unsafe {
        FSD_SHARED_VADDR = overlapping.as_mut_ptr() as u64;
        seed_reserved_map(0x1000, 2056);
    }
    assert_eq!(s_dma_allocate_common_buffer(adapter_address(), 4096, &mut logical, 0),
        0x4000_1000, "an overlapping range must advance past the pending map");
    assert_eq!(logical, 0x2000);
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 2);

    let mut unknown = vec![0u64; 4096];
    unsafe {
        FSD_SHARED_VADDR = unknown.as_mut_ptr() as u64;
        seed_reserved_map(0x1000, 0);
    }
    assert_eq!(s_dma_allocate_common_buffer(adapter_address(), 4096, &mut logical, 0), 0,
        "an unknown pending extent must still block the grant");
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 2,
        "unknown ownership cannot reach the provider");
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn authenticated_conflict_recycles_only_its_unclaimed_slot() {
    let mut shared = vec![0u64; 4096];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    REGISTER_EFFECTS.store(0, Ordering::Relaxed);
    REGISTER_REPLY_VALID.store(true, Ordering::Release);
    REGISTER_SUCCEEDS.store(true, Ordering::Release);
    REGISTER_FORGED_CONFLICT.store(true, Ordering::Release);
    let mut logical = 0i64;
    assert_eq!(s_dma_allocate_common_buffer(adapter_address(), 4096, &mut logical, 0),
        0x4000_1000);
    assert_eq!(logical, 0x2000);
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 2);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) }, 4096);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_MAP_REGISTER) }, 0);
}

#[test]
fn malformed_root_reply_cannot_publish_or_clear_a_pending_claim() {
    let mut shared = vec![0u64; 4096];
    unsafe { FSD_SHARED_VADDR = shared.as_mut_ptr() as u64; }
    REGISTER_EFFECTS.store(0, Ordering::Relaxed);
    REGISTER_REPLY_VALID.store(false, Ordering::Release);
    REGISTER_SUCCEEDS.store(true, Ordering::Release);
    REGISTER_FORGED_CONFLICT.store(false, Ordering::Release);
    let mut logical = 0i64;
    assert_eq!(s_dma_allocate_common_buffer(adapter_address(), 4096, &mut logical, 0), 0);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
    assert_eq!(logical, 0);

    REGISTER_FORGED_CONFLICT.store(true, Ordering::Release);
    assert_eq!(s_dma_allocate_common_buffer(adapter_address(), 4096, &mut logical, 0), 0);
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 2);
    assert_eq!(unsafe { dma_record_load(record(1), SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
    assert!(!LOCKED.load(Ordering::Acquire));
}

#[test]
fn uncertain_registration_stays_reserved_and_successful_free_clears_once() {
    let mut shared = vec![0u64; 4096];
    REGISTER_EFFECTS.store(0, Ordering::Relaxed);
    FREE_EFFECTS.store(0, Ordering::Relaxed);
    REGISTER_REPLY_VALID.store(true, Ordering::Release);
    REGISTER_FORGED_CONFLICT.store(false, Ordering::Release);
    REGISTER_SUCCEEDS.store(false, Ordering::Release);
    unsafe {
        FSD_SHARED_VADDR = shared.as_mut_ptr() as u64;
        ADAPTER[7] = 77;
        FRESH_ADAPTER[7] = 88;
    }
    let adapter = adapter_address();
    let mut logical = 0i64;
    assert_eq!(s_dma_allocate_common_buffer(adapter, 4096, &mut logical, 0), 0);
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
    assert!(!LOCKED.load(Ordering::Acquire));

    // The uncertain claim owns only its requested range. A second allocation on the
    // same adapter may use the adjacent range without replaying the first effect.
    REGISTER_SUCCEEDS.store(true, Ordering::Release);
    assert_eq!(s_dma_allocate_common_buffer(adapter, 4096, &mut logical, 0), 0x4000_1000);
    assert_eq!(logical, 0x2000);
    assert_eq!(REGISTER_EFFECTS.load(Ordering::Relaxed), 2);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) }, DMA_RECORD_RESERVED);
    assert_eq!(unsafe { dma_record_load(record(1), SH_DMA_ALLOC_RECORD_LEN) }, 4096);

    // A new independent projection models a fresh adapter generation; the
    // uncertain first projection remains allocated until its owner retires.
    let mut fresh = vec![0u64; 4096];
    unsafe { FSD_SHARED_VADDR = fresh.as_mut_ptr() as u64; }
    let adapter = fresh_adapter_address();
    assert_eq!(s_dma_allocate_common_buffer(adapter, 4096, &mut logical, 0), 0x5000_0000);
    assert_eq!(logical, 0x2000);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) }, 4096);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_SOURCE_VA) }, 99);
    s_dma_free_common_buffer(adapter, 4096, logical, 0x5000_0000, 0);
    assert_eq!(FREE_EFFECTS.load(Ordering::Relaxed), 1);
    assert_eq!(unsafe { dma_record_load(record(0), SH_DMA_ALLOC_RECORD_LEN) }, 0);
    s_dma_free_common_buffer(adapter, 4096, logical, 0x5000_0000, 0);
    assert_eq!(FREE_EFFECTS.load(Ordering::Relaxed), 1);
    assert!(!LOCKED.load(Ordering::Acquire));
}
"#;
