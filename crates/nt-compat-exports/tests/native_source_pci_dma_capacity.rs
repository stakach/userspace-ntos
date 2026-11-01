//! Exercise the native PCI DMA capacity and the real common-buffer allocation bound.

use std::process::Command;

#[test]
fn pci_dma_apertures_fit_libernt_storport_common_buffer() {
    let executive = include_str!("../../../components/ntos-executive/src/main.rs");
    let handoff = include_str!("../../../components/ntos-executive/src/boot_storage_dma_handoff.rs");
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let constants = [
        constant(executive, "AHCI_BOOT_DMA_PAGES"),
        constant(executive, "AHCI_IOVA"),
        constant(executive, "HOSTED_PCI_DMA_WINDOW_IOVA"),
        constant(executive, "HOSTED_PCI_DMA_WINDOW_PAGES"),
        constant(executive, "HOSTED_PCI_DMA_WINDOW_LEN"),
        constant(handoff, "HOSTED_BOOT_AHCI_IOVA"),
    ];
    let start = driver
        .find("extern \"win64\" fn s_dma_allocate_common_buffer(")
        .expect("native common-buffer allocator");
    let end = driver[start..]
        .find("\n/// `FreeCommonBuffer`")
        .expect("next native allocator function");
    let allocate = &driver[start..start + end];
    syn::parse_str::<syn::ItemFn>(allocate).expect("complete native common-buffer allocator");
    // The fixture executes on the host, where the Windows x64 ABI is unavailable on macOS.
    // Change only the ABI declaration; the allocation body remains the production function.
    let host_allocate = allocate.replacen(
        "extern \"win64\" fn s_dma_allocate_common_buffer(",
        "extern \"C\" fn s_dma_allocate_common_buffer(",
        1,
    );

    let harness = format!("{}\n{PORTS}\n{host_allocate}\n{CASES}", constants.join("\n"));
    let directory = std::env::temp_dir().join(format!(
        "nt-source-pci-dma-capacity-{}",
        std::process::id()
    ));
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
        "native PCI DMA fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native PCI DMA regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn constant<'a>(source: &'a str, name: &str) -> &'a str {
    source
        .lines()
        .find(|line| line.contains(&format!("const {name}:")))
        .unwrap_or_else(|| panic!("native constant {name}"))
}

const PORTS: &str = r#"
use std::ptr::{read_volatile, write_unaligned, write_volatile};

const HOSTED_DMA_COMMON_ALIGNMENT: u64 = 64;
const HOSTED_DMA_RECORD_KIND_COMMON: u64 = 1;
const SH_DMA_REQUESTED_LEN: u64 = 0;
const SH_DMA_ALLOCATED_VA: u64 = 8;
const SH_DMA_ALLOCATED_LOGICAL: u64 = 16;
const SH_DMA_ALLOC_RECORD_COUNT: u64 = 24;
const SH_DMA_ALLOC_CURSOR: u64 = 32;
const SH_DMA_ALLOC_RECORDS: u64 = 512;
const SH_DMA_ALLOC_RECORD_SIZE: u64 = 128;
const SH_DMA_ALLOC_RECORD_LOGICAL: u64 = 0;
const SH_DMA_ALLOC_RECORD_LEN: u64 = 8;
const SH_DMA_ALLOC_RECORD_VA: u64 = 16;
const SH_DMA_ALLOC_RECORD_KIND: u64 = 24;
const SH_DMA_ALLOC_RECORD_SOURCE_VA: u64 = 32;
const SH_DMA_ALLOC_RECORD_FLAGS: u64 = 40;
const SH_DMA_ALLOC_RECORD_MAP_REGISTER: u64 = 48;
const SH_DMA_ALLOC_RECORD_ADAPTER_ID: u64 = 56;
const FSD_SERVICE_DMA_ADAPTER_LABEL: u64 = 1;
const HOSTED_DMA_SERVICE_REGISTER_COMMON_BUFFER: u64 = 16;
const HOSTED_DMA_SERVICE_OPERATION_SHIFT: u64 = 56;
const HOSTED_DMA_CONFLICT_RETRY_LIMIT: u32 = 64;
const DMA_RECORD_RESERVED: u64 = u64::MAX;
const STATUS_SUCCESS: i32 = 0;

mod nt_status {
    pub struct NtStatus;
    impl NtStatus {
        pub const CONFLICTING_ADDRESSES: Self = Self;
        pub fn raw(self) -> i32 { 0xC0000018u32 as i32 }
    }
}

struct HostedDmaAllocationGuard;
impl HostedDmaAllocationGuard { fn acquire() -> Self { Self } }

static mut FSD_SHARED_VADDR: u64 = 0;
static mut GRANT_LEN: u64 = 0;

struct HostedDmaAdapterMetadata {
    adapter_id: u64,
    grant_va: u64,
    grant_len: u64,
    grant_logical: u64,
}
fn dma_adapter_metadata(adapter: u64) -> Option<HostedDmaAdapterMetadata> {
    if adapter != 7 { return None; }
    Some(HostedDmaAdapterMetadata {
        adapter_id: 7,
        grant_va: 0x4000_0000,
        grant_len: unsafe { GRANT_LEN },
        grant_logical: 0x1000,
    })
}
fn first_free_dma_allocation_record(base: u64) -> Option<u64> {
    for index in 0..2 {
        let record = base + SH_DMA_ALLOC_RECORDS + index * SH_DMA_ALLOC_RECORD_SIZE;
        if unsafe { read_volatile((record + SH_DMA_ALLOC_RECORD_LOGICAL) as *const u64) } == 0 {
            return Some(record);
        }
    }
    None
}
fn begin_dma_allocation_record(record: u64) {
    unsafe { write_volatile((record + SH_DMA_ALLOC_RECORD_LEN) as *mut u64, DMA_RECORD_RESERVED) }
}
fn dma_record_store(record: u64, offset: u64, value: u64) {
    unsafe { write_volatile((record + offset) as *mut u64, value) }
}
fn publish_dma_allocation_record(record: u64, length: u64, _direction: u64) {
    dma_record_store(record, SH_DMA_ALLOC_RECORD_LEN, length)
}
fn dma_root_conflict_next(_adapter: u64, _logical: u64, _length: u64) -> Result<Option<u64>, ()> {
    Ok(None)
}
fn call_on5(_label: u64, adapter: u64, operation: u64, logical: u64, va: u64, length: u64) -> (u64, u64, u64, u64, u64) {
    assert_eq!(adapter, 7);
    assert_eq!(operation, HOSTED_DMA_SERVICE_REGISTER_COMMON_BUFFER << HOSTED_DMA_SERVICE_OPERATION_SHIFT);
    assert!(logical >= 0x1000 && logical + length <= 0x1000 + unsafe { GRANT_LEN });
    assert_eq!(va, 0x4000_0000 + logical - 0x1000);
    (0, STATUS_SUCCESS as u64, logical, 0, 0)
}
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}
fn dma_allocation_range_overlaps(base: u64, adapter_id: u64, grant_logical: u64, offset: u64, length: u64) -> Option<u64> {
    let end = offset.checked_add(length)?;
    for index in 0..2 {
        let record = base + SH_DMA_ALLOC_RECORDS + index * SH_DMA_ALLOC_RECORD_SIZE;
        let logical = unsafe { read_volatile((record + SH_DMA_ALLOC_RECORD_LOGICAL) as *const u64) };
        if logical == 0 || unsafe { read_volatile((record + SH_DMA_ALLOC_RECORD_ADAPTER_ID) as *const u64) } != adapter_id { continue; }
        let prior_offset = logical.checked_sub(grant_logical)?;
        let prior_len = unsafe { read_volatile((record + SH_DMA_ALLOC_RECORD_LEN) as *const u64) };
        let prior_end = prior_offset.checked_add(prior_len)?;
        if offset < prior_end && prior_offset < end { return Some(prior_end); }
    }
    None
}
"#;

const CASES: &str = r#"
const STORPORT_COMMON_BUFFER_LEN: u64 = 1024 * 1024;
const PRIOR_ALLOCATION_LEN: u64 = 4096;
const IOPT_LEAF_END: u64 = 0x20_0000;

#[test]
fn both_device_apertures_cover_storport_and_stay_in_one_iopt_leaf() {
    assert!(HOSTED_PCI_DMA_WINDOW_LEN >= STORPORT_COMMON_BUFFER_LEN + PRIOR_ALLOCATION_LEN);
    assert_eq!(HOSTED_PCI_DMA_WINDOW_LEN, HOSTED_PCI_DMA_WINDOW_PAGES * 0x1000);
    assert!(HOSTED_PCI_DMA_WINDOW_IOVA > 0);
    assert!(HOSTED_BOOT_AHCI_IOVA >= AHCI_IOVA + AHCI_BOOT_DMA_PAGES * 0x1000);
    for start in [HOSTED_PCI_DMA_WINDOW_IOVA, HOSTED_BOOT_AHCI_IOVA] {
        assert!(start.checked_add(HOSTED_PCI_DMA_WINDOW_LEN).unwrap() <= IOPT_LEAF_END);
    }
}

#[test]
fn native_allocator_accepts_exact_grant_and_rejects_oversized_request() {
    let mut shared = vec![0u64; 256];
    unsafe {
        FSD_SHARED_VADDR = shared.as_mut_ptr() as u64;
        GRANT_LEN = HOSTED_PCI_DMA_WINDOW_LEN;
    }
    let mut logical = 0i64;
    assert_eq!(s_dma_allocate_common_buffer(7, (HOSTED_PCI_DMA_WINDOW_LEN + 1) as u32, &mut logical, 0), 0);
    assert_eq!(logical, 0);
    assert_eq!(s_dma_allocate_common_buffer(7, PRIOR_ALLOCATION_LEN as u32, &mut logical, 0), 0x4000_0000);
    assert_eq!(logical, 0x1000);
    assert_eq!(s_dma_allocate_common_buffer(7, STORPORT_COMMON_BUFFER_LEN as u32, &mut logical, 0), 0x4000_0000 + PRIOR_ALLOCATION_LEN);
    assert_eq!(logical, 0x1000 + PRIOR_ALLOCATION_LEN as i64);
    assert_eq!(shared[(SH_DMA_ALLOC_RECORDS + SH_DMA_ALLOC_RECORD_SIZE + SH_DMA_ALLOC_RECORD_LEN) as usize / 8], STORPORT_COMMON_BUFFER_LEN);
}
"#;
