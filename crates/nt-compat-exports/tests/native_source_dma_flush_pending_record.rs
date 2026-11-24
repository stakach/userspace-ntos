//! A pending DMA record cannot be consumed as a published transfer mapping.

use std::process::Command;

#[test]
fn flush_rejects_pending_map_record_but_accepts_published_mapping() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("unsafe fn dma_find_map_record(")
        .expect("native map-record lookup");
    let end = source[start..]
        .find("\nextern \"win64\" fn s_dma_free_map_registers(")
        .expect("following native export");
    let body = &source[start..start + end];
    syn::parse_file(body).expect("complete native record lookup and flush body");
    let host_body = body.replacen(
        "extern \"win64\" fn s_dma_flush_adapter_buffers(",
        "fn s_dma_flush_adapter_buffers(",
        1,
    );
    let fixture = format!("{PORTS}\n{host_body}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-dma-flush-pending-record-{}",
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
        "native DMA pending-record regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::ptr::read_volatile;
use std::sync::atomic::{AtomicUsize, Ordering};

const HOSTED_DMA_RECORD_KIND_MAP_TRANSFER: u64 = 2;
const HOSTED_DMA_RECORD_KIND_COHERENT_MAP: u64 = 3;
const DMA_RECORD_RESERVED: u64 = u64::MAX;
const SH_DMA_ALLOC_RECORD_LOGICAL: u64 = 0;
const SH_DMA_ALLOC_RECORD_LEN: u64 = 0x08;
const SH_DMA_ALLOC_RECORD_VA: u64 = 0x10;
const SH_DMA_ALLOC_RECORD_KIND: u64 = 0x18;
const SH_DMA_ALLOC_RECORD_SOURCE_VA: u64 = 0x20;
const SH_DMA_ALLOC_RECORD_MAP_REGISTER: u64 = 0x30;
const SH_DMA_ALLOC_RECORD_ADAPTER_ID: u64 = 0x38;
static COPIES: AtomicUsize = AtomicUsize::new(0);
static mut FSD_SHARED_VADDR: u64 = 0;

struct HostedDmaAdapterMetadata { adapter_id: u64 }
unsafe fn dma_adapter_metadata(adapter: u64) -> Option<HostedDmaAdapterMetadata> {
    (adapter == 7).then_some(HostedDmaAdapterMetadata { adapter_id: 7 })
}
unsafe fn dma_allocation_record_capacity(_: u64) -> u64 { 1 }
unsafe fn dma_allocation_record(sh: u64, index: u64) -> Option<u64> {
    (index == 0).then_some(sh)
}
unsafe fn dma_record_load(record: u64, offset: u64) -> u64 {
    read_volatile((record + offset) as *const u64)
}
unsafe fn dma_copy_bytes(destination: u64, source: u64, length: u64) {
    assert_eq!((destination, source, length), (0x5000, 0x4000, 64));
    COPIES.fetch_add(1, Ordering::Relaxed);
}
"#;

const CASES: &str = r#"
fn record(length: u64) -> [u64; 8] {
    let mut record = [0u64; 8];
    record[(SH_DMA_ALLOC_RECORD_LOGICAL / 8) as usize] = 0x1000;
    record[(SH_DMA_ALLOC_RECORD_LEN / 8) as usize] = length;
    record[(SH_DMA_ALLOC_RECORD_VA / 8) as usize] = 0x4000;
    record[(SH_DMA_ALLOC_RECORD_KIND / 8) as usize] = HOSTED_DMA_RECORD_KIND_MAP_TRANSFER;
    record[(SH_DMA_ALLOC_RECORD_SOURCE_VA / 8) as usize] = 0x5000;
    record[(SH_DMA_ALLOC_RECORD_MAP_REGISTER / 8) as usize] = 41;
    record[(SH_DMA_ALLOC_RECORD_ADAPTER_ID / 8) as usize] = 7;
    record
}

#[test]
fn pending_record_is_not_a_flushable_mapping() {
    COPIES.store(0, Ordering::Relaxed);
    let mut record = record(DMA_RECORD_RESERVED);
    unsafe { FSD_SHARED_VADDR = record.as_mut_ptr() as u64; }
    assert_eq!(s_dma_flush_adapter_buffers(7, 17, 41, 0x5000, 64, 0), 0);
    assert_eq!(COPIES.load(Ordering::Relaxed), 0);
}

#[test]
fn published_record_flushes_the_exact_mapping() {
    COPIES.store(0, Ordering::Relaxed);
    let mut record = record(64);
    unsafe { FSD_SHARED_VADDR = record.as_mut_ptr() as u64; }
    assert_eq!(s_dma_flush_adapter_buffers(7, 17, 41, 0x5000, 64, 0), 1);
    assert_eq!(COPIES.load(Ordering::Relaxed), 1);
}
"#;
