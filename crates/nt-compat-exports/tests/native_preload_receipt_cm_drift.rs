//! A completed resident boot source closure survives unrelated SYSTEM hive publications.

use std::process::Command;

#[test]
fn native_preload_receipt_tracks_source_and_pool_identity_across_cm_writes() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_driver_preload.rs");
    let resident = item(source, "fn resident_catalog_receipt_is_valid", "\npub(crate) unsafe fn receipt_is_current");
    let valid = item(source, "pub(crate) unsafe fn receipt_is_current", "\npub(crate) unsafe fn current_receipt");
    let current = item(source, "pub(crate) unsafe fn current_receipt", "\nstatic mut SOURCES");
    syn::parse_str::<syn::ItemFn>(resident).expect("native pinned receipt validation");
    syn::parse_str::<syn::ItemFn>(valid).expect("native receipt validation");
    syn::parse_str::<syn::ItemFn>(current).expect("native current receipt lookup");

    let harness = format!("{MOCKS}\n{resident}\n{valid}\n{current}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-preload-cm-drift-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
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
    assert!(compiled.status.success(), "native preload fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "native preload receipt regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr));
}

fn item<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let begin = source.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let finish = source[begin..].find(end).unwrap_or_else(|| panic!("missing boundary {end}"));
    // Preserve the real function body; the fixture only supplies its external dependencies.
    &source[begin..begin + finish]
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Fat32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreloadReceipt {
    generation: u64,
    pool_epoch: u64,
    watermark: u64,
    services: usize,
    bytes: u64,
}

struct Catalog {
    complete: bool,
    receipt: Option<PreloadReceipt>,
    generation: u64,
    pool_epoch: u64,
    bytes: u64,
}

impl Catalog {
    fn complete(&self) -> bool { self.complete }
    fn receipt(&self) -> Option<PreloadReceipt> { self.receipt }
    fn generation(&self) -> u64 { self.generation }
    fn pool_epoch(&self) -> u64 { self.pool_epoch }
    fn bytes(&self) -> u64 { self.bytes }
}

static mut SOURCES: Option<Catalog> = None;
static LIVE_CONFIG_MANAGER_SYSTEM_GENERATION: AtomicU64 = AtomicU64::new(0);
static FAIL_REFRESH: AtomicBool = AtomicBool::new(false);
mod fs_loader {
    use std::sync::atomic::AtomicU64;
    pub static POOL_EPOCH: AtomicU64 = AtomicU64::new(0);
    pub static POOL_NEXT: AtomicU64 = AtomicU64::new(0);
    pub unsafe fn exec_fs() -> Option<super::Fat32> { Some(super::Fat32) }
}
mod boot_storage_dma_handoff {
    pub fn boot_disk_reads_admitted() -> bool { true }
}
unsafe fn stage_registry_boot_sources(_fs: &Fat32, generation: u64) -> Option<PreloadReceipt> {
    if FAIL_REFRESH.load(Ordering::Acquire) { return None; }
    let old = SOURCES.as_ref()?.receipt?;
    let refreshed = PreloadReceipt { generation, ..old };
    SOURCES = Some(Catalog {
        complete: true, receipt: Some(refreshed), generation,
        pool_epoch: old.pool_epoch, bytes: old.bytes,
    });
    Some(refreshed)
}
"#;

const CASES: &str = r#"
#[test]
fn unrelated_system_hive_publication_keeps_the_exact_resident_closure() {
    let receipt = PreloadReceipt {
        generation: 2, pool_epoch: 7, watermark: 0x2000, services: 37, bytes: 0x5000,
    };
    unsafe {
        SOURCES = Some(Catalog {
            complete: true, receipt: Some(receipt), generation: 2, pool_epoch: 7,
            bytes: 0x5000,
        });
    }
    fs_loader::POOL_EPOCH.store(7, Ordering::Release);
    fs_loader::POOL_NEXT.store(0x3000, Ordering::Release);
    LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.store(3, Ordering::Release);
    let refreshed = PreloadReceipt { generation: 3, ..receipt };
    assert_eq!(unsafe { current_receipt() }, Some(refreshed));
    assert_eq!(unsafe { SOURCES.as_ref().unwrap().receipt }, Some(refreshed));

    // The same CM drift cannot excuse a changed source catalog or recycled pool pin.
    unsafe { SOURCES.as_mut().unwrap().bytes += 1; }
    assert_eq!(unsafe { current_receipt() }, None);
    unsafe { SOURCES.as_mut().unwrap().bytes = refreshed.bytes; }
    fs_loader::POOL_EPOCH.store(8, Ordering::Release);
    assert_eq!(unsafe { current_receipt() }, None);
    fs_loader::POOL_EPOCH.store(7, Ordering::Release);
    fs_loader::POOL_NEXT.store(refreshed.watermark - 1, Ordering::Release);
    assert_eq!(unsafe { current_receipt() }, None);

    // A failed candidate cannot replace the published receipt.
    fs_loader::POOL_NEXT.store(refreshed.watermark, Ordering::Release);
    LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.store(4, Ordering::Release);
    FAIL_REFRESH.store(true, Ordering::Release);
    assert_eq!(unsafe { current_receipt() }, None);
    assert_eq!(unsafe { SOURCES.as_ref().unwrap().receipt }, Some(refreshed));
}
"#;
