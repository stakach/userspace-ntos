//! Path attribute syscalls must not re-enter synchronous boot FAT after native handoff.

use std::process::Command;

fn production_attribute_methods() -> String {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = source.find("    unsafe fn nt_query_attributes_file_service(")
        .expect("production NtQueryAttributesFile service");
    let end = source[start..].find("\n    unsafe fn publish_file_create_result(")
        .expect("end of production attribute services");
    source[start..start + end].to_owned()
}

#[test]
fn absolute_attribute_queries_wait_for_native_mounted_route() {
    let methods = production_attribute_methods();
    let harness = [r#"
#![allow(dead_code, unused_unsafe, static_mut_refs)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static NATIVE: AtomicBool = AtomicBool::new(false);
static JOURNAL_OWNS: AtomicBool = AtomicBool::new(false);
static FAT_READS: AtomicUsize = AtomicUsize::new(0);
static NATIVE_ROUTES: AtomicUsize = AtomicUsize::new(0);
static mut NT_QUERY_ATTR_FOLDED_SCRATCH: [u8; 512] = [0; 512];
static mut NT_QUERY_ATTR_RELATIVE_SCRATCH: [u8; 512] = [0; 512];
const NAMED_OBJECT_PATH_CAP: usize = 512;
const FILE_OBJECT_NAME_CAP: usize = 512;
const STATUS_DEVICE_NOT_READY: u32 = 0xc000_00a3;

mod nt_fs {
    pub const DIRECTORY_OPEN_PATH_CAP: usize = 1024;
    pub const STATUS_SUCCESS: u32 = 0;
    pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
    pub const FILE_BASIC_INFORMATION: u32 = 4;
    pub const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;
    #[derive(Clone, Copy)] pub struct FileMetadata;
}

mod smss_attribute_probe_trace {
    pub fn trace_smss_attribute_candidate(_: usize, _: u64, _: &[u16], _: bool) {}
}

mod writable_fs {
    use crate::{nt_fs, JOURNAL_OWNS};
    use std::sync::atomic::Ordering;
    pub mod registry_journal {
        pub fn owns_volume() -> bool {
            crate::JOURNAL_OWNS.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    pub fn writable_path_into(_: &[u16], _: &mut [u8], _: &mut [u8]) -> Option<usize> {
        Some(0)
    }
    pub fn volume_path_into(_: &[u16], _: &mut [u8], _: &mut [u8]) -> Option<usize> {
        Some(0)
    }
    pub fn query_metadata_relative(_: &[u8]) -> Result<Option<nt_fs::FileMetadata>, u32> {
        Ok(None)
    }
    pub fn query_metadata_relative_if_mounted(_: &[u8])
        -> Result<Option<nt_fs::FileMetadata>, u32> {
        if JOURNAL_OWNS.load(Ordering::SeqCst) { Err(0x8000_0011) }
        else { Ok(None) }
    }
}

mod fs_loader {
    use crate::{nt_fs, FAT_READS, NATIVE};
    use std::sync::atomic::Ordering;
    pub fn query_nt_path_metadata_into(name: &[u16], _: &mut [u8], _: &mut [u8])
        -> Option<nt_fs::FileMetadata> {
        let expected: Vec<u16> = r"\??\C:\Windows\bin\autochk.exe".encode_utf16().collect();
        assert_eq!(name, expected, "the test must traverse the actual installed-file name");
        if NATIVE.load(Ordering::SeqCst) {
            FAT_READS.fetch_add(1, Ordering::SeqCst);
        }
        Some(nt_fs::FileMetadata)
    }
}

#[derive(Clone, Copy)]
enum FileParseRoot {
    Absolute,
    FatDirectory { first_cluster: u32, object_id: u32 },
    OverlayFile(u64),
    HostedFile { file_id: u64, device_id: u64 },
    NonDirectoryFile,
    ObjectDirectory { index: usize },
}
struct DirectoryOpen;
impl DirectoryOpen { fn volume_relative_path(&self) -> &[u8] { b"Windows" } }
struct DirectoryOpens;
impl DirectoryOpens {
    fn get(&self, _: u32) -> Result<&DirectoryOpen, u32> { Err(0xc000_0008) }
}
struct CapturedFileObjectAttributes { name: Vec<u16>, attributes: u32 }
impl CapturedFileObjectAttributes { fn name(&self) -> &[u16] { &self.name } }
struct Registry;
impl Registry { fn resolve_name(&self, _: &[u8]) -> Option<usize> { None } }
static REGISTRY: Registry = Registry;
#[derive(Clone, Copy)] struct LoopCtx { reg: *const Registry }
enum LoaderOp { QueryAttributesFile }
unsafe fn loader_trace_record(_: usize, _: LoaderOp, _: u32, _: Option<usize>, _: u64,
    _: u64, _: &[u8]) {}
fn trace_sync_fat_after_handoff(_: usize, _: &[u8], _: usize, _: u64,
    _: Option<(u32, u32, &[u8])>, _: &[u16]) {}
fn print_str(_: &[u8]) {}
fn debug_put_char(_: u8) {}

struct ExecNtHandler {
    loop_ctx: Option<LoopCtx>,
    directory_opens: DirectoryOpens,
    pi: usize,
    current_tid: u64,
}
impl ExecNtHandler {
    fn mounted_target_for_legacy_fat_child(&self, _: FileParseRoot, _: &[u16], _: &mut [u16])
        -> Result<Option<(u64, usize)>, u32> {
        panic!("absolute attribute query reached legacy directory target")
    }
    unsafe fn query_mounted_attributes_on_target(&mut self, _: u64, _: &[u16], _: u32,
        _: u32, _: u64) -> Option<u32> {
        panic!("absolute attribute query reached relative target")
    }
    fn query_native_mounted_attributes(&mut self, name: &[u16], _: u32, class: u32, _: u64)
        -> Option<u32> {
        if !NATIVE.load(Ordering::SeqCst) { return None; }
        assert_eq!(name, r"\??\C:\Windows\bin\autochk.exe".encode_utf16().collect::<Vec<_>>());
        assert!(class == nt_fs::FILE_BASIC_INFORMATION
            || class == nt_fs::FILE_NETWORK_OPEN_INFORMATION);
        NATIVE_ROUTES.fetch_add(1, Ordering::SeqCst);
        Some(0x103)
    }
    unsafe fn capture_file_object_attributes(&self, _: u64)
        -> Result<CapturedFileObjectAttributes, u32> {
        Ok(CapturedFileObjectAttributes {
            name: r"\??\C:\Windows\bin\autochk.exe".encode_utf16().collect(),
            attributes: 0x40,
        })
    }
    fn resolve_file_parse_root(&self, _: &CapturedFileObjectAttributes)
        -> Result<FileParseRoot, u32> { Ok(FileParseRoot::Absolute) }
    fn normalize_object_directory_file_name<'a>(&self, root: FileParseRoot,
        name: &'a [u16], _: &mut [u8], _: &mut [u16])
        -> Result<(FileParseRoot, &'a [u16]), u32> { Ok((root, name)) }
    unsafe fn query_local_file_relative(&self, _: FileParseRoot, _: &[u16])
        -> Result<nt_fs::FileMetadata, u32> { panic!("absolute test reached relative lookup") }
    unsafe fn write_file_basic_information(&mut self, _: u64, _: nt_fs::FileMetadata)
        -> bool { true }
    unsafe fn write_file_network_open_information(&mut self, _: u64, _: nt_fs::FileMetadata)
        -> bool { true }
"#, &methods, r#"
}

fn handler() -> ExecNtHandler {
    ExecNtHandler {
        loop_ctx: Some(LoopCtx { reg: &REGISTRY }),
        directory_opens: DirectoryOpens,
        pi: 3,
        current_tid: 17,
    }
}

#[test]
fn basic_attributes_do_not_read_boot_fat_after_native_handoff() {
    let _guard = TEST_LOCK.lock().unwrap();
    NATIVE.store(true, Ordering::SeqCst);
    FAT_READS.store(0, Ordering::SeqCst);
    NATIVE_ROUTES.store(0, Ordering::SeqCst);
    let status = unsafe { handler().nt_query_attributes_file_service(&[0, 0]) };
    assert!(status == 0 || status == 0x103, "unexpected basic status: {status:#x}");
    assert_eq!(FAT_READS.load(Ordering::SeqCst), 0,
        "NtQueryAttributesFile used synchronous boot FAT after Native handoff");
    assert_eq!(NATIVE_ROUTES.load(Ordering::SeqCst), 1);
}

#[test]
fn full_attributes_do_not_read_boot_fat_after_native_handoff() {
    let _guard = TEST_LOCK.lock().unwrap();
    NATIVE.store(true, Ordering::SeqCst);
    FAT_READS.store(0, Ordering::SeqCst);
    NATIVE_ROUTES.store(0, Ordering::SeqCst);
    let status = unsafe { handler().nt_query_full_attributes_file_service(&[0, 0]) };
    assert!(status == 0 || status == 0x103, "unexpected full status: {status:#x}");
    assert_eq!(FAT_READS.load(Ordering::SeqCst), 0,
        "NtQueryFullAttributesFile used synchronous boot FAT after Native handoff");
    assert_eq!(NATIVE_ROUTES.load(Ordering::SeqCst), 1);
}

#[test]
fn journal_owned_absolute_attributes_route_before_busy_overlay_probe() {
    let _guard = TEST_LOCK.lock().unwrap();
    NATIVE.store(true, Ordering::SeqCst);
    JOURNAL_OWNS.store(true, Ordering::SeqCst);
    NATIVE_ROUTES.store(0, Ordering::SeqCst);
    FAT_READS.store(0, Ordering::SeqCst);
    let basic = unsafe { handler().nt_query_attributes_file_service(&[0, 0]) };
    let full = unsafe { handler().nt_query_full_attributes_file_service(&[0, 0]) };
    JOURNAL_OWNS.store(false, Ordering::SeqCst);
    assert_eq!((basic, full), (0x103, 0x103));
    assert_eq!(NATIVE_ROUTES.load(Ordering::SeqCst), 2);
    assert_eq!(FAT_READS.load(Ordering::SeqCst), 0);
}
"#].concat();
    let directory = std::env::temp_dir().join(format!(
        "nt-absolute-attr-handoff-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "actual attribute service fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "absolute attribute handoff regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}
