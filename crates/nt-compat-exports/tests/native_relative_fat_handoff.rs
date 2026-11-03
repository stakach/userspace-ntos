//! A legacy directory handle must not issue boot-AHCI FAT reads after native handoff.

use std::process::Command;

fn query_method() -> String {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = source.find("    unsafe fn query_local_file_relative(")
        .expect("production relative metadata query");
    let end = source[start..].find("\n    unsafe fn write_file_basic_information(")
        .expect("end of relative metadata query");
    source[start..start + end].to_owned()
}

fn mounted_target_method() -> String {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = source.find("    fn mounted_target_for_legacy_fat_child(")
        .expect("production legacy directory target policy");
    let end = source[start..].find("\n    fn decode_set_file_name_units(")
        .expect("end of legacy directory target policy");
    source[start..start + end].to_owned()
}

#[test]
fn mounted_target_rejects_stale_mount_generation_and_invalid_child_paths() {
    let method = mounted_target_method();
    let harness = [r#"
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
static MOUNT: AtomicU64 = AtomicU64::new(17);
static ROUTE: AtomicU8 = AtomicU8::new(2);
const FILE_OBJECT_NAME_CAP: usize = 1024;
const STATUS_DEVICE_NOT_READY: u32 = 0xc00000a3;
const STATUS_INVALID_HANDLE: u32 = 0xc0000008;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xc0000033;
mod nt_fs {
    pub const DIRECTORY_OPEN_PATH_CAP: usize = 1024;
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum BlockSourceKind { Boot, Draining, Native }
    pub fn nt_file_relative_path_into(name: &[u16], _: &mut [u8], out: &mut [u8]) -> Option<usize> {
        if name.is_empty() || name[0] == b'\\' as u16 || name.len() > out.len() { return None; }
        let mut length = 0;
        for component in String::from_utf16(name).ok()?.split('\\') {
            if component.is_empty() || component == ".." || component == "." { return None; }
            if length != 0 { out[length] = b'\\'; length += 1; }
            for byte in component.bytes() {
                if !byte.is_ascii() || length >= out.len() { return None; }
                out[length] = byte.to_ascii_lowercase(); length += 1;
            }
        }
        Some(length)
    }
}
mod fs_loader {
    #[derive(Clone, Copy)]
    pub struct Mount(u64);
    impl Mount { pub fn value(self) -> u64 { self.0 } }
    pub unsafe fn exec_fs_mount_identity() -> Option<Mount> {
        Some(Mount(crate::MOUNT.load(std::sync::atomic::Ordering::SeqCst)))
    }
    pub fn exec_block_route_kind(_: Mount) -> Option<crate::nt_fs::BlockSourceKind> {
        Some(match crate::ROUTE.load(std::sync::atomic::Ordering::SeqCst) {
            0 => crate::nt_fs::BlockSourceKind::Boot,
            1 => crate::nt_fs::BlockSourceKind::Draining,
            _ => crate::nt_fs::BlockSourceKind::Native,
        })
    }
}
mod mounted_volume { pub fn exec_volume_device() -> Option<u64> { Some(41) } }
mod driver_launch {
    pub fn require_registered_kernel_filesystem_device(id: u64) -> Result<(), u32> {
        if id == 41 { Ok(()) } else { Err(0xc0000010) }
    }
}
#[derive(Clone, Copy)]
enum FileParseRoot { FatDirectory { first_cluster: u32, object_id: u32 }, Other }
struct DirectoryOpen { first_cluster: u32, mount: u64, path: Vec<u8> }
impl DirectoryOpen {
    fn physical_mount(&self) -> Option<u64> { Some(self.mount) }
    fn volume_relative_path(&self) -> &[u8] { &self.path }
}
struct DirectoryOpens { open: DirectoryOpen }
impl DirectoryOpens {
    fn get(&self, id: u32) -> Result<&DirectoryOpen, u32> {
        if id == 7 { Ok(&self.open) } else { Err(STATUS_INVALID_HANDLE) }
    }
}
struct ExecNtHandler { directory_opens: DirectoryOpens }
impl ExecNtHandler {
    fn capture_relative_file_path(name: &[u16], folded: &mut [u8], out: &mut [u8])
        -> Result<usize, u32> {
        nt_fs::nt_file_relative_path_into(name, folded, out).ok_or(STATUS_OBJECT_NAME_INVALID)
    }
    fn join_volume_relative_path(parent: &[u8], child: &[u8], out: &mut [u8])
        -> Result<usize, u32> {
        let length = parent.len().checked_add(1).and_then(|n| n.checked_add(child.len()))
            .filter(|&n| n <= out.len()).ok_or(STATUS_OBJECT_NAME_INVALID)?;
        out[..parent.len()].copy_from_slice(parent);
        out[parent.len()] = b'\\';
        out[parent.len()+1..length].copy_from_slice(child);
        Ok(length)
    }
"#, &method, r#"
}
#[test]
fn retained_root_policy() {
    let handler = ExecNtHandler { directory_opens: DirectoryOpens { open: DirectoryOpen {
        first_cluster: 12, mount: 17, path: b"windows\\system32".to_vec(),
    } } };
    let mut out = [0u16; nt_fs::DIRECTORY_OPEN_PATH_CAP];
    let child: Vec<u16> = "msgina.dll".encode_utf16().collect();
    let root = FileParseRoot::FatDirectory { first_cluster: 12, object_id: 7 };
    let expected = r"windows\system32\msgina.dll";
    let length = expected.encode_utf16().count();
    assert_eq!(handler.mounted_target_for_legacy_fat_child(root, &child, &mut out), Ok(Some((41, length))));
    assert_eq!(String::from_utf16(&out[..length]).unwrap(), expected);
    ROUTE.store(0, Ordering::SeqCst);
    assert_eq!(handler.mounted_target_for_legacy_fat_child(root, &child, &mut out), Ok(None));
    ROUTE.store(1, Ordering::SeqCst);
    assert_eq!(handler.mounted_target_for_legacy_fat_child(root, &child, &mut out), Ok(Some((41, length))));
    assert_eq!(handler.mounted_target_for_legacy_fat_child(
        FileParseRoot::FatDirectory { first_cluster: 13, object_id: 7 }, &child, &mut out),
        Err(STATUS_INVALID_HANDLE));
    assert_eq!(handler.mounted_target_for_legacy_fat_child(
        FileParseRoot::FatDirectory { first_cluster: 12, object_id: 8 }, &child, &mut out),
        Err(STATUS_INVALID_HANDLE));
    MOUNT.store(18, Ordering::SeqCst);
    assert_eq!(handler.mounted_target_for_legacy_fat_child(root, &child, &mut out),
        Err(STATUS_INVALID_HANDLE));
    MOUNT.store(17, Ordering::SeqCst);
    let traversal: Vec<u16> = r"..\secret".encode_utf16().collect();
    assert_eq!(handler.mounted_target_for_legacy_fat_child(root, &traversal, &mut out),
        Err(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(handler.mounted_target_for_legacy_fat_child(root, &child, &mut out[..4]),
        Err(STATUS_OBJECT_NAME_INVALID));
}
"#].concat();
    let directory = std::env::temp_dir().join(format!(
        "nt-relative-fat-owner-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "retained directory fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "retained directory regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

#[test]
fn legacy_relative_query_cannot_read_boot_fat_after_native_handoff() {
    let method = query_method();
    let harness = [r#"
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static NATIVE: AtomicBool = AtomicBool::new(false);
static FAT_READS: AtomicUsize = AtomicUsize::new(0);
const FILE_OBJECT_NAME_CAP: usize = 256;
const STATUS_INVALID_HANDLE: u32 = 0xc0000008;
const STATUS_DEVICE_NOT_READY: u32 = 0xc00000a3;
const STATUS_NOT_SUPPORTED: u32 = 0xc00000bb;
mod nt_fs {
    pub const DIRECTORY_OPEN_PATH_CAP: usize = 256;
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum BlockSourceKind { Boot, Draining, Native }
    pub const STATUS_NOT_A_DIRECTORY: u32 = 0xc0000103;
    pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc0000034;
    pub const STATUS_INVALID_HANDLE: u32 = 0xc0000008;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FileMetadata;
}
mod writable_fs {
    pub unsafe fn query_metadata_relative_to_directory(_: u64, _: &[u8])
        -> Result<crate::nt_fs::FileMetadata, u32> { Err(0xc0000034) }
    pub fn query_metadata_relative_if_mounted(_: &[u8])
        -> Result<Option<crate::nt_fs::FileMetadata>, u32> { Ok(None) }
}
struct FatEntry { metadata: nt_fs::FileMetadata }
mod fs_loader {
    #[derive(Clone, Copy)]
    pub struct Mount;
    impl Mount { pub fn value(self) -> u64 { 17 } }
    pub unsafe fn exec_fs_mount_identity() -> Option<Mount> { Some(Mount) }
    pub fn exec_block_route_kind(_: Mount) -> Option<crate::nt_fs::BlockSourceKind> {
        Some(if crate::NATIVE.load(std::sync::atomic::Ordering::SeqCst) {
            crate::nt_fs::BlockSourceKind::Native
        } else { crate::nt_fs::BlockSourceKind::Boot })
    }
    pub unsafe fn fat_open_path_metadata_from(_: &u8, _: u32, _: &[u8])
        -> Option<crate::FatEntry> {
        crate::FAT_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(crate::FatEntry { metadata: crate::nt_fs::FileMetadata })
    }
}
fn exec_fs() -> Option<u8> { Some(1) }
fn trace_sync_fat_after_handoff(_: usize, _: &[u8], _: usize, _: u64,
    _: Option<(u32, u32, &[u8])>, _: &[u16]) {}
enum FileParseRoot {
    Absolute, OverlayFile(u64), FatDirectory { first_cluster: u32, object_id: u32 },
    NonDirectoryFile, HostedFile { file_id: u64, device_id: u64 }, ObjectDirectory { index: usize },
}
struct DirectoryOpen { first_cluster: u32, physical_mount: u64 }
impl DirectoryOpen {
    fn volume_relative_path(&self) -> &[u8] { b"windows\\system32" }
    fn physical_mount(&self) -> Option<u64> { Some(self.physical_mount) }
}
struct DirectoryOpens { open: DirectoryOpen }
impl DirectoryOpens {
    fn get(&self, object_id: u32) -> Result<&DirectoryOpen, u32> {
        if object_id == 7 { Ok(&self.open) } else { Err(STATUS_INVALID_HANDLE) }
    }
}
struct ExecNtHandler { directory_opens: DirectoryOpens, pi: usize, current_tid: u64 }
impl ExecNtHandler {
    fn capture_relative_file_path(name: &[u16], _: &mut [u8], output: &mut [u8])
        -> Result<usize, u32> {
        for (i, &unit) in name.iter().enumerate() { output[i] = unit as u8; }
        Ok(name.len())
    }
    fn join_volume_relative_path(parent: &[u8], child: &[u8], output: &mut [u8])
        -> Result<usize, u32> {
        let len = parent.len() + 1 + child.len();
        output[..parent.len()].copy_from_slice(parent);
        output[parent.len()] = b'\\';
        output[parent.len()+1..len].copy_from_slice(child);
        Ok(len)
    }
"#, &method, r#"
}
#[test]
fn old_directory_query_waits_for_native_file_route() {
    let handler = ExecNtHandler { directory_opens: DirectoryOpens {
        open: DirectoryOpen { first_cluster: 12, physical_mount: 17 },
    }, pi: 0, current_tid: 24 };
    NATIVE.store(true, Ordering::SeqCst);
    let name: Vec<u16> = "msgina.dll".encode_utf16().collect();
    let _ = unsafe { handler.query_local_file_relative(
        FileParseRoot::FatDirectory { first_cluster: 12, object_id: 7 }, &name) };
    assert_eq!(FAT_READS.load(Ordering::SeqCst), 0,
        "native handoff cannot call synchronous boot FAT through an old directory handle");
    NATIVE.store(false, Ordering::SeqCst);
    assert!(unsafe { handler.query_local_file_relative(
        FileParseRoot::FatDirectory { first_cluster: 12, object_id: 7 }, &name) }.is_ok());
    assert_eq!(FAT_READS.load(Ordering::SeqCst), 1,
        "Boot route retains its real local FAT reader");
}
"#].concat();
    let directory = std::env::temp_dir().join(format!(
        "nt-relative-fat-handoff-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "actual query fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "legacy relative query regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

#[test]
fn relative_open_callers_must_route_before_legacy_fat_lookup() {
    let open = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let open_service = open.split("unsafe fn nt_open_file_service(").nth(1)
        .expect("native NtOpenFile service");
    let local = open_service.find("self.create_local_file_relative(")
        .expect("legacy relative NtOpenFile path");
    let admission = &open_service[..local];
    assert!(admission.contains("FileParseRoot::FatDirectory")
        && admission.contains("mounted_target_for_legacy_fat_child")
        && admission.contains("create_registered_file_from_target"),
        "NtOpenFile must check the mounted route and legacy parent identity before local FAT lookup");
    let create = include_str!("../../../components/ntos-executive/src/exec_file_create.rs");
    let create_service = create.split("unsafe fn nt_create_file_service(").nth(1)
        .expect("native NtCreateFile service");
    let local = create_service.find("self.create_local_file_relative(")
        .expect("legacy relative NtCreateFile path");
    let admission = &create_service[..local];
    assert!(admission.contains("FileParseRoot::FatDirectory")
        && admission.contains("mounted_target_for_legacy_fat_child")
        && admission.contains("create_registered_file_from_target"),
        "NtCreateFile must check the mounted route and legacy parent identity before local FAT lookup");
}

#[test]
fn relative_attribute_queries_use_mounted_owner_and_local_fat_is_fail_closed() {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let basic = source.split("unsafe fn nt_query_attributes_file_service(").nth(1).unwrap();
    let full = source.split("unsafe fn nt_query_full_attributes_file_service(").nth(1).unwrap();
    for service in [basic, full] {
        let local = service.find("self.query_local_file_relative(").unwrap();
        assert!(service[..local].contains("mounted_target_for_legacy_fat_child")
            && service[..local].contains("query_mounted_attributes_on_target"));
    }
    let query = query_method();
    let guard = query.find("exec_block_route_kind(mount)").unwrap();
    let fat = query.find("fat_open_path_metadata_from").unwrap();
    assert!(guard < fat, "local query must reject handoff before Boot FAT lookup");
    let mounted_volume = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
    let device = mounted_volume.split("fn exec_volume_device_for_mount(").nth(1).unwrap()
        .split("\n}").next().unwrap();
    assert!(device.contains("published.exact_device(physical, mount_id_for_live_device(device_id))"),
        "the published physical FAT mount and live logical File binding must both match");
}
