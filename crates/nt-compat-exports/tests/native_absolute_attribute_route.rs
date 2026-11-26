//! Name-based attribute queries on a registered kernel filesystem must use its canonical
//! CREATE/QUERY after the native block handoff, whatever absolute spelling names the file.

use std::process::Command;

fn between(source: &str, start: &str, end: &str) -> String {
    let begin = source.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let finish = source[begin..].find(end).unwrap_or_else(|| panic!("missing {end}"));
    source[begin..begin + finish].to_owned()
}

#[test]
fn device_spelled_attribute_query_enters_the_registered_volume_after_handoff() {
    let exec = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let attribute = include_str!("../../../components/ntos-executive/src/exec_attribute_query.rs");
    let selector = between(exec,
        "    /// Classify an absolute name for the shared nt-fs mounted-volume route contract.",
        "\n    fn readonly_disk_open_entry(");
    let query = between(attribute, "    pub(super) unsafe fn query_native_mounted_attributes(",
        "    /// Query a validated target on the exact mounted File device.");
    let contract = include_str!("../../nt-fs/src/volume_open_route.rs");
    let harness = format!(r#"
#![allow(dead_code, unused_imports, unused_unsafe)]
extern crate alloc;
use std::sync::atomic::{{AtomicU8, AtomicUsize, Ordering}};
use std::sync::Mutex;
pub use nt_fs::BlockSourceKind;
static LOCK: Mutex<()> = Mutex::new(());
static ROUTE: AtomicU8 = AtomicU8::new(2);
static RESOLVES: AtomicUsize = AtomicUsize::new(0);
static TARGETS: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
const FILE_OBJECT_NAME_CAP: usize = 512;
const FILE_VOLUME_RELATIVE_CAP: usize = 512;
const STATUS_DEVICE_NOT_READY: u32 = 0xc000_00a3;
const QUERIED: u32 = 0x5151;
mod volume_open_route {{ {contract} }}
mod nt_fs {{
    pub use crate::volume_open_route::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BlockSourceKind {{ Boot, Draining, Native }}
    pub const STATUS_SUCCESS: u32 = 0;
    pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
    pub const STATUS_NOT_SAME_DEVICE: u32 = 0xc000_00d4;
    pub const FILE_BASIC_INFORMATION: u32 = 4;
    pub const FILE_DIRECTORY_FILE: u32 = 0x1;
    pub fn nt_path_to_volume_relative(path: &[u16], _: &[u8]) -> Option<Vec<u8>> {{
        let name = String::from_utf16_lossy(path).to_ascii_lowercase();
        name.strip_prefix(r"\??\c:\").map(|name| name.as_bytes().to_vec())
    }}
}}
mod installed_layout {{ pub const ROOT: &[u8] = b"reactos"; }}
mod fs_loader {{
    #[derive(Clone, Copy)] pub struct Mount;
    pub unsafe fn exec_fs_mount_identity() -> Option<Mount> {{ Some(Mount) }}
    pub fn exec_block_route_kind(_: Mount) -> Option<crate::nt_fs::BlockSourceKind> {{
        Some(match crate::ROUTE.load(std::sync::atomic::Ordering::SeqCst) {{
            0 => crate::nt_fs::BlockSourceKind::Boot,
            1 => crate::nt_fs::BlockSourceKind::Draining,
            _ => crate::nt_fs::BlockSourceKind::Native,
        }})
    }}
}}
mod writable_fs {{
    pub mod volume_owner {{ pub fn owns_volume() -> bool {{ false }} }}
    pub fn volume_path_into(name: &[u16], _: &mut [u8], out: &mut [u8]) -> Option<usize> {{
        let relative = crate::nt_fs::nt_path_to_volume_relative(name, b"reactos")?;
        out[..relative.len()].copy_from_slice(&relative);
        Some(relative.len())
    }}
}}
mod mounted_volume {{ pub fn exec_volume_device() -> Option<u64> {{ Some(41) }} }}
mod driver_launch {{
    fn units(name: &str) -> Vec<u16> {{ name.encode_utf16().collect() }}
    pub fn resolve_hosted_device_file_name(name: &[u16], _: bool)
        -> Result<(u64, Vec<u16>), u32> {{
        crate::RESOLVES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let lower = String::from_utf16_lossy(name).to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(r"\device\harddiskvolume1") {{
            return Ok((41, units(rest)));
        }}
        if let Some(rest) = lower.strip_prefix(r"\??\c:") {{ return Ok((41, units(rest))); }}
        if lower == r"\device\null" {{ return Ok((9, Vec::new())); }}
        Err(0xc000_003a)
    }}
    pub fn require_registered_kernel_filesystem_device(id: u64) -> Result<(), u32> {{
        if id == 41 {{ Ok(()) }} else {{ Err(0xc000_0010) }}
    }}
    pub fn resolve_kernel_directory_file_name(name: &[u16], ci: bool)
        -> Result<(u64, Vec<u16>), u32> {{
        let (device, relative) = resolve_hosted_device_file_name(name, ci)?;
        require_registered_kernel_filesystem_device(device)?;
        Ok((device, relative))
    }}
}}
mod smss_attribute_probe_trace {{
    pub fn trace_smss_attribute_resolution(_: usize, _: u64, _: &[u16],
        _: Option<(u64, &[u16])>, _: u32) {{}}
}}
mod handler {{
    use crate::*;
    pub struct ExecNtHandler {{ pub pi: usize, pub current_tid: u64 }}
    impl ExecNtHandler {{ {selector} }}
    impl ExecNtHandler {{
        pub(super) unsafe fn query_mounted_attributes_on_target(&mut self, device_id: u64,
            relative: &[u16], _: u32, _: u32, _: u64) -> Option<u32> {{
            crate::TARGETS.lock().unwrap().push((device_id, String::from_utf16_lossy(relative)));
            Some(crate::QUERIED)
        }}
{query}
    }}
}}
use handler::ExecNtHandler;

fn query(name: &str, route: u8) -> Option<u32> {{
    ROUTE.store(route, Ordering::SeqCst);
    RESOLVES.store(0, Ordering::SeqCst);
    TARGETS.lock().unwrap().clear();
    let name: Vec<u16> = name.encode_utf16().collect();
    let mut handler = ExecNtHandler {{ pi: 3, current_tid: 9 }};
    unsafe {{ handler.query_native_mounted_attributes(&name, 0x40, nt_fs::FILE_BASIC_INFORMATION, 0x1000) }}
}}

#[test]
fn device_spelled_name_after_handoff_queries_the_mounted_device() {{
    let _guard = LOCK.lock().unwrap();
    for route in [1, 2] {{
        assert_eq!(query(r"\Device\HarddiskVolume1\reactos\system32\msgina.dll", route),
            Some(QUERIED), "post-handoff device-spelled attribute query missed the mounted Device");
        assert_eq!(TARGETS.lock().unwrap().as_slice(),
            &[(41, r"\reactos\system32\msgina.dll".to_owned())]);
    }}
}}

#[test]
fn installed_spelling_after_handoff_queries_the_mounted_device() {{
    let _guard = LOCK.lock().unwrap();
    assert_eq!(query(r"\??\C:\reactos\system32\msgina.dll", 2), Some(QUERIED));
    assert_eq!(TARGETS.lock().unwrap().as_slice(),
        &[(41, r"\reactos\system32\msgina.dll".to_owned())]);
}}

#[test]
fn boot_reader_keeps_installed_spellings_without_an_object_manager_lookup() {{
    let _guard = LOCK.lock().unwrap();
    assert_eq!(query(r"\??\C:\reactos\system32\msgina.dll", 0), None);
    assert_eq!(RESOLVES.load(Ordering::SeqCst), 0);
    assert!(TARGETS.lock().unwrap().is_empty());
}}

#[test]
fn names_outside_the_volume_report_not_found_after_handoff() {{
    let _guard = LOCK.lock().unwrap();
    for name in [r"\Device\Null", r"\Device\Missing\x.dll"] {{
        assert_eq!(query(name, 2), Some(nt_fs::STATUS_OBJECT_NAME_NOT_FOUND), "{{name}}");
        assert!(TARGETS.lock().unwrap().is_empty());
    }}
}}
"#);
    let directory = std::env::temp_dir().join(format!(
        "nt-absolute-attribute-route-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "production attribute route fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "absolute attribute route regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}
