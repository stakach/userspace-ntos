//! Absolute regular-file opens on a registered kernel filesystem must enter its canonical
//! CREATE after the native block handoff instead of the boot loader's synchronous FAT lookup.

use std::process::Command;

fn production_route_selector() -> String {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = source.find("    /// Classify an absolute name for the shared nt-fs mounted-volume route contract.")
        .expect("production absolute-name classifier");
    let end = source[start..].find("\n    fn readonly_disk_open_entry(")
        .expect("end of absolute-open route selector");
    source[start..start + end].to_owned()
}

fn run_fixture(prefix: &str, harness: String) {
    let directory = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "production route fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "absolute regular-file route regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

#[test]
fn device_spelled_regular_file_enters_the_registered_volume_after_handoff() {
    let selector = production_route_selector();
    let contract = include_str!("../../nt-fs/src/volume_open_route.rs");
    let harness = format!(r#"
#![allow(dead_code, unused_imports)]
extern crate alloc;
pub use nt_fs::BlockSourceKind;
mod volume_open_route {{ {contract} }}
mod nt_fs {{
    pub use crate::volume_open_route::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BlockSourceKind {{ Boot, Draining, Native }}
    pub const FILE_DIRECTORY_FILE: u32 = 0x1;
    pub fn nt_path_to_volume_relative(path: &[u16], _: &[u8]) -> Option<Vec<u8>> {{
        let name = String::from_utf16_lossy(path).to_ascii_lowercase();
        name.strip_prefix(r"\??\c:\").map(|name| name.as_bytes().to_vec())
    }}
}}
mod installed_layout {{ pub const ROOT: &[u8] = b"reactos"; }}
mod driver_launch {{
    pub fn require_registered_kernel_filesystem_device(id: u64) -> Result<(), u32> {{
        if id == 41 {{ Ok(()) }} else {{ Err(0xc000_0010) }}
    }}
}}
mod writable_fs {{
    pub mod registry_journal {{ pub fn owns_volume() -> bool {{ false }} }}
}}
struct ExecNtHandler;
impl ExecNtHandler {{ {selector} }}

fn units(name: &str) -> Vec<u16> {{ name.encode_utf16().collect() }}
fn resolved(device: u64, remaining: &str) -> Result<(u64, Vec<u16>), u32> {{
    Ok((device, units(remaining)))
}}
const NON_DIRECTORY: u32 = 0x40;

#[test]
fn device_child_open_after_handoff_reaches_mounted_create() {{
    let name = units(r"\Device\HarddiskVolume1\reactos\system32\msgina.dll");
    let target = resolved(41, r"\reactos\system32\msgina.dll");
    for phase in [nt_fs::BlockSourceKind::Draining, nt_fs::BlockSourceKind::Native] {{
        assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
            &name, NON_DIRECTORY, Some(phase), Some(&target)),
            "post-handoff device-spelled regular file falls to the legacy local open path: {{phase:?}}");
    }}
}}

#[test]
fn installed_spelling_keeps_the_boot_reader_until_handoff() {{
    let name = units(r"\??\C:\reactos\system32\msgina.dll");
    let target = resolved(41, r"\reactos\system32\msgina.dll");
    assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, NON_DIRECTORY, Some(nt_fs::BlockSourceKind::Boot), Some(&target)));
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, NON_DIRECTORY, Some(nt_fs::BlockSourceKind::Native), Some(&target)));
}}

#[test]
fn unregistered_device_child_never_enters_the_mounted_create() {{
    let name = units(r"\Device\NamedPipe\lsass");
    let target = resolved(7, r"\lsass");
    for phase in [nt_fs::BlockSourceKind::Boot, nt_fs::BlockSourceKind::Native] {{
        assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
            &name, NON_DIRECTORY, Some(phase), Some(&target)));
    }}
}}
"#);
    run_fixture("nt-absolute-regular-file-route", harness);
}
