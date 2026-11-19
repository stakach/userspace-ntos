//! A checked system-image load reads installed bytes through the boot loader's synchronous FAT
//! reader only on the Boot inline route. Once the native block handoff starts, the registered
//! mounted-volume Device owns those names and the direct FAT reader must not be entered.

use std::process::Command;

fn production_load_installed() -> String {
    let source = include_str!("../../../components/ntos-executive/src/win32k_image_loader.rs");
    let start = source.find("pub(crate) unsafe fn load_installed(name: &str, pml4: u64)")
        .expect("production installed system-image loader");
    let end = source[start..].find("\n/// Map only bytes retained by the routed owner")
        .expect("end of installed system-image loader");
    source[start..start + end].to_owned()
}

#[test]
fn installed_system_image_loads_never_read_boot_fat_after_handoff() {
    let loader = production_load_installed();
    let contract = include_str!("../../nt-fs/src/volume_open_route.rs");
    let harness = format!(r#"
#![allow(dead_code, unused_imports, unused_unsafe)]
extern crate alloc;
use std::sync::atomic::{{AtomicU8, AtomicUsize, Ordering}};
use std::sync::Mutex;
pub use nt_fs::BlockSourceKind;
mod volume_open_route {{ {contract} }}
mod nt_fs {{
    pub use crate::volume_open_route::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BlockSourceKind {{ Boot, Draining, Native }}
}}

static LOCK: Mutex<()> = Mutex::new(());
// 0 = no installed mount, 1 = Boot, 2 = Draining, 3 = Native.
static ROUTE: AtomicU8 = AtomicU8::new(0);
static FAT_LOOKUPS: AtomicUsize = AtomicUsize::new(0);
static FAT_READS: AtomicUsize = AtomicUsize::new(0);
static MAPPED: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFailure {{
    FileMissing, InvalidImage, MissingExport, InsufficientResources, NativeFailure, DeviceNotReady,
}}
mod module_namespace {{
    pub fn module_leaf(name: &str) -> Result<String, ()> {{
        Ok(name.rsplit('\\').next().unwrap().to_ascii_lowercase())
    }}
    pub fn core_role(name: &str) -> Option<()> {{ (name == "ntoskrnl.exe").then_some(()) }}
}}
mod installed_layout {{
    pub const SYSTEM32_PREFIX: &[u8] = b"reactos\\system32\\";
    pub const DRIVERS_PREFIX: &[u8] = b"reactos\\system32\\drivers\\";
}}
#[derive(Clone, Copy)]
pub struct Mount;
mod fs_loader {{
    use std::sync::atomic::Ordering;
    pub unsafe fn exec_fs_mount_identity() -> Option<crate::Mount> {{
        (crate::ROUTE.load(Ordering::SeqCst) != 0).then_some(crate::Mount)
    }}
    pub fn exec_block_route_kind(_: crate::Mount) -> Option<crate::nt_fs::BlockSourceKind> {{
        match crate::ROUTE.load(Ordering::SeqCst) {{
            1 => Some(crate::nt_fs::BlockSourceKind::Boot),
            2 => Some(crate::nt_fs::BlockSourceKind::Draining),
            3 => Some(crate::nt_fs::BlockSourceKind::Native),
            _ => None,
        }}
    }}
    pub unsafe fn pool_alloc(_: u32) -> Option<u64> {{ Some(0x4000) }}
}}
// The boot FAT handle stays published after the handoff; only the route says who owns it.
pub struct Fs;
unsafe fn exec_fs() -> Option<Fs> {{ Some(Fs) }}
unsafe fn fat_open_path(_: &Fs, _: &[u8]) -> Option<(u32, u32)> {{
    FAT_LOOKUPS.fetch_add(1, Ordering::SeqCst);
    Some((12, 0x400))
}}
unsafe fn fat_read_file(_: &Fs, _: u32, length: u32, _: u64) -> u32 {{
    FAT_READS.fetch_add(1, Ordering::SeqCst);
    length
}}
unsafe fn loaded_name(_: &str, _: u64) -> Option<(u64, u32)> {{ None }}
pub struct ImageSnapshot;
unsafe fn load_snapshot(_: &str, _: &[u8], _: u64, _: u64, length: u32,
    _: Option<&[ImageSnapshot]>) -> Result<(u64, u32), LoadFailure> {{
    MAPPED.fetch_add(1, Ordering::SeqCst);
    Ok((0x10_0000, length))
}}

{loader}

fn reset(route: u8) {{
    ROUTE.store(route, Ordering::SeqCst);
    FAT_LOOKUPS.store(0, Ordering::SeqCst);
    FAT_READS.store(0, Ordering::SeqCst);
    MAPPED.store(0, Ordering::SeqCst);
}}

#[test]
fn draining_and_native_routes_never_enter_the_boot_fat_reader() {{
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    for route in [2, 3] {{
        reset(route);
        let result = unsafe {{ load_installed("framebuf.dll", 0x5000) }};
        assert_eq!((FAT_LOOKUPS.load(Ordering::SeqCst), FAT_READS.load(Ordering::SeqCst)), (0, 0),
            "post-handoff system-image load used the synchronous boot FAT reader (route {{route}})");
        assert_eq!(MAPPED.load(Ordering::SeqCst), 0, "no snapshot was acquired to map");
        assert_eq!(result, Err(LoadFailure::DeviceNotReady),
            "the mounted-volume owner, not a FAT miss, must answer (route {{route}})");
    }}
}}

#[test]
fn boot_inline_route_keeps_the_synchronous_reader() {{
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    reset(1);
    assert_eq!(unsafe {{ load_installed("framebuf.dll", 0x5000) }}, Ok((0x10_0000, 0x400)));
    assert_eq!(FAT_READS.load(Ordering::SeqCst), 1);
    assert_eq!(MAPPED.load(Ordering::SeqCst), 1);
}}

#[test]
fn an_unmounted_volume_is_not_ready_rather_than_read() {{
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    reset(0);
    assert_eq!(unsafe {{ load_installed("framebuf.dll", 0x5000) }},
        Err(LoadFailure::DeviceNotReady));
    assert_eq!(FAT_LOOKUPS.load(Ordering::SeqCst) + FAT_READS.load(Ordering::SeqCst), 0);
}}
"#);
    let directory = std::env::temp_dir().join(format!(
        "nt-installed-image-reader-route-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "production loader fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "installed system-image route regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}
