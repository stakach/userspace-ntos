//! An installed-volume NtOpenFile must retain its exact CREATE while boot AHCI drains.

extern crate alloc;

use nt_fs::{
    layered_file_open_decision, BlockOperation, BlockRouteError, BlockRouteOwner, BlockSource,
    FatPathGeometry, FatPathLookup, FatPathProgress, LayeredFileOpenDecision, FILE_OPEN,
};
use std::process::Command;

#[path = "../../../components/ntos-executive/src/mounted_create_lookup.rs"]
mod mounted_create_lookup;

#[test]
fn absolute_installed_open_enters_mounted_create_before_synchronous_fat_fallback() {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = source.find("    fn route_absolute_open_to_kernel_file(")
        .expect("production absolute-open route selector");
    let end = source[start..].find("\n    fn readonly_disk_open_entry(")
        .expect("end of absolute-open route selector");
    let selector = &source[start..start + end];
    let open = source.split("unsafe fn nt_open_file_service(").nth(1)
        .expect("native NtOpenFile service");
    let routed = open.find("Self::route_absolute_open_to_kernel_file(name16, open_options, mount_route)")
        .expect("native NtOpenFile consumes production route selector");
    let fallback = open.find("crate::writable_fs::writable_path_into")
        .expect("native NtOpenFile synchronous installed-volume fallback");
    assert!(routed < fallback, "route admission must precede synchronous FAT lookup");

    // Compile and execute the actual selector body. The current directory-only behavior is
    // deliberately RED for a regular installed file while the exact mount is Draining.
    let harness = format!(r#"
mod nt_fs {{
    #[derive(Clone, Copy)]
    pub enum BlockSourceKind {{ Boot, Draining, Native }}
    pub const FILE_DIRECTORY_FILE: u32 = 1;
    pub fn nt_path_to_volume_relative(path: &[u16], _: &[u8]) -> Option<Vec<u8>> {{
        let name = String::from_utf16_lossy(path).to_ascii_lowercase();
        name.strip_prefix(r"\??\c:\").map(|name| name.as_bytes().to_vec())
    }}
}}
mod installed_layout {{ pub const ROOT: &[u8] = b"Windows"; }}
mod writable_fs {{
    pub mod registry_journal {{
        use std::cell::Cell;
        thread_local! {{ static OWNED: Cell<bool> = const {{ Cell::new(false) }}; }}
        pub fn owns_volume() -> bool {{ OWNED.with(Cell::get) }}
        pub fn set_owned(value: bool) {{ OWNED.with(|owned| owned.set(value)); }}
    }}
}}
struct ExecNtHandler;
impl ExecNtHandler {{ {selector} }}
#[test]
fn installed_file_open_waits_for_native_mount() {{
    let name: Vec<u16> = r"\??\C:\Windows\System32\autochk.exe".encode_utf16().collect();
    let unrelated: Vec<u16> = r"\Device\NamedPipe\foo".encode_utf16().collect();
    assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0, Some(nt_fs::BlockSourceKind::Boot)));
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0, Some(nt_fs::BlockSourceKind::Draining)),
        "Draining installed-file open must enter the retained mounted CREATE lane");
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0, Some(nt_fs::BlockSourceKind::Native)));
    assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
        &unrelated, 0, Some(nt_fs::BlockSourceKind::Draining)));
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 1, Some(nt_fs::BlockSourceKind::Boot)));
}}
#[test]
fn installed_dll_open_waits_while_registry_journal_owns_boot_volume() {{
    let name: Vec<u16> = r"\??\C:\Windows\System32\msgina.dll".encode_utf16().collect();
    writable_fs::registry_journal::set_owned(true);
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0x60, Some(nt_fs::BlockSourceKind::Boot)),
        "journal-owned installed DLL must retain CREATE until overlay ownership returns");
    writable_fs::registry_journal::set_owned(false);
    assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0x60, Some(nt_fs::BlockSourceKind::Boot)),
        "after release the ordinary Boot route may inspect the overlay again");
}}
"#);
    let directory = std::env::temp_dir().join(format!(
        "nt-native-mounted-open-drain-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native route fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "native NtOpenFile cutover regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

#[test]
fn create_file_routes_journal_owned_volume_before_overlay_admission() {
    let source = include_str!("../../../components/ntos-executive/src/exec_file_create.rs");
    let create = source.split("unsafe fn nt_create_file_service(").nth(1)
        .expect("native NtCreateFile service");
    let route = create.find("Self::route_absolute_open_to_kernel_file(name16, create_options, mount_route)")
        .expect("native NtCreateFile must consume the same journal-aware mounted File route");
    let overlay = create.find("crate::writable_fs::query_metadata_relative_if_mounted")
        .expect("native NtCreateFile overlay lookup");
    assert!(route < overlay, "journal ownership must retain CREATE before overlay admission");
}

#[test]
fn released_journal_restores_overlay_precedence_for_an_installed_dll() {
    assert_eq!(
        layered_file_open_decision(Ok(true), true, 0x0010_0021, FILE_OPEN, 0x60),
        Ok(LayeredFileOpenDecision::UseOverlay),
        "an overlay file wins once its journal returns namespace ownership",
    );
}

#[test]
fn pending_create_keeps_exact_mount_and_sector_until_native_completion() {
    let mut route = BlockRouteOwner::new(7, 1_000).unwrap();
    route.begin_drain(7).unwrap();
    let geometry = FatPathGeometry {
        fat_start_sector: 1, data_start_sector: 100,
        total_sectors: 200, sectors_per_cluster: 1,
    };
    let lookup = FatPathLookup::new(geometry, 2, b"windows\\system32\\autochk.exe").unwrap();
    let mut creates = mounted_create_lookup::CreateLookupQueue::new();
    creates.capture(0x21, 7, b"autochk.exe".to_vec(), lookup).unwrap();
    assert!(creates.take_resolved().is_none(), "no early absence or handle publication");
    let claim = creates.claim_next().unwrap();
    let operation = BlockOperation::Read { lba: u64::from(claim.request.sector), sectors: 1 };
    assert_eq!(route.admit_boot(7, BlockSource::Fat, operation),
        Err(BlockRouteError::WrongPhase), "drain cannot issue direct AHCI");
    assert!(creates.take_resolved().is_none());
    assert!(creates.claim_next().is_none(), "claimed sector cannot be replayed");

    route.commit_native(7, 0x44).unwrap();
    let ticket = route.enter_native(7, BlockSource::Fat, operation).unwrap();
    route.lose_native(ticket).unwrap();
    assert_eq!(route.complete_native(ticket, 511), Err(BlockRouteError::Incomplete));
    assert!(creates.take_resolved().is_none());
    route.complete_native(ticket, 512).unwrap();
    assert_eq!(creates.complete(claim, Ok(&[0; 512])), Ok(FatPathProgress::NotFound));
    let resolved = creates.take_resolved().expect("exact terminal CREATE");
    assert_eq!(resolved.irp, 0x21);
    assert_eq!(resolved.mount, 7);
    assert_eq!(resolved.payload.as_slice(), b"autochk.exe");
    assert!(creates.take_resolved().is_none(), "CREATE completes once");
}
