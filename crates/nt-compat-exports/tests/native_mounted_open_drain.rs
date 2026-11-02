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
fn parked_mounted_create_remains_a_live_signaler_until_native_service_drives_it() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let native_block = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let volume = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");

    // The exact bootstat CREATE is retained after SMSS parks, even before any physical IRP
    // has entered. A queue owner is sufficient to keep the native service lane runnable.
    let mut queue = mounted_create_lookup::CreateLookupQueue::new();
    queue.capture_resolved_root(1, 7, ()).unwrap();
    assert!(queue.has_outstanding());
    assert!(volume.contains("pub(crate) fn mounted_create_outstanding() -> bool"));
    assert!(native_block.contains("crate::mounted_volume::claim_mounted_create_sector()"));
    assert!(driver.contains("mounted_native_block::service()"));
    assert!(service.contains("if badge == DELAY_TIMER_BADGE"));
    assert!(service.contains("let native_blocks = driver_launch::service_mounted_native_blocks() as u64"));

    // Every terminal all-parked admission must recognize that queued CREATE as a signaler.
    // Keep each check local to its own guard; a mention elsewhere cannot satisfy this test.
    let crash_guard = service.split_once("macro_rules! park_and_log")
        .unwrap().1.split_once("macro_rules! mark_wait_parked").unwrap().0;
    let waiting_guard = service.split_once("macro_rules! mark_wait_parked")
        .unwrap().1.split_once("// Boot-milestone watchdog").unwrap().0;
    let lsass_guard = service.split_once("b\"lsass-post-signal-fault\"")
        .unwrap().1.split_once("[quiesce] every live process parked/waiting").unwrap().0;
    for (name, guard) in [
        ("crash park", crash_guard),
        ("cooperative wait", waiting_guard),
        ("LSASS fault", lsass_guard),
    ] {
        assert!(guard.contains("!crate::mounted_volume::mounted_create_outstanding()"),
            "{name} quiesced while an exact mounted CREATE can still drive its parked caller");
    }
}

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
fn native_resolved_writable_create_has_a_continuation_beyond_resident_busy() {
    let backend = include_str!("../../../components/ntos-executive/src/mounted_volume_backend.rs");
    let service = backend.split_once("fn service_resolved_create(&mut self) -> usize")
        .expect("actual mounted CREATE service").1
        .split_once("fn service_resolved_directory(&mut self)")
        .expect("CREATE service boundary").0;
    let overlay = backend.split_once("fn create_overlay(")
        .expect("actual writable open path").1
        .split_once("fn binding(").expect("overlay boundary").0;
    assert!(service.contains("&owner.parameters, !deferred_boot"),
        "native resolved CREATE currently enters the resident-only decision");
    assert!(overlay.contains("OverlayCreateSpec") && !overlay.contains("if resident_only { return Err(RESIDENT_BUSY); }"),
        "native writable CREATE must capture a typed preparation decision");
    assert!(service.contains("restore_resolved(resolved)"),
        "a busy resident dependency must retain the exact CREATE owner");

    // Exercise the production queue with a bootstat-like writable File owner. Its resolved
    // result cannot issue another FAT sector; restoring it twice preserves the same IRP.
    assert_eq!(layered_file_open_decision(Ok(true), true, 0x3, FILE_OPEN, 0),
        Ok(LayeredFileOpenDecision::UseOverlay));
    let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 100,
        total_sectors: 200, sectors_per_cluster: 1 };
    let lookup = FatPathLookup::new(geometry, 2, b"bootstat.dat").unwrap();
    let mut creates = mounted_create_lookup::CreateLookupQueue::new();
    creates.capture(0x225, 7, b"bootstat.dat".to_vec(), lookup).unwrap();
    let claim = creates.claim_next().unwrap();
    assert_eq!(creates.complete(claim, Ok(&[0; 512])), Ok(FatPathProgress::NotFound));
    for _ in 0..2 {
        let resolved = creates.take_resolved().unwrap();
        assert_eq!((resolved.irp, resolved.mount), (0x225, 7));
        creates.restore_resolved(resolved).unwrap();
        assert!(creates.has_outstanding());
        assert_eq!(creates.first_state(), Some((0x225, 7, b"resolved".as_slice())));
        assert!(creates.claim_next().is_none(), "resolved CREATE has no new physical signaler");
    }

    assert!(backend.contains("OverlayPreparations")
        && service.contains("pending_overlays"),
        "native writable CREATE needs an independently driven preparation owner; resident-only retry cannot complete it");
    let native = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let mount = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
    let writable = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    assert!(native.contains("SectorClaim::Overlay")
        && native.contains("claim_mounted_overlay_sector"),
        "the outer native block owner must drive overlay sectors without reentering backend dispatch");
    assert!(mount.contains("MOUNT_OVERLAY_QUEUE") && mount.contains("mounted_overlay_outstanding"),
        "prepared CREATE must stay visible to the no-signaler guard");
    assert!(backend.contains("self.pending_overlays.borrow_mut().take_next_ready()")
        && backend.contains("self.opens.finish(context, file,")
        && backend.contains("file_context: Some(context.raw())"),
        "resident completion must publish the canonical File context for the exact IRP");
    assert!(backend.contains("query_metadata_relative_if_mounted(")
        && backend.contains("spec.materialize_parent = false"),
        "an existing upper parent must win without a lower FAT parent read");
    assert!(writable.contains("pub(crate) unsafe fn create_prepared_overlay_relative_if_mounted")
        && writable.contains("fs.create_prepared_overlay_relative(")
        && writable.contains("match mounted_namespace_fs()"),
        "native overlay completion must use the non-mounting resident transaction");
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
