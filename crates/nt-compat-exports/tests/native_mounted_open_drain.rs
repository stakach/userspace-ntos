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
    let routed = open.find("Self::route_absolute_open_to_kernel_file(name16, open_options, mount_route, resolved)")
        .expect("native NtOpenFile consumes production route selector");
    let fallback = open.find("crate::writable_fs::writable_path_into")
        .expect("native NtOpenFile synchronous installed-volume fallback");
    assert!(routed < fallback, "route admission must precede synchronous FAT lookup");

    // Compile and execute the actual selector body. The current directory-only behavior is
    // deliberately RED for a regular installed file while the exact mount is Draining.
    let volume_route = include_str!("../../../components/ntos-executive/src/exec_volume_open_route.rs");
    let harness = format!(r#"
extern crate alloc;
mod exec_volume_open_route {{ {volume_route} }}
mod driver_launch {{
    pub fn require_registered_kernel_filesystem_device(_: u64) -> Result<(), u32> {{ Ok(()) }}
}}
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
        &name, 0, Some(nt_fs::BlockSourceKind::Boot), None));
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0, Some(nt_fs::BlockSourceKind::Draining), None),
        "Draining installed-file open must enter the retained mounted CREATE lane");
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0, Some(nt_fs::BlockSourceKind::Native), None));
    assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
        &unrelated, 0, Some(nt_fs::BlockSourceKind::Draining), None));
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 1, Some(nt_fs::BlockSourceKind::Boot), None));
}}
#[test]
fn installed_dll_open_waits_while_registry_journal_owns_boot_volume() {{
    let name: Vec<u16> = r"\??\C:\Windows\System32\msgina.dll".encode_utf16().collect();
    writable_fs::registry_journal::set_owned(true);
    assert!(ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0x60, Some(nt_fs::BlockSourceKind::Boot), None),
        "journal-owned installed DLL must retain CREATE until overlay ownership returns");
    writable_fs::registry_journal::set_owned(false);
    assert!(!ExecNtHandler::route_absolute_open_to_kernel_file(
        &name, 0x60, Some(nt_fs::BlockSourceKind::Boot), None),
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
    let route = create.find("Self::route_absolute_open_to_kernel_file(name16, create_options, mount_route, resolved)")
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
fn acknowledged_native_fat_sector_can_dispatch_its_successor_in_the_same_service_turn() {
    // The production cursor makes the second sector claimable as soon as the first terminal
    // feeds it. Waiting for another outer service turn adds one whole wakeup per FAT component.
    let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 100,
        total_sectors: 200, sectors_per_cluster: 1 };
    let lookup = FatPathLookup::new(geometry, 2, b"windows\\file.txt").unwrap();
    let mut creates = mounted_create_lookup::CreateLookupQueue::new();
    creates.capture(0x226, 7, (), lookup).unwrap();
    let first = creates.claim_next().unwrap();
    assert_eq!(first.request.sector, 100);
    assert!(creates.claim_next().is_none(), "entered command cannot be claimed twice");
    let mut root = [0u8; 512];
    root[..11].copy_from_slice(b"WINDOWS    ");
    root[11] = 0x10;
    root[26..28].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(creates.complete(first, Ok(&root)), Ok(FatPathProgress::Pending));
    let second = creates.claim_next().expect("exact first terminal enables next FAT sector");
    assert_eq!((second.irp, second.mount, second.request.sector), (0x226, 7, 101));
    assert!(creates.claim_next().is_none(), "only one physical successor can enter");

    let source = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let poll = source.split_once("unsafe fn poll_pending() -> usize")
        .expect("actual native completion poll").1
        .split_once("static SERVICE_ACTIVE").expect("poll boundary").0;
    let ack = poll.find("acknowledge_completed_irp_strict").expect("strict native ACK");
    let slot_release = poll.find("slot.take().expect").expect("exact pending owner retirement");
    assert!(ack < slot_release,
        "a pending command must be strictly ACKed before its physical slot is reusable");
    let service = source.split_once("pub(super) unsafe fn service() -> usize")
        .expect("actual top-level native block service").1
        .split_once("unsafe fn service_registry_exact(").expect("service boundary").0;
    assert!(service.contains("NativeServiceGuard::enter()")
        && service.contains("poll_pending()")
        && service.contains("dispatch_claim("),
        "the same guarded turn must own completion and next dispatch");
    assert!(!service.contains("return poll_pending();"),
        "strict ACK already made the next FAT sector claimable; do not wait another outer wakeup");
    let pending_branch = service.split_once("if (&*core::ptr::addr_of!(PENDING)).is_some() {")
        .expect("exact pending-slot branch").1
        .split_once("\n    }").expect("pending-slot branch boundary").0;
    let pending_wait = pending_branch.split_once("if settled == 0 {")
        .expect("an unsettled physical slot must block successor dispatch").1
        .split_once('}').expect("complete pending wait guard").0;
    assert!(pending_branch.contains("let settled = poll_pending();")
        && pending_wait.contains("return 0;"),
        "an unproven terminal or refused ACK must retain the occupied slot and forbid next dispatch");
    let (published_route, retained_route) = service
        .split_once("let Some(route) = native_disk_relation::retained_native_storage_recheck_route()")
        .expect("retained-route fallback follows the published-route branch");
    assert!(published_route.contains("drain_cached_claims(CACHE_CLAIMS_PER_TURN")
        && published_route.contains("return settled.saturating_add(driven);")
        && published_route.matches("dispatch_claim(").count() == 1
        && retained_route.matches("dispatch_claim(").count() == 1,
        "the bounded published-route drain and single retained-route command must be disjoint");
    assert!(!service.contains("pump_hosted_io_completions"),
        "native block service must not nest a completion pump");
}

#[test]
fn native_completion_irq_polls_exact_physical_slot_before_receiving_again() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let irq = service.split_once("let current_irq_lines = driver_launch::latch_hosted_irq_badge(badge);")
        .expect("root hardware IRQ dispatch").1
        .split_once("if pending_driver_start_redrive_needed(&nt_handler)")
        .expect("end of pure IRQ branch").0;
    let drain = irq.find("driver_launch::drain_pending_hosted_irqs()")
        .expect("physical IRQ and its DPCs are drained");
    let pure_irq = irq.find("if current_irq_lines != 0")
        .expect("pure hardware IRQ branch");
    let branch = &irq[pure_irq..];
    let pending = branch.find("driver_launch::mounted_native_physical_irp_pending()")
        .expect("only an entered native command needs an IRQ completion poll");
    let poll = branch.find("service_mounted_native_blocks_and_redrive_backends()")
        .expect("publish and ACK the exact native completion on its IRQ");
    let receive = branch.find("component_recv!(fault_ep")
        .expect("root receives after the IRQ checkpoint");
    assert!(drain < pure_irq && pending < poll && poll < receive,
        "DPC completion must reach the native slot before root sleeps for another timer");
    let helper = service.split_once("fn service_mounted_native_blocks_and_redrive_backends()")
        .expect("shared native settlement helper").1;
    assert!(helper.split_once("\n}").expect("helper end").0
        .contains("driver_launch::service_mounted_native_blocks()"),
        "the IRQ helper must retain exact physical slot settlement");
}

#[test]
fn irq_completed_during_nested_dispatch_is_polled_after_pending_slot_publication() {
    // The component pump can service the physical IRQ and its DPC before the dispatch Call
    // returns PENDING. At that point no native Pending slot exists for the IRQ path to poll.
    // Installing the slot must therefore be followed by one exact completion probe in this
    // guarded turn, without waiting for the next timer or replaying the physical command.
    let source = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let service = source.split_once("pub(super) unsafe fn service() -> usize")
        .expect("top-level native block service").1
        .split_once("unsafe fn service_registry_exact(").expect("service boundary").0;
    assert!(service.contains("NativeServiceGuard::enter()"),
        "nested completion must not reenter the physical dispatcher");

    let pending = source.split_once(
        "Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {")
        .expect("retained pending dispatch branch").1
        .split_once("\n        Err(status) => {").expect("pending dispatch boundary").0;
    let installed = pending.find("*core::ptr::addr_of_mut!(PENDING) = Some(Pending {")
        .expect("retain the exact physical claim, ticket and IRP before probing");
    let published = pending.find("NATIVE_PENDING_IRP.store(irp_id.raw(), Ordering::Release)")
        .expect("publish the exact pending IRP to nested observers");
    let poll = pending.find("poll_pending()")
        .expect("an IRQ completed inside dispatch must be observed before this turn returns");
    assert!(installed < published && published < poll,
        "the pending owner must exist before completion import or strict acknowledgement");
    assert_eq!(pending.matches("poll_pending()").count(), 1,
        "a single bounded probe suffices; an unproven completion remains pending");
    assert!(!pending.contains("dispatch_claim(") && !pending.contains("loop {"),
        "a nested completion must not recursively issue unbounded successors");

    let completion = source.split_once("unsafe fn poll_pending() -> usize")
        .expect("exact native completion poll").1
        .split_once("static SERVICE_ACTIVE").expect("poll boundary").0;
    for identity in ["completion.client_id", "completion.driver_id", "completion.device_id",
        "completion.requestor_tid", "completion.major"] {
        assert!(completion.contains(identity), "retain exact completion authority: {identity}");
    }
    let ack = completion.find("acknowledge_completed_irp_strict")
        .expect("strict completion ACK");
    let release = completion.find("slot.take().expect")
        .expect("physical slot retirement after ACK");
    assert!(ack < release && completion[ack..release].contains("return 0;"),
        "uncertain ACK must retain the occupied physical slot");
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
