//! DriverEntry call-gate tests against synthetic PE images + a Rust mock driver
//! (this host is aarch64; real x64 execution is proven in QEMU, M9).

use nt_driver_host::{
    DriverHost, DriverServices, DriverState, EntryContext, LoadError, MockGate, NullBridge,
};
use nt_driver_test_fixtures::pe_importing;
use nt_kernel_abi::{major, DriverObject, GuestAddr};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const ARENA_BASE: u64 = 0xFFFF_F800_0000_0000;
const TRAMP_BASE: u64 = 0x7F00_0000_0000;

fn host() -> DriverHost {
    DriverHost::new(ARENA_BASE, 64 * 1024, TRAMP_BASE)
}

/// A mock `DriverEntry`: install CREATE/CLOSE/DEVICE_CONTROL dispatch + unload,
/// return STATUS_SUCCESS. Models what a real driver's machine code would do.
fn mock_driver_entry(ctx: &EntryContext, services: &mut DriverServices) -> i32 {
    let mem = services.arena_mut();
    let mut drv: DriverObject = mem.read(ctx.driver_object).unwrap();
    drv.major_function[major::IRP_MJ_CREATE as usize] = GuestAddr(0x9001);
    drv.major_function[major::IRP_MJ_CLOSE as usize] = GuestAddr(0x9002);
    drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize] = GuestAddr(0x9003);
    drv.driver_unload = GuestAddr(0x90FF);
    assert!(mem.write(ctx.driver_object, drv));
    0 // STATUS_SUCCESS
}

#[test]
fn loads_maps_and_calls_driver_entry() {
    let bytes = pe_importing(
        "ntoskrnl.exe",
        &["IoCreateDevice", "IoCreateSymbolicLink", "DbgPrint"],
    );
    let mut host = host();
    host.load(
        &bytes,
        IMAGE_BASE,
        "\\Registry\\Machine\\System\\Services\\SurtTest",
    )
    .unwrap();
    assert_eq!(host.state(), DriverState::Loaded);

    // Every import was bound to a trampoline + patched into the IAT.
    assert_eq!(host.bound_trampolines().len(), 3);
    let pe = nt_pe_loader::PeFile::parse(&bytes).unwrap();
    let img = host.image().unwrap();
    for dll in pe.imports().unwrap() {
        for f in dll.functions {
            if let nt_pe_loader::ImportRef::ByName {
                name, iat_slot_rva, ..
            } = f
            {
                let bound = host
                    .bound_trampolines()
                    .iter()
                    .find(|(_, n, _)| *n == name)
                    .map(|(_, _, a)| *a)
                    .unwrap();
                assert_eq!(img.u64_at_rva(iat_slot_rva).unwrap(), bound);
            }
        }
    }

    // Run DriverEntry via the mock gate.
    host.start(&MockGate(mock_driver_entry), &mut NullBridge)
        .unwrap();
    assert_eq!(host.state(), DriverState::Started);
    assert_eq!(host.entry_status(), 0);
    assert_eq!(
        host.dispatch(major::IRP_MJ_DEVICE_CONTROL),
        Some(GuestAddr(0x9003))
    );
    assert_eq!(host.dispatch(major::IRP_MJ_CREATE), Some(GuestAddr(0x9001)));
    assert!(host.dispatch(major::IRP_MJ_READ).is_none()); // never installed
    assert_eq!(host.unload_routine(), Some(GuestAddr(0x90FF)));
}

#[test]
fn unsupported_import_blocks_load() {
    let bytes = pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoConnectInterrupt"]);
    let mut host = host();
    match host.load(&bytes, IMAGE_BASE, "\\Registry\\...") {
        Err(LoadError::BlockedImports(report)) => {
            assert!(!report.runnable());
            assert_eq!(report.blocking().count(), 1);
        }
        other => panic!("expected BlockedImports, got {other:?}"),
    }
    assert_eq!(host.state(), DriverState::Unloaded);
}

#[test]
fn driver_entry_failure_cleans_up() {
    let bytes = pe_importing("ntoskrnl.exe", &["IoCreateDevice"]);
    let mut host = host();
    host.load(&bytes, IMAGE_BASE, "\\Registry\\...").unwrap();

    // A driver whose DriverEntry returns STATUS_UNSUCCESSFUL.
    let failing = MockGate(|_ctx: &EntryContext, _svc: &mut DriverServices| 0xC000_0001u32 as i32);
    match host.start(&failing, &mut NullBridge) {
        Err(LoadError::DriverEntryFailed(s)) => assert_eq!(s, 0xC000_0001u32 as i32),
        other => panic!("expected DriverEntryFailed, got {other:?}"),
    }
    assert_eq!(host.state(), DriverState::Failed);
    // The partial projections were retired (spec §9 failure path).
    let drv = host.driver_object_addr().unwrap();
    assert!(host
        .runtime()
        .validate(drv, nt_driver_runtime::ObjectKind::DriverObject)
        .is_none());
}

#[test]
fn start_before_load_is_rejected() {
    let mut host = host();
    assert!(matches!(
        host.start(&MockGate(mock_driver_entry), &mut NullBridge),
        Err(LoadError::NotLoaded)
    ));
}
