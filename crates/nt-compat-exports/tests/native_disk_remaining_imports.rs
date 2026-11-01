//! Pinned disk.sys imports must use live native owners and a real data cell.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const BOOT: &str = include_str!("../../../components/ntos-executive/src/hosted_boot_driver_reinitialization.rs");
const ORDINARY: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_reinitialization.rs");
const TEMP: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_make_temporary.rs");
const SAFE: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_safe_boot.rs");
const DIRECTORY: &str = include_str!("../../../components/ntos-executive/src/exec_directory_object.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/provider_directory_broker.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn boot_reinit_registration_is_owned_and_drained_after_boot_driver_launch() {
    assert!(LAUNCH.contains("\"IoRegisterBootDriverReinitialization\""));
    for evidence in ["validated_registration", "register_boot", "BOOTREINIT_REGISTERED",
        "open_boot_phase", "begin_next_boot", "run_pending_boot_callbacks"] {
        assert!(BOOT.contains(evidence), "boot callback must retain {evidence}");
    }
    let launch = SERVICE.find("launch_live_pnp_plans(").expect("boot driver launch");
    let first_critical = SERVICE.find("unsafe fn start_committed_critical_children(")
        .expect("deferred PnP DriverEntry phase");
    let drain = SERVICE.find("run_pending_boot_callbacks(").expect("boot callback phase");
    assert!(launch < first_critical && first_critical < drain,
        "boot callbacks run after deferred critical PnP DriverEntry admission");
    let before_critical = &SERVICE[launch..first_critical];
    assert!(!before_critical.contains("run_pending_boot_callbacks("),
        "initial PnP plan launch cannot seal the boot callback phase before disk.sys loads");
}

#[test]
fn ordinary_reinit_registered_inside_boot_callback_is_drained_after_boot_ack() {
    let pump = &SERVICE[SERVICE.find("unsafe fn pump_hosted_io_and_redrive_driver_starts(")
        .expect("hosted I/O pump")..];
    let boot = pump.find("driver_launch::run_pending_boot_callbacks()").expect("boot drain");
    let ordinary = pump.find("driver_launch::run_pending_ordinary_callbacks()")
        .expect("ordinary drain after boot callback");
    assert!(boot < ordinary);
    assert!(ORDINARY.contains("begin_next_ready("));
    assert!(ORDINARY.contains("acknowledge(ticket)"));
    assert!(ORDINARY.contains("boot_drain_active"));
}

#[test]
fn make_temporary_uses_canonical_directory_handle_and_lifetime() {
    assert!(LAUNCH.contains("\"ZwMakeTemporaryObject\""));
    assert!(TEMP.contains("make_temporary_with_label"));
    assert!(BROKER.contains("make_temporary_provider_directory_object"));
    assert!(DIRECTORY.contains("lookup_native_object_directory_handle"));
    assert!(DIRECTORY.contains("entry.permanent = false"));
    assert!(DIRECTORY.contains("close_provider_directory_object"));
}

#[test]
fn safe_boot_import_is_a_writable_ulong_data_cell() {
    assert!(LAUNCH.contains("\"InitSafeBootMode\""));
    assert!(SAFE.contains("SAFE_BOOT_MODE_OFFSET"));
    assert!(SAFE.contains("write_volatile"));
    assert!(SAFE.contains("as *mut u32"));
    assert!(SAFE.contains("pub(super) const SAFE_BOOT_MODE_VA"));
}
