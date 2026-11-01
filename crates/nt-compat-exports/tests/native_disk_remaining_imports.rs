//! Pinned disk.sys imports must use live native owners and a real data cell.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const BOOT: &str =
    include_str!("../../../components/ntos-executive/src/hosted_boot_driver_reinitialization.rs");
const ORDINARY: &str =
    include_str!("../../../components/ntos-executive/src/hosted_driver_reinitialization.rs");
const TEMP: &str =
    include_str!("../../../components/ntos-executive/src/hosted_driver_make_temporary.rs");
const DIRECTORY_PROTOCOL: &str =
    include_str!("../../../components/ntos-executive/src/win32k_subsystem/directory_object.rs");
const SAFE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_driver_safe_boot.rs");
const BROKER: &str =
    include_str!("../../../components/ntos-executive/src/provider_directory_broker.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn boot_reinit_registration_is_owned_and_drained_after_boot_driver_launch() {
    assert!(LAUNCH.contains("\"IoRegisterBootDriverReinitialization\""));
    for evidence in [
        "validated_registration",
        "register_boot",
        "BOOTREINIT_REGISTERED",
        "open_boot_phase",
        "begin_next_boot",
        "run_pending_boot_callbacks",
    ] {
        assert!(
            BOOT.contains(evidence),
            "boot callback must retain {evidence}"
        );
    }
    let launch = SERVICE
        .find("launch_live_pnp_plans(")
        .expect("boot driver launch");
    let first_critical = SERVICE
        .find("unsafe fn start_committed_critical_children(")
        .expect("deferred PnP DriverEntry phase");
    let drain = SERVICE
        .find("run_pending_boot_callbacks(")
        .expect("boot callback phase");
    assert!(
        launch < first_critical && first_critical < drain,
        "boot callbacks run after deferred critical PnP DriverEntry admission"
    );
    let before_critical = &SERVICE[launch..first_critical];
    assert!(
        !before_critical.contains("run_pending_boot_callbacks("),
        "initial PnP plan launch cannot seal the boot callback phase before disk.sys loads"
    );
}

#[test]
fn ordinary_reinit_registered_inside_boot_callback_is_drained_after_boot_ack() {
    let pump = &SERVICE[SERVICE
        .find("unsafe fn pump_hosted_io_and_redrive_driver_starts(")
        .expect("hosted I/O pump")..];
    let boot = pump
        .find("driver_launch::run_pending_boot_callbacks()")
        .expect("boot drain");
    let ordinary = pump
        .find("driver_launch::run_pending_ordinary_callbacks()")
        .expect("ordinary drain after boot callback");
    assert!(boot < ordinary);
    assert!(ORDINARY.contains("begin_next_ready("));
    assert!(ORDINARY.contains("acknowledge(ticket)"));
    assert!(ORDINARY.contains("boot_drain_active"));
}

#[test]
fn make_temporary_routes_driver_op15_through_retained_canonical_effect() {
    assert!(LAUNCH.contains("\"ZwMakeTemporaryObject\""));
    assert!(TEMP.contains("make_temporary_with_label"));
    assert!(DIRECTORY_PROTOCOL.contains("const MAKE_TEMPORARY: u64 = 15;"));
    assert!(
        DIRECTORY_PROTOCOL.contains("call_with_label(label, MAKE_TEMPORARY, handle, 0, 0, false)")
    );

    let dispatch = &BROKER[BROKER
        .find("pub(crate) unsafe fn dispatch(")
        .expect("provider directory dispatch")..];
    let op15 = dispatch
        .find("7 | 15 => broker.submit_effect(")
        .expect("make-temporary and close enter retained effect dispatch");
    let ordinary = dispatch
        .find("match broker.dispatch(")
        .expect("ordinary directory operations remain distinct");
    assert!(op15 < ordinary);
    assert!(dispatch[op15..ordinary].contains("broker.submit_effect("));

    let effect = &BROKER[BROKER
        .find("unsafe fn submit_effect(")
        .expect("retained provider directory effect")..];
    let identity = effect
        .find("provider_directory_effect_identity(")
        .expect("the exact PM directory handle and DELETE grant are admitted");
    let retained = effect
        .find("park_retained_service(")
        .expect("the provider Reply is retained before canonical mutation");
    let canonical = effect
        .find("make_temporary_provider_directory_canonical(")
        .expect("op 15 changes the canonical directory owner");
    let local = effect
        .find("finish_provider_directory_make_temporary(")
        .expect("local permanence follows canonical completion");
    assert!(identity < retained && retained < canonical && canonical < local);
    // The backing's pending/terminal lease behavior is exercised by
    // nt-user-host::canonical_directory_backing unit tests.
}

#[test]
fn safe_boot_import_is_a_writable_ulong_data_cell() {
    assert!(LAUNCH.contains("\"InitSafeBootMode\""));
    assert!(SAFE.contains("SAFE_BOOT_MODE_OFFSET"));
    assert!(SAFE.contains("write_volatile"));
    assert!(SAFE.contains("as *mut u32"));
    assert!(SAFE.contains("pub(super) const SAFE_BOOT_MODE_VA"));
}
