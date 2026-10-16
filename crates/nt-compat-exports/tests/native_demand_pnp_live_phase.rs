//! A registry-selected PnP DriverEntry may synchronously open another driver's device.
//! The pinned LiberNT BasicDisplay boot/system driver does this with
//! IoGetDeviceObjectPointer after loading dxgkrnl. The CREATE continuation requires
//! the live ExecNtHandler, so both PnP Start classes launch after registration.

const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn all_registry_pnp_launch_occurs_after_live_file_handler_registration() {
    let boot_loop = MAIN
        .split("// Registry-selected PnP plans, PCI grants, and resource windows are already captured.")
        .nth(1)
        .expect("bootstrap PnP selection")
        .split("// The storage host read the installed SMSS image")
        .next()
        .expect("bootstrap PnP selection boundary");
    assert!(boot_loop.contains("[config_pnp_plan, config_demand_pnp_plan]"),
        "both Start classes must retain precomputed devnode selection");
    assert!(!boot_loop.contains("launch_boot_driver_service("),
        "no registry PnP DriverEntry may run before the live handler");

    let live = SERVICE
        .split("register_service_delay_drain_context(&mut nt_handler, delay_queue);")
        .nth(1)
        .expect("live handler registration");
    let demand = live.find("launch_live_pnp_plans(")
        .expect("PnP launch in live handler phase");
    let first_receive = live.find("// Per-hosted-process state")
        .expect("first live receive setup");
    assert!(demand < first_receive,
        "PnP dependencies must load before user-mode receive begins");
    assert!(live[demand..first_receive].contains("&[boot_system_pnp_plan, demand_pnp_plan]"),
        "both registry PnP Start classes must use the live handler phase");
}
