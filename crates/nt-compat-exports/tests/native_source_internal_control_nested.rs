const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");

#[test]
fn retained_internal_control_runs_during_nested_driver_activation() {
    assert!(LAUNCH.contains("fn nested_hosted_internal_control_ready()"));
    assert!(LAUNCH.contains("fn redrive_nested_hosted_internal_control("));

    let nested_sweep = SERVICE
        .split("pub(crate) unsafe fn redrive_nested_hosted_file_work()")
        .nth(1)
        .expect("nested hosted work sweep")
        .split("pub(crate) unsafe fn watchdog_defer_if_hosted_work_can_run")
        .next()
        .expect("end of nested sweep");
    assert!(nested_sweep.contains("nested_hosted_internal_control_ready()"));
    assert!(nested_sweep.contains("redrive_nested_hosted_internal_control(handler)"));

    assert!(PUMP.contains("service_sec_image::nested_hosted_file_work_ready()"));
    let nested_pump = SERVICE
        .split("pub(crate) unsafe fn nested_hosted_file_work_ready()")
        .nth(1)
        .expect("nested pump readiness checks")
        .split("pub(crate) unsafe fn redrive_nested_hosted_file_work()")
        .next()
        .expect("end of readiness checks");
    assert!(nested_pump.contains("nested_hosted_internal_control_ready()"));
}
