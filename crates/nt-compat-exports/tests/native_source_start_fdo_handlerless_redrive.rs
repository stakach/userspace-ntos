//! A retained FDO START parked during AddDevice can redrive before the live File handler exists.

#[test]
fn nested_start_fdo_uses_retained_process_authority_without_file_handler() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_start_fdo_work.rs");
    let prepare = &work[work.find("unsafe fn prepare_and_dispatch(").unwrap()..];
    let prepare = &prepare[..prepare.find("unsafe fn dispatch_prepared(").unwrap()];
    assert!(prepare.contains("with_provider_process_manager(|pm| self.actor.validate(pm))"));
    assert!(!prepare.contains("(*handler).pm"));

    let runner = &work[work.find("pub(super) unsafe fn redrive_nested_ready(").unwrap()..];
    assert!(runner.contains("redrive_one(true)"));

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("pub(crate) unsafe fn nested_hosted_start_fdo_ready()"));
    assert!(launch.contains("pub(crate) unsafe fn redrive_nested_hosted_start_fdo()"));

    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let handlerless = &service[service.find("unsafe fn redrive_nested_hosted_input_work() -> bool {").unwrap()..];
    let handlerless = &handlerless[..handlerless.find("\n}").unwrap()];
    assert!(handlerless.contains("nested_hosted_start_fdo_ready()"));
    assert!(handlerless.contains("redrive_nested_hosted_start_fdo()"));
    let outer = &service[service.find("pub(crate) unsafe fn redrive_nested_hosted_file_work() -> bool {").unwrap()..];
    let guard = &outer[..outer.find("// Check each owner just before entering its runner.").unwrap()];
    assert!(guard.contains("if handler.is_null() { return redrive_nested_hosted_input_work(); }"));
}
