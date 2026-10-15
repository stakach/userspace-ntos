//! A parked PCI-to-ACPI START must publish the provider's terminal before testing readiness.

#[test]
fn nested_lower_pnp_start_pumps_provider_completion_before_eligibility() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_lower_pnp_work.rs");
    let start = work.find("unsafe fn ready_for_nested_step(&self) -> bool {").unwrap();
    let end = work[start..].find("unsafe fn dispatch_provider(").unwrap() + start;
    let readiness = &work[start..end];

    let pump = readiness.find("pump_io_manager()").expect(
        "retained lower START must make the native provider completion visible to the I/O Manager",
    );
    let retained = readiness.find("self.retained.is_some()").unwrap();
    let completed = readiness
        .find("completed_irp(retained.provider_irp())")
        .unwrap();
    assert!(retained < pump && pump < completed);

    let runner = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let nested = runner
        .find("pub(crate) unsafe fn redrive_nested_hosted_file_work() -> bool {")
        .unwrap();
    let nested = &runner[nested..runner[nested..].find("\n}").unwrap() + nested];
    assert!(nested.contains("nested_hosted_lower_pnp_ready()"));
    assert!(nested.contains("redrive_nested_hosted_lower_pnp(handler)"));
}
