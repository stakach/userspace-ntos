//! The retained scheduler reports work without changing its ownership order.

const SCHEDULER: &str = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");

#[test]
fn retained_scheduler_service_returns_an_observation_only_sample() {
    let service = SCHEDULER.split("pub(crate) unsafe fn service_irq_yield(").nth(1).unwrap()
        .split("\n}\n\nimpl Drop for ComponentSchedulerScope").next().unwrap();
    let park = service.find("runtime::nested::park_current()").unwrap();
    let timer = service.find("service_hosted_timer_work()").unwrap();
    let irq = service.find("drain_pending_hosted_irqs_snapshot()").unwrap();
    let dpc = service.find("drain_hosted_driver_dpcs()").unwrap();
    let prepare = service.find("dispatcher_bootstrap::prepare_receive()").unwrap();
    let restore = service.find("runtime::nested::restore(&mut parent)").unwrap();
    assert!(park < timer && timer < irq && irq < dpc && dpc < prepare && prepare < restore);
    assert!(service.contains("SchedulerServiceClock::new(")
        && service.contains("SchedulerServiceSample"),
        "RED: each retained service pass needs a stack-local phase sample");
}

#[test]
fn only_the_exact_observed_scsi_claim_records_the_sample() {
    let scheduler = SCHEDULER.split("unsafe fn hosted_component_pump_inner(").nth(1).unwrap();
    let yield_loop = scheduler.split("while result.scheduler_yielded {").nth(1).unwrap()
        .split("\n    if result.completed {").next().unwrap();
    assert!(yield_loop.contains("observed_owner")
        && yield_loop.contains("record_scheduler_service("),
        "RED: record the returned sample only through the admitted SCSI owner claim");
    assert!(yield_loop.contains("scope.service_irq_yield(channel.shared_va)"));
}
