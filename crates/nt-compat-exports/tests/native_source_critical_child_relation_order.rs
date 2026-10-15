//! A terminal bus START must enumerate its children before a sibling START can hold the
//! global PnP lifecycle dispatch gate.

#[test]
fn queued_initial_bus_relations_precede_new_critical_child_start() {
    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let schedule = start
        .split("unsafe fn schedule_initial_bus_relations(")
        .nth(1)
        .expect("successful START must schedule its initial bus relation");
    let schedule = &schedule[..schedule.find("unsafe fn apply_devnode_progress(").unwrap()];
    assert!(schedule.contains("enqueue_hosted_initial_bus_relations(device_id)"));

    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let outer = service
        .split("unsafe fn pump_hosted_io_and_redrive_driver_starts(")
        .nth(1)
        .expect("missing outer PnP scheduler");
    let outer = &outer[..outer.find("fn pending_driver_start_redrive_needed(").unwrap()];
    let redrive = outer
        .find("pending_driver_start_redrive_all(nt_handler)")
        .expect("missing terminal START redrive");
    let critical = outer
        .find("start_committed_critical_children(nt_handler)")
        .expect("missing critical child admission");
    assert!(redrive < critical, "the PCI START may queue relations in redrive");

    let admission = service
        .split("unsafe fn start_committed_critical_children(")
        .nth(1)
        .expect("missing critical child scheduler");
    let admission = &admission[..admission
        .find("unsafe fn pump_hosted_io_and_redrive_driver_starts(")
        .unwrap()];
    let relation_guard = admission
        .find("driver_launch::hosted_bus_relation_pending()")
        .expect("a queued PCI BusRelations request must defer new critical child STARTs");
    let claim = admission
        .find("driver_launch::claim_hosted_critical_child_start(")
        .expect("missing critical child claim");
    assert!(
        relation_guard < claim,
        "relation admission must run before claiming and dispatching a child START"
    );
}
