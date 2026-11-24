//! A failed StartDevice still owns its completion and cleanup, but must not wait for
//! resource-use receipts that are required only to publish a successful start.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn between<'a>(start: &str, end: &str) -> &'a str {
    SOURCE
        .split_once(start)
        .unwrap_or_else(|| panic!("missing native path: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing native path end: {end}"))
        .0
}

#[test]
fn failed_start_settles_before_success_only_resource_publication() {
    let publication = between(
        "unsafe fn finish_hosted_start_publication(",
        "unsafe fn finish_hosted_stop_publication(",
    );
    let status = publication
        .find("let terminal_status = transaction")
        .expect("use the retained driver completion status");
    let failed_exit = publication
        .find("if !terminal_status.is_success() {")
        .expect("failed StartDevice must settle without success publication");
    let return_ok = publication[failed_exit..]
        .find("return Ok(());")
        .expect("failed StartDevice must let the retained terminal receipt progress")
        + failed_exit;
    let first_success_gate = publication
        .find("hosted_mmio_broker::validate_publication(binding, bus_owned_root_proof)?")
        .expect("successful StartDevice still validates exact MMIO use");
    assert!(status < failed_exit && return_ok < first_success_gate);
    for gate in [
        "hosted_device_publication_decision::start_publication(",
        "replay_hosted_dma_allocation_records(binding, sh)?",
        "refresh_hosted_device_interrupt_state_from_retained(binding, state)",
        "crate::power_manager::complete_start(binding.pdo_device_id)?",
    ] {
        assert!(
            return_ok < publication.find(gate).expect("successful start publication gate"),
            "failure must bypass {gate}",
        );
    }
}

#[test]
fn failed_start_keeps_lifecycle_receipt_and_original_driver_error() {
    let lifecycle = between(
        "unsafe fn complete_hosted_pnp_lifecycle(",
        "unsafe fn finish_hosted_start_publication(",
    );
    for required in [
        "complete_start_device_dispatch(token, fdo_device_id, io_receipt)",
        "nt_pnp_manager::DeviceState::Failed",
        ".start_receipt = Some(receipt)",
    ] {
        assert!(lifecycle.contains(required), "missing failed-start lifecycle: {required}");
    }

    let drain = between(
        "unsafe fn drain_hosted_pnp_completions()",
        "pub(crate) unsafe fn observe_hosted_pnp_start(",
    );
    let ordered = [
        "complete_hosted_pnp_lifecycle(irp_id, completion_status)",
        "set_hosted_pnp_driver_status(",
        "acknowledge_completed_irp_strict(irp_id)",
        "mark_pending_start_irp_retired(irp_id)",
        "finish_hosted_pnp_publication(irp_id)",
        "mark_pending_start_publication_committed(irp_id)",
        "HostedPnpTransactionPhase::Terminal",
    ];
    let mut previous = 0;
    for step in ordered {
        let position = drain.find(step).unwrap_or_else(|| panic!("missing settlement step: {step}"));
        assert!(position >= previous, "settlement step out of order: {step}");
        previous = position;
    }

    let terminal = between(
        "unsafe fn take_terminal_hosted_pnp_start(",
        "pub(crate) unsafe fn print_hosted_pnp_pending_proofs(",
    );
    assert!(terminal.contains("receipt.start_status() != driver_status.raw() as u32"));
    assert!(terminal.contains("Ok((driver_status, receipt))"));
}
