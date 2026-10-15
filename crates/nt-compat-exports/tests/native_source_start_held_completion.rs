//! An inline completion defers only while its exact source allocation has a live pin.

#[test]
fn completed_start_dispatch_transfers_held_source_before_graph_release() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let completed = &driver[driver.find("HOSTED_IRP_COMPLETED_DISPATCH => {").unwrap()..];
    let completed = &completed[..completed.find("HOSTED_IRP_COMPLETING_DISPATCH => {").unwrap()];
    assert!(completed.contains("retained_caller_source_pin(owner_node, canonical_irp_id, irp)"));
    assert!(completed.contains("dispatch_return_with_retained_source"));
    assert!(!completed.contains("armed_held_pnp_source_matches"));
    assert!(!completed.contains("acknowledge_held_pnp_if_terminal(irp)"));
    assert!(completed.contains("return (STATUS_PENDING as i32, 0)"));
}

/// A source ticket identifies the projection; only an actual lower-forward or StartIo pin
/// transfers an inline terminal to the deferred publisher.
#[test]
fn source_ticket_alone_does_not_defer_inline_completion() {
    use nt_io_manager::source_irp_ledger::{SourceIrpAllocation, SourceIrpLedger, SourceIrpLedgerError, SourceIrpOwner};
    use nt_io_manager::{CompletionOwnerPhase, HostedDomainId, HostedDomainIdentity};

    let mut ledger = SourceIrpLedger::new();
    let allocation = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedCaller(4),
        domain: HostedDomainIdentity { domain_id: HostedDomainId(4), cookie: 9 },
        component_address: 0x1000,
        bytes: 0x200,
        stack_count: 2,
        pool_generation: 7,
    };
    let ticket = ledger.register(allocation).unwrap();
    assert_eq!(ledger.retirement_ready(ticket, allocation), Ok(()));
    assert_eq!(
        CompletionOwnerPhase::CompletedDispatch.dispatch_return_with_retained_source(false, false),
        None,
    );

    assert_eq!(
        ledger.pin_hosted_forward(4, allocation.domain, allocation.component_address),
        Ok((ticket, allocation)),
    );
    assert_eq!(ledger.retirement_ready(ticket, allocation), Err(SourceIrpLedgerError::Pinned));

    assert_eq!(
        CompletionOwnerPhase::CompletedDispatch
            .dispatch_return_with_retained_source(false, true),
        Some(CompletionOwnerPhase::Ready),
    );
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let completed = &driver[driver.find("HOSTED_IRP_COMPLETED_DISPATCH => {").unwrap()..];
    let completed = &completed[..completed.find("HOSTED_IRP_COMPLETING_DISPATCH => {").unwrap()];
    assert!(completed.contains("retained_caller_source_pin(owner_node, canonical_irp_id, irp)"));
    assert!(completed.contains("dispatch_return_with_retained_source"));
    assert!(completed.contains("return (STATUS_PENDING as i32, 0)"));

    let source = &driver[driver.find("unsafe fn retained_caller_source_pin(").unwrap()..];
    let source = &source[..source.find("unsafe fn claim_pending_irp_completion(").unwrap()];
    assert!(source.contains("FSD_SERVICE_SOURCE_IRP_LABEL"));
    assert!(source.contains("11,"));
    assert!(source.contains("owner_node"));
    assert!(source.contains("canonical_irp_id"));
    assert!(source.contains("irp"));

    let service = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let exact = &service[service.find("11 => {").unwrap()..];
    let exact = &exact[..exact.find("7 | 8 | 9 | 10 => {").unwrap()];
    assert!(exact.contains("let node_generation = row.node_generation"));
    assert!(exact.contains("Some(node_generation)"));
    assert!(exact.contains("row.canonical_irp_id == canonical_irp_id"));
    assert!(exact.contains("row.allocation.component_address == raw_irp"));
    assert!(exact.contains("SourceIrpLedgerError::Pinned"));

    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let publisher = &ledger[ledger.find("pub(super) fn caller_completion_publishable(").unwrap()..];
    let publisher = &publisher[..publisher.find("pub(super) fn release_pending_terminal(").unwrap()];
    assert!(publisher.contains("row.node_generation == node_generation"));
    assert!(publisher.contains("row.canonical_irp_id == canonical_irp_id"));
    assert!(publisher.contains("row.allocation.component_address == raw_irp"));
    assert!(publisher.contains("ledger().retirement_ready(ticket, row_allocation).is_ok()"));
}

#[test]
fn start_ack_service_requires_an_exact_post_unwind_terminal_event() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let direct = &driver[driver.find("if exact_fdo != 0 {").unwrap()..];
    let direct = &direct[..direct.find("let (label, classification").unwrap()];
    assert!(direct.find("mark_direct_start_terminal(irp, start_token)").unwrap()
        < direct.find("retire_direct_pnp_ack(irp, start_token, 7)").unwrap());
    let held = &driver[driver.find("unsafe fn acknowledge_held_pnp_if_terminal(").unwrap()..];
    let held = &held[..held.find("extern \"win64\" fn s_io_complete_request").unwrap()];
    assert!(held.contains("table.terminal(irp)"));
    assert!(held.contains("finish_held_pnp_ack(ack)"));

    let work = include_str!("../../../components/ntos-executive/src/hosted_start_fdo_work.rs");
    let ack = &work[work.find("pub(super) unsafe fn acknowledge(").unwrap()..];
    let ack = &ack[..ack.find("pub(super) unsafe fn service(").unwrap()];
    assert!(ack.find("start_fdo_terminal_evidence(").unwrap()
        < ack.find("retire_stopped_acknowledged_retained_service(").unwrap());
    assert!(ack.contains("if held_completion { 8 } else { 7 }"));
}

#[test]
fn cancelled_start_retires_only_after_exact_source_release_yields_stop_witness() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_start_fdo_work.rs");
    let cancelled = &work[work.find("unsafe fn advance_cancelled(&mut self)").unwrap()..];
    let cancelled = &cancelled[..cancelled.find("unsafe fn advance_ack(&mut self)").unwrap()];
    let release = cancelled.find("self.source.release_terminal()").unwrap();
    let witness = cancelled.find("StartFdoSourceStopWitness::after_native_source_stop(").unwrap();
    let retire = cancelled.find("terminal.retire_after_source_stop(io_manager_mut(), witness)").unwrap();
    assert!(release < witness && witness < retire);
    assert!(cancelled.contains("if released.is_err() {\n                return false;"));
    assert!(cancelled.contains("self.source_stop_witness = Some(witness)"));
}
