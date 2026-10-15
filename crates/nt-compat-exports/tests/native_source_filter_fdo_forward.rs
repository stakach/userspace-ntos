//! The class FDO FILTER edge owns a retained lower dispatch and source completion.

#[test]
fn filter_fdo_service_uses_exact_lower_route_and_second_ack() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let service = &driver[driver
        .find("pub(crate) unsafe fn service_hosted_lower_pnp_forward(")
        .unwrap()..];
    let service = &service[..service
        .find("\n/// Admit the retained class CONNECT")
        .unwrap()];
    assert!(service.contains("hosted_filter_fdo_work::is_exact_fdo_target"));
    assert!(service.contains("operation == 3"));
    assert!(service.contains("operation == 4 || operation == 5"));
    let receipt = &driver[driver
        .find("pub(crate) fn service_hosted_source_irp_lifetime(")
        .unwrap()..];
    let receipt = &receipt[..receipt
        .find("pub(crate) fn service_hosted_driver_ps_get_current_thread_id")
        .unwrap()];
    assert!(receipt.contains("op == 6 && result.0 == STATUS_SUCCESS"));
    assert!(receipt.contains("hosted_filter_fdo_work::observe_provider_input"));

    let native = &driver[driver
        .find("if forwarded_minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS as u64")
        .unwrap()..];
    let native = &native[..native
        .find("if forwarded_minor == nt_pnp_abi::IRP_MN_START_DEVICE")
        .unwrap()];
    assert!(native.contains("let completion = complete_hosted_irp(irp)"));
    assert!(native.contains("completion == HostedIrpUnwindOutcome::MoreProcessingRequired"));
    let reserve = native.find("reserve_held_pnp_completion(irp, 5)").unwrap();
    let dispatch = native.find("call_on4(").unwrap();
    let bind = native.find("bind_held_pnp_completion(irp, filter_token)").unwrap();
    let arm = native.find("arm_held_pnp_completion(irp, filter_token)").unwrap();
    assert!(reserve < dispatch && dispatch < bind && bind < arm);
    assert!(native.contains("retire_direct_pnp_ack(irp, filter_token, 4)"));
    assert!(!native.contains("WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64"));
}

#[test]
fn pending_filter_completion_pumps_before_observing_exact_provider_irp() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_filter_fdo_work.rs");
    let poll = &work[work.find("unsafe fn poll_provider(&mut self)").unwrap()..];
    let poll = &poll[..poll.find("\n    unsafe fn publish_source").unwrap()];
    let pump = poll.find("pump_io_manager()").unwrap();
    let observe = poll.find("completed_irp(retained.provider_irp())").unwrap();
    assert!(pump < observe);
    assert!(poll.contains("self.physical.storage_instance"));
    assert!(poll.contains("self.physical.storage_domain"));
    assert!(poll.contains("retained.identity()"));
    assert!(poll.contains("retained.prepare_completion("));
    let capture =
        include_str!("../../../components/ntos-executive/src/hosted_filter_fdo_capture.rs");
    let initial = &capture[capture.find("pub(super) unsafe fn capture(").unwrap()..];
    assert!(initial.contains("pin_temporary_pool_range(inst, input, 1)"));
    assert!(initial.contains("input_pin: Some(input_pin)"));
    assert!(initial.contains("canonical_source_irp: IrpId"));
    assert!(!initial.contains("read_value::<IoStackLocation>(irp.current_stack_location.0)"));
    assert!(initial.contains("hosted_device_by_identity(domain, next.device_object.0)"));
    assert!(initial.contains("hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)"));
    assert!(initial.contains("next_stack_address(allocation, &irp)"));
    assert!(initial.contains("release_temporary_pool_pin(&mut input_pin)"));
}

#[test]
fn filter_provider_keeps_canonical_requestor_identity() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_filter_fdo_work.rs");
    let prepare = &work[work
        .find("unsafe fn prepare_and_dispatch(&mut self")
        .unwrap()..];
    let prepare = &prepare[..prepare
        .find("unsafe fn dispatch_prepared(&mut self")
        .unwrap()];
    assert!(prepare.contains("let requestor_tid = source_irp.requestor_tid;"));
    assert!(prepare.contains("requestor_tid,\n"));
    assert!(!prepare.contains("u64::from(self.caller.original_thread().thread_id())"));
}

#[test]
fn nested_accepted_pdo_filter_uses_published_outer_edge_and_local_ack() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_filter_fdo_work.rs");
    let edge =
        include_str!("../../../components/ntos-executive/src/hosted_accepted_pdo_filter_edge.rs");
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(work.contains("hosted_accepted_pdo_filter_edge::publish("));
    assert!(work.contains("hosted_accepted_pdo_filter_edge::retire_unentered("));
    assert!(edge.contains("active_caller_projection_matches("));
    assert!(edge.contains("hosted_source_irp_ledger::pin("));
    let compact_edge: String = edge.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact_edge.contains("row.edge.consume_proof("));
    assert!(edge.contains("caller_terminal_ready(ticket, allocation)"));
    assert!(edge.contains("release_pending_terminal(ticket, allocation)"));
    let service = &driver[driver
        .find("pub(crate) unsafe fn service_hosted_lower_pnp_forward(")
        .unwrap()..];
    let service = &service[..service
        .find("\n/// Admit the retained class CONNECT")
        .unwrap()];
    assert!(service.contains("hosted_accepted_pdo_filter_edge::acknowledge("));
    let native = &driver[driver
        .find("if forwarded_minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS as u64")
        .unwrap()..];
    let native = &native[..native
        .find("if forwarded_minor == nt_pnp_abi::IRP_MN_START_DEVICE")
        .unwrap()];
    assert!(
        native.contains("if accepted != 0 {")
            && native.contains("bind_held_pnp_completion(irp, filter_token)")
    );
    assert!(native.contains("if completion == HostedIrpUnwindOutcome::MoreProcessingRequired"));
    assert!(native.contains("arm_held_pnp_completion(irp, filter_token)"));
    assert!(native.contains("retire_direct_pnp_ack(irp, filter_token, 4)"));
}

#[test]
fn inline_accepted_pdo_filter_reply_explicitly_clears_ack_token_register() {
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let route = &pump[pump
        .find("label == crate::driver_launch::FSD_SERVICE_LOWER_PNP_FORWARD_LABEL")
        .unwrap()..];
    let compact: String = route.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact
        .contains("iflabel==crate::driver_launch::FSD_SERVICE_LOWER_PNP_FORWARD_LABEL&&msg.m0==3"));
    assert!(compact.contains(
        "pump_reply_recv4_into!(ch,*reply_cap,msg,3,statusasu32asu64,u64::from(accepted),0,0)"
    ));
}

#[test]
fn synchronous_class_start_uses_exact_cross_domain_fdo_forward() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let native = &driver[driver
        .find("extern \"win64\" fn s_iof_call_driver(")
        .unwrap()..];
    let start = &native[native
        .find("if forwarded_minor == nt_pnp_abi::IRP_MN_START_DEVICE as u64")
        .unwrap()..];
    let start = &start[..start.find("let (_, result, handled").unwrap()];
    let service = &driver[driver
        .find("pub(crate) unsafe fn service_hosted_lower_pnp_forward(")
        .unwrap()..];
    assert!(service.contains("hosted_start_fdo_work::is_exact_fdo_target"));
    assert!(start.contains("let (kind_label, kind_status, exact_fdo"));
    assert!(start.contains("(FSD_SERVICE_LOWER_PNP_FORWARD_LABEL << 12) | 4,\n                9,"));
    assert!(
        start.contains("(FSD_SERVICE_LOWER_PNP_FORWARD_LABEL << 12) | 4,\n                    6,")
    );
    assert!(start.contains("FSD_SERVICE_LOWER_PNP_FORWARD_LABEL"));
    assert!(start.contains("complete_hosted_irp(irp)"));
    let reserve = start.find("reserve_held_pnp_completion(irp, 8)").unwrap();
    let dispatch = reserve + start[reserve..].find("call_on4(").unwrap();
    let bind = start.find("bind_held_pnp_completion(irp, start_token)").unwrap();
    let arm = start.find("arm_held_pnp_completion(irp, start_token)").unwrap();
    assert!(reserve < dispatch && dispatch < bind && bind < arm);
    assert!(start.contains("retire_direct_pnp_ack(irp, start_token, 7)"));
    assert!(start.contains("completion == HostedIrpUnwindOutcome::MoreProcessingRequired"));
    let capture =
        include_str!("../../../components/ntos-executive/src/hosted_start_fdo_capture.rs");
    assert!(capture.contains("pin_temporary_pool_range(inst, raw_address, 1)"));
    assert!(capture.contains("pin_temporary_pool_range(inst, translated_address, 1)"));
    assert!(capture.contains("release_pending_terminal(self.ticket, self.allocation)"));
    assert!(capture.contains("let upper_address = current.device_object.0;"));
    assert!(capture.contains("stack.device_object.0 != target_address"));
    assert!(capture.contains("current.device_object.0 != self.upper_address"));
    assert!(capture.contains("stack.device_object.0 != self.target_address"));
    let first_pin = capture
        .find("pin_temporary_pool_range(inst, raw_address, 1)")
        .unwrap();
    let unlock = capture.find("drop(memory);").unwrap();
    assert!(unlock < first_pin);
    assert!(capture[first_pin..].contains("let memory = SourcePoolMemory::new(inst)"));
    assert!(capture.contains("observed_current.device_object.0 != upper_address"));
    assert!(capture.contains("observed_next.device_object.0 != target_address"));
    let work = include_str!("../../../components/ntos-executive/src/hosted_start_fdo_work.rs");
    assert!(work.contains("PreparedStartFdoForward::prepare("));
    assert!(work.contains("pump_io_manager()"));
    assert!(work.contains("completed_irp(retained.provider_irp())"));
    assert!(work.contains("work.source.caller_terminal_ready()"));
    assert!(work.contains("retained.identity()"));
    assert!(work.contains("retained.prepare_completion("));
    assert!(service.contains("operation == 7 || operation == 8"));
}
