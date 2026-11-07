//! The first packet owner must be admitted from the root's exact op6 projection.
//! Native packet imports may be published only with the retained callback and terminal path.

use std::path::Path;

fn native(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    std::fs::read_to_string(path).expect("native StartIo source")
}

#[test]
fn projected_packet_admission_uses_root_node_and_physical_source_owner() {
    let source = native("hosted_source_irp_ledger.rs");
    let adapter = native("hosted_start_io.rs");
    let memory = native("hosted_start_io_packet.rs");
    assert!(source.contains("fn admit_projected_start_io_packet("));
    assert!(source.contains("StartIoAdmission::acquire_projected("));
    assert!(source.contains("caller_projections()"));
    assert!(source.contains("projected_node("));
    assert!(adapter.contains("fn prepare_first_projected_packet("));
    assert!(adapter.contains("CurrentReceipt::new("));
    assert!(adapter.contains("LivePacket::new("));
    assert!(memory.contains("hosted_instance_pool_lock("));
    assert!(memory.contains("impl LockedStartIoMemory for LockedFirstPacketMemory"));
}

#[test]
fn input_packet_imports_reach_native_start_io_adapters() {
    let launch = native("driver_launch.rs");
    let registry = launch
        .split("fn register_fsd_trampolines(")
        .nth(1)
        .expect("import registry");
    for (import, adapter) in [
        ("IoStartPacket", "s_io_start_packet"),
        ("IoStartNextPacket", "s_io_start_next_packet"),
    ] {
        assert!(registry.contains(&format!("\"{import}\",")),
            "{import} must have a real native PE binding");
        assert!(registry.contains(&format!("hosted_start_io::{adapter}")),
            "{import} must bind its native adapter");
    }
}

#[test]
fn i8042prt_debug_import_has_an_explicit_native_handler() {
    let launch = native("driver_launch.rs");
    let registry = launch
        .split("fn register_fsd_trampolines(")
        .nth(1)
        .expect("import registry");
    assert!(registry.contains("bind_kd_debug_export(reg)"),
        "the shared native Kd binder must be registered");
    let binder = launch
        .split("fn bind_kd_debug_export(")
        .nth(1)
        .expect("shared native Kd binder")
        .split("\n}")
        .next()
        .unwrap();
    assert!(binder.contains("\"KdSystemDebugControl\","),
        "i8042prt's strict PE import must resolve to a native handler");
    assert!(binder.contains("hosted_kd_debug::s_kd_system_debug_control"),
        "debug-control behavior must have a focused native adapter");
}

#[test]
fn first_packet_ingress_routes_through_authenticated_root_service() {
    let launch = native("driver_launch.rs");
    let adapter = native("hosted_start_io.rs");
    assert!(adapter.contains("fn service_start_packet("),
        "authenticated root ingress must own the first packet operation");
    assert!(launch.contains("hosted_start_io::service_start_packet("),
        "root device service must route the packet request");
}

#[test]
fn first_packet_commit_retains_current_and_callback_before_reply() {
    let adapter = native("hosted_start_io.rs");
    let memory = native("hosted_start_io_packet.rs");
    assert!(adapter.contains("fn commit_first_projected_packet("));
    assert!(adapter.contains("StartIoCallbackFence::new("));
    assert!(adapter.contains("struct FirstPacketCurrentSlot"));
    assert!(adapter.contains("first_packet_current()"));
    assert!(adapter.contains("fn begin_first_packet_reply("));
    assert!(adapter.contains("fn first_packet_callback_returned("));
    assert!(adapter.contains("retain_hosted_device_projection_reference("));
    assert!(adapter.contains("release_prepared_first_packet("));
    assert!(adapter.contains("release_projected_start_io_packet("));
    assert!(memory.contains("start_io::start_packet::<_, ()>("));
    assert!(memory.contains("prepare_update("));
    assert!(memory.contains("prepared_update.commit("));
}

#[test]
fn first_packet_commit_revalidates_node_under_same_pool_lock_as_queue_write() {
    let memory = native("hosted_start_io_packet.rs");
    let source = native("hosted_source_irp_ledger.rs");
    let acquire = memory.split("fn locked_first_packet_memory(").nth(1)
        .expect("locked packet adapter");
    let check = acquire.find("projected_start_io_node_matches_locked(")
        .expect("same-lock pending node revalidation");
    let pool = acquire.find("hosted_instance_pool_lock(").expect("physical pool lock");
    assert!(pool < check, "node must be revalidated after acquiring physical pool lock");
    assert!(source.contains("fn projected_start_io_node_matches_locked("));
}

#[test]
fn terminal_observation_uses_first_then_source_then_pool_lock_order() {
    let source = native("hosted_source_irp_ledger.rs");
    let retirement = source.split("7 | 8 | 9 | 10 => {").nth(1)
        .expect("caller projection retirement");
    let first = retirement.find("(op == 7).then(hosted_start_io::lock_first_packets)")
        .expect("first-packet transaction lock");
    let ledger = retirement.find("let _guard = lock();").expect("source ledger lock");
    let pool = retirement.find("hosted_instance_pool_lock(inst.exec_pool_va)")
        .expect("physical pool lock");
    assert!(first < ledger && ledger < pool);
    let adapter = native("hosted_start_io.rs");
    let terminal = adapter.split("fn observe_terminal_before_retirement(").nth(1)
        .expect("terminal observation");
    assert!(!terminal.split("fn settle_first_packet(").next().unwrap().contains("let _guard = lock_first_packets()"),
        "observation must use its caller's already-held first-packet lock");
}

#[test]
fn committed_callback_and_terminal_observations_do_not_fail_on_cleanup_refusal() {
    let adapter = native("hosted_start_io.rs");
    let callback = adapter.split("fn first_packet_callback_returned(").nth(1).unwrap()
        .split("fn observe_terminal_before_retirement(").next().unwrap();
    let terminal = adapter.split("fn observe_terminal_before_retirement(").nth(1).unwrap()
        .split("fn settle_first_packet(").next().unwrap();
    assert!(callback.contains("let _ = settle_first_packet(index);"));
    assert!(callback.contains("Ok(())"));
    assert!(!terminal.contains("settle_first_packet(index)"),
        "terminal poll must leave local release to the drain after IoManager's borrow ends");
    assert!(terminal.contains("Ok(())"));
}

#[test]
fn native_completion_pump_retries_start_io_checked_cleanup() {
    let launch = native("driver_launch.rs");
    let pump = launch.split("fn pump_hosted_io_completions(").nth(1).unwrap()
        .split("fn hosted_file_retry_deadline(").next().unwrap();
    assert!(pump.contains("hosted_start_io::drain_cleanup()"),
        "cleanup needs a root pump path even when no later StartIo call arrives");
}

#[test]
fn ready_completion_waits_for_exact_start_io_callback_before_publication() {
    let launch = native("driver_launch.rs");
    let poll = launch.split("fn poll_hosted_completion_at_storage(").nth(1).unwrap()
        .split("fn ").next().unwrap();
    assert!(poll.contains("caller_completion_publishable("),
        "READY ownership must be checked before publication");
    let source = native("hosted_source_irp_ledger.rs");
    let gate = source.split("fn caller_completion_publishable(").nth(1).unwrap()
        .split("fn ").next().unwrap();
    assert!(gate.contains("hosted_start_io::lock_first_packets()"),
        "completion admission must serialize with callback return and packet publication");
    assert!(gate.contains("HOSTED_IRP_COPYING"),
        "only the claimed READY terminal node may release the source pin");
    assert!(gate.contains("hosted_start_io::observe_terminal_before_retirement("),
        "release the exact retained packet owner before the existing retirement-ready check");
    assert!(gate.find("hosted_start_io::observe_terminal_before_retirement(").unwrap()
        < gate.find("ledger().retirement_ready(").unwrap());
    let adapter = native("hosted_start_io.rs");
    assert!(adapter.contains("ReplyPhase::CallbackReturned"),
        "terminal transfer must wait for callback return");
}

#[test]
fn queued_start_io_uses_actual_wdm_selection_and_retained_source_owner() {
    let adapter = native("hosted_start_io.rs");
    let memory = native("hosted_start_io_packet.rs");
    assert!(adapter.contains("QueuedStartIo<"),
        "queued packets need root-owned exact source/device receipts");
    assert!(memory.contains("Action::Queued"),
        "busy queue insertion must transfer the physical packet owner");
    assert!(memory.contains("Action::Start"),
        "next packet must select from the WDM queue under its lock");
    assert!(adapter.contains(".select("),
        "selected WDM packet must match the retained source identity");
    assert!(memory.contains("remove_device_queue(&mut PreviewQueueMemory(&memory)"),
        "select the actual WDM head with a zero-write preview under the pool lock");
    assert!(adapter.contains("HOSTED_DEVICE_OP_START_NEXT_PACKET_CALLBACK_RETURNED"),
        "selected packet callback return needs its own exact acknowledgement");
    assert!(memory.contains("StartIoSelectionClaim::claim("),
        "selected PENDING node must be exclusively claimed before dequeue");
    let launch = native("driver_launch.rs");
    let completion = launch.split("fn claim_pending_irp_completion(").nth(1).unwrap()
        .split("fn pending_irp_raw_identity_exists(").next().unwrap();
    assert!(completion.contains("HOSTED_IRP_START_IO_SELECTING"));
    let cancel = launch.split("fn claim_pending_irp_cancel_target(").nth(1).unwrap()
        .split("fn cancel_pending_irp(").next().unwrap();
    assert!(cancel.contains("HOSTED_IRP_START_IO_SELECTING"));
}

#[test]
fn busy_start_packet_retains_exact_queued_owner_without_callback() {
    let adapter = native("hosted_start_io.rs");
    let memory = native("hosted_start_io_packet.rs");
    assert!(adapter.contains("QueuedStartIo<QueuedPacketOwner>"));
    assert!(adapter.contains("QueuedStartIo::new(identity, owner)"));
    assert!(memory.contains("Action::Queued { next: None, .. }"));
    assert!(memory.contains("device.flags & start_io::DEFERRED == 0"),
        "unsupported deferred requests must refuse before the physical insertion");
    assert!(adapter.contains("if callback == 0 { return; }"),
        "queued insertion must not invoke DriverStartIo before queue selection");
}

#[test]
fn completed_current_still_authorizes_busy_insertion_and_idle_slot_drains() {
    let memory = native("hosted_start_io_packet.rs");
    assert!(memory.contains("first_packet_current().iter()"));
    assert!(memory.contains("CurrentPhase::Completed => CurrentPacketRelation::Completed"),
        "a settled old callback must not erase CurrentIrp provenance before Next");
    let adapter = native("hosted_start_io.rs");
    let drain = adapter.split("fn drain_cleanup(").nth(1).unwrap()
        .split("fn ").next().unwrap();
    assert!(drain.contains("first_packet_current()"));
    assert!(drain.contains("empty_owner_mut()"));
    assert!(drain.contains("device.release(io_manager_mut())"));
}

#[test]
fn queued_terminal_waits_for_checked_unlink_and_selection_rejects_terminal_node() {
    let adapter = native("hosted_start_io.rs");
    let terminal = adapter.split("fn observe_terminal_before_retirement(").nth(1).unwrap()
        .split("fn settle_first_packet(").next().unwrap();
    assert!(terminal.contains("first_packet_queued().iter().find("));
    assert!(terminal.contains("NtStatus::DELETE_PENDING"));
    let source = native("hosted_source_irp_ledger.rs");
    let queued = source.split("fn projected_start_io_queued_node_matches_locked(").nth(1).unwrap()
        .split("fn ").next().unwrap();
    assert!(queued.contains("HOSTED_IRP_PENDING") && queued.contains("HOSTED_IRP_DISPATCHING"));
    assert!(queued.contains("entry.completion.completed().is_none()"));
    let memory = native("hosted_start_io_packet.rs");
    assert!(memory.contains("projected_start_io_queued_node_matches_locked("));
    assert!(memory.contains("device_queue::remove_entry_device_queue("));
    assert!(memory.contains("projected_start_io_copying_node_matches_locked("));
    assert!(adapter.contains("fn settle_queued_terminal_locked("));
    assert!(adapter.contains("receipt.unlink_terminal(row.source)"));
    assert!(adapter.contains("QueuedPacketState::Unlinked(owner)"));
    assert!(adapter.contains("owner.source.release(ledger)"));
    let gate = source.split("fn caller_completion_publishable(").nth(1).unwrap()
        .split("fn ").next().unwrap();
    assert!(gate.contains("settle_queued_terminal_locked("));
}

#[test]
fn next_packet_accepts_exact_ready_terminal_before_root_poll() {
    let source = native("hosted_source_irp_ledger.rs");
    let ready = source.split("fn projected_start_io_node_matches_locked(").nth(1).unwrap()
        .split("fn ").next().unwrap();
    assert!(ready.contains("HOSTED_IRP_READY") && ready.contains("HOSTED_IRP_PUBLISHED"));
    assert!(ready.contains("entry.completion.completed().is_some()"));
    let adapter = native("hosted_start_io.rs");
    assert!(adapter.contains("service_start_next_packet_locked("));
    let memory = native("hosted_start_io_packet.rs");
    assert!(memory.contains("locked_first_packet_memory("));
    assert!(memory.contains("CurrentPhase::Completed => true"),
        "a completed current keeps scalar provenance after its physical node retires");
    assert!(memory.contains("projected_start_io_live_node_matches_locked("),
        "Next may displace an exact live current before IoCompleteRequest");
    let current = memory.split("let node_valid = unsafe { if terminal_ready {").nth(1).unwrap()
        .split("if !node_valid").next().unwrap();
    assert!(current.contains("projected_start_io_node_matches_locked(")
        && current.contains("instance_index, observed, true"),
        "a READY terminal may precede root poll while CurrentReceipt still owns its live pin");
    assert!(memory.contains("start_io::start_next::<_, ()>("));
    assert!(memory.contains("current.prepare_update(registration, observed.raw_irp, None)"),
        "the per-device current must clear with the WDM Next effect");
    assert!(adapter.contains("owner.retain_source(packet)"),
        "a displaced live packet must remain pinned by its exact callback fence");
}
