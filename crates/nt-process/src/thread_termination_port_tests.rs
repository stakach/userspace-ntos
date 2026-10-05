use super::*;

fn thread() -> (ProcessManager, ThreadId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("client.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    (pm, tid)
}

fn register(pm: &mut ProcessManager, tid: ThreadId, endpoint: u64) -> ThreadTerminationPortTicket {
    let ticket = pm.prepare_thread_termination_port(tid).unwrap();
    pm.register_thread_termination_port(&ticket, endpoint)
        .unwrap();
    ticket
}

#[test]
fn checked_refusal_is_not_delivery_and_requires_reference_release_ack() {
    let (mut pm, tid) = thread();
    let ticket = register(&mut pm, tid, 17);
    assert_eq!(
        pm.acknowledge_thread_termination_port_refusal(&ticket, 0xc000_0037),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.begin_thread_termination_port_delivery(&ticket).unwrap();
    for status in [0, 0x103, 0x4000_0000, 0x8000_0005] {
        assert_eq!(
            pm.acknowledge_thread_termination_port_refusal(&ticket, status),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            pm.peek_thread_termination_port(tid).unwrap().unwrap().phase,
            ThreadTerminationPortPhase::DeliveryPending
        );
    }
    assert_eq!(
        pm.begin_thread_termination_port_release(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.acknowledge_thread_termination_port_refusal(&ticket, 0xc000_0037)
        .unwrap();
    let snapshot = pm.peek_thread_termination_port(tid).unwrap().unwrap();
    assert_eq!(snapshot.phase, ThreadTerminationPortPhase::Refused);
    assert_eq!(snapshot.refusal_status, Some(0xc000_0037));
    assert_eq!(snapshot.endpoint, Some(17));
    assert_eq!(
        pm.acknowledge_thread_termination_port_delivery(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.acknowledge_thread_termination_port_refusal(&ticket, 0xc000_0008),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.acknowledge_thread_termination_port_release(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.begin_thread_termination_port_release(&ticket).unwrap();
    assert_eq!(
        pm.peek_thread_termination_port(tid)
            .unwrap()
            .unwrap()
            .refusal_status,
        Some(0xc000_0037)
    );
    assert_eq!(
        pm.begin_thread_termination_port_release(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.acknowledge_thread_termination_port_release(&ticket)
        .unwrap();
    assert!(pm.peek_thread_termination_port(tid).unwrap().is_none());
}

#[test]
fn registrations_grow_preserve_duplicate_references_and_deliver_lifo() {
    let (mut pm, tid) = thread();
    let ports = [11, 22, 11, 33, 44, 55, 66, 77];
    for endpoint in ports {
        register(&mut pm, tid, endpoint);
    }
    for endpoint in ports.into_iter().rev() {
        let record = pm.peek_thread_termination_port(tid).unwrap().unwrap();
        assert_eq!(record.endpoint, Some(endpoint));
        pm.begin_thread_termination_port_delivery(&record.ticket)
            .unwrap();
        pm.acknowledge_thread_termination_port_delivery(&record.ticket)
            .unwrap();
        pm.begin_thread_termination_port_release(&record.ticket)
            .unwrap();
        pm.acknowledge_thread_termination_port_release(&record.ticket)
            .unwrap();
    }
    assert!(pm.peek_thread_termination_port(tid).unwrap().is_none());
}

#[test]
fn acquisition_reservation_refusal_and_known_preentry_cancel_preserve_owner() {
    let (mut pm, tid) = thread();
    assert_eq!(
        pm.prepare_thread_termination_port_with_reserve(tid, usize::MAX),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(pm.peek_thread_termination_port(tid).unwrap().is_none());
    let ticket = pm.prepare_thread_termination_port(tid).unwrap();
    assert_eq!(
        pm.prepare_thread_termination_port(tid),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.cancel_thread_termination_port(&ticket).unwrap();
    assert_eq!(
        pm.cancel_thread_termination_port(&ticket),
        Err(STATUS_INVALID_HANDLE)
    );
    let bound = register(&mut pm, tid, 91);
    assert_eq!(
        pm.cancel_thread_termination_port(&bound),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.peek_thread_termination_port(tid)
            .unwrap()
            .unwrap()
            .endpoint,
        Some(91)
    );
}

#[test]
fn uncertain_send_and_release_cannot_replay_or_reclaim() {
    let (mut pm, tid) = thread();
    let ticket = register(&mut pm, tid, 91);
    pm.exit_thread(tid, 0).unwrap();
    assert!(!pm.can_reclaim_thread(tid));
    pm.begin_thread_termination_port_delivery(&ticket).unwrap();
    assert_eq!(
        pm.begin_thread_termination_port_delivery(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.begin_thread_termination_port_release(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    assert!(!pm.can_reclaim_thread(tid));
    pm.acknowledge_thread_termination_port_delivery(&ticket)
        .unwrap();
    pm.begin_thread_termination_port_release(&ticket).unwrap();
    assert_eq!(
        pm.begin_thread_termination_port_release(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.acknowledge_thread_termination_port_delivery(&ticket),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.peek_thread_termination_port(tid).unwrap().unwrap().phase,
        ThreadTerminationPortPhase::ReleasePending
    );
    pm.acknowledge_thread_termination_port_release(&ticket)
        .unwrap();
    assert_eq!(
        pm.acknowledge_thread_termination_port_release(&ticket),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(pm.can_reclaim_thread(tid));
}

#[test]
fn tickets_are_exact_manager_and_thread_lifetime_and_capture_original_create_time() {
    let (mut pm, tid) = thread();
    pm.threads.get_mut(&tid).unwrap().create_time_100ns = 12345;
    let ticket = register(&mut pm, tid, 91);
    let (mut foreign, foreign_tid) = thread();
    assert_eq!(tid, foreign_tid);
    let foreign_ticket = register(&mut foreign, tid, 92);
    assert_eq!(
        foreign.begin_thread_termination_port_delivery(&ticket),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.begin_thread_termination_port_delivery(&foreign_ticket),
        Err(STATUS_INVALID_HANDLE)
    );
    // Structural corruption fixture: a different activation cannot borrow an older reference.
    pm.threads.get_mut(&tid).unwrap().activation_generation += 1;
    assert_eq!(
        pm.begin_thread_termination_port_delivery(&ticket),
        Err(STATUS_INVALID_HANDLE)
    );
    let snapshot = pm.peek_thread_termination_port(tid).unwrap().unwrap();
    assert_eq!(snapshot.create_time_100ns, 12345);
    assert_eq!(snapshot.phase, ThreadTerminationPortPhase::Registered);
    assert_eq!(snapshot.endpoint, Some(91));
}

#[test]
fn registration_refuses_missing_and_terminated_thread_and_zero_reference() {
    let (mut pm, tid) = thread();
    assert_eq!(
        pm.prepare_thread_termination_port(tid + 4),
        Err(STATUS_INVALID_HANDLE)
    );
    let ticket = pm.prepare_thread_termination_port(tid).unwrap();
    assert_eq!(
        pm.register_thread_termination_port(&ticket, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.cancel_thread_termination_port(&ticket).unwrap();
    pm.exit_thread(tid, 0).unwrap();
    assert_eq!(
        pm.prepare_thread_termination_port(tid),
        Err(STATUS_THREAD_IS_TERMINATING)
    );
    assert!(pm.peek_thread_termination_port(tid).unwrap().is_none());
}
