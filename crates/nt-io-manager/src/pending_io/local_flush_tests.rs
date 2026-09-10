use super::*;

const ACCESS_VIOLATION: u32 = 0xc000_0005;
const GUARD_PAGE: u32 = 0x8000_0001;
const DEVICE_ERROR: u32 = 0xc000_0185;
const IOSB: u64 = 0x1000;
const CAP: u64 = 55;

fn request(id: u64, status: u32, mode: LocalFlushMode) -> PendingFileIo {
    let flush = PendingLocalFlush::new(status, mode).unwrap();
    PendingFileIo {
        file_id: 1,
        irp_id: id,
        major: nt_io_abi::major::IRP_MJ_FLUSH_BUFFERS,
        operation: PendingFileIoOperation::LocalFlush(flush),
        tid: 7,
        iosb_va: if flush.publishes_iosb() { IOSB } else { 0 },
        signal_file: flush.signals_file(),
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        reply_cap: CAP,
        reply_required: true,
        ..PendingFileIo::default()
    }
}

fn park(table: &mut PendingFileIoTable, status: u32, mode: LocalFlushMode) -> (usize, u64) {
    let claim = table.reserve().unwrap();
    let id = table.local_operation_id(claim).unwrap();
    let slot = table
        .park_reserved(claim, request(id, status, mode))
        .unwrap();
    (slot, id)
}

fn retire(table: &mut PendingFileIoTable, slot: usize, id: u64) -> PendingFileIo {
    assert!(table.finish_exact(slot, id).is_none());
    assert!(table
        .mark_local_reference_released_exact(slot, id)
        .is_none());
    if table.get(slot).unwrap().signal_file {
        assert!(table.claim_reply_cap_exact(slot, id).is_none());
        table
            .mark_delivery_exact(slot, id, IO_DELIVERY_FILE_PUBLISHED)
            .unwrap();
    }
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(CAP)));
    table.mark_reply_published_exact(slot, id).unwrap();
    assert!(table.completion_surfaces_settled_exact(slot, id));
    table.mark_backend_acked_exact(slot, id).unwrap();
    assert!(table.finish_exact(slot, id).is_none());
    table.mark_local_reference_released_exact(slot, id).unwrap();
    assert!(table
        .mark_local_reference_released_exact(slot, id)
        .is_none());
    let completed = table.finish_exact(slot, id).unwrap();
    assert!(table.finish_exact(slot, id).is_none());
    completed
}

#[test]
fn captured_mode_and_severity_determine_inline_flush_policy() {
    for mode in [
        LocalFlushMode::SynchronousFile,
        LocalFlushMode::SynchronousApi,
    ] {
        assert!(PendingLocalFlush::new(0x103, mode).is_none());
        for status in [0, 0x4000_0001, GUARD_PAGE, DEVICE_ERROR] {
            let flush = PendingLocalFlush::new(status, mode).unwrap();
            assert_eq!(flush.status(), status);
            assert_eq!(flush.mode(), mode);
            assert_eq!(flush.syscall_status(), status);
            assert_eq!(
                flush.publishes_iosb(),
                mode == LocalFlushMode::SynchronousApi || status >> 30 != 3
            );
            assert_eq!(
                flush.signals_file(),
                mode == LocalFlushMode::SynchronousFile && status >> 30 != 3
            );
        }
    }
}

#[test]
fn reserved_id_is_exact_and_no_output_owner_can_be_attached() {
    let mut table = PendingFileIoTable::new();
    let claim = table.reserve().unwrap();
    let id = table.local_operation_id(claim).unwrap();
    let valid = request(id, 0, LocalFlushMode::SynchronousApi);
    assert!(table.park(valid).is_none());
    assert_eq!(
        table.park_reserved(
            claim,
            PendingFileIo {
                irp_id: id + 1,
                ..valid
            }
        ),
        Err(PendingFileIoParkError::InvalidRecord)
    );
    assert_eq!(table.local_operation_id(claim), Some(id));
    table.reserve_local_output(claim, 0).unwrap();
    assert_eq!(
        table.park_reserved(claim, valid),
        Err(PendingFileIoParkError::InvalidRecord)
    );
    assert!(table.cancel_reservation(claim));
    let next = table.reserve().unwrap();
    assert_ne!(table.local_operation_id(next), Some(id));
    assert_eq!(
        table.park_reserved(next, valid),
        Err(PendingFileIoParkError::InvalidRecord)
    );
    let next_id = table.local_operation_id(next).unwrap();
    let capacity = table.allocation_capacity();
    let slot = table
        .park_reserved(next, request(next_id, 0, LocalFlushMode::SynchronousApi))
        .unwrap();
    assert_eq!(table.allocation_capacity(), capacity);
    assert!(!table.matches_completion_exact(
        slot,
        next_id,
        1,
        7,
        nt_io_abi::major::IRP_MJ_FLUSH_BUFFERS
    ));
}

#[test]
fn malformed_shapes_do_not_consume_the_exact_reservation() {
    let changes: &[fn(&mut PendingFileIo)] = &[
        |p| p.major = nt_io_abi::major::IRP_MJ_READ,
        |p| p.output_va = 1,
        |p| p.output_len = 1,
        |p| p.output_offset = 1,
        |p| p.apc_routine = 1,
        |p| p.apc_context = 1,
        |p| p.event_obj_idx = 1,
        |p| p.publish_iocp = true,
        |p| p.completion_port_suppressed = false,
        |p| p.sync_lock_owner_tid = p.tid,
        |p| p.signal_file = true,
        |p| p.iosb_va = 0,
        |p| p.consumer_abandoned = true,
        |p| p.user_apc_interrupt_requested = true,
        |p| p.control_code = 1,
        |p| p.delivery_state = IO_DELIVERY_IOSB_FAULTED,
        |p| {
            if let PendingFileIoOperation::LocalFlush(ref mut flush) = p.operation {
                flush.iosb_fault_status = Some(ACCESS_VIOLATION);
            }
        },
    ];
    for change in changes {
        let mut table = PendingFileIoTable::new();
        let claim = table.reserve().unwrap();
        let id = table.local_operation_id(claim).unwrap();
        let mut invalid = request(id, 0, LocalFlushMode::SynchronousApi);
        change(&mut invalid);
        assert_eq!(
            table.park_reserved(claim, invalid),
            Err(PendingFileIoParkError::InvalidRecord)
        );
        assert_eq!(table.local_operation_id(claim), Some(id));
        table
            .park_reserved(claim, request(id, 0, LocalFlushMode::SynchronousApi))
            .unwrap();
    }
    for status in [0, DEVICE_ERROR] {
        let mut table = PendingFileIoTable::new();
        let claim = table.reserve().unwrap();
        let id = table.local_operation_id(claim).unwrap();
        let mut invalid = request(id, status, LocalFlushMode::SynchronousFile);
        invalid.iosb_va = if invalid.iosb_va == 0 { IOSB } else { 0 };
        assert_eq!(
            table.park_reserved(claim, invalid),
            Err(PendingFileIoParkError::InvalidRecord)
        );
    }
}

#[test]
fn mode_status_and_permanent_fault_matrix_preserves_backing_result() {
    for mode in [
        LocalFlushMode::SynchronousFile,
        LocalFlushMode::SynchronousApi,
    ] {
        for status in [0, 0x4000_0001, GUARD_PAGE, DEVICE_ERROR] {
            for fault in [None, Some(ACCESS_VIOLATION), Some(GUARD_PAGE)] {
                let mut table = PendingFileIoTable::new();
                let (slot, id) = park(&mut table, status, mode);
                let original = table.get(slot).unwrap();
                assert!(original.is_local());
                assert_eq!(original.local_terminal_result(), Some((status, 0)));
                assert!(table.mark_iosb_faulted_exact(slot, id, IOSB).is_none());
                let expected = if original.iosb_va != 0 {
                    assert!(table.claim_reply_cap_exact(slot, id).is_none());
                    assert!(table
                        .mark_delivery_exact(slot, id, IO_DELIVERY_FILE_PUBLISHED)
                        .is_none());
                    if let Some(fault) = fault {
                        assert_eq!(
                            table.mark_local_flush_iosb_faulted_exact(slot, id, IOSB, fault),
                            Some(IO_DELIVERY_IOSB_FAULTED)
                        );
                        assert!(table
                            .mark_delivery_exact(slot, id, IO_DELIVERY_IOSB_PUBLISHED)
                            .is_none());
                        if mode == LocalFlushMode::SynchronousApi {
                            fault
                        } else {
                            status
                        }
                    } else {
                        table
                            .mark_delivery_exact(slot, id, IO_DELIVERY_IOSB_PUBLISHED)
                            .unwrap();
                        status
                    }
                } else {
                    assert!(table
                        .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, ACCESS_VIOLATION)
                        .is_none());
                    assert!(table
                        .mark_delivery_exact(slot, id, IO_DELIVERY_IOSB_PUBLISHED)
                        .is_none());
                    status
                };
                let pending = table.get(slot).unwrap();
                assert_eq!(pending.iosb_va, original.iosb_va);
                assert_eq!(pending.local_terminal_result(), Some((status, 0)));
                assert_eq!(pending.local_syscall_status(), Some(expected));
                let completed = retire(&mut table, slot, id);
                assert_eq!(completed.local_terminal_result(), Some((status, 0)));
                assert_eq!(completed.local_syscall_status(), Some(expected));
            }
        }
    }
}

#[test]
fn fault_settlement_rejects_wrong_identity_status_and_every_settled_state() {
    let mut table = PendingFileIoTable::new();
    let (slot, id) = park(&mut table, 0, LocalFlushMode::SynchronousApi);
    let original = table.get(slot);
    for (other_slot, other_id, va, status) in [
        (slot + 1, id, IOSB, ACCESS_VIOLATION),
        (slot, id + 1, IOSB, ACCESS_VIOLATION),
        (slot, id, IOSB + 1, ACCESS_VIOLATION),
        (slot, id, 0, ACCESS_VIOLATION),
        (slot, id, IOSB, 0),
        (slot, id, IOSB, 0x103),
        (slot, id, IOSB, 0x4000_0001),
    ] {
        assert!(table
            .mark_local_flush_iosb_faulted_exact(other_slot, other_id, va, status)
            .is_none());
        assert_eq!(table.get(slot), original);
    }
    for state in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_IOSB_FAULTED,
        IO_DELIVERY_REPLY_CLAIMED,
        IO_DELIVERY_REPLY_PUBLISHED,
        IO_DELIVERY_BACKEND_ACKED,
        IO_DELIVERY_LOCAL_REFERENCE_RELEASED,
    ] {
        table.slots[slot].as_mut().unwrap().delivery_state = state;
        assert!(table
            .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, ACCESS_VIOLATION)
            .is_none());
        assert_eq!(table.get(slot).unwrap().local_syscall_status(), Some(0));
    }
    table.slots[slot] = original;
    table
        .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, ACCESS_VIOLATION)
        .unwrap();
    let settled = table.get(slot);
    assert!(table
        .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, GUARD_PAGE)
        .is_none());
    assert_eq!(table.get(slot), settled);
}

#[test]
fn retry_preserves_source_and_return_override_through_reply_and_reference_busy() {
    let mut table = PendingFileIoTable::new();
    let (slot, id) = park(&mut table, DEVICE_ERROR, LocalFlushMode::SynchronousApi);
    let original = table.get(slot).unwrap();
    for _ in 0..3 {
        assert!(table.claim_reply_cap_exact(slot, id).is_none());
        assert!(table.mark_backend_acked_exact(slot, id).is_none());
        assert_eq!(table.get(slot), Some(original));
    }
    table
        .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, ACCESS_VIOLATION)
        .unwrap();
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(CAP)));
    assert_eq!(table.restore_reply_cap_exact(slot, id, CAP), Some(()));
    assert_eq!(
        table.get(slot).unwrap().local_syscall_status(),
        Some(ACCESS_VIOLATION)
    );
    assert!(table
        .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, GUARD_PAGE)
        .is_none());
    let completed = retire(&mut table, slot, id);
    assert_eq!(completed.local_terminal_result(), Some((DEVICE_ERROR, 0)));
    assert_eq!(completed.local_syscall_status(), Some(ACCESS_VIOLATION));
}

#[test]
fn abandonment_preserves_terminal_disposition_until_ack_and_reference_release() {
    for fault_first in [false, true] {
        let mut table = PendingFileIoTable::new();
        let (slot, id) = park(&mut table, 0, LocalFlushMode::SynchronousApi);
        if fault_first {
            table
                .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, ACCESS_VIOLATION)
                .unwrap();
        }
        assert_eq!(table.abandon_thread_transfers_with(7, |_| {}), 1);
        let abandoned = table.get(slot).unwrap();
        assert!(abandoned.consumer_abandoned);
        assert_eq!(abandoned.local_terminal_result(), Some((0, 0)));
        assert_eq!(
            abandoned.local_syscall_status(),
            Some(if fault_first { ACCESS_VIOLATION } else { 0 })
        );
        assert!(table
            .mark_local_flush_iosb_faulted_exact(slot, id, IOSB, GUARD_PAGE)
            .is_none());
        assert!(table.claim_reply_cap_exact(slot, id).is_none());
        table.mark_backend_acked_exact(slot, id).unwrap();
        assert!(table.finish_exact(slot, id).is_none());
        table.mark_local_reference_released_exact(slot, id).unwrap();
        assert!(table.finish_exact(slot, id).is_some());
    }
}

#[test]
fn flush_fault_api_cannot_rewrite_other_local_or_provider_operations() {
    for operation in [
        PendingFileIoOperation::Transfer,
        PendingFileIoOperation::LocalInline(PendingLocalInline {
            status: DEVICE_ERROR,
            information: 12,
        }),
    ] {
        let mut table = PendingFileIoTable::new();
        let mut pending = request(8, 0, LocalFlushMode::SynchronousApi);
        pending.operation = operation;
        let slot = table.park(pending).unwrap();
        assert!(table
            .mark_local_flush_iosb_faulted_exact(slot, 8, IOSB, ACCESS_VIOLATION)
            .is_none());
        assert_eq!(table.get(slot), Some(pending));
        assert_eq!(
            pending.local_syscall_status(),
            if pending.is_local() {
                Some(DEVICE_ERROR)
            } else {
                None
            }
        );
    }
}
