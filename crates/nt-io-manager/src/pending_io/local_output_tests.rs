use super::*;

fn prepared(length: usize) -> (PendingFileIoTable, PendingFileIoReservation, PendingFileIo) {
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    let irp_id = table.local_operation_id(reservation).unwrap();
    table.reserve_local_output(reservation, length).unwrap();
    let pending = PendingFileIo {
        file_id: 1,
        irp_id,
        major: nt_io_abi::major::IRP_MJ_READ,
        operation: PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
            status: 0,
            information: length as u64,
        }),
        tid: 2,
        output_va: if length == 0 { 0 } else { 0x1000 },
        output_len: length as u32,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    };
    (table, reservation, pending)
}

fn finish(table: &mut PendingFileIoTable, slot: usize, irp: u64) {
    table.mark_backend_acked_exact(slot, irp).unwrap();
    assert!(table.finish_exact(slot, irp).is_none());
    table
        .mark_local_reference_released_exact(slot, irp)
        .unwrap();
    table.finish_exact(slot, irp).unwrap();
    assert!(table.local_outputs[slot].is_none());
}

#[test]
fn allocation_is_exact_zeroed_single_assignment_and_cancel_owned() {
    let (mut table, reservation, _) = prepared(4);
    assert_eq!(
        table.reserved_local_output_mut(reservation).unwrap(),
        &[0; 4]
    );
    table
        .reserved_local_output_mut(reservation)
        .unwrap()
        .copy_from_slice(b"data");
    assert_eq!(
        table.reserve_local_output(reservation, 1),
        Err(INVALID_PARAMETER)
    );
    let crossed = PendingFileIoReservation {
        generation: reservation.generation + 1,
        ..reservation
    };
    assert_eq!(table.reserve_local_output(crossed, 4), Err(INVALID_HANDLE));
    assert_eq!(
        table.reserved_local_output_mut(crossed),
        Err(INVALID_HANDLE)
    );
    assert!(!table.cancel_reservation(crossed));
    assert_eq!(
        table.reserved_local_output_mut(reservation).unwrap(),
        b"data"
    );
    assert!(table.cancel_reservation(reservation));
    assert!(table.local_outputs[reservation.slot].is_none());
    assert_eq!(
        table.reserved_local_output_mut(reservation),
        Err(INVALID_HANDLE)
    );
    let next = table.reserve().unwrap();
    if usize::BITS > 32 {
        assert_eq!(
            table.reserve_local_output(next, usize::MAX),
            Err(INVALID_PARAMETER)
        );
        assert!(table.local_outputs[next.slot].is_none());
    }
    table.reserve_local_output(next, 0).unwrap();
    assert_eq!(table.reserved_local_output_mut(next).unwrap().len(), 0);
}

#[test]
fn failed_commit_retains_buffer_and_claim_for_corrected_exact_commit() {
    let (mut table, reservation, pending) = prepared(4);
    table
        .reserved_local_output_mut(reservation)
        .unwrap()
        .copy_from_slice(b"data");
    let mut wrong_id = pending;
    wrong_id.irp_id += 1;
    let mut wrong_length = pending;
    wrong_length.output_len = 5;
    let mut wrong_info = pending;
    wrong_info.operation = PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
        status: 0,
        information: 5,
    });
    let mut provider = pending;
    provider.operation = PendingFileIoOperation::Transfer;
    for invalid in [wrong_id, wrong_length, wrong_info, provider] {
        assert_eq!(
            table.park_reserved(reservation, invalid),
            Err(PendingFileIoParkError::InvalidRecord)
        );
        assert_eq!(
            table.reserved_local_output_mut(reservation).unwrap(),
            b"data"
        );
    }
    assert!(table.park(pending).is_none());
    let capacities = (
        table.allocation_capacity(),
        table.local_output_allocation_capacity(),
        table.local_outputs[reservation.slot]
            .as_ref()
            .unwrap()
            .capacity(),
    );
    let slot = table.park_reserved(reservation, pending).unwrap();
    assert_eq!(
        (
            table.allocation_capacity(),
            table.local_output_allocation_capacity(),
            table.local_outputs[slot].as_ref().unwrap().capacity()
        ),
        capacities
    );
    assert_eq!(
        table.reserved_local_output_mut(reservation),
        Err(INVALID_HANDLE)
    );
    assert!(!table.cancel_reservation(reservation));
    assert_eq!(table.get(slot), Some(pending));
    let another = table.reserve().unwrap();
    let mut missing_buffer = pending;
    missing_buffer.irp_id = table.local_operation_id(another).unwrap();
    assert_eq!(
        table.park_reserved(another, missing_buffer),
        Err(PendingFileIoParkError::InvalidRecord)
    );
}

#[test]
fn terminal_ranges_are_immutable_checked_and_progress_cannot_shorten_output() {
    let (mut table, reservation, mut pending) = prepared(8);
    table
        .reserved_local_output_mut(reservation)
        .unwrap()
        .copy_from_slice(b"contents");
    pending.operation = PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
        status: 0x8000_0005,
        information: 4,
    });
    let id = pending.irp_id;
    let slot = table.park_reserved(reservation, pending).unwrap();
    assert_eq!(table.local_outputs[slot].as_ref().unwrap(), b"cont");
    let mut scratch = [0xa5; 2];
    for (irp, offset) in [(id + 1, 0), (id, 3), (id, usize::MAX)] {
        assert!(table
            .copy_local_output_bytes_exact(slot, irp, offset, &mut scratch)
            .is_err());
        assert_eq!(scratch, [0xa5; 2]);
    }
    for _ in 0..3 {
        assert_eq!(
            table.copy_local_output_bytes_exact(slot, id, 0, &mut scratch),
            Ok(2)
        );
        assert_eq!(&scratch, b"co");
    }
    assert_eq!(table.advance_output_exact(slot, id, 2, 2), None);
    assert_eq!(table.advance_output_exact(slot, id, 0, 0), None);
    assert_eq!(table.advance_output_exact(slot, id, 2, 4), Some(2));
    assert_eq!(table.advance_output_exact(slot, id, 3, 4), None);
    assert_eq!(table.advance_output_exact(slot, id, 2, 4), Some(4));
    assert_eq!(table.advance_output_exact(slot, id, 0, 4), None);
    assert!(table
        .mark_delivery_exact(slot, id, IO_DELIVERY_BUFFER_PUBLISHED)
        .is_none());
    finish(&mut table, slot, id);
}

#[test]
fn output_must_settle_before_other_surfaces_and_reply() {
    let (mut table, reservation, mut pending) = prepared(2);
    pending.iosb_va = 0x2000;
    pending.signal_file = true;
    pending.event_obj_idx = 3;
    pending.apc_routine = 0x3000;
    pending.reply_required = true;
    pending.reply_cap = 4;
    let id = pending.irp_id;
    let slot = table.park_reserved(reservation, pending).unwrap();
    for flag in [
        IO_DELIVERY_BUFFER_PUBLISHED,
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_APC_PUBLISHED,
        IO_DELIVERY_FILE_LOCK_RELEASED,
        IO_DELIVERY_OUTPUT_FAULTED,
    ] {
        assert!(table.mark_delivery_exact(slot, id, flag).is_none());
    }
    assert!(table
        .mark_iosb_faulted_exact(slot, id, pending.iosb_va)
        .is_none());
    assert!(table.claim_reply_cap_exact(slot, id).is_none());
    assert!(table
        .mark_user_apc_interrupt_requested_exact(slot, id, pending.file_id, pending.tid)
        .is_none());
    table.slots[slot]
        .as_mut()
        .unwrap()
        .user_apc_interrupt_requested = true;
    assert!(table.mark_user_apc_staged_exact(slot, id).is_none());
    table.slots[slot]
        .as_mut()
        .unwrap()
        .user_apc_interrupt_requested = false;
    assert!(!table.completion_surfaces_settled_exact(slot, id));
    assert!(table.mark_backend_acked_exact(slot, id).is_none());
    table.advance_output_exact(slot, id, 2, 2).unwrap();
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_APC_PUBLISHED,
    ] {
        table.mark_delivery_exact(slot, id, flag).unwrap();
    }
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(4)));
    table.mark_reply_published_exact(slot, id).unwrap();
    finish(&mut table, slot, id);
}

#[test]
fn empty_success_and_noncopying_statuses_require_explicit_empty_settlement() {
    for (length, status, information) in [
        (0, 0, 0),
        (4, 0, 0),
        (4, 0x8000_0016, 4),
        (4, 0xc000_0005, 4),
    ] {
        let (mut table, reservation, mut pending) = prepared(length);
        pending.operation = PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
            status,
            information,
        });
        let id = pending.irp_id;
        let slot = table.park_reserved(reservation, pending).unwrap();
        assert!(!table.completion_surfaces_settled_exact(slot, id));
        assert!(table.mark_backend_acked_exact(slot, id).is_none());
        let mut sentinel = [0xa5];
        assert!(table
            .copy_local_output_bytes_exact(slot, id, 0, &mut sentinel)
            .is_err());
        assert_eq!(sentinel, [0xa5]);
        assert_eq!(
            table.copy_local_output_bytes_exact(slot, id, 0, &mut []),
            Ok(0)
        );
        assert_eq!(table.advance_output_exact(slot, id, 0, 0), Some(0));
        assert_eq!(
            table.get(slot).unwrap().local_terminal_result(),
            Some((status, information))
        );
        finish(&mut table, slot, id);
    }
}

#[test]
fn permanent_output_fault_preserves_information_prefix_and_inline_policy() {
    for status in [0x8000_0001, 0xc000_0005] {
        let (mut table, reservation, mut pending) = prepared(4);
        pending.iosb_va = 0x2000;
        pending.apc_routine = 0x3000;
        pending.event_obj_idx = 3;
        pending.signal_file = true;
        table
            .reserved_local_output_mut(reservation)
            .unwrap()
            .copy_from_slice(b"data");
        let id = pending.irp_id;
        let slot = table.park_reserved(reservation, pending).unwrap();
        table.advance_output_exact(slot, id, 2, 4).unwrap();
        let before = table.get(slot);
        for (irp, va, failure) in [
            (id + 1, pending.output_va, status),
            (id, 0, status),
            (id, pending.output_va + 1, status),
            (id, pending.output_va, 0),
            (id, pending.output_va, 0x103),
        ] {
            assert!(table
                .settle_local_output_fault_exact(slot, irp, va, failure)
                .is_none());
            assert_eq!(table.get(slot), before);
        }
        table
            .settle_local_output_fault_exact(slot, id, pending.output_va, status)
            .unwrap();
        let settled = table.get(slot).unwrap();
        assert_eq!(settled.local_terminal_result(), Some((status, 4)));
        assert_eq!(settled.output_offset, 2);
        assert_eq!(settled.output_va, pending.output_va);
        assert_eq!(settled.delivery_state, IO_DELIVERY_OUTPUT_FAULTED);
        assert_eq!(table.local_outputs[slot].as_ref().unwrap(), b"data");
        assert!(table
            .settle_local_output_fault_exact(slot, id, pending.output_va, status)
            .is_none());
        assert!(table.advance_output_exact(slot, id, 2, 4).is_none());
        assert!(table
            .copy_local_output_bytes_exact(slot, id, 0, &mut [0; 1])
            .is_err());
        if status & 0xc000_0000 == 0xc000_0000 {
            assert_eq!(
                (
                    settled.iosb_va,
                    settled.apc_routine,
                    settled.event_obj_idx,
                    settled.signal_file
                ),
                (0, 0, u64::MAX, false)
            );
        } else {
            assert_eq!(
                (
                    settled.iosb_va,
                    settled.apc_routine,
                    settled.event_obj_idx,
                    settled.signal_file
                ),
                (0x2000, 0x3000, 3, true)
            );
            for flag in [
                IO_DELIVERY_IOSB_PUBLISHED,
                IO_DELIVERY_APC_PUBLISHED,
                IO_DELIVERY_EVENT_PUBLISHED,
                IO_DELIVERY_FILE_PUBLISHED,
            ] {
                table.mark_delivery_exact(slot, id, flag).unwrap();
            }
        }
        finish(&mut table, slot, id);
    }
}

#[test]
fn completed_output_and_provider_rows_cannot_be_fault_rewritten() {
    let (mut table, reservation, pending) = prepared(1);
    let id = pending.irp_id;
    let slot = table.park_reserved(reservation, pending).unwrap();
    table.advance_output_exact(slot, id, 1, 1).unwrap();
    assert!(table
        .settle_local_output_fault_exact(slot, id, pending.output_va, 0xc000_0005)
        .is_none());
    finish(&mut table, slot, id);
    let mut provider = pending;
    provider.irp_id += 1;
    provider.operation = PendingFileIoOperation::Transfer;
    assert_eq!(table.park(provider), Some(slot));
    assert!(table
        .settle_local_output_fault_exact(slot, provider.irp_id, provider.output_va, 0xc000_0005)
        .is_none());
    assert!(table
        .copy_local_output_bytes_exact(slot, provider.irp_id, 0, &mut [])
        .is_err());
}

#[test]
fn abandonment_keeps_terminal_storage_until_final_reference_retirement() {
    let (mut table, reservation, pending) = prepared(4);
    let id = pending.irp_id;
    let slot = table.park_reserved(reservation, pending).unwrap();
    table.advance_output_exact(slot, id, 2, 4).unwrap();
    assert_eq!(table.abandon_thread_transfers_with(pending.tid, |_| {}), 1);
    assert!(table.local_outputs[slot].is_some());
    assert_eq!(
        table.get(slot).unwrap().local_terminal_result(),
        Some((0, 4))
    );
    assert!(table
        .copy_local_output_bytes_exact(slot, id, 0, &mut [0; 1])
        .is_err());
    assert!(table
        .settle_local_output_fault_exact(slot, id, pending.output_va, 0xc000_0005)
        .is_none());
    assert!(table.completion_surfaces_settled_exact(slot, id));
    finish(&mut table, slot, id);
}

#[test]
fn extraction_reset_and_reused_slots_do_not_retain_previous_buffers() {
    let (mut table, reservation, pending) = prepared(4);
    let id = pending.irp_id;
    let slot = table.park_reserved(reservation, pending).unwrap();
    assert_eq!(table.take_thread_with(pending.tid, |_| {}), 1);
    assert!(table.local_outputs[slot].is_none());
    assert!(table
        .copy_local_output_bytes_exact(slot, id, 0, &mut [])
        .is_err());
    let next = table.reserve().unwrap();
    assert_eq!(next.slot, slot);
    table.reserve_local_output(next, 1).unwrap();
    assert!(!table.reset());
    assert!(table.cancel_reservation(next));
    assert!(table.reset());
    assert!(table.local_outputs.is_empty());
    assert!(table.is_empty());
    assert!(table.has_capacity());
    assert!(table.reserved_local_output_mut(next).is_err());
    let fresh = table.reserve().unwrap();
    assert!(fresh.generation > next.generation);
    assert!(table.local_outputs[fresh.slot].is_none());
}
