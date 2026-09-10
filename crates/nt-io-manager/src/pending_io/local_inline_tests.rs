use super::*;

const ID: u64 = 71;
const FILE: u64 = 72;
const TID: u64 = 73;

fn inline() -> PendingFileIo {
    PendingFileIo {
        file_id: FILE,
        irp_id: ID,
        major: nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status: 0,
            information: 0x1_0000_0001,
        }),
        tid: TID,
        badge: 74,
        iosb_va: 0x1000,
        apc_routine: 0x2000,
        apc_context: 0x3000,
        signal_file: true,
        event_obj_idx: 75,
        reply_cap: 76,
        reply_required: true,
        ..PendingFileIo::default()
    }
}

fn publish_surfaces(table: &mut PendingFileIoTable, slot: usize, id: u64) {
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
        IO_DELIVERY_APC_PUBLISHED,
    ] {
        table.mark_delivery_exact(slot, id, flag).unwrap();
    }
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(76)));
    table.mark_reply_published_exact(slot, id).unwrap();
}

#[test]
fn exact_reserved_insertion_keeps_terminal_information_without_payload() {
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    let request = inline();
    let slot = table.park_reserved(reservation, request).unwrap();
    assert_eq!(table.get(slot), Some(request));
    assert!(request.is_local());
    assert_eq!(request.local_terminal_result(), Some((0, 0x1_0000_0001)));
    assert_eq!(
        table.park_reserved(reservation, request),
        Err(PendingFileIoParkError::StaleReservation)
    );
    let other = table.reserve().unwrap();
    assert_eq!(
        table.park_reserved(other, request),
        Err(PendingFileIoParkError::DuplicateIrp)
    );
    assert!(table.cancel_reservation(other));
    assert_eq!(table.get(slot), Some(request));
}

#[test]
fn local_wait_correlations_cannot_match_provider_completions() {
    for (major, operation) in [
        (
            nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
            PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
                wait_id: 1,
                status: nt_status::NtStatus::PENDING.raw() as u32,
                alertable: false,
            }),
        ),
        (
            nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
            PendingFileIoOperation::LocalDirectoryNotify(PendingLocalDirectoryNotify {
                notify_id: 1,
                status: nt_status::NtStatus::PENDING.raw() as u32,
                information: 0,
                alertable: false,
            }),
        ),
    ] {
        let mut table = PendingFileIoTable::new();
        let pending = PendingFileIo {
            major,
            operation,
            ..inline()
        };
        let slot = table.park(pending).unwrap();
        assert!(!table.matches_completion_exact(slot, ID, FILE, TID, major));
        assert_eq!(table.get(slot), Some(pending));
    }
}

#[test]
fn invalid_local_shapes_do_not_consume_the_reservation() {
    let changes: &[fn(&mut PendingFileIo)] = &[
        |request| {
            request.operation = PendingFileIoOperation::LocalInline(PendingLocalInline {
                status: nt_status::NtStatus::PENDING.raw() as u32,
                information: 0,
            })
        },
        |request| request.major = nt_io_abi::major::IRP_MJ_CREATE,
        |request| request.output_va = 0x4000,
        |request| request.output_len = 1,
        |request| request.output_offset = 1,
        |request| request.publish_iocp = true,
        |request| request.sync_lock_owner_tid = TID,
        |request| request.control_code = 1,
        |request| request.delivery_state = IO_DELIVERY_BACKEND_ACKED,
        |request| request.user_apc_interrupt_requested = true,
        |request| request.file_id = 0,
        |request| request.irp_id = 0,
    ];
    for change in changes {
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let mut request = inline();
        change(&mut request);
        assert_eq!(
            table.park_reserved(reservation, request),
            Err(PendingFileIoParkError::InvalidRecord)
        );
        assert_eq!(table.len(), 0);
        assert!(!table.is_empty());
        assert!(table.park_reserved(reservation, inline()).is_ok());
    }
}

#[test]
fn suppressed_inline_failure_can_omit_iosb_and_other_consumer_surfaces() {
    let mut table = PendingFileIoTable::new();
    let mut request = inline();
    request.operation = PendingFileIoOperation::LocalInline(PendingLocalInline {
        status: 0xc000_000d,
        information: 0,
    });
    request.iosb_va = 0;
    request.apc_routine = 0;
    request.event_obj_idx = u64::MAX;
    let slot = table.park(request).unwrap();
    assert!(!table.completion_surfaces_published_exact(slot, ID));
    table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_FILE_PUBLISHED)
        .unwrap();
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(76)));
    table.mark_reply_published_exact(slot, ID).unwrap();
    table.mark_backend_acked_exact(slot, ID).unwrap();
    assert!(table.finish_exact(slot, ID).is_none());
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    assert_eq!(
        table
            .finish_exact(slot, ID)
            .unwrap()
            .local_terminal_result(),
        Some((0xc000_000d, 0))
    );
}

#[test]
fn each_surface_and_both_final_acknowledgements_gate_retirement() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(inline()).unwrap();
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
        IO_DELIVERY_APC_PUBLISHED,
    ] {
        let before = table.get(slot).unwrap();
        assert!(table.mark_backend_acked_exact(slot, ID).is_none());
        assert!(table
            .mark_local_reference_released_exact(slot, ID)
            .is_none());
        assert!(table.finish_exact(slot, ID).is_none());
        assert_eq!(table.get(slot), Some(before));
        table.mark_delivery_exact(slot, ID, flag).unwrap();
    }
    assert!(table.mark_reply_published_exact(slot, ID).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(76)));
    assert!(table.mark_backend_acked_exact(slot, ID).is_none());
    table.mark_reply_published_exact(slot, ID).unwrap();
    assert!(table.completion_surfaces_published_exact(slot, ID));
    assert!(table
        .mark_local_reference_released_exact(slot, ID)
        .is_none());
    table.mark_backend_acked_exact(slot, ID).unwrap();
    let awaiting_reference = table.get(slot).unwrap();
    for _ in 0..3 {
        assert!(table.finish_exact(slot, ID).is_none());
        assert_eq!(table.get(slot), Some(awaiting_reference));
        assert_eq!(
            awaiting_reference.local_terminal_result(),
            inline().local_terminal_result()
        );
    }
    assert!(table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_LOCAL_REFERENCE_RELEASED)
        .is_none());
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    assert!(table
        .mark_local_reference_released_exact(slot, ID)
        .is_none());
    assert_eq!(
        table
            .finish_exact(slot, ID)
            .unwrap()
            .local_terminal_result(),
        inline().local_terminal_result()
    );
    assert!(table.finish_exact(slot, ID).is_none());
}

#[test]
fn crossed_and_reused_slots_cannot_advance_another_local_owner() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(inline()).unwrap();
    let original = table.get(slot);
    assert!(table
        .mark_delivery_exact(slot, ID + 1, IO_DELIVERY_IOSB_PUBLISHED)
        .is_none());
    assert!(table.claim_reply_cap_exact(slot, ID + 1).is_none());
    assert!(table.mark_backend_acked_exact(slot, ID + 1).is_none());
    assert!(table
        .mark_local_reference_released_exact(slot, ID + 1)
        .is_none());
    assert!(table.finish_exact(slot, ID + 1).is_none());
    assert_eq!(table.get(slot), original);
    publish_surfaces(&mut table, slot, ID);
    table.mark_backend_acked_exact(slot, ID).unwrap();
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    table.finish_exact(slot, ID).unwrap();
    let mut next = inline();
    next.irp_id += 1;
    assert_eq!(table.park(next), Some(slot));
    assert!(table.mark_backend_acked_exact(slot, ID).is_none());
    assert!(table
        .mark_local_reference_released_exact(slot, ID)
        .is_none());
    assert!(table.finish_exact(slot, ID).is_none());
    assert_eq!(table.get(slot), Some(next));
}

#[test]
fn terminal_inline_cannot_be_replaced_or_treated_as_pending_provider_work() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(inline()).unwrap();
    let before = table.get(slot);
    assert!(!table.matches_completion_exact(slot, ID, FILE, TID, inline().major));
    assert!(table.user_apc_interrupt_candidate(TID).is_none());
    assert!(table
        .mark_user_apc_interrupt_requested_exact(slot, ID, FILE, TID)
        .is_none());
    assert!(table.advance_output_exact(slot, ID, 0, 0).is_none());
    assert!(!table.complete_local_byte_lock_exact(ID, 1, 0xc000_0120));
    assert!(!table.complete_local_directory_notify_exact(ID, 1, 0xc000_0120, 0, true));
    assert_eq!(table.get(slot), before);
}

#[test]
fn abandonment_preserves_terminal_result_and_final_reference_obligation() {
    for after_backend_ack in [false, true] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(inline()).unwrap();
        if after_backend_ack {
            publish_surfaces(&mut table, slot, ID);
            table.mark_backend_acked_exact(slot, ID).unwrap();
        } else {
            table
                .mark_delivery_exact(slot, ID, IO_DELIVERY_IOSB_PUBLISHED)
                .unwrap();
        }
        let mut abandoned = None;
        assert_eq!(
            table.abandon_thread_transfers_with(TID, |pending| abandoned = Some(pending)),
            1
        );
        let original = abandoned.unwrap();
        assert_eq!(
            original.local_terminal_result(),
            inline().local_terminal_result()
        );
        let retained = table.get(slot).unwrap();
        assert!(retained.consumer_abandoned);
        assert_eq!(
            retained.local_terminal_result(),
            original.local_terminal_result()
        );
        assert_eq!(
            (retained.iosb_va, retained.apc_routine, retained.reply_cap),
            (0, 0, 0)
        );
        assert!(!retained.signal_file);
        assert!(!retained.reply_required);
        assert!(table.finish_exact(slot, ID).is_none());
        if !after_backend_ack {
            table.mark_backend_acked_exact(slot, ID).unwrap();
        }
        assert!(table.finish_exact(slot, ID).is_none());
        table.mark_local_reference_released_exact(slot, ID).unwrap();
        assert_eq!(
            table
                .finish_exact(slot, ID)
                .unwrap()
                .local_terminal_result(),
            original.local_terminal_result()
        );
    }
}

#[test]
fn rejected_reply_restores_only_its_exact_unpublished_cap() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(inline()).unwrap();
    assert!(table.restore_reply_cap_exact(slot, ID, 76).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(76)));
    let claimed = table.get(slot).unwrap();
    assert_eq!(claimed.reply_cap, 76);
    for (id, cap) in [(ID + 1, 76), (ID, 0), (ID, 77)] {
        assert!(table.restore_reply_cap_exact(slot, id, cap).is_none());
        assert_eq!(table.get(slot), Some(claimed));
    }
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(None));
    table.restore_reply_cap_exact(slot, ID, 76).unwrap();
    assert!(table.restore_reply_cap_exact(slot, ID, 76).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(76)));
    table.mark_reply_published_exact(slot, ID).unwrap();
    assert_eq!(table.get(slot).unwrap().reply_cap, 0);
    assert!(table.restore_reply_cap_exact(slot, ID, 76).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(None));
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
        IO_DELIVERY_APC_PUBLISHED,
    ] {
        table.mark_delivery_exact(slot, ID, flag).unwrap();
    }
    table.mark_backend_acked_exact(slot, ID).unwrap();
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    table.finish_exact(slot, ID).unwrap();
    let mut next = inline();
    next.irp_id += 1;
    assert_eq!(table.park(next), Some(slot));
    assert_eq!(table.claim_reply_cap_exact(slot, ID + 1), Some(Some(76)));
    let replacement = table.get(slot);
    assert!(table.restore_reply_cap_exact(slot, ID, 76).is_none());
    assert_eq!(table.get(slot), replacement);
}

#[test]
fn teardown_defers_claimed_reply_until_rejection_or_publication_settles_it() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(inline()).unwrap();
    table.claim_reply_cap_exact(slot, ID).unwrap().unwrap();
    let claimed = table.get(slot);
    assert_eq!(
        table.abandon_thread_transfers_with(TID, |_| panic!("claimed owner escaped")),
        0
    );
    assert_eq!(
        table.take_thread_with(TID, |_| panic!("claimed owner escaped")),
        0
    );
    assert_eq!(table.get(slot), claimed);
    table.restore_reply_cap_exact(slot, ID, 76).unwrap();
    let mut cap = 0;
    assert_eq!(
        table.abandon_thread_transfers_with(TID, |pending| cap = pending.reply_cap),
        1
    );
    assert_eq!(cap, 76);
    assert_eq!(table.get(slot).unwrap().reply_cap, 0);
    assert!(table.restore_reply_cap_exact(slot, ID, 76).is_none());

    let mut create = inline();
    create.irp_id += 1;
    create.major = nt_io_abi::major::IRP_MJ_CREATE;
    create.operation = PendingFileIoOperation::Create(PendingFileCreate {
        handle_va: 0x4000,
        reservation_pid: 1,
        reserved_handle: 2,
        reservation_generation: 3,
        status: nt_status::NtStatus::PENDING.raw() as u32,
        ..PendingFileCreate::default()
    });
    create.apc_routine = 0;
    create.signal_file = false;
    create.event_obj_idx = u64::MAX;
    let create_slot = table.park(create).unwrap();
    table
        .claim_reply_cap_exact(create_slot, ID + 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        table.take_thread_creates_with(TID, |_| panic!("claimed CREATE escaped")),
        0
    );
    table
        .restore_reply_cap_exact(create_slot, ID + 1, 76)
        .unwrap();
    assert_eq!(table.take_thread_creates_with(TID, |_| {}), 1);
}

#[test]
fn user_apc_redirect_stages_once_across_definitively_rejected_reply() {
    let mut table = PendingFileIoTable::new();
    let mut request = inline();
    request.operation = PendingFileIoOperation::Transfer;
    request.major = nt_io_abi::major::IRP_MJ_READ;
    request.sync_lock_owner_tid = TID;
    let slot = table.park(request).unwrap();
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    assert!(table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_USER_APC_STAGED)
        .is_none());
    table
        .mark_user_apc_interrupt_requested_exact(slot, ID, FILE, TID)
        .unwrap();
    let unstaged = table.get(slot);
    assert!(table.claim_reply_cap_exact(slot, ID).is_none());
    assert!(table.mark_user_apc_staged_exact(slot, ID + 1).is_none());
    assert_eq!(table.get(slot), unstaged);
    table.mark_user_apc_staged_exact(slot, ID).unwrap();
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    assert!(table
        .rollback_user_apc_interrupt_requested_exact(slot, ID)
        .is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(76)));
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    table.restore_reply_cap_exact(slot, ID, 76).unwrap();
    assert_ne!(
        table.get(slot).unwrap().delivery_state & IO_DELIVERY_USER_APC_STAGED,
        0
    );
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(76)));
    table.mark_reply_published_exact(slot, ID).unwrap();
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    assert!(table.restore_reply_cap_exact(slot, ID, 76).is_none());
}

#[test]
fn ordinary_claim_and_abandoned_rows_cannot_manufacture_apc_staging() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(inline()).unwrap();
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    table.claim_reply_cap_exact(slot, ID).unwrap().unwrap();
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    table.restore_reply_cap_exact(slot, ID, 76).unwrap();
    table.abandon_thread_transfers_with(TID, |_| {});
    assert!(table.mark_user_apc_staged_exact(slot, ID).is_none());
    assert!(table.claim_reply_cap_exact(slot, ID).is_none());
}
