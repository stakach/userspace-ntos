use super::*;

const IRP: u64 = 7;
const IOSB: u64 = 0x1000;
const TID: u64 = 11;

fn provider() -> PendingFileIo {
    PendingFileIo {
        file_id: 3,
        irp_id: IRP,
        major: nt_io_abi::major::IRP_MJ_READ,
        tid: TID,
        iosb_va: IOSB,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

fn local() -> PendingFileIo {
    PendingFileIo {
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status: 0x8000_0005,
            information: 41,
        }),
        ..provider()
    }
}

#[test]
fn local_fault_preserves_terminal_and_destination_without_publishing() {
    let mut table = PendingFileIoTable::new();
    let original = local();
    let slot = table.park(original).unwrap();
    assert_eq!(
        table.mark_iosb_faulted_exact(slot, IRP, IOSB),
        Some(IO_DELIVERY_IOSB_FAULTED)
    );
    let retained = table.get(slot).unwrap();
    assert_eq!(retained.iosb_va, IOSB);
    assert_eq!(retained.operation, original.operation);
    assert_eq!(retained.local_terminal_result(), Some((0x8000_0005, 41)));
    assert_eq!(retained.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
    assert!(table.completion_surfaces_settled_exact(slot, IRP));
    assert!(table.finish_exact(slot, IRP).is_none());
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).is_none());
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    let finished = table.finish_exact(slot, IRP).unwrap();
    assert_eq!(finished.iosb_va, IOSB);
    assert_eq!(finished.operation, original.operation);
    assert_eq!(finished.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
}

#[test]
fn fault_requires_exact_live_identity_and_is_not_generically_markable() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(local()).unwrap();
    let original = table.get(slot);
    for (target, irp, iosb) in [
        (slot + 1, IRP, IOSB),
        (slot, IRP + 1, IOSB),
        (slot, IRP, IOSB + 8),
        (slot, IRP, 0),
    ] {
        assert!(table.mark_iosb_faulted_exact(target, irp, iosb).is_none());
        assert_eq!(table.get(slot), original);
    }
    for flags in [
        IO_DELIVERY_IOSB_FAULTED,
        IO_DELIVERY_IOSB_FAULTED | IO_DELIVERY_IOSB_PUBLISHED,
    ] {
        assert!(table.mark_delivery_exact(slot, IRP, flags).is_none());
        assert_eq!(table.get(slot), original);
    }
}

#[test]
fn publication_and_fault_are_mutually_exclusive_and_fault_is_exactly_once() {
    for published_first in [false, true] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(provider()).unwrap();
        if published_first {
            table
                .mark_delivery_exact(slot, IRP, IO_DELIVERY_IOSB_PUBLISHED)
                .unwrap();
        } else {
            table.mark_iosb_faulted_exact(slot, IRP, IOSB).unwrap();
        }
        let settled = table.get(slot);
        assert!(table.mark_iosb_faulted_exact(slot, IRP, IOSB).is_none());
        if !published_first {
            assert!(table
                .mark_delivery_exact(slot, IRP, IO_DELIVERY_IOSB_PUBLISHED)
                .is_none());
        }
        assert_eq!(table.get(slot), settled);
    }
}

#[test]
fn absent_destination_abandonment_and_retirement_progress_reject_faults() {
    let mut table = PendingFileIoTable::new();
    let mut without_iosb = provider();
    without_iosb.iosb_va = 0;
    let slot = table.park(without_iosb).unwrap();
    assert!(table.mark_iosb_faulted_exact(slot, IRP, IOSB).is_none());
    assert!(table.mark_iosb_faulted_exact(slot, IRP, 0).is_none());

    for progress in [
        IO_DELIVERY_BACKEND_ACKED,
        IO_DELIVERY_LOCAL_REFERENCE_RELEASED,
    ] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(local()).unwrap();
        table.slots[slot].as_mut().unwrap().delivery_state = progress;
        let before = table.get(slot);
        assert!(table.mark_iosb_faulted_exact(slot, IRP, IOSB).is_none());
        assert_eq!(table.get(slot), before);
    }
    let mut table = PendingFileIoTable::new();
    let slot = table.park(local()).unwrap();
    table.abandon_thread_transfers_with(TID, |_| {});
    let abandoned = table.get(slot);
    assert!(table.mark_iosb_faulted_exact(slot, IRP, IOSB).is_none());
    assert_eq!(table.get(slot), abandoned);
}

#[test]
fn provider_fault_does_not_skip_payload_signals_apc_reply_or_file_lock() {
    let mut table = PendingFileIoTable::new();
    let request = PendingFileIo {
        output_va: 0x2000,
        output_len: 8,
        signal_file: true,
        event_obj_idx: 1,
        apc_routine: 0x3000,
        reply_cap: 5,
        reply_required: true,
        busy: Some(test_busy(provider().file_id, TID)),
        ..provider()
    };
    let slot = table.park(request).unwrap();
    table.mark_iosb_faulted_exact(slot, IRP, IOSB).unwrap();
    assert!(!table.completion_surfaces_settled_exact(slot, IRP));
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    assert_eq!(table.advance_output_exact(slot, IRP, 4, 8), Some(4));
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    assert_eq!(table.advance_output_exact(slot, IRP, 4, 8), Some(8));
    for flag in [
        IO_DELIVERY_FILE_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_APC_PUBLISHED,
    ] {
        assert!(!table.completion_surfaces_settled_exact(slot, IRP));
        assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
        table.mark_delivery_exact(slot, IRP, flag).unwrap();
    }
    assert!(table.claim_reply_cap_exact(slot, IRP).is_none());
    settle_test_busy(&mut table, slot, IRP);
    assert_eq!(table.claim_reply_cap_exact(slot, IRP), Some(Some(5)));
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    table.mark_reply_published_exact(slot, IRP).unwrap();
    assert!(table.completion_surfaces_settled_exact(slot, IRP));
    assert!(table.finish_exact(slot, IRP).is_none());
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table
        .mark_local_reference_released_exact(slot, IRP)
        .is_none());
    let finished = table.finish_exact(slot, IRP).unwrap();
    assert_eq!(finished.iosb_va, IOSB);
    assert_eq!(finished.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
}

#[test]
fn fault_does_not_skip_iocp_delivery() {
    let mut table = PendingFileIoTable::new();
    let request = PendingFileIo {
        publish_iocp: true,
        ..provider()
    };
    let slot = table.park(request).unwrap();
    table.mark_iosb_faulted_exact(slot, IRP, IOSB).unwrap();
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_IOCP_PUBLISHED)
        .unwrap();
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).is_some());
}

#[test]
fn create_fault_does_not_skip_commit_or_user_handle_publication() {
    let mut table = PendingFileIoTable::new();
    let request = PendingFileIo {
        major: nt_io_abi::major::IRP_MJ_CREATE,
        operation: PendingFileIoOperation::Create(PendingFileCreate {
            handle_va: 0x2000,
            reservation_pid: 1,
            reserved_handle: 2,
            reservation_generation: 3,
            status: nt_status::NtStatus::PENDING.raw() as u32,
            ..PendingFileCreate::default()
        }),
        ..provider()
    };
    let slot = table.park(request).unwrap();
    table.mark_iosb_faulted_exact(slot, IRP, IOSB).unwrap();
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    table.commit_create_exact(slot, IRP, 0, 1, 2).unwrap();
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    table.mark_create_handle_published_exact(slot, IRP).unwrap();
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    let finished = table.finish_exact(slot, IRP).unwrap();
    let PendingFileIoOperation::Create(create) = finished.operation else {
        panic!()
    };
    assert_eq!(
        (create.status, create.information, create.handle_value),
        (0, 1, 2)
    );
    assert_eq!(finished.iosb_va, IOSB);
    assert_eq!(finished.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
}

#[test]
fn retired_and_reused_slots_reject_the_old_fault_identity() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(provider()).unwrap();
    table.mark_iosb_faulted_exact(slot, IRP, IOSB).unwrap();
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    table.finish_exact(slot, IRP).unwrap();
    assert!(table.mark_iosb_faulted_exact(slot, IRP, IOSB).is_none());
    let replacement = PendingFileIo {
        irp_id: IRP + 1,
        ..provider()
    };
    assert_eq!(table.park(replacement), Some(slot));
    assert!(table.mark_iosb_faulted_exact(slot, IRP, IOSB).is_none());
    assert_eq!(table.get(slot), Some(replacement));
    assert!(table.mark_iosb_faulted_exact(slot, IRP + 1, IOSB).is_some());
}
