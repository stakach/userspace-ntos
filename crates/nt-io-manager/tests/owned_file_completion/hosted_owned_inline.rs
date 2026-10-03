//! An already committed executive mutation is not a pending driver completion.
use nt_io_manager::*;

fn terminal(status: u32) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(72),
        irp_id: 71,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::OwnedInline(PendingOwnedInline { status, information: 0 }),
        tid: 73,
        badge: 74,
        iosb_va: 0x1000,
        event_obj_idx: u64::MAX,
        reply_cap: 76,
        reply_required: true,
        completion_port_suppressed: true,
        ..PendingFileIo::default()
    }
}

#[test]
fn hosted_owned_inline_admission_preserves_committed_result_and_rejects_driver_completion() {
    for status in [0, 0xc000_000d] {
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let request = terminal(status);
        let slot = table.park_reserved(reservation, request)
            .expect("a committed Hosted mutation needs a retained delivery owner");
        assert_eq!(table.get(slot), Some(request));
        assert_eq!(request.owned_terminal_result(), Some((status, 0)));
        assert!(!table.matches_completion_exact(slot, 71, 72, 73, request.major));
        assert!(table.advance_output_exact(slot, 71, 0, 0).is_none());
        assert!(table.user_apc_interrupt_candidate(73).is_none());
        assert_eq!(table.get(slot), Some(request));
        assert!(table.finish_exact(slot, 71).is_none());
        assert!(table.mark_backend_acked_exact(slot, 71).is_none(),
            "operation retirement cannot precede delivery");
    }
}

#[test]
fn hosted_owned_inline_abandonment_keeps_the_terminal_result_and_reference_obligation() {
    let mut table = PendingFileIoTable::new();
    let request = terminal(0);
    let slot = table.park(request).expect("retained Hosted-inline owner");
    assert_eq!(table.abandon_thread_transfers_with(73, |pending| {
        assert_eq!(pending.owned_terminal_result(), Some((0, 0)));
    }), 1);
    let retained = table.get(slot).unwrap();
    assert!(retained.consumer_abandoned);
    assert_eq!(retained.owned_terminal_result(), Some((0, 0)));
    assert_eq!(retained.hosted_file_id(), Some(72));
    assert_eq!((retained.iosb_va, retained.reply_cap), (0, 0));
    assert!(table.finish_exact(slot, 71).is_none(), "abandonment does not release the File");
    assert!(table.mark_backend_acked_exact(slot, 72).is_none());
    assert_eq!(table.get(slot), Some(retained));
}
