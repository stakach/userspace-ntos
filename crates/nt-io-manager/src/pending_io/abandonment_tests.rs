use super::*;

fn transfer(irp: u64) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(11),
        irp_id: irp,
        major: nt_io_abi::major::IRP_MJ_READ,
        tid: 13,
        busy: Some(test_busy(11, 13)),
        output_va: 0x1000,
        output_len: 8,
        iosb_va: 0x2000,
        apc_routine: 0x3000,
        apc_context: 0x4000,
        signal_file: true,
        event_obj_idx: 5,
        ..PendingFileIo::default()
    }
}

fn create(irp: u64) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(11),
        irp_id: irp,
        major: nt_io_abi::major::IRP_MJ_CREATE,
        operation: PendingFileIoOperation::Create(PendingFileCreate {
            handle_va: 0x1000,
            desired_access: 3,
            provider_context: 4,
            reservation_pid: 5,
            reserved_handle: 6,
            reservation_generation: 7,
            status: nt_status::NtStatus::PENDING.raw() as u32,
            information: 0,
            handle_value: 0,
        }),
        tid: 13,
        iosb_va: 0x2000,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

#[test]
fn exact_abandonment_preserves_busy_and_never_touches_peer_of_same_thread() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(transfer(12)).unwrap();
    let peer = table.park(transfer(14)).unwrap();
    let original = table.get(slot).unwrap();
    let other = table.get(peer).unwrap();
    assert_eq!(table.abandon_transfer_exact(slot, 99), None);
    assert_eq!(table.abandon_transfer_exact(usize::MAX, 12), None);
    assert_eq!(table.abandon_transfer_exact(slot, 12), Some(original));
    assert_eq!(table.get(peer), Some(other));
    let live = table.get(slot).unwrap();
    assert!(live.consumer_abandoned);
    assert_eq!(live.busy, original.busy);
    assert_eq!(live.irp_id, original.irp_id);
    assert_eq!(live.route, original.route);
    assert_eq!(
        (
            live.output_va,
            live.output_len,
            live.iosb_va,
            live.apc_routine,
            live.apc_context
        ),
        (0, 0, 0, 0, 0)
    );
    assert!(!live.signal_file && !live.publish_iocp && !live.reply_required);
    assert_eq!(live.event_obj_idx, u64::MAX);
    assert_eq!(table.abandon_transfer_exact(slot, 12), None);
    assert!(table.mark_backend_acked_exact(slot, 12).is_none());
    settle_test_busy(&mut table, slot, 12);
    table.mark_backend_acked_exact(slot, 12).unwrap();
    table.finish_exact(slot, 12).unwrap();
    assert_eq!(table.get(peer), Some(other));
}

#[test]
fn claimed_reply_blocks_exact_and_threadwide_abandonment() {
    let mut table = PendingFileIoTable::new();
    let pending = PendingFileIo {
        busy: None,
        reply_required: true,
        reply_cap: 77,
        ..transfer(12)
    };
    let slot = table.park(pending).unwrap();
    assert_eq!(table.claim_reply_cap_exact(slot, 12), Some(Some(77)));
    let claimed = table.get(slot).unwrap();
    assert_eq!(table.abandon_transfer_exact(slot, 12), None);
    assert_eq!(
        table.abandon_thread_transfers_with(13, |_| panic!("claimed reply extracted")),
        0
    );
    assert_eq!(table.get(slot), Some(claimed));
}

#[test]
fn unclaimed_reply_snapshot_is_returned_only_once() {
    let mut table = PendingFileIoTable::new();
    let pending = PendingFileIo {
        reply_required: true,
        reply_cap: 77,
        resume_ip: 1,
        resume_sp: 2,
        resume_flags: 3,
        ..transfer(12)
    };
    let slot = table.park(pending).unwrap();
    let original = table.get(slot).unwrap();
    assert_eq!(table.abandon_transfer_exact(slot, 12), Some(original));
    let live = table.get(slot).unwrap();
    assert_eq!(
        (
            live.reply_cap,
            live.resume_ip,
            live.resume_sp,
            live.resume_flags
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(table.abandon_transfer_exact(slot, 12), None);
    assert_eq!(
        table.abandon_thread_transfers_with(13, |_| panic!("reply extracted twice")),
        0
    );
}

#[test]
fn create_requires_specialized_exact_removal_with_reserved_handle_preserved() {
    let mut table = PendingFileIoTable::new();
    let request = create(12);
    let slot = table.park(request).unwrap();
    let peer = table.park(create(14)).unwrap();
    assert_eq!(table.abandon_transfer_exact(slot, 12), None);
    assert_eq!(
        table.abandon_thread_transfers_with(13, |_| panic!("CREATE abandoned")),
        0
    );
    assert_eq!(table.take_create_exact(slot, 99), None);
    assert_eq!(table.take_create_exact(slot, 12), Some(request));
    assert_eq!(table.take_create_exact(slot, 12), None);
    assert_eq!(table.get(peer), Some(create(14)));
    assert_eq!(
        table.take_thread_creates_with(13, |pending| assert_eq!(pending, create(14))),
        1
    );
    assert!(table.is_empty());
}

#[test]
fn exact_create_removal_refuses_transfer_and_claimed_create() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(transfer(12)).unwrap();
    assert_eq!(table.take_create_exact(slot, 12), None);
    let request = PendingFileIo {
        reply_cap: 77,
        reply_required: true,
        ..create(14)
    };
    let create_slot = table.park(request).unwrap();
    table.commit_create_exact(create_slot, 14, 0, 1, 6).unwrap();
    table
        .mark_create_handle_published_exact(create_slot, 14)
        .unwrap();
    table
        .mark_delivery_exact(create_slot, 14, IO_DELIVERY_IOSB_PUBLISHED)
        .unwrap();
    assert_eq!(table.claim_reply_cap_exact(create_slot, 14), Some(Some(77)));
    let claimed = table.get(create_slot).unwrap();
    assert_eq!(table.take_create_exact(create_slot, 14), None);
    assert_eq!(
        table.take_thread_creates_with(13, |_| panic!("claimed CREATE extracted")),
        0
    );
    assert_eq!(table.get(create_slot), Some(claimed));
}
