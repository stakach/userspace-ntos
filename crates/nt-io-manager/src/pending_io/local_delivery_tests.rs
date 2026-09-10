use super::*;

const IRP: u64 = 20;
const NOTIFY: u64 = 30;
const TID: u64 = 40;
const PENDING: u32 = nt_status::NtStatus::PENDING.raw() as u32;

fn notify() -> PendingFileIo {
    PendingFileIo {
        file_id: 10,
        irp_id: IRP,
        major: nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
        operation: PendingFileIoOperation::LocalDirectoryNotify(PendingLocalDirectoryNotify {
            notify_id: NOTIFY,
            status: PENDING,
            information: 0,
            alertable: false,
        }),
        tid: TID,
        badge: 50,
        output_va: 0x1000,
        output_len: 64,
        iosb_va: 0x2000,
        signal_file: true,
        event_obj_idx: 7,
        ..PendingFileIo::default()
    }
}

fn publish_surfaces(table: &mut PendingFileIoTable, slot: usize, irp: u64) {
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
    ] {
        table.mark_delivery_exact(slot, irp, flag).unwrap();
    }
}

#[test]
fn notification_terminal_survives_surface_ack_and_reference_release_retries() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(notify()).unwrap();
    assert_eq!(table.get(slot).unwrap().local_terminal_result(), None);
    assert!(table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 24, true));
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
    ] {
        let before_retry = table.get(slot).unwrap();
        assert_eq!(before_retry.local_terminal_result(), Some((0, 24)));
        assert_eq!(before_retry.output_offset, 24);
        assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
        assert!(table
            .mark_local_reference_released_exact(slot, IRP)
            .is_none());
        assert!(table.finish_exact(slot, IRP).is_none());
        assert_eq!(table.get(slot), Some(before_retry));
        table.mark_delivery_exact(slot, IRP, flag).unwrap();
    }
    assert!(table.completion_surfaces_published_exact(slot, IRP));
    let awaiting_ack = table.get(slot).unwrap();
    assert!(table.finish_exact(slot, IRP).is_none());
    assert_eq!(table.get(slot), Some(awaiting_ack));
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    let awaiting_reference = table.get(slot).unwrap();
    for _ in 0..3 {
        assert!(table.finish_exact(slot, IRP).is_none());
        assert_eq!(table.get(slot), Some(awaiting_reference));
        assert_eq!(
            table.get(slot).unwrap().local_terminal_result(),
            Some((0, 24))
        );
    }
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    let finished = table.finish_exact(slot, IRP).unwrap();
    assert_eq!(finished.local_terminal_result(), Some((0, 24)));
    assert_ne!(
        finished.delivery_state & IO_DELIVERY_LOCAL_REFERENCE_RELEASED,
        0
    );
    assert!(table.finish_exact(slot, IRP).is_none());
}

#[test]
fn local_reference_release_is_typed_exact_and_one_shot() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(notify()).unwrap();
    assert!(table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 24, true));
    publish_surfaces(&mut table, slot, IRP);
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    let before = table.get(slot).unwrap();
    for flag in [
        IO_DELIVERY_LOCAL_REFERENCE_RELEASED,
        IO_DELIVERY_LOCAL_REFERENCE_RELEASED | IO_DELIVERY_FILE_PUBLISHED,
    ] {
        assert!(table.mark_delivery_exact(slot, IRP, flag).is_none());
    }
    assert!(table
        .mark_local_reference_released_exact(slot, IRP + 1)
        .is_none());
    assert!(table
        .mark_local_reference_released_exact(slot + 1, IRP)
        .is_none());
    assert_eq!(table.get(slot), Some(before));
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    let released = table.get(slot).unwrap();
    assert!(table
        .mark_local_reference_released_exact(slot, IRP)
        .is_none());
    assert_eq!(table.get(slot), Some(released));
    table.finish_exact(slot, IRP).unwrap();
    let mut replacement = notify();
    replacement.irp_id += 1;
    assert_eq!(table.park(replacement), Some(slot));
    assert!(table
        .mark_local_reference_released_exact(slot, IRP)
        .is_none());
    assert!(table.finish_exact(slot, IRP).is_none());
}

#[test]
fn nonterminal_local_request_cannot_release_even_with_all_delivery_bits() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(notify()).unwrap();
    table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_BUFFER_PUBLISHED)
        .unwrap();
    publish_surfaces(&mut table, slot, IRP);
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    let before = table.get(slot).unwrap();
    assert_eq!(before.local_terminal_result(), None);
    assert!(table
        .mark_local_reference_released_exact(slot, IRP)
        .is_none());
    assert!(table.finish_exact(slot, IRP).is_none());
    assert_eq!(table.get(slot), Some(before));
}

#[test]
fn provider_transfer_cannot_receive_a_local_reference_release_mark() {
    let mut request = notify();
    request.operation = PendingFileIoOperation::Transfer;
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request).unwrap();
    table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_BUFFER_PUBLISHED)
        .unwrap();
    publish_surfaces(&mut table, slot, IRP);
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table
        .mark_local_reference_released_exact(slot, IRP)
        .is_none());
    assert!(table.finish_exact(slot, IRP).is_some());
}

#[test]
fn local_byte_lock_retains_reference_after_terminal_backend_ack() {
    let mut request = notify();
    request.major = nt_io_abi::major::IRP_MJ_LOCK_CONTROL;
    request.operation = PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
        wait_id: 31,
        status: PENDING,
        alertable: false,
    });
    request.output_va = 0;
    request.output_len = 0;
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request).unwrap();
    assert!(table.complete_local_byte_lock_exact(IRP, 31, 0xC000_0120));
    assert_eq!(
        table.get(slot).unwrap().local_terminal_result(),
        Some((0xC000_0120, 0))
    );
    publish_surfaces(&mut table, slot, IRP);
    assert!(table.completion_surfaces_published_exact(slot, IRP));
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).is_none());
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    assert!(table
        .mark_local_reference_released_exact(slot, IRP)
        .is_none());
    assert!(table.finish_exact(slot, IRP).is_some());
}

#[test]
fn abandoned_consumer_accepts_real_terminal_information_without_output_capacity() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(notify()).unwrap();
    assert!(!table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 65, true));
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 1);
    let abandoned = table.get(slot).unwrap();
    assert_eq!(abandoned.output_len, 0);
    assert!(abandoned.consumer_abandoned);
    assert!(!table.complete_local_directory_notify_exact(IRP + 1, NOTIFY, 0, 24, false));
    assert!(!table.complete_local_directory_notify_exact(IRP, NOTIFY + 1, 0, 24, false));
    assert!(table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 24, false));
    assert_eq!(
        table.get(slot).unwrap().local_terminal_result(),
        Some((0, 24))
    );
    assert!(table.completion_surfaces_published_exact(slot, IRP));
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).is_none());
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    assert_eq!(
        table
            .finish_exact(slot, IRP)
            .unwrap()
            .local_terminal_result(),
        Some((0, 24))
    );
}

#[test]
fn abandonment_preserves_already_committed_terminal_information() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(notify()).unwrap();
    assert!(table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 24, true));
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 1);
    let abandoned = table.get(slot).unwrap();
    assert_eq!(abandoned.local_terminal_result(), Some((0, 24)));
    assert_eq!(abandoned.output_offset, 0);
    assert_eq!(abandoned.output_len, 0);
    assert!(table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 24, false));
    assert!(!table.complete_local_directory_notify_exact(IRP, NOTIFY, 0, 0, false));
    assert_eq!(table.get(slot), Some(abandoned));
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    assert!(table.finish_exact(slot, IRP).is_some());
}

#[test]
fn local_terminal_helper_never_projects_provider_or_pending_results() {
    let mut request = notify();
    for operation in [
        PendingFileIoOperation::Transfer,
        PendingFileIoOperation::Create(PendingFileCreate::default()),
        PendingFileIoOperation::SetFileName(PendingSetFileNameOperation::default()),
        PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
            status: PENDING,
            ..PendingLocalByteLock::default()
        }),
        request.operation,
    ] {
        request.operation = operation;
        assert_eq!(request.local_terminal_result(), None);
    }
}
