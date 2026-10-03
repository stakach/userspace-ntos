use nt_io_manager::*;

#[test]
fn local_inline_terminal_owner_keeps_exact_overlay_busy_until_delivery_then_releases_once() {
    let owner = FileIoBusyOwner {
        key: FileIoWaitKey::LocalOverlay(0),
        tid: 73,
        mode: nt_io_completion::FileIoMode::SynchronousNonAlertable,
    };
    let request = PendingFileIo {
        route: PendingFileRoute::Local(LocalFileObject::Overlay(0)),
        irp_id: 71,
        tid: owner.tid,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::OwnedInline(PendingOwnedInline { status: 0, information: 0 }),
        busy: Some(PendingFileBusy::new(owner)),
        iosb_va: 0x1000,
        event_obj_idx: u64::MAX,
        completion_port_suppressed: true,
        ..PendingFileIo::default()
    };
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request).expect("local inline delivery owns its exact acquired Busy");
    assert!(table.begin_busy_release_exact(slot, 71).is_err());
    assert_eq!(table.get(slot).unwrap().busy.unwrap().owner(), owner);
    assert!(table.finish_exact(slot, 71).is_none());
    table.mark_delivery_exact(slot, 71, IO_DELIVERY_IOSB_PUBLISHED).unwrap();
    let mut release = table.begin_busy_release_exact(slot, 71).unwrap();
    assert_eq!(release.owner(), owner);
    table.record_busy_release(&mut release, Ok(1)).unwrap();
    assert!(table.begin_busy_release_exact(slot, 71).is_err());
    let mut wake = table.begin_busy_wake_exact(slot, 71).unwrap();
    table.record_busy_wake(&mut wake, Ok(())).unwrap();
    assert!(table.get(slot).unwrap().busy.unwrap().is_settled());
    assert!(table.finish_exact(slot, 71).is_none(), "settled Busy is not File reference release");
    assert!(table.mark_backend_acked_exact(slot, 72).is_none());
    table.mark_backend_acked_exact(slot, 71).unwrap();
    table.mark_owned_reference_released_exact(slot, 71).unwrap();
    assert_eq!(table.finish_exact(slot, 71).unwrap().owned_terminal_result(), Some((0, 0)));
    assert!(table.finish_exact(slot, 71).is_none());
}
