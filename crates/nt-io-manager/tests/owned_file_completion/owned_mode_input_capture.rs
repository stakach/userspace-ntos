use nt_io_manager::*;

fn request() -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(72),
        irp_id: 71,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        tid: 73,
        badge: 74,
        operation: PendingFileIoOperation::OwnedModeInputCapture(PendingOwnedModeInputCapture {
            input_va: 0x2ffc,
            length: 8,
            next_page: 0x2000,
            pending_page: 0,
            pending_token: 0,
            signal_reset: false,
        }),
        busy: Some(PendingFileBusy::new(FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(72), tid: 73,
            mode: nt_io_completion::FileIoMode::SynchronousNonAlertable,
        })),
        iosb_va: 0x1000,
        signal_file: true,
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

#[test]
fn input_pages_require_exact_owner_token_and_terminal_capture_before_mode_commit() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request()).unwrap();
    let identity = table.identity(slot).unwrap();
    let published = table.get_exact(identity).unwrap();
    let mut foreign = PendingFileIoTable::new();
    let other = foreign.park(request()).unwrap();
    let foreign_identity = foreign.identity(other).unwrap();

    assert!(table.begin_mode_input_page_exact(identity, 71, 0x2000, 1).is_none());
    assert!(table.mark_mode_input_signal_reset_exact(foreign_identity, 71).is_none());
    table.mark_mode_input_signal_reset_exact(identity, 71).unwrap();
    assert!(table.finish_mode_input_capture_exact(identity, 71, 0x16).is_none());
    table.complete_mode_input_page_exact(identity, 71, 0x2000, 0, 0).unwrap();
    table.begin_mode_input_page_exact(identity, 71, 0x3000, 99).unwrap();
    assert!(table.complete_mode_input_page_exact(identity, 71, 0x3000, 98, 0).is_none());
    assert!(table.complete_mode_input_page_exact(identity, 71, 0x2000, 99, 0).is_none());
    assert!(table.abort_unentered_mode_input_page_exact(identity, 71, 0x3000, 98).is_none());
    assert!(table.finish_mode_input_capture_exact(identity, 71, 0x16).is_none());
    assert_eq!(table.get_exact(identity).unwrap().busy, published.busy);
    assert!(table.mark_delivery_exact(slot, 71, IO_DELIVERY_IOSB_PUBLISHED).is_none());
    assert!(table.begin_busy_release_exact(slot, 71).is_err());
    assert!(table.finish_owner_exact(identity, 71).is_none());

    table.complete_mode_input_page_exact(identity, 71, 0x3000, 99, 0).unwrap();
    assert!(table.finish_mode_input_capture_exact(foreign_identity, 71, 0x16).is_none());
    table.finish_mode_input_capture_exact(identity, 71, 0x16).unwrap();
    assert_eq!(table.get_exact(identity).unwrap().operation,
        PendingFileIoOperation::OwnedModePrecommit(PendingOwnedModePrecommit {
            requested_mode: 0x16,
        }));
    table.commit_owned_mode_exact(identity, 71, 0).unwrap();
    assert_eq!(table.get_exact(identity).unwrap().owned_terminal_result(), Some((0, 0)));
    assert_eq!(table.get_exact(identity).unwrap().iosb_va, published.iosb_va);
}

#[test]
fn failed_routed_page_suppresses_iosb_and_preserves_busy_until_delivery() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request()).unwrap();
    let identity = table.identity(slot).unwrap();
    table.mark_mode_input_signal_reset_exact(identity, 71).unwrap();
    table.begin_mode_input_page_exact(identity, 71, 0x2000, 99).unwrap();
    assert!(table.fail_mode_input_exact(identity, 71, 0xc000_0005).is_none(),
        "an entered worker cannot be discarded by local failure");
    table.complete_mode_input_page_exact(identity, 71, 0x2000, 99, 0xc000_0005).unwrap();
    let terminal = table.get_exact(identity).unwrap();
    assert_eq!(terminal.owned_terminal_result(), Some((0xc000_0005, 0)));
    assert_eq!(terminal.iosb_va, 0);
    assert!(!terminal.signal_file);
    assert_eq!(terminal.busy.unwrap().owner(), request().busy.unwrap().owner());
    assert_eq!(terminal.delivery_state, 0);
    assert!(table.complete_mode_input_page_exact(identity, 71, 0x2000, 99, 0).is_none());
}

#[test]
fn abandoned_input_keeps_exact_inflight_page_until_its_callback() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request()).unwrap();
    let identity = table.identity(slot).unwrap();
    table.mark_mode_input_signal_reset_exact(identity, 71).unwrap();
    table.begin_mode_input_page_exact(identity, 71, 0x2000, 99).unwrap();
    assert_eq!(table.abandon_thread_transfers_with(73, |_| {}), 1);
    assert!(table.fail_mode_input_exact(identity, 71, 0xc000_0120).is_none());
    assert!(table.finish_owner_exact(identity, 71).is_none());
    table.complete_mode_input_page_exact(identity, 71, 0x2000, 99, 0).unwrap();
    table.fail_mode_input_exact(identity, 71, 0xc000_0120).unwrap();
    assert_eq!(table.get_exact(identity).unwrap().owned_terminal_result(), Some((0xc000_0120, 0)));
}
