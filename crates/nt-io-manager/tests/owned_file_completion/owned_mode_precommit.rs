use nt_io_manager::*;

fn request(local: bool) -> PendingFileIo {
    let key = if local { FileIoWaitKey::LocalOverlay(0) } else { FileIoWaitKey::Hosted(72) };
    PendingFileIo {
        route: if local { PendingFileRoute::Local(LocalFileObject::Overlay(0)) }
            else { PendingFileRoute::Hosted(72) },
        irp_id: 71,
        tid: 73,
        badge: 74,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::OwnedModePrecommit(PendingOwnedModePrecommit {
            requested_mode: 0x16,
        }),
        busy: Some(PendingFileBusy::new(FileIoBusyOwner {
            key, tid: 73, mode: nt_io_completion::FileIoMode::SynchronousNonAlertable,
        })),
        iosb_va: 0x1000,
        event_obj_idx: u64::MAX,
        completion_port_suppressed: true,
        ..PendingFileIo::default()
    }
}

#[test]
fn precommit_retains_exact_busy_and_reference_without_terminal_surfaces() {
    for local in [false, true] {
        let mut table = PendingFileIoTable::new();
        let request = request(local);
        let slot = table.park(request).expect("executive precommit must retain its acquired owner");
        let identity = table.identity(slot).unwrap();
        let published = table.get_exact(identity).unwrap();
        assert_eq!(published.busy.unwrap().owner(), request.busy.unwrap().owner());
        assert_eq!(request.owned_terminal_result(), None);
        assert_eq!(request.owned_syscall_status(), None);
        assert!(!table.matches_completion_exact(slot, 71, 72, 73, request.major));
        assert!(table.advance_output_exact(slot, 71, 0, 0).is_none());
        for flag in [IO_DELIVERY_BUFFER_PUBLISHED, IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_FILE_PUBLISHED, IO_DELIVERY_EVENT_PUBLISHED, IO_DELIVERY_IOCP_PUBLISHED] {
            assert!(table.mark_delivery_exact(slot, 71, flag).is_none());
        }
        assert!(table.begin_busy_release_exact(slot, 71).is_err());
        assert!(table.mark_backend_acked_exact(slot, 71).is_none());
        assert!(table.mark_owned_reference_released_exact(slot, 71).is_none());
        assert!(table.record_owned_reference_release_exact(identity, 71,
            nt_io_completion::FileReferenceRelease::default()).is_none());
        assert!(table.finish_owner_exact(identity, 71).is_none());
        assert_eq!(table.get_exact(identity), Some(published), "no-effect Busy cannot mutate delivery");
    }
}

#[test]
fn exact_precommit_transitions_once_to_immutable_executive_terminal() {
    for status in [0, 0xc000_000d] {
        let mut table = PendingFileIoTable::new();
        let before = request(true);
        let slot = table.park(before).unwrap();
        let identity = table.identity(slot).unwrap();
        let published = table.get_exact(identity).unwrap();
        let mut foreign = PendingFileIoTable::new();
        let foreign_slot = foreign.park(before).unwrap();
        let foreign_identity = foreign.identity(foreign_slot).unwrap();
        assert!(table.commit_owned_mode_exact(foreign_identity, 71, status).is_none());
        assert!(table.commit_owned_mode_exact(identity, 72, status).is_none());
        assert_eq!(table.get_exact(identity), Some(published));
        assert_eq!(table.commit_owned_mode_exact(identity, 71, status), Some(()));
        let terminal = table.get_exact(identity).unwrap();
        assert_eq!(terminal.owned_terminal_result(), Some((status, 0)));
        assert_eq!(terminal.busy, published.busy);
        assert_eq!((terminal.route, terminal.tid, terminal.badge),
            (before.route, before.tid, before.badge));
        if status == 0 {
            assert_eq!(terminal.iosb_va, before.iosb_va);
        }
        assert_eq!(terminal.delivery_state, 0);
        assert!(table.commit_owned_mode_exact(identity, 71, status ^ 1).is_none());
        assert_eq!(table.get_exact(identity), Some(terminal));
        assert!(!table.matches_completion_exact(slot, 71, 72, 73, terminal.major));
        table.mark_delivery_exact(slot, 71, IO_DELIVERY_IOSB_PUBLISHED).unwrap();
        let mut release = table.begin_busy_release_exact(slot, 71).unwrap();
        table.record_busy_release(&mut release, Ok(1)).unwrap();
        let mut wake = table.begin_busy_wake_exact(slot, 71).unwrap();
        table.record_busy_wake(&mut wake, Ok(())).unwrap();
        table.mark_backend_acked_exact(slot, 71).unwrap();
        table.mark_owned_reference_released_exact(slot, 71).unwrap();
        table.finish_owner_exact(identity, 71).unwrap();
        let reused = table.park(before).unwrap();
        assert_eq!(slot, reused);
        assert!(table.commit_owned_mode_exact(identity, 71, 0).is_none());
        assert_eq!(table.get(reused).unwrap().operation, before.operation);
        assert_eq!(table.get(reused).unwrap().delivery_state, 0);
    }
}

#[test]
fn precommit_failure_transition_suppresses_unpublished_completion_surfaces() {
    let mut table = PendingFileIoTable::new();
    let mut input = request(false);
    input.signal_file = true;
    let slot = table.park(input).unwrap();
    let identity = table.identity(slot).unwrap();
    table.commit_owned_mode_exact(identity, 71, 0xc000_000d).unwrap();
    let terminal = table.get_exact(identity).unwrap();
    assert_eq!(terminal.owned_terminal_result(), Some((0xc000_000d, 0)));
    assert_eq!(terminal.iosb_va, 0, "failed class16 preparation cannot publish an IOSB");
    assert!(!terminal.signal_file, "failure cannot signal successful File completion");
    assert_eq!(terminal.delivery_state, 0, "suppression is not a synthetic publication");
    assert_eq!(terminal.busy.unwrap().owner(), input.busy.unwrap().owner());
}

#[test]
fn abandonment_preserves_precommit_scalar_and_busy_until_explicit_terminal() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request(true)).unwrap();
    let identity = table.identity(slot).unwrap();
    let published = table.get_exact(identity).unwrap();
    assert_eq!(table.abandon_thread_transfers_with(73, |_| {}), 1);
    let retained = table.get_exact(identity).unwrap();
    assert!(retained.consumer_abandoned);
    assert_eq!(retained.operation, request(true).operation);
    assert_eq!(retained.busy, published.busy);
    assert_eq!(retained.owned_terminal_result(), None);
    assert!(table.begin_busy_release_exact(slot, 71).is_err());
    assert!(table.finish_owner_exact(identity, 71).is_none());
    assert_eq!(table.commit_owned_mode_exact(identity, 71, 0xc000_0120), Some(()));
    assert_eq!(table.get_exact(identity).unwrap().owned_terminal_result(), Some((0xc000_0120, 0)));
}
