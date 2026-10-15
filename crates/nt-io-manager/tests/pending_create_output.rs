use nt_io_manager::{
    PendingFileCreate, PendingFileIo, PendingFileIoOperation, PendingFileIoTable, PendingFileRoute,
    IO_DELIVERY_HANDLE_PUBLISHED, IO_DELIVERY_IOSB_PUBLISHED,
};

use nt_io_manager::{
    CreateOutputSettlement as Settlement, PendingCreateOutputAction as Action,
    PendingCreateOutputObservation as Observation,
};

fn create() -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(3),
        irp_id: 7,
        major: 0,
        iosb_va: 0x2000,
        event_obj_idx: u64::MAX,
        operation: PendingFileIoOperation::Create(PendingFileCreate {
            handle_va: 0x1000,
            reserved_handle: 42,
            reservation_pid: 1,
            reservation_generation: 1,
            status: 0x103,
            ..PendingFileCreate::default()
        }),
        ..PendingFileIo::default()
    }
}

#[test]
fn success_requires_separate_exact_ack_for_each_output_stage() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(create()).unwrap();
    let identity = table.identity(slot).unwrap();
    table.commit_create_exact(slot, 7, 0, 1, 42).unwrap();
    for action in [
        Action::CommitHandle,
        Action::Handle,
        Action::Information,
        Action::Status,
    ] {
        assert_eq!(table.create_output_action_exact(identity, 7), Some(action));
        assert!(table.mark_backend_acked_exact(slot, 7).is_none());
        let before = table.get(slot);
        table
            .observe_create_output_exact(identity, 7, action, Observation::RetryNoEffect)
            .unwrap();
        assert_eq!(table.get(slot), before);
        table
            .observe_create_output_exact(identity, 7, action, Observation::Succeeded)
            .unwrap();
        assert!(table
            .observe_create_output_exact(identity, 7, action, Observation::Succeeded)
            .is_none());
    }
    assert_eq!(
        table.create_output_action_exact(identity, 7),
        Some(Action::Complete)
    );
    let retained = table.get(slot).unwrap();
    let PendingFileIoOperation::Create(result) = retained.operation else {
        panic!("CREATE");
    };
    assert!(result.output.table_handle_committed());
    assert_eq!(result.output.status_settlement(), Settlement::Published);
    assert_eq!(retained.owned_syscall_status(), Some(0));
    assert!(table.completion_surfaces_settled_exact(slot, 7));
    table.mark_backend_acked_exact(slot, 7).unwrap();
    table.finish_exact(slot, 7).unwrap();
    let reused = table.park(create()).unwrap();
    assert_eq!(reused, slot);
    assert!(table.create_output_action_exact(identity, 7).is_none());
    assert!(table
        .observe_create_output_exact(identity, 7, Action::Status, Observation::Succeeded)
        .is_none());
}

#[test]
fn permanent_fault_keeps_terminal_and_committed_handle_but_overrides_syscall() {
    for failed_action in [Action::Handle, Action::Information, Action::Status] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(create()).unwrap();
        let identity = table.identity(slot).unwrap();
        table.commit_create_exact(slot, 7, 0, 9, 42).unwrap();
        for action in [
            Action::CommitHandle,
            Action::Handle,
            Action::Information,
            Action::Status,
        ] {
            if action == failed_action {
                break;
            }
            table
                .observe_create_output_exact(identity, 7, action, Observation::Succeeded)
                .unwrap();
        }
        table
            .observe_create_output_exact(
                identity,
                7,
                failed_action,
                Observation::UserFault(0x8000_0001),
            )
            .unwrap();
        let retained = table.get(slot).unwrap();
        let PendingFileIoOperation::Create(result) = retained.operation else {
            panic!("CREATE");
        };
        assert_eq!(
            (result.status, result.information, result.handle_value),
            (0, 9, 42)
        );
        assert!(result.output.table_handle_committed());
        assert_eq!(retained.owned_syscall_status(), Some(0x8000_0001));
        assert_eq!(
            table.create_output_action_exact(identity, 7),
            Some(Action::Complete)
        );
        assert_eq!(
            result.output.status_settlement(),
            if failed_action == Action::Status {
                Settlement::Faulted
            } else {
                Settlement::Skipped
            }
        );
        assert_eq!(retained.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
        assert!(table.completion_surfaces_settled_exact(slot, 7));
        table.mark_backend_acked_exact(slot, 7).unwrap();
        table.finish_exact(slot, 7).unwrap();
    }
}

#[test]
fn uncertain_effect_quarantines_each_stage_without_replay_or_retirement() {
    for uncertain_action in [
        Action::CommitHandle,
        Action::Handle,
        Action::Information,
        Action::Status,
    ] {
        let mut table = PendingFileIoTable::new();
        let slot = table
            .park(PendingFileIo {
                reply_required: true,
                reply_cap: 77,
                ..create()
            })
            .unwrap();
        let identity = table.identity(slot).unwrap();
        table.commit_create_exact(slot, 7, 0, 9, 42).unwrap();
        for action in [
            Action::CommitHandle,
            Action::Handle,
            Action::Information,
            Action::Status,
        ] {
            if action == uncertain_action {
                break;
            }
            table
                .observe_create_output_exact(identity, 7, action, Observation::Succeeded)
                .unwrap();
        }
        table
            .observe_create_output_exact(
                identity,
                7,
                uncertain_action,
                Observation::Uncertain(0xc000_009a),
            )
            .unwrap();
        let retained = table.get(slot);
        assert_eq!(
            table.create_output_action_exact(identity, 7),
            Some(Action::Uncertain)
        );
        assert!(table
            .observe_create_output_exact(identity, 7, uncertain_action, Observation::Succeeded)
            .is_none());
        assert!(table
            .observe_create_output_exact(identity, 7, Action::Uncertain, Observation::RetryNoEffect)
            .is_none());
        assert!(!table.completion_surfaces_settled_exact(slot, 7));
        assert!(table.claim_reply_cap_exact(slot, 7).is_none());
        assert!(table.mark_backend_acked_exact(slot, 7).is_none());
        assert!(table.finish_exact(slot, 7).is_none());
        assert!(table.take_create_exact(slot, 7).is_none());
        assert_eq!(
            table.take_thread_with(0, |_| panic!("uncertain CREATE discarded")),
            0
        );
        assert_eq!(table.get(slot), retained);
        assert_eq!(table.get(slot).unwrap().owned_syscall_status(), None);
    }
}

#[test]
fn mismatched_identity_phase_and_ack_do_not_change_owner() {
    let mut table = PendingFileIoTable::new();
    let mut foreign = PendingFileIoTable::new();
    let slot = table.park(create()).unwrap();
    let foreign_slot = foreign.park(create()).unwrap();
    let identity = table.identity(slot).unwrap();
    let foreign_identity = foreign.identity(foreign_slot).unwrap();
    table.commit_create_exact(slot, 7, 0, 1, 42).unwrap();
    let retained = table.get(slot);
    for (id, irp, action, observation) in [
        (
            foreign_identity,
            7,
            Action::CommitHandle,
            Observation::Succeeded,
        ),
        (identity, 8, Action::CommitHandle, Observation::Succeeded),
        (identity, 7, Action::Handle, Observation::Succeeded),
        (identity, 7, Action::Information, Observation::Succeeded),
        (
            identity,
            7,
            Action::CommitHandle,
            Observation::UserFault(0xc000_0005),
        ),
    ] {
        assert!(table
            .observe_create_output_exact(id, irp, action, observation)
            .is_none());
        assert_eq!(table.get(slot), retained);
    }
    assert!(table
        .mark_delivery_exact(slot, 7, IO_DELIVERY_IOSB_PUBLISHED)
        .is_none());
    assert_eq!(table.get(slot), retained);
}

#[test]
fn warning_skips_handle_and_preserves_actual_iosb_fields() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(create()).unwrap();
    let identity = table.identity(slot).unwrap();
    table
        .commit_create_exact(slot, 7, 0x8000_0005, 19, 0)
        .unwrap();
    assert_eq!(
        table.create_output_action_exact(identity, 7),
        Some(Action::Information)
    );
    table
        .observe_create_output_exact(identity, 7, Action::Information, Observation::Succeeded)
        .unwrap();
    assert!(table.mark_backend_acked_exact(slot, 7).is_none());
    table
        .observe_create_output_exact(identity, 7, Action::Status, Observation::Succeeded)
        .unwrap();
    let retained = table.get(slot).unwrap();
    assert_eq!(retained.delivery_state & IO_DELIVERY_HANDLE_PUBLISHED, 0);
    assert_eq!(retained.owned_syscall_status(), Some(0x8000_0005));
    assert!(table.completion_surfaces_settled_exact(slot, 7));
}

#[test]
fn handle_copy_cannot_precede_exact_table_handle_acknowledgement() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(create()).unwrap();
    table.commit_create_exact(slot, 7, 0, 1, 42).unwrap();
    let before = table.get(slot);
    let identity = table.identity(slot).unwrap();
    assert_eq!(
        table.observe_create_output_exact(identity, 7, Action::Handle, Observation::Succeeded),
        None,
        "terminal metadata is not acknowledgement that the handle entered its process table"
    );
    assert_eq!(table.get(slot), before);
    assert!(table.mark_backend_acked_exact(slot, 7).is_none());
}

#[test]
fn failed_create_skips_outputs_without_claiming_publication() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(create()).unwrap();
    table
        .commit_create_exact(slot, 7, 0xc000_0034, 19, 0)
        .unwrap();
    assert!(
        table.completion_surfaces_settled_exact(slot, 7),
        "ordinary error has no Handle or IOSB publication obligations"
    );
    let retained = table.get(slot).unwrap();
    assert_eq!(
        retained.delivery_state & (IO_DELIVERY_HANDLE_PUBLISHED | IO_DELIVERY_IOSB_PUBLISHED),
        0,
        "skipping outputs must not claim a user-memory effect"
    );
    let identity = table.identity(slot).unwrap();
    assert!(table
        .observe_create_output_exact(identity, 7, Action::Handle, Observation::Succeeded)
        .is_none());
    assert!(
        table.finish_exact(slot, 7).is_none(),
        "backend ACK remains independently required"
    );
    table.mark_backend_acked_exact(slot, 7).unwrap();
    let finished = table.finish_exact(slot, 7).unwrap();
    assert!(
        matches!(finished.operation, PendingFileIoOperation::Create(result)
        if result.status == 0xc000_0034 && result.information == 19 && result.handle_value == 0)
    );
}
