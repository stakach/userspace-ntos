use super::*;

fn name_query(irp: u64) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(11),
        irp_id: irp,
        major: nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
        operation: PendingFileIoOperation::ObjectNameQuery(PendingObjectNameQuery {
            information_va: 0x7000,
            length: 512,
            return_length_va: 0x6ff8,
        }),
        tid: 13,
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

/// The filesystem's FileNameInformation is not what the caller asked for: the row never lets
/// the generic delivery copy the IRP's output or publish an IO_STATUS_BLOCK.
#[test]
fn a_pended_name_query_owns_no_generic_completion_surface() {
    let mut table = PendingFileIoTable::new();
    assert!(table.park(name_query(21)).is_some());
    // A synchronous File is still signalled when its query completes.
    assert!(table.park(PendingFileIo { signal_file: true, ..name_query(20) }).is_some());
    for broken in [
        PendingFileIo { output_va: 0x7000, output_len: 512, ..name_query(22) },
        PendingFileIo { iosb_va: 0x5000, ..name_query(23) },
        PendingFileIo { apc_routine: 0x4000, ..name_query(24) },
        PendingFileIo { event_obj_idx: 3, ..name_query(25) },
        PendingFileIo { major: nt_io_abi::major::IRP_MJ_READ, ..name_query(26) },
        PendingFileIo {
            route: PendingFileRoute::Local(LocalFileObject::Overlay(1)),
            ..name_query(27)
        },
    ] {
        assert_eq!(table.park(broken), None);
    }
}

#[test]
fn the_formatted_answer_becomes_the_rows_terminal_status_once() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(name_query(21)).unwrap();
    let identity = table.identity(slot).unwrap();
    assert_eq!(table.get(slot).unwrap().owned_terminal_result(), None);
    // The wrong IRP, a stale identity and STATUS_PENDING settle nothing.
    assert_eq!(table.complete_object_name_query_exact(identity, 99, 0), None);
    assert_eq!(table.complete_object_name_query_exact(identity, 21, 0x103), None);
    let stale = PendingFileIoIdentity { generation: identity.generation + 1, ..identity };
    assert_eq!(table.complete_object_name_query_exact(stale, 21, 0), None);
    assert_eq!(table.get(slot).unwrap().owned_terminal_result(), None);

    assert_eq!(table.complete_object_name_query_exact(identity, 21, 0x8000_0005), Some(()));
    let live = table.get(slot).unwrap();
    assert_eq!(live.owned_terminal_result(), Some((0x8000_0005, 0)));
    assert_eq!(live.owned_syscall_status(), Some(0x8000_0005));
    assert_eq!(live.route, PendingFileRoute::Hosted(11));
    // The IRP is acknowledged by now; a second completion has nothing to settle.
    assert_eq!(table.complete_object_name_query_exact(identity, 21, 0), None);
    assert!(!table.matches_completion_exact(slot, 21, 11, 13, nt_io_abi::major::IRP_MJ_QUERY_INFORMATION));
}
