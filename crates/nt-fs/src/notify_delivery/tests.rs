use super::*;

fn completed() -> (DirectoryNotifyTable<u64>, DirectoryNotifyId) {
    let mut table = DirectoryNotifyTable::new();
    let id = table
        .register(7, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 128, 19)
        .unwrap();
    assert_eq!(
        table.report_change(DirectoryChange {
            full_path: r"\file",
            filter: FILE_NOTIFY_CHANGE_FILE_NAME,
            action: FILE_ACTION_ADDED,
        }),
        1
    );
    (table, id)
}

#[test]
fn repeated_partial_copies_retain_the_complete_result_until_acknowledgement() {
    let (mut table, id) = completed();
    let expected = table
        .completion_exact(id, &19)
        .unwrap()
        .unwrap()
        .bytes
        .clone();
    let mut first = [0xA5; 5];
    let mut repeated = [0xA5; 5];
    assert_eq!(table.copy_completion_bytes(id, &19, 0, &mut first), Ok(5));
    assert_eq!(
        table.copy_completion_bytes(id, &19, 0, &mut repeated),
        Ok(5)
    );
    assert_eq!(first, repeated);
    assert_eq!(&first, &expected[..5]);
    let mut rest = alloc::vec![0xA5; expected.len() - 5];
    assert_eq!(
        table.copy_completion_bytes(id, &19, 5, &mut rest),
        Ok(rest.len())
    );
    assert_eq!(rest, expected[5..]);
    assert_eq!(
        table.completion_exact(id, &19).unwrap().unwrap().bytes,
        expected
    );
    assert_eq!(table.acknowledge_completion(id, &19), Ok(()));
    assert_eq!(table.completion_exact(id, &19), Ok(None));
}

#[test]
fn crossed_and_missing_identities_preserve_output_and_other_completions() {
    let (mut table, id) = completed();
    let missing = DirectoryNotifyId::from_raw(id.raw() + 1).unwrap();
    for (target, context) in [(id, 20), (missing, 19), (DirectoryNotifyId(0), 19)] {
        let mut output = [0xA5; 4];
        assert_eq!(
            table.copy_completion_bytes(target, &context, 0, &mut output),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(output, [0xA5; 4]);
        assert_eq!(
            table.acknowledge_completion(target, &context),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(table.completion_exact(id, &19).unwrap().is_some());
    }
    assert_eq!(table.completion_exact(id, &20), Err(STATUS_INVALID_HANDLE));
    assert_eq!(table.completion_exact(missing, &19), Ok(None));
    assert_eq!(
        table.completion_exact(DirectoryNotifyId(0), &19),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn invalid_copy_ranges_never_change_output_or_consume_completion() {
    let (table, id) = completed();
    let len = table
        .completion_exact(id, &19)
        .unwrap()
        .unwrap()
        .bytes
        .len();
    for offset in [len - 3, len, len + 1, usize::MAX] {
        let mut output = [0xA5; 4];
        assert_eq!(
            table.copy_completion_bytes(id, &19, offset, &mut output),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(output, [0xA5; 4]);
        assert!(table.completion_exact(id, &19).unwrap().is_some());
    }
    assert_eq!(table.copy_completion_bytes(id, &19, len, &mut []), Ok(0));
    assert_eq!(
        table.copy_completion_bytes(id, &19, len + 1, &mut []),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn malformed_terminal_shapes_are_retained_without_publishing_bytes() {
    for (status, information, bytes) in [
        (0x0000_0103, 0, Vec::new()),
        (STATUS_SUCCESS, 2, alloc::vec![1]),
        (STATUS_SUCCESS, 0, alloc::vec![1]),
        (STATUS_CANCELLED, 1, alloc::vec![1]),
        (STATUS_NOTIFY_ENUM_DIR, 1, alloc::vec![1]),
        (STATUS_NOTIFY_CLEANUP, 1, alloc::vec![1]),
    ] {
        let mut table = DirectoryNotifyTable::new();
        let id = DirectoryNotifyId::from_raw(1).unwrap();
        table.completions.push_back(DirectoryNotifyCompletion {
            id,
            context: 19,
            status,
            information,
            bytes,
        });
        let mut output = [0xA5; 1];
        assert_eq!(
            table.completion_exact(id, &19),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            table.copy_completion_bytes(id, &19, 0, &mut output),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(output, [0xA5; 1]);
        assert_eq!(
            table.acknowledge_completion(id, &19),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(table.completions.len(), 1);
        assert_eq!(table.completion(id).unwrap().status, status);
    }
}

#[test]
fn cancellation_has_zero_output_and_acknowledges_exactly_once() {
    let mut table = DirectoryNotifyTable::new();
    let id = table
        .register(7, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 128, 19)
        .unwrap();
    assert!(table.cancel(id));
    assert_eq!(
        table.completion_exact(id, &19).unwrap().unwrap().status,
        STATUS_CANCELLED
    );
    assert_eq!(table.copy_completion_bytes(id, &19, 0, &mut []), Ok(0));
    let mut output = [0xA5];
    assert_eq!(
        table.copy_completion_bytes(id, &19, 0, &mut output),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(output, [0xA5]);
    assert_eq!(table.acknowledge_completion(id, &19), Ok(()));
    assert_eq!(
        table.acknowledge_completion(id, &19),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(table.completion_exact(id, &19), Ok(None));
}

#[test]
fn acknowledging_one_completion_never_consumes_another() {
    let (mut table, first) = completed();
    let second = table
        .register(8, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 128, 20)
        .unwrap();
    assert!(table.cancel(second));
    assert_eq!(
        table.acknowledge_completion(first, &20),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(table.acknowledge_completion(second, &20), Ok(()));
    assert_eq!(
        table.acknowledge_completion(second, &20),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(table.completion_exact(first, &19).unwrap().is_some());
    assert_eq!(table.acknowledge_completion(first, &19), Ok(()));
}

#[test]
fn cleanup_does_not_replace_a_ready_completion_awaiting_delivery() {
    let (mut table, ready) = completed();
    let before = table
        .completion_exact(ready, &19)
        .unwrap()
        .unwrap()
        .bytes
        .clone();
    let pending = table
        .register(7, r"\", FILE_NOTIFY_CHANGE_FILE_NAME, true, 128, 20)
        .unwrap();
    assert_eq!(table.cleanup_file_object(7), 1);
    assert_eq!(table.cleanup_file_object(7), 0);
    let retained = table.completion_exact(ready, &19).unwrap().unwrap();
    assert_eq!(retained.status, STATUS_SUCCESS);
    assert_eq!(retained.bytes, before);
    assert_eq!(
        table
            .completion_exact(pending, &20)
            .unwrap()
            .unwrap()
            .status,
        STATUS_NOTIFY_CLEANUP
    );
    assert_eq!(table.acknowledge_completion(ready, &19), Ok(()));
    assert!(table.completion_exact(pending, &20).unwrap().is_some());
}

#[test]
fn delivery_does_not_require_a_cloneable_context() {
    #[derive(PartialEq)]
    struct Context(u64);
    let mut table = DirectoryNotifyTable::new();
    let id = table
        .register(
            7,
            r"\",
            FILE_NOTIFY_CHANGE_FILE_NAME,
            true,
            128,
            Context(19),
        )
        .unwrap();
    assert!(table.cancel(id));
    assert!(table.completion_exact(id, &Context(19)).unwrap().is_some());
    assert_eq!(
        table.copy_completion_bytes(id, &Context(19), 0, &mut []),
        Ok(0)
    );
    assert_eq!(table.acknowledge_completion(id, &Context(19)), Ok(()));
}
