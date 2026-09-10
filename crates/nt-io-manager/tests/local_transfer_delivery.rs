//! Real local-transfer/terminal-delivery composition. User copy and native admission are external
//! boundaries; these tests do not execute either native mechanism or retry an output payload.

use nt_fs::*;
use nt_io_manager::*;

const ID: u64 = 0xf100_0000_0000_0001;
const FILE: u64 = 0;
const TID: u64 = 51;
const REPLY: u64 = 52;
const PATH: &str = r"\??\C:\transfer";

fn fixture(synchronous: bool) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(PATH, b"abcdef"));
    let open = fs.zw_create_file(
        PATH,
        FILE_READ_DATA | FILE_WRITE_DATA | if synchronous { SYNCHRONIZE } else { 0 },
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE
            | if synchronous {
                FILE_SYNCHRONOUS_IO_NONALERT
            } else {
                0
            },
    );
    assert_eq!(open.status, STATUS_SUCCESS);
    (fs, open.handle)
}

fn terminal(major: u8, status: u32, information: u64, synchronous: bool) -> PendingFileIo {
    let publish = nt_io_completion::file_io_status_publishes_completion(status, true);
    PendingFileIo {
        route: PendingFileRoute::Local(LocalFileObject::Overlay(FILE)),
        irp_id: ID,
        major,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status,
            information,
        }),
        tid: TID,
        iosb_va: if publish { 0x1000 } else { 0 },
        event_obj_idx: if publish { 53 } else { u64::MAX },
        signal_file: publish && synchronous,
        reply_required: true,
        reply_cap: REPLY,
        ..PendingFileIo::default()
    }
}

fn settle_reply_with_rejection(table: &mut PendingFileIoTable, slot: usize) {
    let terminal = table.get(slot).unwrap().local_terminal_result();
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(REPLY)));
    // A definitive native send rejection returns the exact cap; no user copy is repeated.
    table.restore_reply_cap_exact(slot, ID, REPLY).unwrap();
    assert_eq!(table.get(slot).unwrap().local_terminal_result(), terminal);
    assert!(table.finish_exact(slot, ID).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(REPLY)));
    table.mark_reply_published_exact(slot, ID).unwrap();
    table.mark_backend_acked_exact(slot, ID).unwrap();
    assert!(table.finish_exact(slot, ID).is_none());
}

#[test]
fn accepted_read_and_write_survive_surface_reply_and_reference_release_retries() {
    for read_operation in [true, false] {
        let (mut fs, handle) = fixture(true);
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        fs.zw_begin_file_io(handle).unwrap();
        fs.set_current_time_100ns(100);

        let (major, status, transferred) = if read_operation {
            let mut staging = [0; 8];
            let resolved = resolve_regular_file_read_offset(Some(3), true, 0).unwrap();
            let result = fs.read_backing_into(handle, resolved.value(), &mut staging);
            assert_eq!(result, (STATUS_SUCCESS, 3));
            let position = resolved
                .completion_position(true, staging.len(), result.0, result.1)
                .unwrap();
            assert_eq!(fs.complete_read(handle, result.1, position), STATUS_SUCCESS);
            let mut user_output = [0; 3];
            user_output.copy_from_slice(&staging[..result.1]);
            assert_eq!(user_output, *b"def");
            (nt_io_abi::major::IRP_MJ_READ, result.0, result.1)
        } else {
            let resolved = resolve_regular_file_write_offset(
                Some(FILE_WRITE_TO_END_OF_FILE),
                true,
                0,
                6,
                false,
            )
            .unwrap();
            let result = fs.zw_write_file(handle, Some(resolved.value()), b"XY");
            assert_eq!(result, (STATUS_SUCCESS, 2));
            let position = resolved
                .completion_position(true, 2, result.0, result.1)
                .unwrap();
            assert_eq!(fs.complete_file_position(handle, position), STATUS_SUCCESS);
            (nt_io_abi::major::IRP_MJ_WRITE, result.0, result.1)
        };
        let accepted = fs.query_file_object_information(handle).unwrap();
        assert_eq!(accepted.current_offset, if read_operation { 6 } else { 8 });
        assert_eq!(
            if read_operation {
                accepted.metadata.last_access_time
            } else {
                accepted.metadata.last_write_time
            },
            100
        );
        let bytes = fs.file_bytes(PATH).unwrap().to_vec();
        let slot = table
            .park_reserved(
                reservation,
                terminal(major, status, transferred as u64, true),
            )
            .unwrap();
        let owner = table.get(slot).unwrap();
        assert_eq!(
            (owner.output_va, owner.output_len, owner.output_offset),
            (0, 0, 0)
        );
        assert!(table.advance_output_exact(slot, ID, 0, 0).is_none());

        // After the transfer, another clock value makes any repeated metadata accounting visible.
        fs.set_current_time_100ns(999);
        let root = fs.zw_create_file(
            r"\??\C:\",
            FILE_LIST_DIRECTORY,
            0,
            0,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        );
        assert_eq!(root.status, STATUS_SUCCESS);
        fs.zw_notify_change_directory_file(
            root.handle,
            FILE_NOTIFY_CHANGE_LAST_ACCESS | FILE_NOTIFY_CHANGE_LAST_WRITE,
            false,
            256,
            ID,
        )
        .unwrap();
        for flag in [IO_DELIVERY_IOSB_PUBLISHED, IO_DELIVERY_EVENT_PUBLISHED] {
            let before_retry = table.get(slot);
            assert!(table.mark_backend_acked_exact(slot, ID).is_none());
            assert!(table.finish_exact(slot, ID).is_none());
            assert_eq!(table.get(slot), before_retry);
            assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
            table.mark_delivery_exact(slot, ID, flag).unwrap();
        }
        assert!(!fs.zw_is_file_signaled(handle).unwrap());
        fs.zw_set_file_signaled(handle, true).unwrap();
        table
            .mark_delivery_exact(slot, ID, IO_DELIVERY_FILE_PUBLISHED)
            .unwrap();
        settle_reply_with_rejection(&mut table, slot);

        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        for _ in 0..2 {
            // A refused release admission performs no release and leaves the exact owner live.
            assert!(table.finish_exact(slot, ID).is_none());
            assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
            assert_eq!(
                table.get(slot).unwrap().local_terminal_result(),
                Some((status, transferred as u64))
            );
        }
        assert!(fs.pop_directory_notify_completion().is_none());
        assert_eq!(fs.file_bytes(PATH).unwrap(), bytes.as_slice());
        fs.zw_release_io_reference(handle).unwrap();
        table.mark_local_reference_released_exact(slot, ID).unwrap();
        table.finish_exact(slot, ID).unwrap();
        assert_eq!(
            fs.query_file_object_information(handle),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(fs.file_bytes(PATH).unwrap(), bytes.as_slice());
    }
}

#[test]
fn definitive_read_copy_fault_keeps_accepted_position_and_access_metadata() {
    let (mut fs, handle) = fixture(true);
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    fs.set_current_time_100ns(123);
    let mut staging = [0; 4];
    let resolved = resolve_regular_file_read_offset(Some(1), true, 0).unwrap();
    let (status, read) = fs.read_backing_into(handle, resolved.value(), &mut staging);
    assert_eq!((status, read), (STATUS_SUCCESS, 4));
    let position = resolved.completion_position(true, 4, status, read).unwrap();
    assert_eq!(fs.complete_read(handle, read, position), STATUS_SUCCESS);
    let accepted = fs.query_file_object_information(handle).unwrap();
    assert_eq!(accepted.current_offset, 5);
    assert_eq!(accepted.metadata.last_access_time, 123);

    // Explicit external-copy outcome: a prefix reached the user before a definitive fault.
    // This is not a native memory-copy implementation, and no retry of this payload follows.
    let mut user_output = [0xcc; 4];
    user_output[..2].copy_from_slice(&staging[..2]);
    let copy_status = 0xc000_0005; // STATUS_ACCESS_VIOLATION
    let pending = terminal(
        nt_io_abi::major::IRP_MJ_READ,
        copy_status,
        read as u64,
        true,
    );
    assert_eq!(pending.iosb_va, 0);
    assert_eq!(pending.event_obj_idx, u64::MAX);
    assert!(!pending.signal_file);
    let slot = table.park_reserved(reservation, pending).unwrap();
    fs.set_current_time_100ns(999);
    settle_reply_with_rejection(&mut table, slot);
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
    assert_eq!(
        table.get(slot).unwrap().delivery_state
            & (IO_DELIVERY_FILE_PUBLISHED | IO_DELIVERY_EVENT_PUBLISHED),
        0
    );
    assert_eq!(user_output, [b'b', b'c', 0xcc, 0xcc]);
    assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
    assert_eq!(
        table.get(slot).unwrap().local_terminal_result(),
        Some((copy_status, read as u64))
    );
    fs.zw_release_io_reference(handle).unwrap();
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    table.finish_exact(slot, ID).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
}

#[test]
fn asynchronous_completed_write_keeps_exact_reply_until_delivery_or_abandonment() {
    for abandon in [false, true] {
        let (mut fs, handle) = fixture(false);
        assert_eq!(fs.complete_file_position(handle, Some(4)), STATUS_SUCCESS);
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        fs.zw_begin_file_io(handle).unwrap();
        let resolved = resolve_regular_file_write_offset(Some(1), false, 4, 6, false).unwrap();
        let result = fs.zw_write_file(handle, Some(resolved.value()), b"XY");
        assert_eq!(result, (STATUS_SUCCESS, 2));
        let position = resolved
            .completion_position(false, 2, result.0, result.1)
            .unwrap();
        assert_eq!(position, None);
        assert_eq!(fs.complete_file_position(handle, position), STATUS_SUCCESS);
        let slot = table
            .park_reserved(
                reservation,
                terminal(
                    nt_io_abi::major::IRP_MJ_WRITE,
                    result.0,
                    result.1 as u64,
                    false,
                ),
            )
            .unwrap();
        assert_eq!(fs.current_offset(handle), Some(4));
        assert!(!fs.zw_is_file_signaled(handle).unwrap());
        assert!(table.get(slot).unwrap().reply_required);
        if abandon {
            let mut released_reply = None;
            assert_eq!(
                table.abandon_thread_transfers_with(TID, |owner| released_reply =
                    Some(owner.reply_cap)),
                1
            );
            assert_eq!(released_reply, Some(REPLY));
            assert!(table.get(slot).unwrap().consumer_abandoned);
            table.mark_backend_acked_exact(slot, ID).unwrap();
        } else {
            table
                .mark_delivery_exact(slot, ID, IO_DELIVERY_IOSB_PUBLISHED)
                .unwrap();
            table
                .mark_delivery_exact(slot, ID, IO_DELIVERY_EVENT_PUBLISHED)
                .unwrap();
            settle_reply_with_rejection(&mut table, slot);
        }
        assert_eq!(
            table.get(slot).unwrap().local_terminal_result(),
            Some((STATUS_SUCCESS, 2))
        );
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        assert!(table.finish_exact(slot, ID).is_none());
        assert_eq!(fs.current_offset(handle), Some(4));
        assert_eq!(fs.file_bytes(PATH), Some(&b"aXYdef"[..]));
        fs.zw_release_io_reference(handle).unwrap();
        table.mark_local_reference_released_exact(slot, ID).unwrap();
        table.finish_exact(slot, ID).unwrap();
        assert_eq!(
            fs.query_file_object_information(handle),
            Err(STATUS_INVALID_HANDLE)
        );
    }
}
