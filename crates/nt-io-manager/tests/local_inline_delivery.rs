use nt_fs::*;
use nt_io_manager::*;

const REQUEST: u64 = 0xf000_0000_0000_0001;
const FILE_OBJECT: u64 = 0xe000_0000_0000_0000;
const REPLY: u64 = 19;

fn file() -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    let opened = fs.zw_create_file(
        r"\??\C:\owned",
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(opened.handle, 0);
    (fs, opened.handle)
}

fn terminal(status: u32, major: u8, synchronous: bool, event: u64) -> PendingFileIo {
    let publish = nt_io_completion::file_io_status_publishes_completion(status, true);
    PendingFileIo {
        file_id: FILE_OBJECT,
        irp_id: REQUEST,
        tid: 37,
        major,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status,
            information: 0,
        }),
        iosb_va: if publish { 0x1000 } else { 0 },
        apc_routine: if publish { 0x2000 } else { 0 },
        event_obj_idx: if publish { event } else { u64::MAX },
        signal_file: publish && (synchronous || event == u64::MAX),
        reply_required: true,
        reply_cap: REPLY,
        ..PendingFileIo::default()
    }
}

fn reply_and_ack(table: &mut PendingFileIoTable, slot: usize) {
    assert_eq!(
        table.claim_reply_cap_exact(slot, REQUEST),
        Some(Some(REPLY))
    );
    table.mark_reply_published_exact(slot, REQUEST).unwrap();
    table.mark_backend_acked_exact(slot, REQUEST).unwrap();
    assert!(table.finish_exact(slot, REQUEST).is_none());
}

#[test]
fn granted_lock_survives_surface_reply_and_reference_release_retries() {
    let (mut fs, handle) = file();
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    let mut locks = ByteRangeLockTable::new();
    let request = ByteRangeLockRequest::new(
        fs.query_file_object_information(handle)
            .unwrap()
            .metadata
            .file_id,
        ByteRangeLockOwner::new(FILE_OBJECT, 7, 0),
        0,
        32,
        true,
    );
    assert_eq!(
        locks.lock(request, true, REQUEST),
        ByteRangeLockResult::Granted
    );
    let slot = table
        .park_reserved(
            reservation,
            terminal(
                STATUS_SUCCESS,
                nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
                true,
                9,
            ),
        )
        .unwrap();
    // The real operation is already done. A failed IOSB copy changes no progress or lock state.
    assert_eq!(locks.active_count(), 1);
    assert_eq!(
        table.get(slot).unwrap().local_terminal_result(),
        Some((0, 0))
    );
    assert!(table.finish_exact(slot, REQUEST).is_none());
    table
        .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_IOSB_PUBLISHED)
        .unwrap();
    table
        .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_EVENT_PUBLISHED)
        .unwrap();
    // A refused filesystem admission leaves File signaling and its reference owned.
    assert!(!fs.zw_is_file_signaled(handle).unwrap());
    assert_eq!(locks.active_count(), 1);
    fs.zw_set_file_signaled(handle, true).unwrap();
    table
        .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_FILE_PUBLISHED)
        .unwrap();
    table
        .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_APC_PUBLISHED)
        .unwrap();
    assert_eq!(
        table.claim_reply_cap_exact(slot, REQUEST),
        Some(Some(REPLY))
    );
    table.restore_reply_cap_exact(slot, REQUEST, REPLY).unwrap();
    assert!(table.finish_exact(slot, REQUEST).is_none());
    assert_eq!(
        table.get(slot).unwrap().local_terminal_result(),
        Some((0, 0))
    );
    reply_and_ack(&mut table, slot);
    assert_eq!(locks.active_count(), 1);
    assert_eq!(locks.unlock_single(request), STATUS_SUCCESS);
    // Closing the handle during late release cannot remove the operation's reference.
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.query_file_object_information(handle).is_ok());
    assert!(table.finish_exact(slot, REQUEST).is_none());
    fs.zw_release_io_reference(handle).unwrap();
    table
        .mark_local_reference_released_exact(slot, REQUEST)
        .unwrap();
    table.finish_exact(slot, REQUEST).unwrap();
    assert_eq!(locks.active_count(), 0);
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn failed_notification_leaves_file_and_event_unsignaled_for_every_open_mode() {
    for synchronous in [false, true] {
        for event in [u64::MAX, 9] {
            let (mut fs, handle) = file();
            let mut table = PendingFileIoTable::new();
            let reservation = table.reserve().unwrap();
            fs.zw_begin_file_io(handle).unwrap();
            let status = fs
                .zw_notify_change_directory_file(
                    handle,
                    FILE_NOTIFY_CHANGE_FILE_NAME,
                    false,
                    128,
                    REQUEST,
                )
                .unwrap_err();
            assert_eq!(status, STATUS_NOT_A_DIRECTORY);
            assert!(fs.pop_directory_notify_completion().is_none());
            let pending = terminal(
                status,
                nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
                synchronous,
                event,
            );
            assert_eq!(pending.iosb_va, 0);
            assert_eq!(pending.apc_routine, 0);
            assert_eq!(pending.event_obj_idx, u64::MAX);
            assert!(!pending.signal_file);
            let slot = table.park_reserved(reservation, pending).unwrap();
            reply_and_ack(&mut table, slot);
            assert_eq!(
                table.get(slot).unwrap().delivery_state
                    & (IO_DELIVERY_FILE_PUBLISHED | IO_DELIVERY_EVENT_PUBLISHED),
                0
            );
            assert_eq!(
                table.get(slot).unwrap().local_terminal_result(),
                Some((status, 0))
            );
            fs.zw_release_io_reference(handle).unwrap();
            table
                .mark_local_reference_released_exact(slot, REQUEST)
                .unwrap();
            table.finish_exact(slot, REQUEST).unwrap();
            assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
            assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        }
    }
}

#[test]
fn inline_warnings_keep_completion_surfaces_and_file_signal_policy() {
    for status in [0x8000_0005u32, 0x8000_0006] {
        // BUFFER_OVERFLOW, NO_MORE_FILES
        for synchronous in [false, true] {
            for event in [u64::MAX, 9] {
                let (mut fs, handle) = file();
                let mut table = PendingFileIoTable::new();
                let reservation = table.reserve().unwrap();
                fs.zw_begin_file_io(handle).unwrap();
                let pending = terminal(
                    status,
                    nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
                    synchronous,
                    event,
                );
                assert_ne!(pending.iosb_va, 0);
                assert_ne!(pending.apc_routine, 0);
                assert_eq!(pending.event_obj_idx, event);
                assert_eq!(pending.signal_file, synchronous || event == u64::MAX);
                let slot = table.park_reserved(reservation, pending).unwrap();
                assert!(table.mark_backend_acked_exact(slot, REQUEST).is_none());
                table
                    .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_IOSB_PUBLISHED)
                    .unwrap();
                table
                    .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_APC_PUBLISHED)
                    .unwrap();
                if event != u64::MAX {
                    table
                        .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_EVENT_PUBLISHED)
                        .unwrap();
                }
                if pending.signal_file {
                    fs.zw_set_file_signaled(handle, true).unwrap();
                    table
                        .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_FILE_PUBLISHED)
                        .unwrap();
                }
                reply_and_ack(&mut table, slot);
                assert_eq!(fs.zw_is_file_signaled(handle), Ok(pending.signal_file));
                let progress = table.get(slot).unwrap().delivery_state;
                assert_eq!(
                    progress & IO_DELIVERY_FILE_PUBLISHED != 0,
                    pending.signal_file
                );
                assert_eq!(
                    progress & IO_DELIVERY_EVENT_PUBLISHED != 0,
                    event != u64::MAX
                );
                fs.zw_release_io_reference(handle).unwrap();
                table
                    .mark_local_reference_released_exact(slot, REQUEST)
                    .unwrap();
                assert_eq!(
                    table
                        .finish_exact(slot, REQUEST)
                        .unwrap()
                        .local_terminal_result(),
                    Some((status, 0))
                );
                assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
            }
        }
    }
}

#[test]
fn abandonment_preserves_terminal_operation_and_releases_only_after_ack() {
    let (mut fs, handle) = file();
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    let slot = table
        .park_reserved(
            reservation,
            terminal(
                STATUS_SUCCESS,
                nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
                true,
                9,
            ),
        )
        .unwrap();
    let mut abandoned = Vec::new();
    table.abandon_thread_transfers_with(37, |pending| abandoned.push(pending));
    assert_eq!(abandoned.len(), 1);
    assert_eq!(abandoned[0].reply_cap, REPLY);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.query_file_object_information(handle).is_ok());
    let retained = table.get(slot).unwrap();
    assert!(retained.consumer_abandoned);
    assert_eq!(retained.local_terminal_result(), Some((0, 0)));
    assert_eq!(retained.iosb_va, 0);
    assert_eq!(retained.apc_routine, 0);
    if retained.signal_file {
        fs.zw_set_file_signaled(handle, true).unwrap();
        table
            .mark_delivery_exact(slot, REQUEST, IO_DELIVERY_FILE_PUBLISHED)
            .unwrap();
    }
    table.mark_backend_acked_exact(slot, REQUEST).unwrap();
    assert!(table.finish_exact(slot, REQUEST).is_none());
    fs.zw_release_io_reference(handle).unwrap();
    table
        .mark_local_reference_released_exact(slot, REQUEST)
        .unwrap();
    table.finish_exact(slot, REQUEST).unwrap();
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
}
