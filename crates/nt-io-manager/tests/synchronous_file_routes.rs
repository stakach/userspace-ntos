//! Typed wait routes composed with canonical local and hosted File ownership.
//! Retry outcomes are fixture inputs; these tests do not execute native IPC or syscall ingress.

use nt_fs::*;
use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::{
    FileIoWaitKey, FileIoWaitRoute, SynchronousFileRetryOutcome, SynchronousFileWaitTable,
    SynchronousFileWaiter,
};

const MODE: FileIoMode = FileIoMode::SynchronousAlertable;
const ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE;
const DEVICE: u64 = 7;
const SERVICE: u32 = 191;
const PI: u32 = 2;

fn local_files() -> (FileSystem, u64, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\routed", b"abcdef"));
    let mut open = || {
        let result = fs.zw_create_file(
            r"\??\C:\routed",
            ACCESS,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
        );
        assert_eq!(result.status, STATUS_SUCCESS);
        result.handle
    };
    let zero = open();
    let second = open();
    assert_eq!(
        zero, 0,
        "the first canonical local File identity is valid zero"
    );
    assert_ne!(second, zero);
    (fs, zero, second)
}

fn waiter(route: FileIoWaitRoute, tid: u64) -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        route,
        0x40,
        ACCESS,
        SERVICE,
        PI,
        tid,
        tid + 100,
        MODE,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = tid + 200;
    waiter.reply_mrs = core::array::from_fn(|index| 0xa000 + index as u64);
    waiter
}

fn hosted(file_id: u64) -> FileIoWaitRoute {
    FileIoWaitRoute::Hosted {
        file_id,
        device_id: DEVICE,
        fs_context: 0x1234,
    }
}

fn local(file_object: u64) -> FileIoWaitRoute {
    FileIoWaitRoute::LocalOverlay { file_object }
}

#[test]
fn equal_numeric_routes_and_local_zero_have_independent_fifo_grants() {
    let (mut fs, zero, same_id) = local_files();
    let mut files = FileCompletionTable::<1>::new();
    files.insert_file_with_mode(same_id, DEVICE, MODE).unwrap();
    let mut queue = SynchronousFileWaitTable::new();

    for (file, active_tid, waiting_tid) in [(zero, 10, 11), (same_id, 20, 21)] {
        assert_eq!(
            fs.zw_acquire_file_io(file, active_tid),
            Ok(FileIoAcquireResult::Acquired)
        );
        assert_eq!(
            fs.zw_acquire_file_io(file, waiting_tid),
            Ok(FileIoAcquireResult::Contended { alertable: true })
        );
        queue.park(waiter(local(file), waiting_tid)).unwrap();
    }
    files.retain_file(same_id).unwrap();
    assert_eq!(
        files.begin_io(same_id, 30),
        Ok(FileIoAcquireResult::Acquired)
    );
    files.retain_file(same_id).unwrap();
    assert_eq!(
        files.begin_io(same_id, 31),
        Ok(FileIoAcquireResult::Contended { alertable: true })
    );
    queue.park(waiter(hosted(same_id), 31)).unwrap();

    fs.zw_release_file_io(zero, 10).unwrap();
    fs.zw_release_io_reference(zero).unwrap();
    fs.zw_release_file_io(same_id, 20).unwrap();
    fs.zw_release_io_reference(same_id).unwrap();
    files.release_io(same_id, 30).unwrap();
    files.release_file(same_id).unwrap();

    // Promoting one domain must not suppress an unrelated domain with the same numeric ID.
    for (route, tid) in [
        (hosted(same_id), 31),
        (local(same_id), 21),
        (local(zero), 11),
    ] {
        let (slot, captured) = queue.oldest_waiting_for_file(route.key()).unwrap();
        assert_eq!(captured.route, route);
        assert_eq!(captured.tid, tid);
        match route {
            FileIoWaitRoute::Hosted { file_id, .. } => {
                assert_eq!(files.promote_io_waiter(file_id, tid), Ok(0));
            }
            FileIoWaitRoute::LocalOverlay { file_object } => {
                assert_eq!(fs.zw_promote_file_io_waiter(file_object, tid), Ok(0));
            }
        }
        queue.promote_exact(slot, route.key(), tid).unwrap();
        assert!(queue.oldest_waiting_for_file(route.key()).is_none());
    }
    assert_eq!(files.io_lock_owner(same_id), Ok(Some(31)));
    assert_eq!(fs.zw_file_io_state(same_id).unwrap().owner_tid, Some(21));
    assert_eq!(fs.zw_file_io_state(zero).unwrap().owner_tid, Some(11));
    assert!(queue.has_retry_delivery_for_file(FileIoWaitKey::Hosted(same_id)));
    assert!(queue.has_retry_delivery_for_file(FileIoWaitKey::LocalOverlay(same_id)));
    assert!(queue.has_retry_delivery_for_file(FileIoWaitKey::LocalOverlay(zero)));

    // Retire each reply and adopt the retained grant through its owning domain.
    for (route, tid) in [
        (local(zero), 11),
        (local(same_id), 21),
        (hosted(same_id), 31),
    ] {
        let identity = queue.next_retry_for_file(route.key()).unwrap();
        let mut attempt = queue.begin_retry(identity).unwrap();
        assert_eq!(attempt.waiter().route, route);
        queue
            .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
            .unwrap();
        queue.finish_retry(identity, Ok(())).unwrap();
        let mut ingress = queue
            .begin_ingress(PI, tid, tid + 100, SERVICE)
            .unwrap()
            .unwrap();
        let mut adoption = queue.begin_adoption(&mut ingress).unwrap();
        let captured = adoption.waiter();
        assert_eq!(captured.route, route);
        let result = match captured.route {
            FileIoWaitRoute::Hosted { file_id, .. } => files.adopt_io_grant(file_id, tid),
            FileIoWaitRoute::LocalOverlay { file_object } => fs.zw_adopt_file_io(file_object, tid),
        };
        assert_eq!(result, Ok(()));
        queue
            .record_adoption(&mut adoption, result)
            .unwrap()
            .unwrap();
        match captured.route {
            FileIoWaitRoute::Hosted { file_id, .. } => {
                files.release_io(file_id, tid).unwrap();
                files.release_file(file_id).unwrap();
            }
            FileIoWaitRoute::LocalOverlay { file_object } => {
                fs.zw_release_file_io(file_object, tid).unwrap();
                fs.zw_release_io_reference(file_object).unwrap();
                assert_eq!(fs.zw_file_io_state(file_object).unwrap().references, 1);
            }
        }
    }
    assert!(queue.is_empty());
    assert_eq!(fs.zw_close(zero), STATUS_SUCCESS);
    assert_eq!(fs.zw_close(same_id), STATUS_SUCCESS);
    assert!(files.release_handle(same_id).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(same_id),
        Ok(FileIoAcquireResult::Acquired)
    );
    files.mark_cleanup_lifecycle_started(same_id).unwrap();
    files.release_cleanup_io(same_id).unwrap();
    assert!(
        files
            .release_cleanup_reference(same_id)
            .unwrap()
            .close_required
    );
}

#[test]
fn closed_local_handle_keeps_captured_route_access_mode_and_adopts_once_after_retry_ack() {
    let (mut fs, file, other) = local_files();
    assert_eq!(fs.zw_close(other), STATUS_SUCCESS);
    let mut queue = SynchronousFileWaitTable::new();
    assert_eq!(
        fs.zw_acquire_file_io(file, 10),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(
        fs.zw_acquire_file_io(file, 20),
        Ok(FileIoAcquireResult::Contended { alertable: true })
    );
    let original = waiter(local(file), 20);
    let slot = queue.park(original).unwrap();
    assert_eq!(fs.zw_close(file), STATUS_SUCCESS);
    assert_eq!(fs.zw_retain_io_reference(file), Err(STATUS_INVALID_HANDLE));
    fs.zw_release_file_io(file, 10).unwrap();
    fs.zw_release_io_reference(file).unwrap();
    fs.zw_promote_file_io_waiter(file, 20).unwrap();
    queue.promote_exact(slot, original.key(), 20).unwrap();
    assert!(queue
        .retry_identity(slot, FileIoWaitKey::Hosted(file), 20)
        .is_none());
    let identity = queue.retry_identity(slot, original.key(), 20).unwrap();
    let owned = fs.zw_file_io_state(file).unwrap();
    assert_eq!(owned.references, 2, "one grant and one cleanup reference");
    assert_eq!(owned.handle_references, 0);
    assert!(owned.cleanup_pending);

    let mut rejected = queue.begin_retry(identity).unwrap();
    queue
        .record_retry(&mut rejected, SynchronousFileRetryOutcome::NotEntered(13))
        .unwrap();
    assert_eq!(fs.zw_file_io_state(file), Ok(owned));
    let mut acknowledged = queue.begin_retry(identity).unwrap();
    let captured = acknowledged.waiter();
    assert_eq!(captured.route, original.route);
    assert_eq!(captured.mode, original.mode);
    assert_eq!(captured.granted_access, original.granted_access);
    assert_eq!(captured.handle, original.handle);
    assert_eq!(captured.reply_mrs, original.reply_mrs);
    queue
        .record_retry(&mut acknowledged, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(!queue
        .finish_retry(identity, Err(STATUS_ACCESS_DENIED))
        .unwrap());
    assert!(queue.begin_ingress(PI, 20, 120, SERVICE).is_err());
    assert!(queue.take_exact(slot, original.key(), 20).is_none());
    assert_eq!(fs.zw_file_io_state(file), Ok(owned));
    assert!(queue.finish_retry(identity, Ok(())).unwrap());
    assert!(queue.begin_ingress(PI, 20, 120, SERVICE + 1).is_err());
    let mut ingress = queue.begin_ingress(PI, 20, 120, SERVICE).unwrap().unwrap();
    let mut adoption = queue.begin_adoption(&mut ingress).unwrap();
    let retry = adoption.waiter();
    assert_eq!(
        (retry.route, retry.mode, retry.granted_access),
        (original.route, MODE, ACCESS)
    );
    assert_eq!(retry.reply_cap, 0);
    let FileIoWaitRoute::LocalOverlay { file_object } = retry.route else {
        panic!("the retry must retain its original local File route");
    };
    let result = fs.zw_adopt_file_io(file_object, retry.tid);
    assert_eq!(result, Ok(()));
    queue
        .record_adoption(&mut adoption, result)
        .unwrap()
        .unwrap();
    assert_eq!(
        fs.zw_file_io_state(file),
        Ok(owned),
        "adoption must not retain again"
    );
    assert!(fs.zw_adopt_file_io(file_object, retry.tid).is_err());
    assert_eq!(
        fs.zw_set_information_file(file_object, FILE_POSITION_INFORMATION, &37u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    assert_eq!(fs.current_offset(file_object), Some(37));
    fs.zw_release_file_io(file_object, retry.tid).unwrap();
    let delivered = fs.zw_file_io_state(file_object).unwrap();
    assert!(!delivered.cleanup_pending);
    assert_eq!(
        delivered.references, 1,
        "delivery owns the final reference after cleanup"
    );
    fs.zw_release_io_reference(file_object).unwrap();
    assert_eq!(fs.zw_file_io_state(file_object), Err(STATUS_INVALID_HANDLE));
    assert!(queue.is_empty());
}

#[test]
fn exact_route_cancellation_uses_each_domains_reference_contract() {
    let (mut fs, zero, file) = local_files();
    assert_eq!(fs.zw_close(zero), STATUS_SUCCESS);
    let mut files = FileCompletionTable::<1>::new();
    files.insert_file_with_mode(file, DEVICE, MODE).unwrap();
    let mut queue = SynchronousFileWaitTable::new();
    fs.zw_acquire_file_io(file, 10).unwrap();
    fs.zw_acquire_file_io(file, 20).unwrap();
    let local_slot = queue.park(waiter(local(file), 20)).unwrap();
    files.retain_file(file).unwrap();
    files.begin_io(file, 30).unwrap();
    files.retain_file(file).unwrap();
    files.begin_io(file, 40).unwrap();
    let hosted_slot = queue.park(waiter(hosted(file), 40)).unwrap();

    assert!(queue
        .take_alertable_waiting_exact(local_slot, FileIoWaitKey::Hosted(file), 20)
        .is_none());
    assert!(queue
        .take_exact(hosted_slot, FileIoWaitKey::LocalOverlay(file), 40)
        .is_none());
    assert_eq!(fs.zw_file_io_state(file).unwrap().references, 3);
    assert_eq!(files.io_waiter_count(file), Ok(1));
    let cancelled = queue
        .take_alertable_waiting_exact(local_slot, local(file).key(), 20)
        .unwrap();
    assert_eq!(cancelled.route, local(file));
    assert_eq!(fs.zw_cancel_file_io_waiter(file), Ok(0));
    let after = fs.zw_file_io_state(file).unwrap();
    assert_eq!(
        after.references, 2,
        "local cancellation includes its waiter reference"
    );
    assert!(queue
        .take_exact(local_slot, local(file).key(), 20)
        .is_none());
    assert!(fs.zw_cancel_file_io_waiter(file).is_err());
    assert_eq!(fs.zw_file_io_state(file), Ok(after));
    assert_eq!(
        files.io_waiter_count(file),
        Ok(1),
        "local cancellation cannot consume hosted count"
    );

    let cancelled = queue
        .take_exact(hosted_slot, hosted(file).key(), 40)
        .unwrap();
    assert_eq!(cancelled.route, hosted(file));
    assert_eq!(files.cancel_io_waiter(file), Ok(0));
    assert!(files.cancel_io_waiter(file).is_err());
    fs.zw_release_file_io(file, 10).unwrap();
    fs.zw_release_io_reference(file).unwrap();
    assert_eq!(fs.zw_close(file), STATUS_SUCCESS);
    assert_eq!(fs.zw_file_io_state(file), Err(STATUS_INVALID_HANDLE));
    files.release_io(file, 30).unwrap();
    files.release_file(file).unwrap();
    assert!(files.release_handle(file).unwrap().cleanup_required);
    assert_eq!(files.begin_cleanup(file), Ok(FileIoAcquireResult::Acquired));
    files.mark_cleanup_lifecycle_started(file).unwrap();
    files.release_cleanup_io(file).unwrap();
    assert!(
        !files
            .release_cleanup_reference(file)
            .unwrap()
            .close_required
    );
    // Hosted cancellation changes only the count. Its separate reference is still live.
    assert!(files.release_file(file).unwrap().close_required);
    assert!(files.io_mode(file).is_err());
    assert!(queue.is_empty());
}
