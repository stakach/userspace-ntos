//! Wait cancellation composed with real hosted/local File policy and cleanup lifetimes.
//! Wake and capability outcomes are fixture inputs, not native IPC or desktop proof.

use nt_fs as fs;
use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const FILE: u64 = 1;
const DEVICE: u64 = 7;
const FIRST: u64 = 20;
const SECOND: u64 = 21;
const THIRD: u64 = 22;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;
const REFUSED: u32 = 0xc000_0001;

thread_local! {
    static COUNT_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

fn count_allocation() {
    let _ = COUNT_ALLOCATIONS.try_with(|enabled| {
        if enabled.get() {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation();
        System.realloc(ptr, layout, size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn without_allocations<T>(work: impl FnOnce() -> T) -> T {
    struct Disable;
    impl Drop for Disable {
        fn drop(&mut self) {
            COUNT_ALLOCATIONS.with(|enabled| enabled.set(false));
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    COUNT_ALLOCATIONS.with(|enabled| enabled.set(true));
    let disable = Disable;
    let result = work();
    drop(disable);
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    result
}

fn hosted(file_id: u64) -> FileIoWaitRoute {
    FileIoWaitRoute::Hosted {
        file_id,
        device_id: DEVICE,
        fs_context: 9,
    }
}

fn waiter(route: FileIoWaitRoute, tid: u64) -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        route,
        0x40,
        3,
        191,
        2,
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
    waiter
}

fn hosted_active() -> FileCompletionTable<1> {
    let mut files = FileCompletionTable::new();
    files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, FIRST),
        Ok(FileIoAcquireResult::Acquired)
    );
    files
}

fn local_files() -> (fs::FileSystem, [u64; 2]) {
    let mut files = fs::FileSystem::new(fs::MemFs::new());
    assert!(files.provision_file(r"\??\C:\cancel", b"real local file"));
    let handles = std::array::from_fn(|_| {
        let opened = files.zw_create_file(
            r"\??\C:\cancel",
            fs::FILE_READ_DATA | fs::SYNCHRONIZE,
            0,
            fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            fs::FILE_OPEN,
            fs::FILE_NON_DIRECTORY_FILE | fs::FILE_SYNCHRONOUS_IO_NONALERT,
        );
        assert_eq!(opened.status, fs::STATUS_SUCCESS);
        opened.handle
    });
    assert_eq!(handles, [0, FILE]);
    (files, handles)
}

fn finish_hosted_cleanup(files: &mut FileCompletionTable<1>) {
    assert!(files.promote_cleanup_if_ready(FILE).unwrap());
    files.mark_cleanup_lifecycle_started(FILE).unwrap();
    files.release_cleanup_io(FILE).unwrap();
    assert!(
        files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
}

fn completed(
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
    effect: SynchronousFileCancelEffect,
    receipt: SynchronousFileCancelReceipt,
) {
    apply(table, identity, effect, |_| receipt);
}

fn apply(
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
    effect: SynchronousFileCancelEffect,
    source: impl FnOnce(&mut SynchronousFileWaitTable) -> SynchronousFileCancelReceipt,
) -> SynchronousFileCancelReceipt {
    let mut attempt = table.begin_cancellation(identity).unwrap();
    assert_eq!(attempt.effect(), effect);
    assert!(table.begin_cancellation(identity).is_err());
    let receipt = source(table);
    table
        .record_cancellation(
            &mut attempt,
            SynchronousFileCancelOutcome::Completed(receipt),
        )
        .unwrap();
    receipt
}

fn rejected(
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
    effect: SynchronousFileCancelEffect,
) {
    let mut attempt = table.begin_cancellation(identity).unwrap();
    assert_eq!(attempt.effect(), effect);
    table
        .record_cancellation(
            &mut attempt,
            SynchronousFileCancelOutcome::NotEntered(REFUSED),
        )
        .unwrap();
    assert!(table.finish_cancellation(identity).is_none());
}

fn retire_reply(table: &mut SynchronousFileWaitTable, identity: SynchronousFileCancelIdentity) {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    rejected(table, identity, Effect::RevokeReply);
    completed(table, identity, Effect::RevokeReply, Receipt::ReplyRevoked);
    rejected(table, identity, Effect::RetireReplyCap);
    completed(
        table,
        identity,
        Effect::RetireReplyCap,
        Receipt::ReplyCapRetired,
    );
}

fn adopt(
    table: &mut SynchronousFileWaitTable,
    slot: usize,
    key: FileIoWaitKey,
    tid: u64,
    source: impl FnOnce() -> Result<(), u32>,
) {
    let identity = table.retry_identity(slot, key, tid).unwrap();
    let mut retry = table.begin_retry(identity).unwrap();
    table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(table.finish_retry(identity, Ok(())).unwrap());
    let mut ingress = table
        .begin_ingress(2, tid, tid + 100, 191)
        .unwrap()
        .unwrap();
    let mut adoption = table.begin_adoption(&mut ingress).unwrap();
    let result = source();
    assert_eq!(result, Ok(()));
    table
        .record_adoption(&mut adoption, result)
        .unwrap()
        .unwrap();
}

#[test]
fn failed_publication_reuses_its_reserved_row_without_postfailure_allocation() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let mut files = hosted_active();
    let mut table = SynchronousFileWaitTable::with_initial_reserve(1);
    let reservation = table.reserve().unwrap();
    let capacity = table.capacity();
    let mut unpublished = waiter(hosted(FILE), SECOND);
    unpublished.reply_cap = 0;

    without_allocations(|| {
        files.retain_file(FILE).unwrap();
        assert_eq!(
            files.begin_io(FILE, SECOND),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        // Reply publication definitively failed before a capability was transferred.
        let identity = table.cancel_reserved(reservation, unpublished).unwrap();
        assert_eq!(table.len(), 1);
        rejected(&mut table, identity, Effect::Policy);
        assert_eq!(files.io_waiter_count(FILE), Ok(1));
        apply(&mut table, identity, Effect::Policy, |_| {
            Receipt::HostedPolicy {
                waiters: files.cancel_io_waiter(FILE).unwrap(),
            }
        });
        completed(&mut table, identity, Effect::Wake, Receipt::Wake);
        rejected(&mut table, identity, Effect::HostedReference);
        let Receipt::HostedReference(release) =
            apply(&mut table, identity, Effect::HostedReference, |_| {
                Receipt::HostedReference(files.release_file(FILE).unwrap())
            })
        else {
            unreachable!()
        };
        assert!(!release.close_required);
        assert_eq!(
            table.cancellation(identity).unwrap().reference_release,
            Some(release)
        );
        assert_eq!(table.finish_cancellation(identity).unwrap().reply_cap, 0);
        assert_eq!(table.capacity(), capacity);
        assert!(table.is_empty());
        assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
    });
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    files.release_io(FILE, FIRST).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    finish_hosted_cleanup(&mut files);
}

#[test]
fn hosted_promoted_cancellation_retains_receipts_through_wake_and_capability_retries() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let mut files = hosted_active();
    let mut table = SynchronousFileWaitTable::new();
    let mut slots = [0; 2];
    for (index, tid) in [SECOND, THIRD].into_iter().enumerate() {
        let reservation = table.reserve().unwrap();
        files.retain_file(FILE).unwrap();
        assert_eq!(
            files.begin_io(FILE, tid),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        slots[index] = table
            .park_reserved(reservation, waiter(hosted(FILE), tid))
            .unwrap();
    }
    files.release_io(FILE, FIRST).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    files.promote_io_waiter(FILE, SECOND).unwrap();
    table
        .promote_exact(slots[0], FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let identity = table
        .wait_identity(slots[0], FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let identity = table.request_cancellation(identity).unwrap();
    rejected(&mut table, identity, Effect::Policy);
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(SECOND)));
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    let policy = apply(&mut table, identity, Effect::Policy, |_| {
        Receipt::HostedPolicy {
            waiters: files.cancel_promoted_io(FILE, SECOND).unwrap().waiters,
        }
    });
    assert_eq!(policy, Receipt::HostedPolicy { waiters: 1 });
    rejected(&mut table, identity, Effect::Wake);
    assert_eq!(
        table.cancellation(identity).unwrap().policy_waiters,
        Some(1)
    );
    assert_eq!(files.io_lock_owner(FILE), Ok(None));
    assert_eq!(files.io_waiter_count(FILE), Ok(1));
    apply(&mut table, identity, Effect::Wake, |table| {
        files.promote_io_waiter(FILE, THIRD).unwrap();
        table
            .promote_exact(slots[1], FileIoWaitKey::Hosted(FILE), THIRD)
            .unwrap();
        Receipt::Wake
    });
    rejected(&mut table, identity, Effect::HostedReference);
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(THIRD)));
    let Receipt::HostedReference(release) =
        apply(&mut table, identity, Effect::HostedReference, |_| {
            Receipt::HostedReference(files.release_file(FILE).unwrap())
        })
    else {
        unreachable!()
    };
    assert!(!release.close_required);
    retire_reply(&mut table, identity);
    assert_eq!(
        table.cancellation(identity).unwrap().reference_release,
        Some(release)
    );
    assert_eq!(
        table.cancellation(identity).unwrap().policy_waiters,
        Some(1)
    );
    table.finish_cancellation(identity).unwrap();
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(THIRD)));
    adopt(
        &mut table,
        slots[1],
        FileIoWaitKey::Hosted(FILE),
        THIRD,
        || files.adopt_io_grant(FILE, THIRD),
    );
    files.release_io(FILE, THIRD).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    finish_hosted_cleanup(&mut files);
    assert!(table.is_empty());
}

#[test]
fn local_zero_and_equal_numeric_hosted_files_keep_cancellation_and_references_separate() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let (mut local, handles) = local_files();
    let mut files = hosted_active();
    let mut table = SynchronousFileWaitTable::new();
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, 121),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let hosted_slot = table.park(waiter(hosted(FILE), 121)).unwrap();
    for file in handles {
        let route = FileIoWaitRoute::LocalOverlay { file_object: file };
        let key = route.key();
        assert_eq!(
            local.zw_acquire_file_io(file, FIRST),
            Ok(FileIoAcquireResult::Acquired)
        );
        let mut slots = [0; 2];
        for (index, tid) in [SECOND, THIRD].into_iter().enumerate() {
            assert_eq!(
                local.zw_acquire_file_io(file, tid),
                Ok(FileIoAcquireResult::Contended { alertable: false })
            );
            slots[index] = table.park(waiter(route, tid)).unwrap();
        }
        local.zw_release_file_io(file, FIRST).unwrap();
        local.zw_release_io_reference(file).unwrap();
        local.zw_promote_file_io_waiter(file, SECOND).unwrap();
        table.promote_exact(slots[0], key, SECOND).unwrap();
        assert_eq!(local.zw_close(file), fs::STATUS_SUCCESS);
        assert_eq!(local.zw_file_io_state(file).unwrap().references, 3);
        let identity = table.wait_identity(slots[0], key, SECOND).unwrap();
        let identity = table.request_cancellation(identity).unwrap();
        apply(&mut table, identity, Effect::Policy, |_| {
            Receipt::LocalPolicy {
                waiters: local
                    .zw_cancel_promoted_file_io(file, SECOND)
                    .unwrap()
                    .waiters,
            }
        });
        let state = local.zw_file_io_state(file).unwrap();
        assert_eq!(state.references, 2);
        assert!(state.cleanup_pending);
        rejected(&mut table, identity, Effect::Wake);
        assert_eq!(local.zw_file_io_state(file).unwrap(), state);
        apply(&mut table, identity, Effect::Wake, |table| {
            local.zw_promote_file_io_waiter(file, THIRD).unwrap();
            table.promote_exact(slots[1], key, THIRD).unwrap();
            Receipt::Wake
        });
        // Local cancellation already released its reference. The next effect must be cap revoke.
        retire_reply(&mut table, identity);
        assert_eq!(
            table.cancellation(identity).unwrap().reference_release,
            None
        );
        table.finish_cancellation(identity).unwrap();
        assert_eq!(local.zw_file_io_state(file).unwrap().references, 2);
        assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
        assert_eq!(files.io_waiter_count(FILE), Ok(1));
        assert_eq!(
            table
                .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
                .unwrap()
                .0,
            hosted_slot
        );
        adopt(&mut table, slots[1], key, THIRD, || {
            local.zw_adopt_file_io(file, THIRD)
        });
        local.zw_release_file_io(file, THIRD).unwrap();
        let state = local.zw_file_io_state(file).unwrap();
        assert!(!state.cleanup_pending);
        assert_eq!(state.references, 1);
        local.zw_release_io_reference(file).unwrap();
        assert_eq!(local.zw_file_io_state(file), Err(fs::STATUS_INVALID_HANDLE));
    }
    let identity = table
        .wait_identity(hosted_slot, FileIoWaitKey::Hosted(FILE), 121)
        .unwrap();
    let identity = table.request_cancellation(identity).unwrap();
    apply(&mut table, identity, Effect::Policy, |_| {
        Receipt::HostedPolicy {
            waiters: files.cancel_io_waiter(FILE).unwrap(),
        }
    });
    completed(&mut table, identity, Effect::Wake, Receipt::Wake);
    apply(&mut table, identity, Effect::HostedReference, |_| {
        Receipt::HostedReference(files.release_file(FILE).unwrap())
    });
    retire_reply(&mut table, identity);
    table.finish_cancellation(identity).unwrap();
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    files.begin_cleanup(FILE).unwrap();
    files.release_io(FILE, FIRST).unwrap();
    files.release_file(FILE).unwrap();
    finish_hosted_cleanup(&mut files);
    assert!(table.is_empty());
}

#[test]
fn indeterminate_or_dropped_policy_attempts_retain_waiters_and_block_cleanup() {
    for indeterminate in [false, true] {
        let mut files = hosted_active();
        let mut table = SynchronousFileWaitTable::new();
        files.retain_file(FILE).unwrap();
        assert_eq!(
            files.begin_io(FILE, SECOND),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        let slot = table.park(waiter(hosted(FILE), SECOND)).unwrap();
        let identity = table
            .wait_identity(slot, FileIoWaitKey::Hosted(FILE), SECOND)
            .unwrap();
        let identity = table.request_cancellation(identity).unwrap();
        let mut attempt = table.begin_cancellation(identity).unwrap();
        assert_eq!(attempt.effect(), SynchronousFileCancelEffect::Policy);
        if indeterminate {
            table
                .record_cancellation(
                    &mut attempt,
                    SynchronousFileCancelOutcome::Indeterminate(REFUSED),
                )
                .unwrap();
        }
        drop(attempt);
        assert!(table.begin_cancellation(identity).is_err());
        assert!(table.finish_cancellation(identity).is_none());
        assert!(table
            .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
            .is_none());
        assert!(files.release_handle(FILE).unwrap().cleanup_required);
        assert_eq!(
            files.begin_cleanup(FILE),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        files.release_io(FILE, FIRST).unwrap();
        assert!(!files.release_file(FILE).unwrap().close_required);
        assert_eq!(files.io_waiter_count(FILE), Ok(1));
        assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
        assert_eq!(table.cancellation(identity).unwrap().policy_waiters, None);
        assert!(!table.reset());
    }
}

#[test]
fn last_local_waiter_cancellation_retires_file_before_wake_and_capability_cleanup() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let (mut local, [file, peer]) = local_files();
    let mut table = SynchronousFileWaitTable::new();
    assert_eq!(
        local.zw_acquire_file_io(file, FIRST),
        Ok(FileIoAcquireResult::Acquired)
    );
    let reservation = table.reserve().unwrap();
    assert_eq!(
        local.zw_acquire_file_io(file, SECOND),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let route = FileIoWaitRoute::LocalOverlay { file_object: file };
    let slot = table
        .park_reserved(reservation, waiter(route, SECOND))
        .unwrap();
    let identity = table.wait_identity(slot, route.key(), SECOND).unwrap();
    assert_eq!(local.zw_close(file), fs::STATUS_SUCCESS);
    local.zw_release_file_io(file, FIRST).unwrap();
    local.zw_release_io_reference(file).unwrap();
    let state = local.zw_file_io_state(file).unwrap();
    assert_eq!(state.references, 2);
    assert_eq!(state.waiters, 1);
    assert!(state.cleanup_pending);

    let identity = table.request_cancellation(identity).unwrap();
    apply(&mut table, identity, Effect::Policy, |_| {
        Receipt::LocalPolicy {
            waiters: local.zw_cancel_file_io_waiter(file).unwrap(),
        }
    });
    assert_eq!(local.zw_file_io_state(file), Err(fs::STATUS_INVALID_HANDLE));
    assert_eq!(
        table.cancellation(identity).unwrap().policy_waiters,
        Some(0)
    );
    rejected(&mut table, identity, Effect::Wake);
    // The committed local receipt proves there are no remaining waiters. No backing File query
    // or reference release is permitted here: policy already retired the last reference and row.
    apply(&mut table, identity, Effect::Wake, |table| {
        let owner = table.cancellation(identity).unwrap();
        assert_eq!(owner.waiter.route, route);
        assert_eq!(owner.policy_waiters, Some(0));
        Receipt::Wake
    });
    retire_reply(&mut table, identity);
    assert_eq!(
        table.cancellation(identity).unwrap().reference_release,
        None
    );
    table.finish_cancellation(identity).unwrap();
    assert!(table.is_empty());
    assert_eq!(local.zw_file_io_state(peer).unwrap().references, 1);
    assert_eq!(local.zw_close(peer), fs::STATUS_SUCCESS);
}
