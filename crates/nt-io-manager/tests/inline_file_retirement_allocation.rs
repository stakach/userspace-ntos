//! Allocation refusal at admission and allocation-free retirement after real File acquisition.
//! Wake/followup have no work in this fixture; this is not native callout or IPC proof.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::inline_file_retirement::{
    InlineFileRetirementEffect as Effect, InlineFileRetirementError as Error,
    InlineFileRetirementOutcome as Outcome, InlineFileRetirementPhase as Phase,
    InlineFileRetirementTable as Table,
};
use nt_io_manager::{FileIoBusyOwner, FileIoWaitKey};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static REFUSE: Cell<bool> = const { Cell::new(false) };
    static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}

struct RefusingAllocator;

fn refuse_allocation() -> bool {
    REFUSE
        .try_with(|refuse| {
            if refuse.get() {
                ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

// SAFETY: Requests are either refused with null or forwarded unchanged to System; deallocation
// always uses the original allocator, and refusal state is isolated to the exercising thread.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse_allocation() {
            core::ptr::null_mut()
        } else {
            System.alloc(layout)
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse_allocation() {
            core::ptr::null_mut()
        } else {
            System.alloc_zeroed(layout)
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuse_allocation() {
            core::ptr::null_mut()
        } else {
            System.realloc(ptr, layout, size)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: RefusingAllocator = RefusingAllocator;

fn refusing_allocations<T>(work: impl FnOnce() -> T) -> (T, usize) {
    struct Disable;
    impl Drop for Disable {
        fn drop(&mut self) {
            REFUSE.with(|refuse| refuse.set(false));
        }
    }
    ATTEMPTS.with(|attempts| attempts.set(0));
    REFUSE.with(|refuse| refuse.set(true));
    let disable = Disable;
    let result = work();
    drop(disable);
    (result, ATTEMPTS.with(Cell::get))
}

const FILE: u64 = 17;
const DEVICE: u64 = 31;
const TID: u64 = 24;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;

fn owner() -> FileIoBusyOwner {
    FileIoBusyOwner {
        key: FileIoWaitKey::Hosted(FILE),
        tid: TID,
        mode: MODE,
    }
}

#[test]
fn refused_reservation_leaves_no_owner_or_file_acquisition() {
    let mut files = FileCompletionTable::<1>::new();
    files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
    let mut retained = Table::new();
    let (refused, allocations) = refusing_allocations(|| retained.reserve(owner()));
    assert_eq!(refused, Err(Error::ReservationFailed));
    assert!(allocations > 0);
    assert!(retained.is_empty());
    assert_eq!(retained.slot_len(), 0);
    assert_eq!(retained.next_ready_after(None), None);
    assert_eq!(files.io_lock_owner(FILE), Ok(None));
    assert_eq!(files.io_waiter_count(FILE), Ok(0));

    let reservation = retained.reserve(owner()).unwrap();
    let (cancelled, allocations) = refusing_allocations(|| retained.cancel_reserved(reservation));
    assert_eq!(cancelled, Ok(()));
    assert_eq!(allocations, 0);
    assert!(retained.is_empty());
}

#[test]
fn acquired_inline_owner_retires_all_effects_under_allocator_refusal() {
    let mut files = FileCompletionTable::<1>::new();
    files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
    let mut retained = Table::new();
    let reservation = retained.reserve(owner()).unwrap();
    assert_eq!(
        files.acquire_file_io(FILE, TID),
        Ok(FileIoAcquireResult::Acquired)
    );

    let ((finished, release), allocations) = refusing_allocations(|| {
        let id = retained.activate(reservation).unwrap();
        assert_eq!(retained.active_owner(id), Ok(owner()));
        retained.retire_active(id).unwrap();
        for effect in [
            Effect::ReleasePolicy,
            Effect::Wake,
            Effect::ReleaseReference,
            Effect::ReferenceFollowup,
        ] {
            let mut refused = retained.begin_step(id).unwrap();
            assert_eq!(refused.effect(), effect);
            retained
                .record_step(&mut refused, Outcome::NotEntered(5))
                .unwrap();
            let mut attempt = retained.begin_step(id).unwrap();
            assert_eq!(attempt.effect(), effect);
            let outcome = match effect {
                Effect::ReleasePolicy => Outcome::PolicyReleased {
                    waiters: files.release_io(FILE, attempt.owner().tid).unwrap().waiters,
                },
                Effect::Wake => {
                    assert_eq!(attempt.policy_waiters(), Some(0));
                    Outcome::Completed(Effect::Wake)
                }
                Effect::ReleaseReference => {
                    Outcome::ReferenceReleased(files.release_file(FILE).unwrap())
                }
                Effect::ReferenceFollowup => {
                    let release = attempt.reference_release().unwrap();
                    assert!(!release.cleanup_required);
                    assert!(!release.close_required);
                    assert_eq!(release.port_id, None);
                    Outcome::Completed(Effect::ReferenceFollowup)
                }
            };
            retained.record_step(&mut attempt, outcome).unwrap();
        }
        assert_eq!(retained.get(id).unwrap().phase, Phase::Complete);
        let release = retained.get(id).unwrap().reference_release;
        (retained.finish(id), release)
    });

    assert_eq!(allocations, 0);
    assert_eq!(finished, Some(owner()));
    assert_eq!(release.unwrap().device_id, DEVICE);
    assert!(retained.is_empty());
    assert_eq!(files.io_lock_owner(FILE), Ok(None));
    assert_eq!(files.io_mode(FILE), Ok(MODE));
}
