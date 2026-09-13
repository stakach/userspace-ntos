use nt_io_manager::file_io_capture::FileIoCaptureTable;
use nt_io_manager::{
    CreateOptions, DeviceId, FileId, FileRecord, FileState, IoManager, MockObjectPort, ShareAccess,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, ObjectId, UnicodeString};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static REFUSE_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}

struct RefusingAllocator;

fn refuse_allocation() -> bool {
    REFUSE_AFTER
        .try_with(|remaining| match remaining.get() {
            None => false,
            Some(value) => {
                ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
                if value == 0 {
                    true
                } else {
                    remaining.set(Some(value - 1));
                    false
                }
            }
        })
        .unwrap_or(false)
}

// SAFETY: Unrefused requests are forwarded unchanged to System. Thread-local refusal never
// changes deallocation of already-owned storage.
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

fn refusing_after<T>(allowed: usize, work: impl FnOnce() -> T) -> (T, usize) {
    struct Disable;
    impl Drop for Disable {
        fn drop(&mut self) {
            REFUSE_AFTER.with(|value| value.set(None));
        }
    }
    ATTEMPTS.with(|value| value.set(0));
    REFUSE_AFTER.with(|value| value.set(Some(allowed)));
    let disable = Disable;
    let result = work();
    drop(disable);
    (result, ATTEMPTS.with(Cell::get))
}

fn allocated() -> (IoManager<MockObjectPort>, FileId, DeviceId) {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let device = DeviceId(1);
    let file = io.add_file(FileRecord::new(
        ObjectId::NULL,
        client,
        device,
        AccessMask::empty(),
        ShareAccess::empty(),
        CreateOptions::empty(),
        UnicodeString::new(),
    ));
    io.file_mut(file).unwrap().state = FileState::Open;
    (io, file, device)
}

#[test]
fn both_table_and_pointer_storage_refusal_precede_reference_ownership() {
    for allowed in [0, 1] {
        let (mut io, file, device) = allocated();
        let mut table = FileIoCaptureTable::new();
        let (result, attempts) =
            refusing_after(allowed, || table.capture(&mut io, file, device, 7));
        assert_eq!(result.unwrap_err(), NtStatus::INSUFFICIENT_RESOURCES);
        assert_eq!(attempts, allowed + 1);
        assert!(table.is_empty());
        assert_eq!(io.file_reference_count(file), 0);
        let mut capture = table.capture(&mut io, file, device, 7).unwrap();
        table.retire(&mut capture).unwrap();
        table.release_retired(&mut io, capture.identity()).unwrap();
    }
}

#[test]
fn retirement_refusal_and_recovery_allocate_nothing() {
    let (mut io, file, device) = allocated();
    let (mut wrong, _, _) = allocated();
    let mut table = FileIoCaptureTable::new();
    let mut capture = table.capture(&mut io, file, device, 7).unwrap();
    let ((retired, refused, recovered), attempts) = refusing_after(0, || {
        let retired = table.retire(&mut capture);
        let refused = table.release_retired(&mut wrong, capture.identity());
        let recovered = table.redrive(&mut io, 1);
        (retired, refused, recovered)
    });
    assert_eq!(attempts, 0);
    assert_eq!(retired, Ok(()));
    assert_eq!(refused, Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(recovered.released, 1);
    assert!(table.is_empty());
    assert_eq!(io.file_reference_count(file), 0);
}
