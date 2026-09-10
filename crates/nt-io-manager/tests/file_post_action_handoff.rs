//! Early File-owner publication composed with real I/O Manager IRPs and File Busy policy.
//! The mock driver and reply/copy outcomes are controlled fixtures, not native IPC proof.

use nt_io_abi::major;
use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath, UnicodeString};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const TID: u64 = 21;
const PRIOR: u64 = 20;
const NEXT: u64 = 22;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct Allocator;

fn count_allocation() {
    let _ = TRACK.try_with(|track| {
        if track.get() {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
    });
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        System.alloc(layout)
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
static ALLOCATOR: Allocator = Allocator;

fn no_allocation<T>(work: impl FnOnce() -> T) -> T {
    struct Disable;
    impl Drop for Disable {
        fn drop(&mut self) {
            TRACK.with(|track| track.set(false));
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    TRACK.with(|track| track.set(true));
    let disable = Disable;
    let result = work();
    drop(disable);
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    result
}

fn path(name: &str) -> NtPath {
    NtPath::parse_str(name).unwrap()
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    handle: HandleValue,
    file: FileId,
    device: DeviceId,
    files: FileCompletionTable<1>,
    pending: PendingFileIoTable,
}

impl Fixture {
    fn new(pending: bool, complete_on_pump: bool) -> Self {
        let mut backend = MockDriverBackend::new().with_read_data(b"data");
        backend.set_force_pending(pending);
        if complete_on_pump {
            backend.set_pending_completion(NtStatus::SUCCESS, 0);
        }
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(&path(r"\Driver\Handoff"), Box::new(backend))
            .unwrap();
        io.create_device(
            driver,
            Some(&path(r"\Device\Handoff")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = io
            .open(
                client,
                &path(r"\Device\Handoff"),
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let (file, device, _) = io
            .reference_open_file_details(client, handle, AccessMask::GENERIC_READ)
            .unwrap();
        let mut files = FileCompletionTable::new();
        files
            .insert_file_with_mode(file.raw(), device.raw(), MODE)
            .unwrap();
        Self {
            io,
            client,
            handle,
            file,
            device,
            files,
            pending: PendingFileIoTable::new(),
        }
    }

    fn waiter(&self, tid: u64) -> SynchronousFileWaiter {
        let mut waiter = SynchronousFileWaiter::waiting(
            FileIoWaitRoute::Hosted {
                file_id: self.file.raw(),
                device_id: self.device.raw(),
                fs_context: 0,
            },
            0x40,
            1,
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

    fn acquire(&mut self, promoted: bool) {
        if !promoted {
            assert_eq!(
                self.files.acquire_file_io(self.file.raw(), TID),
                Ok(FileIoAcquireResult::Acquired)
            );
            self.files.set_signaled(self.file.raw(), false).unwrap();
            return;
        }
        assert_eq!(
            self.files.acquire_file_io(self.file.raw(), PRIOR),
            Ok(FileIoAcquireResult::Acquired)
        );
        let mut waiters = SynchronousFileWaitTable::new();
        let reservation = waiters.reserve().unwrap();
        assert_eq!(
            self.files.acquire_file_io(self.file.raw(), TID),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        let slot = waiters
            .park_reserved(reservation, self.waiter(TID))
            .unwrap();
        self.files.release_io(self.file.raw(), PRIOR).unwrap();
        self.files.release_file(self.file.raw()).unwrap();
        self.files.promote_io_waiter(self.file.raw(), TID).unwrap();
        waiters
            .promote_exact(slot, FileIoWaitKey::Hosted(self.file.raw()), TID)
            .unwrap();
        adopt(&mut self.files, &mut waiters, slot, self.file.raw(), TID);
        self.files.set_signaled(self.file.raw(), false).unwrap();
        assert!(waiters.is_empty());
    }

    fn publish(&mut self, saved_reply: bool) -> (usize, IrpId) {
        let reservation = self.pending.reserve().unwrap();
        let mut output = [0; 4];
        assert_eq!(
            self.io.read(self.client, self.handle, 0, &mut output),
            Err(NtStatus::PENDING)
        );
        let irp = self.io.pending_irps()[0];
        assert_eq!(self.io.irp(irp).unwrap().file_id, Some(self.file));
        let owner = PendingFileIo {
            route: PendingFileRoute::Hosted(self.file.raw()),
            irp_id: irp.raw(),
            major: major::IRP_MJ_READ,
            pi: 2,
            tid: TID,
            badge: TID + 100,
            busy: Some(PendingFileBusy::new(FileIoBusyOwner {
                key: FileIoWaitKey::Hosted(self.file.raw()),
                tid: TID,
                mode: MODE,
            })),
            iosb_va: 0x1000,
            signal_file: true,
            event_obj_idx: u64::MAX,
            reply_cap: if saved_reply { 47 } else { 0 },
            reply_required: saved_reply,
            ..PendingFileIo::default()
        };
        let capacity = self.pending.allocation_capacity();
        let slot = no_allocation(|| self.pending.park_reserved(reservation, owner).unwrap());
        assert_eq!(self.pending.allocation_capacity(), capacity);
        (slot, irp)
    }

    fn release_terminal_busy(&mut self, slot: usize, irp: IrpId) {
        assert_eq!(self.io.irp(irp).unwrap().state, IrpState::Completed);
        assert_eq!(self.io.next_completed_irp().unwrap().id, irp);
        let mut release = self
            .pending
            .begin_busy_release_exact(slot, irp.raw())
            .unwrap();
        let result = self
            .files
            .release_io(self.file.raw(), TID)
            .map(|released| released.waiters);
        self.pending
            .record_busy_release(&mut release, result)
            .unwrap();
        let mut wake = self.pending.begin_busy_wake_exact(slot, irp.raw()).unwrap();
        self.pending.record_busy_wake(&mut wake, Ok(())).unwrap();
    }

    fn finish(&mut self, slot: usize, irp: IrpId) {
        assert!(self
            .pending
            .completion_surfaces_settled_exact(slot, irp.raw()));
        self.io.acknowledge_completed_irp(irp).unwrap();
        self.pending
            .mark_backend_acked_exact(slot, irp.raw())
            .unwrap();
        self.pending.finish_exact(slot, irp.raw()).unwrap();
        assert!(
            !self
                .files
                .release_file(self.file.raw())
                .unwrap()
                .close_required
        );
        assert!(self.io.irp(irp).is_none());
    }

    fn close(mut self) {
        assert!(
            self.files
                .release_handle(self.file.raw())
                .unwrap()
                .cleanup_required
        );
        assert_eq!(
            self.files.begin_cleanup(self.file.raw()),
            Ok(FileIoAcquireResult::Acquired)
        );
        self.files
            .mark_cleanup_lifecycle_started(self.file.raw())
            .unwrap();
        self.files.release_cleanup_io(self.file.raw()).unwrap();
        assert!(
            self.files
                .release_cleanup_reference(self.file.raw())
                .unwrap()
                .close_required
        );
        self.io.close(self.client, self.handle).unwrap();
        assert!(self.pending.is_empty());
    }
}

fn adopt(
    files: &mut FileCompletionTable<1>,
    waiters: &mut SynchronousFileWaitTable,
    slot: usize,
    file: u64,
    tid: u64,
) {
    let identity = waiters
        .retry_identity(slot, FileIoWaitKey::Hosted(file), tid)
        .unwrap();
    let mut retry = waiters.begin_retry(identity).unwrap();
    waiters
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    waiters.finish_retry(identity, Ok(())).unwrap();
    let mut ingress = waiters
        .begin_ingress(2, tid, tid + 100, 191)
        .unwrap()
        .unwrap();
    let mut adoption = waiters.begin_adoption(&mut ingress).unwrap();
    let result = files.adopt_io_grant(file, tid);
    assert_eq!(result, Ok(()));
    waiters
        .record_adoption(&mut adoption, result)
        .unwrap()
        .unwrap();
}

#[test]
fn early_abandonment_retains_fresh_and_adopted_busy_until_real_cancel_completion() {
    for promoted in [false, true] {
        let mut fixture = Fixture::new(true, false);
        fixture.acquire(promoted);
        let (slot, irp) = fixture.publish(false);
        let owner = fixture
            .pending
            .abandon_transfer_exact(slot, irp.raw())
            .unwrap();
        assert!(fixture
            .pending
            .abandon_transfer_exact(slot, irp.raw())
            .is_none());
        assert_eq!(owner.irp_id, irp.raw());
        assert_eq!(owner.reply_cap, 0);
        assert!(fixture.pending.get(slot).unwrap().consumer_abandoned);
        assert_eq!(
            fixture.files.io_lock_owner(fixture.file.raw()),
            Ok(Some(TID))
        );
        assert!(fixture
            .pending
            .mark_backend_acked_exact(slot, irp.raw())
            .is_none());
        assert!(fixture.pending.finish_exact(slot, irp.raw()).is_none());
        fixture.io.cancel(fixture.client, irp).unwrap();
        assert_eq!(
            fixture.io.irp(irp).unwrap().state,
            IrpState::CancelRequested
        );
        assert_eq!(
            fixture.files.io_lock_owner(fixture.file.raw()),
            Ok(Some(TID))
        );
        assert_eq!(fixture.io.pump(), 1);
        assert_eq!(
            fixture.io.next_completed_irp().unwrap().status,
            NtStatus::CANCELLED
        );
        fixture.release_terminal_busy(slot, irp);
        fixture.finish(slot, irp);
        fixture.close();
    }
}

#[test]
fn completion_during_teardown_still_finds_the_already_published_owner() {
    let mut fixture = Fixture::new(true, true);
    fixture.acquire(false);
    let (slot, irp) = fixture.publish(false);
    assert_eq!(
        fixture.pending.abandon_thread_transfers_with(TID, |owner| {
            assert_eq!(owner.irp_id, irp.raw());
            assert_eq!(fixture.io.pump(), 1);
            assert_eq!(
                fixture.io.next_completed_irp().unwrap().status,
                NtStatus::SUCCESS
            );
            assert_eq!(
                fixture.files.io_lock_owner(fixture.file.raw()),
                Ok(Some(TID))
            );
        }),
        1
    );
    assert!(fixture.pending.get(slot).unwrap().consumer_abandoned);
    assert!(!fixture.pending.is_empty());
    fixture.release_terminal_busy(slot, irp);
    fixture.finish(slot, irp);
    fixture.close();
}

#[test]
fn a_live_saved_reply_blocks_ack_and_retirement_until_its_exact_send_settles() {
    let mut fixture = Fixture::new(true, true);
    fixture.acquire(false);
    let (slot, irp) = fixture.publish(true);
    assert_eq!(fixture.io.pump(), 1);
    fixture
        .pending
        .mark_delivery_exact(slot, irp.raw(), IO_DELIVERY_IOSB_PUBLISHED)
        .unwrap();
    fixture
        .files
        .set_signaled(fixture.file.raw(), true)
        .unwrap();
    fixture
        .pending
        .mark_delivery_exact(slot, irp.raw(), IO_DELIVERY_FILE_PUBLISHED)
        .unwrap();
    fixture.release_terminal_busy(slot, irp);
    assert!(fixture
        .pending
        .mark_backend_acked_exact(slot, irp.raw())
        .is_none());
    assert!(fixture.pending.finish_exact(slot, irp.raw()).is_none());
    let cap = fixture
        .pending
        .claim_reply_cap_exact(slot, irp.raw())
        .unwrap()
        .unwrap();
    assert_eq!(cap, 47);
    assert!(fixture
        .pending
        .abandon_transfer_exact(slot, irp.raw())
        .is_none());
    assert_eq!(
        fixture
            .pending
            .abandon_thread_transfers_with(TID, |_| panic!("claimed reply remains owned")),
        0
    );
    // A definitively rejected send may restore only this exact reply capability.
    fixture
        .pending
        .restore_reply_cap_exact(slot, irp.raw(), cap)
        .unwrap();
    assert!(fixture
        .pending
        .mark_backend_acked_exact(slot, irp.raw())
        .is_none());
    assert_eq!(
        fixture.pending.claim_reply_cap_exact(slot, irp.raw()),
        Some(Some(cap))
    );
    fixture
        .pending
        .mark_reply_published_exact(slot, irp.raw())
        .unwrap();
    fixture.finish(slot, irp);
    fixture.close();
}

#[test]
fn inline_terminal_io_releases_fifo_without_manufacturing_a_pending_irp() {
    let mut fixture = Fixture::new(false, false);
    fixture.acquire(false);
    let mut waiters = SynchronousFileWaitTable::new();
    let reservation = waiters.reserve().unwrap();
    assert_eq!(
        fixture.files.acquire_file_io(fixture.file.raw(), NEXT),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let slot = waiters
        .park_reserved(reservation, fixture.waiter(NEXT))
        .unwrap();
    assert!(fixture
        .files
        .promote_io_waiter(fixture.file.raw(), NEXT)
        .is_err());
    assert_eq!(
        fixture.files.io_lock_owner(fixture.file.raw()),
        Ok(Some(TID))
    );
    let mut output = [0; 4];
    assert_eq!(
        fixture
            .io
            .read(fixture.client, fixture.handle, 0, &mut output),
        Ok(4)
    );
    assert_eq!(&output, b"data");
    assert_eq!(fixture.io.irp_count(), 0);
    assert!(fixture.pending.is_empty());
    assert_eq!(
        fixture
            .files
            .release_io(fixture.file.raw(), TID)
            .unwrap()
            .waiters,
        1
    );
    fixture.files.release_file(fixture.file.raw()).unwrap();
    fixture
        .files
        .promote_io_waiter(fixture.file.raw(), NEXT)
        .unwrap();
    waiters
        .promote_exact(slot, FileIoWaitKey::Hosted(fixture.file.raw()), NEXT)
        .unwrap();
    adopt(
        &mut fixture.files,
        &mut waiters,
        slot,
        fixture.file.raw(),
        NEXT,
    );
    fixture.files.release_io(fixture.file.raw(), NEXT).unwrap();
    fixture.files.release_file(fixture.file.raw()).unwrap();
    fixture.close();
}

struct PendingCreate;

impl DriverDispatchBackend for PendingCreate {
    fn dispatch_irp(
        &mut self,
        _: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        assert_eq!(irp.major, major::IRP_MJ_CREATE);
        Ok(DispatchOutcome::Pending)
    }
    fn cancel_irp(&mut self, _: IrpId) -> Result<(), NtStatus> {
        Ok(())
    }
}

#[test]
fn pending_create_stays_with_its_specialized_handle_publication_owner() {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let driver = io
        .create_driver(&path(r"\Driver\CreateHandoff"), Box::new(PendingCreate))
        .unwrap();
    let device = io
        .create_device(
            driver,
            Some(&path(r"\Device\CreateHandoff")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let file = io
        .allocate_external_file(
            client,
            device,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            UnicodeString::new(),
        )
        .unwrap();
    let result = io
        .build_and_dispatch_external_to_device(
            client,
            device,
            Some(file),
            0,
            TID,
            major::IRP_MJ_CREATE,
            IoParameters::Create(CreateParameters::default()),
            0,
            0,
            &mut [],
        )
        .unwrap();
    let ExternalDispatchResult::Pending { irp_id } = result else {
        panic!("CREATE must pend in this fixture")
    };
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let slot = pending
        .park_reserved(
            reservation,
            PendingFileIo {
                route: PendingFileRoute::Hosted(file.raw()),
                irp_id: irp_id.raw(),
                major: major::IRP_MJ_CREATE,
                operation: PendingFileIoOperation::Create(PendingFileCreate {
                    handle_va: 0x2000,
                    reservation_pid: 2,
                    reserved_handle: 0x40,
                    reservation_generation: 1,
                    status: NtStatus::PENDING.raw() as u32,
                    ..PendingFileCreate::default()
                }),
                tid: TID,
                iosb_va: 0x1000,
                event_obj_idx: u64::MAX,
                ..PendingFileIo::default()
            },
        )
        .unwrap();
    assert_eq!(
        pending.abandon_thread_transfers_with(TID, |_| panic!("CREATE is not a transfer")),
        0
    );
    assert!(!pending.get(slot).unwrap().consumer_abandoned);
    assert!(pending
        .begin_busy_release_exact(slot, irp_id.raw())
        .is_err());
    assert!(pending.take_create_exact(slot, irp_id.raw() + 1).is_none());
    let owner = pending.take_create_exact(slot, irp_id.raw()).unwrap();
    assert!(matches!(owner.operation, PendingFileIoOperation::Create(_)));
    assert_eq!(owner.irp_id, irp_id.raw());
    assert_eq!(io.irp(irp_id).unwrap().state, IrpState::Pending);
    assert!(pending.is_empty());
    // The specialized CREATE teardown retains the canonical IRP; this fixture never invents
    // a terminal cancellation or completes it through transfer/Busy retirement.
    assert!(io.irp(irp_id).is_some());
}
