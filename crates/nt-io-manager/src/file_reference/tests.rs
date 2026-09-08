use super::*;
use crate::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext,
    DispatchOutcome, DriverCompletion, DriverDispatchBackend, FileRecord, IrpId, IrpProjection,
    MockDriverBackend, MockObjectPort, ShareAccess,
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;
use nt_io_abi::major;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath, ObjectId, UnicodeString};

struct Recording {
    driver: MockDriverBackend,
    calls: Rc<RefCell<Vec<u8>>>,
    reject_close: Rc<RefCell<bool>>,
}
impl DriverDispatchBackend for Recording {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push(irp.major);
        if irp.major == major::IRP_MJ_CLOSE && *self.reject_close.borrow() {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        self.driver.dispatch_irp(ctx, irp)
    }
    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.driver.cancel_irp(irp)
    }
    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.driver.poll_completion()
    }
    fn acknowledge_completion(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.driver.acknowledge_completion(irp)
    }
}

type Setup = (
    IoManager<MockObjectPort>,
    ClientId,
    HandleValue,
    FileId,
    Rc<RefCell<Vec<u8>>>,
    Rc<RefCell<bool>>,
);
fn opened(pending: bool) -> Setup {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let reject_close = Rc::new(RefCell::new(false));
    let mut driver = MockDriverBackend::new();
    if pending {
        driver.set_force_pending(true);
        driver.set_pending_completion(NtStatus::SUCCESS, 0);
    }
    let driver_id = io
        .create_driver(
            &NtPath::parse_str("\\Driver\\FileRefs").unwrap(),
            Box::new(Recording {
                driver,
                calls: calls.clone(),
                reject_close: reject_close.clone(),
            }),
        )
        .unwrap();
    let path = NtPath::parse_str("\\Device\\FileRefs").unwrap();
    io.create_device(
        driver_id,
        Some(&path),
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )
    .unwrap();
    let handle = io
        .open(
            client,
            &path,
            AccessMask::GENERIC_READ,
            ShareAccess::empty(),
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let (file, _) = io
        .reference_open_file(client, handle, AccessMask::empty())
        .unwrap();
    (io, client, handle, file, calls, reject_close)
}

fn count(calls: &Rc<RefCell<Vec<u8>>>, major: u8) -> usize {
    calls
        .borrow()
        .iter()
        .filter(|&&value| value == major)
        .count()
}

#[test]
fn last_handle_cleanup_does_not_close_pointer_referenced_file() {
    let (mut io, client, handle, file, calls, _) = opened(false);
    let mut owner = io.retain_file_reference(file).unwrap();
    io.close(client, handle).unwrap();
    assert_eq!(count(&calls, major::IRP_MJ_CLEANUP), 1);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    assert_eq!(io.file(file).unwrap().state, FileState::ClosePending);
    io.retain_file_reference_owned(&mut owner).unwrap();
    io.release_file_reference_one(&mut owner).unwrap();
    assert_eq!(io.file_reference_count(file), 1);
    io.release_file_reference(&mut owner).unwrap();
    assert_eq!(
        count(&calls, major::IRP_MJ_CLOSE),
        0,
        "release must not invoke a backend"
    );
    assert!(io.file(file).unwrap().close_retry_queued);
    io.pump();
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
    assert!(io.file(file).is_none());
    io.pump();
    assert_eq!(count(&calls, major::IRP_MJ_CLEANUP), 1);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn npfs_completion_then_pointer_dereference_preserves_file_until_both_drain() {
    let (mut io, client, handle, file, calls, _) = opened(true);
    let mut owner = io.retain_file_reference(file).unwrap();
    assert_eq!(
        io.read(client, handle, 0, &mut [0; 8]),
        Err(NtStatus::PENDING)
    );
    let irp = io.pending_irps()[0];
    io.close(client, handle).unwrap();
    io.pump();
    assert!(io.completed_irp(irp).is_some());
    io.acknowledge_completed_irp(irp).unwrap();
    assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    io.release_file_reference(&mut owner).unwrap();
    assert!(io.file(file).is_some());
    io.pump();
    assert!(io.file(file).is_none());
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn pointer_release_before_irp_ack_also_waits_for_irp() {
    let (mut io, client, handle, file, calls, _) = opened(true);
    let mut owner = io.retain_file_reference(file).unwrap();
    assert_eq!(
        io.read(client, handle, 0, &mut [0; 8]),
        Err(NtStatus::PENDING)
    );
    let irp = io.pending_irps()[0];
    io.close(client, handle).unwrap();
    io.release_file_reference(&mut owner).unwrap();
    io.pump();
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    io.acknowledge_completed_irp(irp).unwrap();
    assert!(io.file(file).is_none());
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn split_merge_and_wrong_manager_preserve_all_counts() {
    let (mut io, _, _, file, _, _) = opened(false);
    let (mut wrong, _, _, foreign, _, _) = opened(false);
    assert_eq!(file, foreign);
    let mut owner = io.retain_file_reference(file).unwrap();
    io.retain_file_reference_owned(&mut owner).unwrap();
    let mut part = io.split_file_reference_one(&mut owner).unwrap();
    assert_eq!(io.file_reference_count(file), 2);
    assert_eq!(
        wrong.release_file_reference(&mut part),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        wrong.retain_file_reference_owned(&mut part),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(part.count(), 1);
    io.merge_file_references(&mut owner, &mut part).unwrap();
    assert_eq!(owner.count(), 2);
    assert!(!part.is_held());
    assert_eq!(
        io.release_file_reference(&mut part),
        Err(NtStatus::INVALID_PARAMETER)
    );
    io.release_file_reference(&mut owner).unwrap();
    assert_eq!(io.file_reference_count(file), 0);
}

#[test]
fn raw_removal_and_object_reference_release_are_blocked() {
    let (mut io, _, _, file, _, _) = opened(false);
    let owner = io.retain_file_reference(file).unwrap();
    let reference = io.file(file).unwrap().object_reference;
    assert_ne!(reference, 0);
    assert!(io.remove_file(file).is_none());
    assert_eq!(io.release_file_record(file), Err(NtStatus::DELETE_PENDING));
    assert_eq!(io.file(file).unwrap().object_reference, reference);
    assert!(owner.is_held());
}

#[test]
fn no_resurrection_after_handle_release_or_close_entry() {
    let (mut io, _, _, file, _, _) = opened(false);
    {
        let record = io.file_mut(file).unwrap();
        record.state = FileState::CleanupComplete;
        record.close_deferred = true;
    }
    assert_eq!(
        io.retain_file_reference(file).unwrap_err(),
        NtStatus::FILE_CLOSED
    );
    {
        let record = io.file_mut(file).unwrap();
        record.state = FileState::ClosePending;
        record.close_dispatched = true;
        record.outstanding_irp_refs = 1; // CLOSE's own IRP is not resurrection authority.
    }
    assert_eq!(
        io.retain_file_reference(file).unwrap_err(),
        NtStatus::FILE_CLOSED
    );
}

#[test]
fn explicit_cleanup_with_handle_and_active_cleanup_irp_allow_reference() {
    let (mut io, client, handle, file, _, _) = opened(false);
    io.cleanup(client, handle).unwrap();
    assert!(!io.file(file).unwrap().close_deferred);
    let mut owner = io.retain_file_reference(file).unwrap();
    io.release_file_reference(&mut owner).unwrap();
    {
        let record = io.file_mut(file).unwrap();
        record.state = FileState::CleanupPending;
        record.close_deferred = true;
        record.outstanding_irp_refs = 1;
    }
    let mut during_cleanup = io.retain_file_reference(file).unwrap();
    io.release_file_reference(&mut during_cleanup).unwrap();
}

#[test]
fn rejected_close_stays_queued_and_cannot_resurrect() {
    let (mut io, client, handle, file, calls, reject) = opened(false);
    *reject.borrow_mut() = true;
    io.close(client, handle).unwrap();
    assert!(io.file(file).unwrap().close_retry_queued);
    assert!(!io.file(file).unwrap().close_dispatched);
    assert_eq!(
        io.retain_file_reference(file).unwrap_err(),
        NtStatus::FILE_CLOSED
    );
    let before = count(&calls, major::IRP_MJ_CLOSE);
    io.pump();
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), before + 1);
    assert!(io.file(file).unwrap().close_retry_queued);
    *reject.borrow_mut() = false;
    io.pump();
    assert!(io.file(file).is_none());
}

fn allocated(
    io: &mut IoManager<MockObjectPort>,
    client: ClientId,
    device: crate::DeviceId,
) -> FileId {
    io.add_file(FileRecord::new(
        ObjectId::NULL,
        client,
        device,
        AccessMask::empty(),
        ShareAccess::empty(),
        CreateOptions::empty(),
        UnicodeString::new(),
    ))
}

#[test]
fn allocated_and_failed_create_records_retire_without_fabricated_driver_irps() {
    let (mut io, client, _, existing, calls, _) = opened(false);
    let device = io.file(existing).unwrap().device_id;
    for failed_create in [false, true] {
        let file = allocated(&mut io, client, device);
        let mut owner = io.retain_file_reference(file).unwrap();
        if failed_create {
            io.file_mut(file).unwrap().state = FileState::Closed;
        }
        let before = calls.borrow().len();
        io.release_external_file(client, file).unwrap();
        assert!(io.file(file).unwrap().close_deferred);
        io.release_file_reference(&mut owner).unwrap();
        io.pump();
        assert!(io.file(file).is_none());
        assert_eq!(calls.borrow().len(), before);
    }
}

#[test]
fn slot_reuse_rejects_old_identity_and_emptied_owner() {
    let (mut io, client, handle, file, _, _) = opened(false);
    let device = io.file(file).unwrap().device_id;
    let mut owner = io.retain_file_reference(file).unwrap();
    io.close(client, handle).unwrap();
    io.release_file_reference(&mut owner).unwrap();
    io.pump();
    let replacement = allocated(&mut io, client, device);
    assert_eq!(file.slot(), replacement.slot());
    assert_ne!(file, replacement);
    assert_eq!(
        io.retain_file_reference(file).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
    assert_eq!(
        io.release_file_reference(&mut owner),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.file_reference_count(replacement), 0);
}

#[test]
fn queued_close_scan_is_bounded_and_fair_without_queue_allocations() {
    let (mut io, client, _, existing, _, _) = opened(false);
    let device = io.file(existing).unwrap().device_id;
    let mut files = Vec::new();
    for _ in 0..130 {
        let file = allocated(&mut io, client, device);
        let mut owner = io.retain_file_reference(file).unwrap();
        io.release_external_file(client, file).unwrap();
        io.release_file_reference(&mut owner).unwrap();
        files.push(file);
    }
    let report = io.pump_with_report();
    assert!(!report.storage_grew);
    assert_eq!(
        files.iter().filter(|&&id| io.file(id).is_none()).count(),
        64
    );
    io.pump();
    assert_eq!(
        files.iter().filter(|&&id| io.file(id).is_none()).count(),
        128
    );
    io.pump();
    assert!(files.iter().all(|&id| io.file(id).is_none()));
    assert_eq!(io.deferred_file_close_queued, 0);
}

#[test]
fn close_queue_summary_is_idempotent_and_removal_clears_it() {
    let (mut io, client, _, existing, _, _) = opened(false);
    let device = io.file(existing).unwrap().device_id;
    let file = allocated(&mut io, client, device);
    io.queue_deferred_file_close(file);
    io.queue_deferred_file_close(file);
    assert_eq!(io.deferred_file_close_queued, 1);
    assert!(!io.take_deferred_file_close(FileId::NULL));
    assert_eq!(io.deferred_file_close_queued, 1);
    let removed = io.remove_file(file).unwrap();
    assert!(!removed.close_retry_queued);
    assert_eq!(io.deferred_file_close_queued, 0);
    io.deferred_file_close_cursor = 987;
    io.pump();
    assert_eq!(
        io.deferred_file_close_cursor, 987,
        "empty queue must skip File scanning"
    );
}

#[test]
fn disconnected_client_keeps_record_only_files_until_pointer_owners_release() {
    let (mut io, client, _, existing, calls, _) = opened(false);
    let device = io.file(existing).unwrap().device_id;
    let allocated_file = allocated(&mut io, client, device);
    let failed_file = allocated(&mut io, client, device);
    let mut allocated_owner = io.retain_file_reference(allocated_file).unwrap();
    let mut failed_owner = io.retain_file_reference(failed_file).unwrap();
    io.file_mut(failed_file).unwrap().state = FileState::Closed;
    io.disconnect_client(client).unwrap();
    assert!(io.file(allocated_file).unwrap().close_deferred);
    assert!(io.file(failed_file).unwrap().close_deferred);
    assert_eq!(count(&calls, major::IRP_MJ_CLEANUP), 1);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
    let before = calls.borrow().len();
    io.release_file_reference(&mut allocated_owner).unwrap();
    io.release_file_reference(&mut failed_owner).unwrap();
    io.pump();
    assert!(io.file(allocated_file).is_none());
    assert!(io.file(failed_file).is_none());
    assert_eq!(calls.borrow().len(), before);
    assert_eq!(io.deferred_file_close_queued, 0);
}

#[test]
fn counted_reference_overflow_preserves_existing_owners_and_totals() {
    let (mut io, _, _, file, _, _) = opened(false);
    let mut owner = io.retain_file_reference(file).unwrap();
    let index = io.file_reference_index(&owner).unwrap();
    owner.count = u64::MAX;
    io.file_references.counts[index].count = u64::MAX;
    assert_eq!(
        io.retain_file_reference_owned(&mut owner),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(owner.count(), u64::MAX);
    assert_eq!(io.file_reference_count(file), u64::MAX);
    assert_eq!(
        io.retain_file_reference(file).unwrap_err(),
        NtStatus::INSUFFICIENT_RESOURCES
    );
    assert_eq!(io.file_reference_count(file), u64::MAX);
    io.release_file_reference(&mut owner).unwrap();
    assert!(!owner.is_held());
    assert_eq!(io.file_reference_count(file), 0);
}

#[test]
fn merge_overflow_and_wrong_file_leave_both_owners_unchanged() {
    let (mut io, client, _, file, _, _) = opened(false);
    let device = io.file(file).unwrap().device_id;
    let other = allocated(&mut io, client, device);
    let mut target = io.retain_file_reference(file).unwrap();
    let mut wrong = io.retain_file_reference(other).unwrap();
    assert_eq!(
        io.merge_file_references(&mut target, &mut wrong),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(target.count(), 1);
    assert_eq!(wrong.count(), 1);
    assert_eq!(io.file_reference_count(file), 1);
    assert_eq!(io.file_reference_count(other), 1);

    let mut source = io.retain_file_reference(file).unwrap();
    let index = io.file_reference_index(&target).unwrap();
    // Force the checked-arithmetic boundary without allocating u64::MAX references.
    target.count = u64::MAX;
    io.file_references.counts[index].count = u64::MAX;
    assert_eq!(
        io.merge_file_references(&mut target, &mut source),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(target.count(), u64::MAX);
    assert_eq!(source.count(), 1);
    assert_eq!(io.file_reference_count(file), u64::MAX);
    target.count = 1;
    io.file_references.counts[index].count = 2;
    io.release_file_reference(&mut target).unwrap();
    io.release_file_reference(&mut source).unwrap();
    io.release_file_reference(&mut wrong).unwrap();
}
