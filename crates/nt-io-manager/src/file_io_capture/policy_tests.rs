//! Canonical capture references composed with the executive's real File policy.
//! Driver outcomes are supplied by a host fixture; this does not execute native IPC.

use super::{FileIoCapture, FileIoCaptureTable};
use crate::*;
use alloc::boxed::Box;
use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath};

struct Fixture {
    io: IoManager<MockObjectPort>,
    policy: FileCompletionTable<1>,
    captures: FileIoCaptureTable,
    client: ClientId,
    handle: HandleValue,
    file: FileId,
    device: DeviceId,
    mode: FileIoMode,
}

impl Fixture {
    fn new(mode: FileIoMode, pending: bool) -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let mut backend = MockDriverBackend::new();
        backend.set_force_pending(pending);
        backend.set_pending_completion(NtStatus::SUCCESS, 0);
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\CapturePolicy").unwrap(),
                Box::new(backend),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\CapturePolicy").unwrap();
        let device = io
            .create_device(
                driver,
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
        let mut policy = FileCompletionTable::new();
        policy
            .insert_file_with_mode(file.raw(), device.raw(), mode)
            .unwrap();
        Self {
            io,
            policy,
            captures: FileIoCaptureTable::new(),
            client,
            handle,
            file,
            device,
            mode,
        }
    }

    fn capture(&mut self) -> FileIoCapture {
        self.captures
            .capture(&mut self.io, self.file, self.device, 1)
            .unwrap()
    }

    fn retire(&mut self, mut capture: FileIoCapture) {
        let identity = capture.identity();
        self.captures.retire(&mut capture).unwrap();
        self.captures
            .release_retired(&mut self.io, identity)
            .unwrap();
    }

    fn start_canonical_cleanup(&mut self) {
        assert!(self
            .policy
            .mark_cleanup_lifecycle_started(self.file.raw())
            .unwrap());
        self.io.close(self.client, self.handle).unwrap();
    }

    fn finish_policy_cleanup(&mut self) {
        assert!(self.io.file(self.file).is_none());
        if self.mode.is_synchronous() {
            self.policy.release_cleanup_io(self.file.raw()).unwrap();
        }
        assert!(
            self.policy
                .release_cleanup_reference(self.file.raw())
                .unwrap()
                .close_required
        );
        assert!(self.policy.io_mode(self.file.raw()).is_err());
    }
}

#[test]
fn cleanup_can_run_during_capture_but_policy_and_canonical_body_survive() {
    for mode in [
        FileIoMode::Asynchronous,
        FileIoMode::SynchronousNonAlertable,
    ] {
        let mut f = Fixture::new(mode, false);
        let capture = f.capture();
        assert!(
            f.policy
                .release_handle(f.file.raw())
                .unwrap()
                .cleanup_required
        );
        assert_eq!(
            f.policy.begin_cleanup(f.file.raw()).unwrap(),
            if mode.is_synchronous() {
                FileIoAcquireResult::Acquired
            } else {
                FileIoAcquireResult::Bypassed
            }
        );
        f.start_canonical_cleanup();
        assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
        assert_eq!(f.policy.io_mode(f.file.raw()), Ok(mode));
        assert_eq!(f.io.file_reference_count(f.file), 1);
        // Current admission refuses a close that won the race. Capture never creates a
        // replacement handle, steals cleanup Busy, or silently changes this status.
        assert!(f.policy.acquire_file_io(f.file.raw(), 20).is_err());
        assert_eq!(capture.file_id(), f.file);
        assert_eq!(capture.granted_access(), 1);
        f.retire(capture);
        assert!(f.io.file(f.file).is_some(), "release only queues CLOSE");
        f.io.pump();
        f.finish_policy_cleanup();
    }
}

#[test]
fn inline_busy_takes_over_capture_protection_without_an_irp() {
    let mut f = Fixture::new(FileIoMode::SynchronousNonAlertable, false);
    let capture = f.capture();
    assert_eq!(
        f.policy.acquire_file_io(f.file.raw(), 20),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert!(
        f.policy
            .release_handle(f.file.raw())
            .unwrap()
            .cleanup_required
    );
    assert_eq!(
        f.policy.begin_cleanup(f.file.raw()),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    f.retire(capture);
    assert_eq!(f.io.file_reference_count(f.file), 0);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    f.policy.release_io(f.file.raw(), 20).unwrap();
    f.policy.release_file(f.file.raw()).unwrap();
    assert!(f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    f.start_canonical_cleanup();
    f.finish_policy_cleanup();
}

#[test]
fn counted_waiter_then_promoted_grant_protects_file_after_capture_retires() {
    let mut f = Fixture::new(FileIoMode::SynchronousAlertable, false);
    assert_eq!(
        f.policy.acquire_file_io(f.file.raw(), 20),
        Ok(FileIoAcquireResult::Acquired)
    );
    let capture = f.capture();
    assert_eq!(
        f.policy.acquire_file_io(f.file.raw(), 21),
        Ok(FileIoAcquireResult::Contended { alertable: true })
    );
    assert!(
        f.policy
            .release_handle(f.file.raw())
            .unwrap()
            .cleanup_required
    );
    assert_eq!(
        f.policy.begin_cleanup(f.file.raw()),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    f.retire(capture);
    f.policy.release_io(f.file.raw(), 20).unwrap();
    f.policy.release_file(f.file.raw()).unwrap();
    assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    assert_eq!(f.policy.promote_io_waiter(f.file.raw(), 21), Ok(0));
    assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    f.policy.adopt_io_grant(f.file.raw(), 21).unwrap();
    assert_eq!(
        f.io.file_reference_count(f.file),
        0,
        "retry needs no new capture retain"
    );
    f.policy.release_io(f.file.raw(), 21).unwrap();
    f.policy.release_file(f.file.raw()).unwrap();
    assert!(f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    f.start_canonical_cleanup();
    f.finish_policy_cleanup();
}

#[test]
fn pending_asynchronous_irp_takes_over_canonical_lifetime() {
    let mut f = Fixture::new(FileIoMode::Asynchronous, true);
    let capture = f.capture();
    f.policy.retain_file(f.file.raw()).unwrap();
    assert_eq!(
        f.io.read(f.client, f.handle, 0, &mut [0; 8]),
        Err(NtStatus::PENDING)
    );
    let irp = f.io.pending_irps()[0];
    f.retire(capture);
    assert_eq!(f.io.file_reference_count(f.file), 0);
    assert!(
        f.policy
            .release_handle(f.file.raw())
            .unwrap()
            .cleanup_required
    );
    assert_eq!(
        f.policy.begin_cleanup(f.file.raw()),
        Ok(FileIoAcquireResult::Bypassed)
    );
    f.start_canonical_cleanup();
    f.io.pump();
    assert!(
        f.io.file(f.file).is_some(),
        "completed IRP still needs consumer ACK"
    );
    assert!(f.io.completed_irp(irp).is_some());
    f.io.acknowledge_completed_irp(irp).unwrap();
    f.policy.release_file(f.file.raw()).unwrap();
    f.finish_policy_cleanup();
}
