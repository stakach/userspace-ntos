//! Canonical capture references composed with the executive's real File policy.
//! Driver outcomes are supplied by a host fixture; this does not execute native IPC.

use super::{FileIoCapture, FileIoCaptureTable};
use crate::inline_file_retirement::{
    InlineFileRetirementEffect as Effect, InlineFileRetirementIdentity as InlineIdentity,
    InlineFileRetirementOutcome as Outcome, InlineFileRetirementTable as InlineTable,
};
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
        Self::with_access(mode, pending, AccessMask::GENERIC_READ)
    }

    fn with_access(mode: FileIoMode, pending: bool, access: AccessMask) -> Self {
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
                access,
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

fn set_access(kind: BufferedSetInformationKind) -> AccessMask {
    AccessMask::from_bits_retain(match kind {
        BufferedSetInformationKind::Ea => 0x10,
        BufferedSetInformationKind::Quota => 0x02,
    })
}

fn valid_set_payload(kind: BufferedSetInformationKind) -> alloc::vec::Vec<u8> {
    match kind {
        BufferedSetInformationKind::Ea => {
            alloc::vec![0, 0, 0, 0, 0, 1, 2, 0, b'A', 0, 0xaa, 0xbb]
        }
        BufferedSetInformationKind::Quota => {
            let mut bytes = alloc::vec![0; 52];
            bytes[4..8].copy_from_slice(&12u32.to_le_bytes());
            bytes[40..].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
            bytes
        }
    }
}

fn reserve_inline(f: &Fixture, tid: u64) -> (InlineTable, InlineIdentity) {
    let mut owners = InlineTable::new();
    let reservation = owners
        .reserve(FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(f.file.raw()),
            tid,
            mode: f.mode,
        })
        .unwrap();
    let identity = owners.activate(reservation).unwrap();
    (owners, identity)
}

fn retire_inline(f: &mut Fixture, owners: &mut InlineTable, identity: InlineIdentity) {
    owners.retire_active(identity).unwrap();
    let mut attempt = owners.begin_step(identity).unwrap();
    assert_eq!(attempt.effect(), Effect::ReleasePolicy);
    let release = f
        .policy
        .release_io(f.file.raw(), attempt.owner().tid)
        .unwrap();
    owners
        .record_step(
            &mut attempt,
            Outcome::PolicyReleased {
                waiters: release.waiters,
            },
        )
        .unwrap();

    let mut attempt = owners.begin_step(identity).unwrap();
    assert_eq!(attempt.effect(), Effect::Wake);
    assert!(f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    f.start_canonical_cleanup();
    owners
        .record_step(&mut attempt, Outcome::Completed(Effect::Wake))
        .unwrap();

    let mut attempt = owners.begin_step(identity).unwrap();
    assert_eq!(attempt.effect(), Effect::ReleaseReference);
    let receipt = f.policy.release_file(f.file.raw()).unwrap();
    assert!(!receipt.cleanup_required);
    assert!(receipt.port_id.is_none());
    owners
        .record_step(&mut attempt, Outcome::ReferenceReleased(receipt))
        .unwrap();
    let mut attempt = owners.begin_step(identity).unwrap();
    assert_eq!(attempt.effect(), Effect::ReferenceFollowup);
    owners
        .record_step(&mut attempt, Outcome::Completed(Effect::ReferenceFollowup))
        .unwrap();
    owners.finish(identity).unwrap();
    assert!(owners.is_empty());
}

#[test]
fn synchronous_buffered_set_failures_keep_busy_across_copy_and_status_publication() {
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        for kind in [
            BufferedSetInformationKind::Ea,
            BufferedSetInformationKind::Quota,
        ] {
            for copy_fails in [false, true] {
                let access = set_access(kind);
                let mut f = Fixture::with_access(mode, false, access);
                let capture = f
                    .captures
                    .capture(&mut f.io, f.file, f.device, access.bits())
                    .unwrap();
                f.policy.set_signaled(f.file.raw(), true).unwrap();
                assert_eq!(
                    f.policy.acquire_file_io(f.file.raw(), 20),
                    Ok(FileIoAcquireResult::Acquired)
                );
                let (mut owners, identity) = reserve_inline(&f, 20);
                f.policy.set_signaled(f.file.raw(), false).unwrap();
                let error = capture_buffered_set_information(kind, 4, |buffer| {
                    assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
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
                    assert_eq!(f.io.file_reference_count(f.file), 1);
                    assert!(f.io.file(f.file).is_some());
                    buffer.fill(0);
                    if copy_fails {
                        Err(NtStatus::ACCESS_VIOLATION)
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                let mut writes = alloc::vec::Vec::new();
                let status = error.publish(|offset, bytes| {
                    assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
                    assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
                    writes.push((offset, bytes.to_vec()));
                    true
                });
                if copy_fails {
                    assert_eq!(status, NtStatus::ACCESS_VIOLATION);
                    assert!(writes.is_empty());
                } else {
                    let expected = match kind {
                        BufferedSetInformationKind::Ea => NtStatus::EA_LIST_INCONSISTENT,
                        BufferedSetInformationKind::Quota => NtStatus::QUOTA_LIST_INCONSISTENT,
                    };
                    assert_eq!(status, expected);
                    assert_eq!(
                        writes,
                        alloc::vec![
                            (0, expected.raw().to_le_bytes().to_vec()),
                            (8, 0u64.to_le_bytes().to_vec())
                        ]
                    );
                }
                assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
                assert!(f.io.pending_irps().is_empty());
                retire_inline(&mut f, &mut owners, identity);
                assert!(
                    f.io.file(f.file).is_some(),
                    "capture still pins the canonical body"
                );
                f.retire(capture);
                f.io.pump();
                f.finish_policy_cleanup();
            }
        }
    }
}

#[test]
fn queued_buffered_set_copies_changed_payload_only_after_exact_grant_adoption() {
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        for kind in [
            BufferedSetInformationKind::Ea,
            BufferedSetInformationKind::Quota,
        ] {
            let access = set_access(kind);
            let mut f = Fixture::with_access(mode, false, access);
            f.policy.set_signaled(f.file.raw(), true).unwrap();
            assert_eq!(
                f.policy.acquire_file_io(f.file.raw(), 20),
                Ok(FileIoAcquireResult::Acquired)
            );
            let capture = f
                .captures
                .capture(&mut f.io, f.file, f.device, access.bits())
                .unwrap();
            let mut waiters = SynchronousFileWaitTable::new();
            let reserved = waiters.reserve().unwrap();
            let admitted = f.policy.acquire_file_io(f.file.raw(), 21).unwrap();
            assert_eq!(
                admitted,
                FileIoAcquireResult::Contended {
                    alertable: mode == FileIoMode::SynchronousAlertable
                }
            );
            let mut copies = 0;
            let valid = valid_set_payload(kind);
            let mut payload = alloc::vec![0xff; valid.len()];
            let mut waiter = SynchronousFileWaiter::waiting(
                FileIoWaitRoute::Hosted {
                    file_id: capture.file_id().raw(),
                    device_id: capture.device_id().raw(),
                    fs_context: capture.fs_context(),
                },
                0x40,
                capture.granted_access(),
                191,
                2,
                21,
                121,
                mode,
                true,
                0,
                0x1002,
                0x2000,
                0x202,
            );
            waiter.reply_cap = 221;
            waiters.park_reserved(reserved, waiter).unwrap();
            assert_eq!(copies, 0);
            assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(true));
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
            payload.copy_from_slice(&valid);
            f.policy.release_io(f.file.raw(), 20).unwrap();
            f.policy.release_file(f.file.raw()).unwrap();
            assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
            let key = FileIoWaitKey::Hosted(f.file.raw());
            let (slot, _) = waiters.oldest_waiting_for_file(key).unwrap();
            f.policy.promote_io_waiter(f.file.raw(), 21).unwrap();
            waiters.promote_exact(slot, key, 21).unwrap();
            let retry = waiters.retry_identity(slot, key, 21).unwrap();
            let mut attempt = waiters.begin_retry(retry).unwrap();
            waiters
                .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
                .unwrap();
            assert!(waiters.finish_retry(retry, Ok(())).unwrap());
            let mut ingress = waiters.begin_ingress(2, 21, 121, 191).unwrap().unwrap();
            let mut adoption = waiters.begin_adoption(&mut ingress).unwrap();
            let adopted = f.policy.adopt_io_grant(f.file.raw(), 21);
            let owner = waiters
                .record_adoption(&mut adoption, adopted)
                .unwrap()
                .unwrap();
            assert_eq!(owner.waiter().granted_access, access.bits());
            assert_eq!(owner.waiter().route, waiter.route);
            assert_eq!(f.io.file_reference_count(f.file), 0);
            assert_eq!(copies, 0);
            let (mut owners, identity) = reserve_inline(&f, 21);
            f.policy.set_signaled(f.file.raw(), false).unwrap();
            let copied = capture_buffered_set_information(kind, payload.len(), |buffer| {
                copies += 1;
                assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
                assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
                buffer.copy_from_slice(&payload);
                Ok(())
            })
            .unwrap();
            assert_eq!(copies, 1);
            assert_eq!(copied, valid);
            assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
            // A later pre-dispatch exit uses the same central retirement owner.
            retire_inline(&mut f, &mut owners, identity);
            f.finish_policy_cleanup();
        }
    }
}

#[test]
fn asynchronous_buffered_set_copy_failure_survives_immediate_cleanup_without_an_irp() {
    for kind in [
        BufferedSetInformationKind::Ea,
        BufferedSetInformationKind::Quota,
    ] {
        let access = set_access(kind);
        let mut f = Fixture::with_access(FileIoMode::Asynchronous, false, access);
        let capture = f
            .captures
            .capture(&mut f.io, f.file, f.device, access.bits())
            .unwrap();
        f.policy.retain_file(f.file.raw()).unwrap();
        f.policy.set_signaled(f.file.raw(), false).unwrap();
        let error = capture_buffered_set_information(kind, 4, |_| {
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
            assert!(f.io.file(f.file).is_some());
            Err(NtStatus::ACCESS_VIOLATION)
        })
        .unwrap_err();
        assert_eq!(
            error.publish(|_, _| panic!("copy fault must not publish IOSB")),
            NtStatus::ACCESS_VIOLATION
        );
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        f.policy.release_file(f.file.raw()).unwrap();
        f.retire(capture);
        f.io.pump();
        f.finish_policy_cleanup();
    }
}
