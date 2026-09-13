//! Canonical capture references composed with the executive's real File policy.
//! Driver outcomes are supplied by a host fixture; this does not execute native IPC.

use super::{FileIoCapture, FileIoCaptureTable};
use crate::inline_file_retirement::{
    InlineFileRetirementEffect as Effect, InlineFileRetirementIdentity as InlineIdentity,
    InlineFileRetirementOutcome as Outcome, InlineFileRetirementTable as InlineTable,
};
use crate::*;
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;
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
        let mut backend = MockDriverBackend::new();
        backend.set_force_pending(pending);
        backend.set_pending_completion(NtStatus::SUCCESS, 0);
        Self::with_backend(mode, access, Box::new(backend))
    }

    fn with_backend(
        mode: FileIoMode,
        access: AccessMask,
        backend: Box<dyn DriverDispatchBackend>,
    ) -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\CapturePolicy").unwrap(),
                backend,
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

struct QueryRecordingDriver {
    lifecycle: MockDriverBackend,
    calls: Rc<RefCell<Vec<IrpProjection>>>,
}

impl DriverDispatchBackend for QueryRecordingDriver {
    fn dispatch_irp(
        &mut self,
        context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push(irp.clone());
        if irp.major == nt_io_abi::major::IRP_MJ_QUERY_INFORMATION {
            context.system_buffer.fill(0x5a);
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: context.system_buffer.len() as u64,
                file_context: None,
            });
        }
        self.lifecycle.dispatch_irp(context, irp)
    }

    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.lifecycle.cancel_irp(irp)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.lifecycle.poll_completion()
    }
}

#[test]
fn owned_file_query_dispatches_captured_route_and_grant_before_close_during_copyout() {
    use nt_io_abi::major;
    let access = AccessMask::from_bits_retain(0x80);
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut f = Fixture::with_backend(
        FileIoMode::SynchronousNonAlertable,
        access,
        Box::new(QueryRecordingDriver {
            lifecycle: MockDriverBackend::new(),
            calls: calls.clone(),
        }),
    );
    let driver = f.io.device(f.device).unwrap().driver_id;
    let dispatch =
        f.io.driver(driver)
            .unwrap()
            .dispatch
            .get(major::IRP_MJ_CREATE);
    f.io.driver_mut(driver)
        .unwrap()
        .dispatch
        .set(major::IRP_MJ_QUERY_INFORMATION, dispatch);
    let capture = f
        .captures
        .capture(&mut f.io, f.file, f.device, access.bits())
        .unwrap();
    assert_eq!(capture.granted_access(), access.bits());
    assert!(query_information_contract(4)
        .unwrap()
        .access_granted(AccessMask::from_bits_retain(capture.granted_access())));
    assert_eq!(
        f.policy.acquire_file_io(f.file.raw(), 20),
        Ok(FileIoAcquireResult::Acquired)
    );
    let (mut owners, identity) = reserve_inline(&f, 20);
    f.policy.set_signaled(f.file.raw(), false).unwrap();
    let parameters = IoParameters::QueryInformation(InformationParameters {
        info_class: 4,
        length: 40,
    });
    let mut output = [0; 40];
    assert_eq!(
        f.io.build_and_dispatch_external_to_device_with_stack_flags(
            f.client,
            capture.device_id(),
            Some(capture.file_id()),
            0,
            20,
            major::IRP_MJ_QUERY_INFORMATION,
            parameters.clone(),
            StackFlags::empty(),
            0,
            40,
            &mut output,
        ),
        Ok(ExternalDispatchResult::Completed {
            status: NtStatus::SUCCESS,
            information: 40,
            file_context: None
        })
    );
    let observed = calls.borrow().last().unwrap().clone();
    assert_eq!(observed.parameters, parameters);
    assert_eq!(observed.file_id, Some(capture.file_id()));
    assert_eq!(observed.device_id, capture.device_id());
    assert_eq!(observed.requestor_tid, 20);
    assert_eq!(output, [0x5a; 40]);
    // A reentrant copyout can close the public handle after the real IRP completed.
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
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert!(f.io.pending_irps().is_empty());
    assert!(f
        .io
        .owned_file_query_metadata(f.client, capture.file_id(), capture.device_id())
        .is_ok());
    f.policy.set_signaled(f.file.raw(), true).unwrap();
    assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
    retire_inline(&mut f, &mut owners, identity);
    assert!(f.io.file(f.file).is_some());
    f.retire(capture);
    f.io.pump();
    f.finish_policy_cleanup();
    assert_eq!(
        calls
            .borrow()
            .iter()
            .map(|irp| irp.major)
            .collect::<Vec<_>>(),
        alloc::vec![
            major::IRP_MJ_CREATE,
            major::IRP_MJ_QUERY_INFORMATION,
            major::IRP_MJ_CLEANUP,
            major::IRP_MJ_CLOSE,
        ]
    );
}

#[test]
fn owned_file_query_inline_metadata_keeps_body_and_busy_through_reentrant_copyout() {
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        let access = AccessMask::from_bits_retain(0x80);
        let mut f = Fixture::with_access(mode, false, access);
        let capture = f
            .captures
            .capture(&mut f.io, f.file, f.device, access.bits())
            .unwrap();
        let options = CreateOptions::WRITE_THROUGH | CreateOptions::NO_INTERMEDIATE_BUFFERING;
        f.io.file_mut(f.file).unwrap().create_options = options;
        f.io.device_mut(f.device).unwrap().alignment_requirement = 0x1ff;
        assert_eq!(
            f.policy.acquire_file_io(f.file.raw(), 20),
            Ok(FileIoAcquireResult::Acquired)
        );
        let (mut owners, identity) = reserve_inline(&f, 20);
        f.policy.set_signaled(f.file.raw(), false).unwrap();
        let metadata =
            f.io.owned_file_query_metadata(f.client, capture.file_id(), capture.device_id())
                .unwrap();
        assert_eq!(metadata.create_options, options);
        assert_eq!(metadata.alignment_requirement, 0x1ff);
        for class in [8, 16, 17] {
            assert!(query_information_contract(class)
                .unwrap()
                .access_granted(AccessMask::from_bits_retain(capture.granted_access())));
        }
        let mut copied = [[0; 4]; 3];
        let mut copyout = |bytes: &mut [[u8; 4]; 3]| {
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
            let still_live =
                f.io.owned_file_query_metadata(f.client, capture.file_id(), capture.device_id())
                    .unwrap();
            assert_eq!(still_live, metadata);
            assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
            let query = nt_fs::QueryMetadata {
                access_flags: capture.granted_access(),
                mode: nt_fs::file_mode_from_create_options(still_live.create_options.bits()),
                alignment_requirement: still_live.alignment_requirement,
                ..Default::default()
            };
            for (class, output) in [8, 16, 17].into_iter().zip(bytes) {
                assert_eq!(nt_fs::encode_query_information(class, query, output), Ok(4));
            }
        };
        copyout(&mut copied);
        assert_eq!(copied[0], access.bits().to_le_bytes());
        assert_eq!(
            copied[1],
            nt_fs::file_mode_from_create_options(options.bits()).to_le_bytes()
        );
        assert_eq!(copied[2], 0x1ffu32.to_le_bytes());
        f.policy.set_signaled(f.file.raw(), true).unwrap();
        assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        assert!(f.io.pending_irps().is_empty());
        retire_inline(&mut f, &mut owners, identity);
        f.retire(capture);
        f.io.pump();
        f.finish_policy_cleanup();
    }
}

#[test]
fn owned_file_query_queued_adoption_retains_grant_but_reads_live_metadata() {
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        let access = AccessMask::from_bits_retain(0x80);
        let mut f = Fixture::with_access(mode, false, access);
        assert_eq!(
            f.policy.acquire_file_io(f.file.raw(), 20),
            Ok(FileIoAcquireResult::Acquired)
        );
        let capture = f
            .captures
            .capture(&mut f.io, f.file, f.device, access.bits())
            .unwrap();
        let before =
            f.io.owned_file_query_metadata(f.client, f.file, f.device)
                .unwrap();
        let key = FileIoWaitKey::Hosted(f.file.raw());
        let mut waiters = SynchronousFileWaitTable::new();
        let reserved = waiters.reserve().unwrap();
        assert_eq!(
            f.policy.acquire_file_io(f.file.raw(), 21),
            Ok(FileIoAcquireResult::Contended {
                alertable: mode == FileIoMode::SynchronousAlertable
            })
        );
        let mut waiter = SynchronousFileWaiter::waiting(
            FileIoWaitRoute::Hosted {
                file_id: capture.file_id().raw(),
                device_id: capture.device_id().raw(),
                fs_context: capture.fs_context(),
            },
            0x40,
            capture.granted_access(),
            71,
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
        let options = CreateOptions::SEQUENTIAL_ONLY | CreateOptions::WRITE_THROUGH;
        // Host-model metadata mutation, not a native FileModeInformation set operation.
        f.io.file_mut(f.file).unwrap().create_options = options;
        f.io.device_mut(f.device).unwrap().alignment_requirement = 0xfff;
        f.policy.release_io(f.file.raw(), 20).unwrap();
        f.policy.release_file(f.file.raw()).unwrap();
        assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
        let (slot, _) = waiters.oldest_waiting_for_file(key).unwrap();
        f.policy.promote_io_waiter(f.file.raw(), 21).unwrap();
        waiters.promote_exact(slot, key, 21).unwrap();
        let retry = waiters.retry_identity(slot, key, 21).unwrap();
        let mut attempt = waiters.begin_retry(retry).unwrap();
        waiters
            .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
            .unwrap();
        assert!(waiters.finish_retry(retry, Ok(())).unwrap());
        let mut ingress = waiters.begin_ingress(2, 21, 121, 71).unwrap().unwrap();
        let mut adoption = waiters.begin_adoption(&mut ingress).unwrap();
        let result = f.policy.adopt_io_grant(f.file.raw(), 21);
        let owner = waiters
            .record_adoption(&mut adoption, result)
            .unwrap()
            .unwrap();
        let adopted = owner.waiter();
        assert_eq!(adopted.granted_access, access.bits());
        assert_eq!(adopted.route, waiter.route);
        assert!(query_information_contract(18)
            .unwrap()
            .access_granted(AccessMask::from_bits_retain(adopted.granted_access)));
        let FileIoWaitRoute::Hosted {
            file_id, device_id, ..
        } = adopted.route
        else {
            panic!("hosted query must retain its original route");
        };
        let (mut owners, identity) = reserve_inline(&f, 21);
        f.policy.set_signaled(f.file.raw(), false).unwrap();
        let live =
            f.io.owned_file_query_metadata(f.client, FileId(file_id), DeviceId(device_id))
                .unwrap();
        assert_ne!(live, before);
        assert_eq!(live.create_options, options);
        assert_eq!(live.alignment_requirement, 0xfff);
        assert_eq!(
            f.io.file_reference_count(f.file),
            0,
            "adoption does not recapture a handle"
        );
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        f.policy.set_signaled(f.file.raw(), true).unwrap();
        assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
        retire_inline(&mut f, &mut owners, identity);
        f.finish_policy_cleanup();
    }
}

struct SetRecordingDriver {
    lifecycle: MockDriverBackend,
    requests: Rc<RefCell<Vec<(IrpProjection, Vec<u8>)>>>,
    pending: bool,
    completion: Option<DriverCompletion>,
}

impl DriverDispatchBackend for SetRecordingDriver {
    fn dispatch_irp(
        &mut self,
        context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.requests
            .borrow_mut()
            .push((irp.clone(), context.system_buffer.to_vec()));
        if irp.major == nt_io_abi::major::IRP_MJ_SET_INFORMATION {
            if self.pending {
                self.completion = Some(DriverCompletion {
                    irp_id: irp.irp_id,
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                });
                return Ok(DispatchOutcome::Pending);
            }
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            });
        }
        self.lifecycle.dispatch_irp(context, irp)
    }

    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        if let Some(completion) = self.completion.as_mut().filter(|item| item.irp_id == irp) {
            completion.status = NtStatus::CANCELLED;
            return Ok(());
        }
        self.lifecycle.cancel_irp(irp)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.completion
            .take()
            .or_else(|| self.lifecycle.poll_completion())
    }
}

type SetRequests = Rc<RefCell<Vec<(IrpProjection, Vec<u8>)>>>;

fn source_set_fixture(pending: bool, access: AccessMask) -> (Fixture, SetRequests) {
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut f = Fixture::with_backend(
        FileIoMode::Asynchronous,
        access,
        Box::new(SetRecordingDriver {
            lifecycle: MockDriverBackend::new(),
            requests: requests.clone(),
            pending,
            completion: None,
        }),
    );
    let driver = f.io.device(f.device).unwrap().driver_id;
    let dispatch =
        f.io.driver(driver)
            .unwrap()
            .dispatch
            .get(nt_io_abi::major::IRP_MJ_CREATE);
    f.io.driver_mut(driver)
        .unwrap()
        .dispatch
        .set(nt_io_abi::major::IRP_MJ_SET_INFORMATION, dispatch);
    (f, requests)
}

#[test]
fn owned_file_set_source_survives_close_during_input_copy_before_admission() {
    let access = AccessMask::from_bits_retain(0x02);
    let (mut f, requests) = source_set_fixture(false, access);
    f.io.file_mut(f.file).unwrap().driver_context = Some(0x1234);
    let capture = f
        .captures
        .capture(&mut f.io, f.file, f.device, access.bits())
        .unwrap();
    let mut input = [0; 8];
    let mut copy_input = |destination: &mut [u8]| {
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
        assert!(f.io.file(capture.file_id()).is_some());
        assert_eq!(f.io.file_reference_count(capture.file_id()), 1);
        destination.copy_from_slice(&0x1234_5678u64.to_le_bytes());
    };
    copy_input(&mut input);
    assert_eq!(input, 0x1234_5678u64.to_le_bytes());
    assert_eq!(capture.file_id(), f.file);
    assert_eq!(capture.device_id(), f.device);
    assert_eq!(capture.fs_context(), 0x1234);
    assert_eq!(capture.granted_access(), access.bits());
    // This proves pre-admission body ownership, not a change to SET Busy ordering.
    assert!(f.policy.acquire_file_io(f.file.raw(), 20).is_err());
    assert!(!requests
        .borrow()
        .iter()
        .any(|(irp, _)| irp.major == nt_io_abi::major::IRP_MJ_SET_INFORMATION));
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    f.retire(capture);
    f.io.pump();
    f.finish_policy_cleanup();
}

#[test]
fn owned_file_set_source_hands_canonical_reference_to_inline_or_pending_irp() {
    use nt_io_abi::major;
    for pending in [false, true] {
        let access = AccessMask::from_bits_retain(0x02);
        let (mut f, requests) = source_set_fixture(pending, access);
        f.io.file_mut(f.file).unwrap().driver_context = Some(0x1234);
        let capture = f
            .captures
            .capture(&mut f.io, f.file, f.device, access.bits())
            .unwrap();
        let mut input = 0x1234_5678_9abc_def0u64.to_le_bytes();
        // A mutable driver context must not replace the source route or grant snapshot.
        // Canonical CREATE access remains valid for the manager's independent dispatch check.
        f.io.file_mut(f.file).unwrap().driver_context = Some(0x9876);
        assert!(set_information_access_granted(
            AccessMask::from_bits_retain(capture.granted_access()),
            20
        ));
        assert_eq!(capture.fs_context(), 0x1234);
        f.policy.retain_file(f.file.raw()).unwrap();
        let parameters = IoParameters::SetInformation(SetInformationParameters {
            info_class: 20,
            length: input.len() as u32,
            target_file: None,
            control: SetInformationControl::None,
        });
        let result =
            f.io.build_and_dispatch_external_to_device_with_stack_flags(
                f.client,
                capture.device_id(),
                Some(capture.file_id()),
                0,
                20,
                major::IRP_MJ_SET_INFORMATION,
                parameters.clone(),
                StackFlags::empty(),
                8,
                0,
                &mut input,
            )
            .unwrap();
        let (request, payload) = requests.borrow().last().unwrap().clone();
        assert_eq!(request.parameters, parameters);
        assert_eq!(request.file_id, Some(capture.file_id()));
        assert_eq!(request.device_id, capture.device_id());
        assert_eq!(request.requestor_tid, 20);
        assert_eq!(payload, input);
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
        if pending {
            let ExternalDispatchResult::Pending { irp_id } = result else {
                panic!("pending fixture must retain a canonical SET IRP");
            };
            assert_eq!(irp_id, request.irp_id);
            assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
            f.io.pump();
            assert!(f.io.completed_irp(irp_id).is_some());
            assert!(
                f.io.file(f.file).is_some(),
                "consumer ACK still owns the source File"
            );
            f.io.acknowledge_completed_irp(irp_id).unwrap();
        } else {
            assert_eq!(
                result,
                ExternalDispatchResult::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None
                }
            );
            assert!(f.io.pending_irps().is_empty());
            assert!(f.io.file(f.file).is_none());
        }
        f.policy.release_file(f.file.raw()).unwrap();
        f.finish_policy_cleanup();
        assert_eq!(
            requests
                .borrow()
                .iter()
                .map(|(irp, _)| irp.major)
                .collect::<Vec<_>>(),
            alloc::vec![
                major::IRP_MJ_CREATE,
                major::IRP_MJ_SET_INFORMATION,
                major::IRP_MJ_CLEANUP,
                major::IRP_MJ_CLOSE,
            ]
        );
    }
}

#[test]
fn owned_file_set_source_access_denial_cannot_be_upgraded_after_capture() {
    let original = AccessMask::from_bits_retain(0x80);
    let (mut f, requests) = source_set_fixture(false, original);
    let capture = f
        .captures
        .capture(&mut f.io, f.file, f.device, original.bits())
        .unwrap();
    // Host-model mutation cannot upgrade the grant already captured from the handle.
    f.io.file_mut(f.file).unwrap().desired_access = AccessMask::GENERIC_ALL;
    f.io.file_mut(f.file).unwrap().create_options = CreateOptions::WRITE_THROUGH;
    let current = f.io.file(f.file).unwrap().desired_access;
    assert!(set_information_access_granted(current, 20));
    assert_eq!(capture.granted_access(), original.bits());
    assert!(!set_information_access_granted(
        AccessMask::from_bits_retain(capture.granted_access()),
        20
    ));
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert!(f.io.pending_irps().is_empty());
    assert_eq!(
        requests.borrow().len(),
        1,
        "denied source must not dispatch an IRP"
    );
    f.retire(capture);
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
    f.finish_policy_cleanup();
}

#[test]
fn ordinary_set_payload_copy_fault_keeps_admitted_busy_and_cleared_event() {
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        let access = AccessMask::from_bits_retain(0x02);
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
        let status = capture_set_information_payload(8, |bytes| {
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
            assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
            assert_eq!(f.io.file_reference_count(f.file), 1);
            bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
            Err(NtStatus::ACCESS_VIOLATION)
        })
        .unwrap_err();
        assert_eq!(status, NtStatus::ACCESS_VIOLATION);
        publish_immediate_set_iosb(status.raw() as u32, 0, |_, _| {
            panic!("capture fault must not publish IOSB")
        });
        assert!(
            !SetInformationCompletionPolicy::immediate_driver().signals_file(status.raw() as u32)
        );
        assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
        assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        assert!(f.io.pending_irps().is_empty());
        retire_inline(&mut f, &mut owners, identity);
        assert!(f.io.file(f.file).is_some());
        f.retire(capture);
        f.io.pump();
        f.finish_policy_cleanup();
    }
}

#[test]
fn ordinary_set_immediate_completion_publishes_while_owned_then_signals_by_status() {
    for mode in [
        FileIoMode::Asynchronous,
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        // These driver outcomes are fixture inputs, not evidence of native driver execution.
        for (status, publishes) in [(0u32, true), (0x8000_0005, true), (0xc000_000d, false)] {
            let access = AccessMask::from_bits_retain(0x02);
            let mut f = Fixture::with_access(mode, false, access);
            let capture = f
                .captures
                .capture(&mut f.io, f.file, f.device, access.bits())
                .unwrap();
            let mut inline = if mode.is_synchronous() {
                assert_eq!(
                    f.policy.acquire_file_io(f.file.raw(), 20),
                    Ok(FileIoAcquireResult::Acquired)
                );
                Some(reserve_inline(&f, 20))
            } else {
                f.policy.retain_file(f.file.raw()).unwrap();
                None
            };
            let completion = SetInformationCompletionPolicy::immediate_driver();
            assert!(completion.resets_file_signal());
            f.policy.set_signaled(f.file.raw(), true).unwrap();
            f.policy.set_signaled(f.file.raw(), false).unwrap();
            let payload = capture_set_information_payload(8, |bytes| {
                assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
                assert!(
                    f.policy
                        .release_handle(f.file.raw())
                        .unwrap()
                        .cleanup_required
                );
                let cleanup = f.policy.begin_cleanup(f.file.raw()).unwrap();
                if mode.is_synchronous() {
                    assert_eq!(cleanup, FileIoAcquireResult::Contended { alertable: false });
                } else {
                    assert_eq!(cleanup, FileIoAcquireResult::Bypassed);
                    f.start_canonical_cleanup();
                }
                bytes.copy_from_slice(&0x1234u64.to_le_bytes());
                Ok(())
            })
            .unwrap();
            assert_eq!(payload, 0x1234u64.to_le_bytes());
            let mut writes = Vec::new();
            publish_immediate_set_iosb(status, 17, |offset, bytes| {
                assert!(f.io.file(f.file).is_some());
                assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
                if mode.is_synchronous() {
                    assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
                }
                writes.push((offset, bytes.to_vec()));
                Ok(())
            });
            if publishes {
                assert_eq!(
                    writes,
                    alloc::vec![
                        (8, 17u64.to_le_bytes().to_vec()),
                        (0, status.to_le_bytes().to_vec())
                    ]
                );
            } else {
                assert!(writes.is_empty());
            }
            if completion.signals_file(status) {
                f.policy.set_signaled(f.file.raw(), true).unwrap();
            }
            assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(publishes));
            assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
            if let Some((owners, identity)) = inline.as_mut() {
                assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
                retire_inline(&mut f, owners, *identity);
            } else {
                f.policy.release_file(f.file.raw()).unwrap();
            }
            f.retire(capture);
            f.io.pump();
            f.finish_policy_cleanup();
        }
    }
}

#[test]
fn ordinary_set_queued_retry_captures_live_payload_only_after_adoption_and_event_clear() {
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        let access = AccessMask::from_bits_retain(0x02);
        let mut f = Fixture::with_access(mode, false, access);
        assert_eq!(
            f.policy.acquire_file_io(f.file.raw(), 20),
            Ok(FileIoAcquireResult::Acquired)
        );
        let capture = f
            .captures
            .capture(&mut f.io, f.file, f.device, access.bits())
            .unwrap();
        f.policy.set_signaled(f.file.raw(), true).unwrap();
        let mut waiters = SynchronousFileWaitTable::new();
        let reservation = waiters.reserve().unwrap();
        assert_eq!(
            f.policy.acquire_file_io(f.file.raw(), 21),
            Ok(FileIoAcquireResult::Contended {
                alertable: mode == FileIoMode::SynchronousAlertable
            })
        );
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
        waiters.park_reserved(reservation, waiter).unwrap();
        let mut payload = (-1i64).to_le_bytes();
        let mut copies = 0;
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
        payload.copy_from_slice(&0x1234u64.to_le_bytes());
        assert_eq!(copies, 0);
        f.policy.release_io(f.file.raw(), 20).unwrap();
        f.policy.release_file(f.file.raw()).unwrap();
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
        let result = f.policy.adopt_io_grant(f.file.raw(), 21);
        let adopted = waiters
            .record_adoption(&mut adoption, result)
            .unwrap()
            .unwrap()
            .waiter();
        assert_eq!(adopted.route, waiter.route);
        assert_eq!(adopted.granted_access, access.bits());
        assert!(set_information_access_granted(
            AccessMask::from_bits_retain(adopted.granted_access),
            20
        ));
        let (mut owners, identity) = reserve_inline(&f, 21);
        f.policy.set_signaled(f.file.raw(), false).unwrap();
        let copied = capture_set_information_payload(payload.len(), |bytes| {
            copies += 1;
            assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
            assert!(!f.policy.promote_cleanup_if_ready(f.file.raw()).unwrap());
            bytes.copy_from_slice(&payload);
            Ok(())
        })
        .unwrap();
        assert_eq!(copies, 1);
        assert_eq!(copied, 0x1234u64.to_le_bytes());
        validate_set_information_value(20, &copied).unwrap();
        assert_eq!(
            f.io.file_reference_count(f.file),
            0,
            "retry does not recapture the closed handle"
        );
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        // A post-capture pre-dispatch error retires the ordinary owner without an IRP.
        retire_inline(&mut f, &mut owners, identity);
        f.finish_policy_cleanup();
    }
}
