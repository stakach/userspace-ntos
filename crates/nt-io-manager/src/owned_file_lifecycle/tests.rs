use super::*;
use alloc::boxed::Box;
use nt_types::{AccessMask, HandleValue, NtPath};
extern crate std;
use std::format;

use crate::file::{CreateOptions, ShareAccess};
use crate::{
    DeviceCharacteristics, DeviceFlags, DeviceType, DriverCompletion, MockDriverBackend,
    MockObjectPort,
};

fn path(value: &str) -> NtPath {
    NtPath::parse_str(value).unwrap()
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        Self { io, client }
    }

    fn driver(&mut self, suffix: &str) -> crate::DeviceId {
        let driver = self
            .io
            .create_driver(
                &path(&format!("\\Driver\\{suffix}")),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        self.io
            .create_device(
                driver,
                Some(&path(&format!("\\Device\\{suffix}"))),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap()
    }

    fn file(&mut self, suffix: &str) -> (HandleValue, FileId) {
        let handle = self
            .io
            .open(
                self.client,
                &path(&format!("\\Device\\{suffix}")),
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let file_id = self
            .io
            .reference_open_file(self.client, handle, AccessMask::empty())
            .unwrap()
            .0;
        let file = self.io.file_mut(file_id).unwrap();
        assert!(file.transition(FileState::CleanupPending));
        file.close_deferred = true;
        (handle, file_id)
    }

    fn begin(&mut self, file_id: FileId) -> FileLifecycleInvocation {
        let prepared = self
            .io
            .prepare_file_lifecycle_owned(self.client, file_id)
            .unwrap();
        self.io.begin_prepared_file_lifecycle(prepared).unwrap()
    }
}

#[test]
fn two_same_driver_files_can_be_in_flight_before_either_returns() {
    let mut f = Fixture::new();
    f.driver("Shared");
    let (_, first) = f.file("Shared");
    let (_, second) = f.file("Shared");
    let first_call = f.begin(first);
    let second_call = f.begin(second);
    assert_ne!(first_call.irp_id(), second_call.irp_id());
    assert_eq!(first_call.target(), second_call.target());
    assert_eq!(
        f.io.irp(first_call.irp_id()).unwrap().state,
        IrpState::Dispatched
    );
    assert_eq!(
        f.io.irp(second_call.irp_id()).unwrap().state,
        IrpState::Dispatched
    );
    assert_eq!(
        f.io.prepare_file_lifecycle_owned(f.client, first)
            .unwrap_err(),
        NtStatus::DELETE_PENDING
    );

    let second_result =
        f.io.finish_file_lifecycle(second_call.returned(FileLifecycleOutcome::Returned {
            status: NtStatus::SUCCESS,
            information: 0,
        }))
        .unwrap();
    assert!(matches!(
        second_result,
        FileLifecycleResult::Returned {
            status: NtStatus::SUCCESS,
            ..
        }
    ));
    assert_eq!(f.io.file(second).unwrap().state, FileState::CleanupComplete);
    assert_eq!(
        f.io.irp(first_call.irp_id()).unwrap().state,
        IrpState::Dispatched
    );
    let first_result =
        f.io.finish_file_lifecycle(first_call.returned(FileLifecycleOutcome::Returned {
            status: NtStatus::SUCCESS,
            information: 0,
        }))
        .unwrap();
    assert!(matches!(
        first_result,
        FileLifecycleResult::Returned {
            status: NtStatus::SUCCESS,
            ..
        }
    ));
    assert_eq!(f.io.file(first).unwrap().state, FileState::CleanupComplete);
}

#[test]
fn nested_files_on_distinct_drivers_keep_distinct_routes() {
    let mut f = Fixture::new();
    f.driver("First");
    f.driver("Second");
    let (_, first) = f.file("First");
    let (_, second) = f.file("Second");
    let first_call = f.begin(first);
    let second_call = f.begin(second);
    assert_ne!(
        first_call.projection().driver_id,
        second_call.projection().driver_id
    );
    assert_ne!(first_call.target(), second_call.target());
    let first_id = first_call.irp_id();
    let second_id = second_call.irp_id();
    f.io.finish_file_lifecycle(first_call.returned(FileLifecycleOutcome::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    }))
    .unwrap();
    assert!(f.io.irp(first_id).is_none());
    assert!(f.io.irp(second_id).is_some());
    f.io.finish_file_lifecycle(second_call.returned(FileLifecycleOutcome::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    }))
    .unwrap();
}

#[test]
fn stale_file_and_irp_generations_do_not_authorize_a_new_effect() {
    let mut f = Fixture::new();
    f.driver("Generation");
    let (_, file_id) = f.file("Generation");
    let prepared =
        f.io.prepare_file_lifecycle_owned(f.client, file_id)
            .unwrap();
    let stale_irp = prepared.irp_id();
    f.io.irp_mut(stale_irp).unwrap().detached_file_owner = false;
    f.io.free_irp(stale_irp).unwrap();
    let (_, replacement_file) = f.file("Generation");
    let replacement =
        f.io.prepare_file_lifecycle_owned(f.client, replacement_file)
            .unwrap();
    assert_eq!(replacement.irp_id().slot(), stale_irp.slot());
    assert_ne!(replacement.irp_id(), stale_irp);
    let rejected = f.io.begin_prepared_file_lifecycle(prepared).unwrap_err();
    assert_eq!(rejected.status(), NtStatus::INVALID_HANDLE);
    f.io.discard_prepared_file_lifecycle(replacement).unwrap();

    // An unknown generation never resolves to the new File body.
    let stale_file = FileId::new(file_id.generation().wrapping_add(1), file_id.slot());
    assert_eq!(
        f.io.prepare_file_lifecycle_owned(f.client, stale_file)
            .unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
}

#[test]
fn proven_nonentry_can_retry_but_indeterminate_entry_cannot() {
    let mut f = Fixture::new();
    f.driver("Ambiguous");
    let (_, first) = f.file("Ambiguous");
    let (_, second) = f.file("Ambiguous");
    let call = f.begin(first);
    let first_irp = call.irp_id();
    let result =
        f.io.finish_file_lifecycle(call.returned(FileLifecycleOutcome::NotEntered {
            status: NtStatus::DEVICE_NOT_CONNECTED,
        }))
        .unwrap();
    let prepared = match result {
        FileLifecycleResult::NotEntered {
            status: NtStatus::DEVICE_NOT_CONNECTED,
            prepared,
        } => prepared,
        other => panic!("expected proven nonentry, got {other:?}"),
    };
    let retried = f.io.begin_prepared_file_lifecycle(prepared).unwrap();
    assert_eq!(retried.irp_id(), first_irp);
    let outstanding =
        f.io.finish_file_lifecycle(retried.returned(FileLifecycleOutcome::Indeterminate {
            transport_status: NtStatus::DEVICE_NOT_CONNECTED,
        }))
        .unwrap();
    let retained = match outstanding {
        FileLifecycleResult::Outstanding(retained) => retained,
        other => panic!("expected retained uncertainty, got {other:?}"),
    };
    assert!(retained.is_indeterminate());
    assert_eq!(f.io.irp(first_irp).unwrap().state, IrpState::Indeterminate);
    assert!(f.io.file(first).unwrap().cleanup_dispatched);
    assert_eq!(
        f.io.prepare_file_lifecycle_owned(f.client, first)
            .unwrap_err(),
        NtStatus::DELETE_PENDING
    );

    // The uncertain first File does not block another independent lifecycle owner.
    let second_call = f.begin(second);
    assert_ne!(second_call.irp_id(), retained.irp_id());
}

#[test]
fn owner_from_another_manager_is_rejected_without_mutation() {
    let mut first = Fixture::new();
    first.driver("Local");
    let (_, file_id) = first.file("Local");
    let prepared = first
        .io
        .prepare_file_lifecycle_owned(first.client, file_id)
        .unwrap();
    let mut second = Fixture::new();
    second.driver("Local");
    let (_, other_file) = second.file("Local");
    let rejection = second
        .io
        .begin_prepared_file_lifecycle(prepared)
        .unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert!(!second.io.file(other_file).unwrap().cleanup_dispatched);
    let (_, prepared) = rejection.into_parts();
    first.io.discard_prepared_file_lifecycle(prepared).unwrap();
}

#[test]
fn cleanup_then_close_uses_one_ordered_invocation_per_major() {
    let mut f = Fixture::new();
    f.driver("Order");
    let (_, file_id) = f.file("Order");
    let cleanup = f.begin(file_id);
    assert_eq!(cleanup.projection().major, major::IRP_MJ_CLEANUP);
    f.io.finish_file_lifecycle(cleanup.returned(FileLifecycleOutcome::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    }))
    .unwrap();
    let file = f.io.file_mut(file_id).unwrap();
    assert!(file.transition(FileState::ClosePending));
    let close = f.begin(file_id);
    assert_eq!(close.projection().major, major::IRP_MJ_CLOSE);
    f.io.finish_file_lifecycle(close.returned(FileLifecycleOutcome::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    }))
    .unwrap();
    assert!(f.io.file(file_id).unwrap().cleanup_dispatched);
    assert!(f.io.file(file_id).unwrap().close_dispatched);
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn pending_lifecycle_retires_only_after_exact_completion_and_owned_ack() {
    let mut f = Fixture::new();
    f.driver("Pending");
    let (_, file_id) = f.file("Pending");
    let call = f.begin(file_id);
    let driver = call.projection().driver_id;
    let irp_id = call.irp_id();
    let retained = match f
        .io
        .finish_file_lifecycle(call.returned(FileLifecycleOutcome::Pending))
        .unwrap()
    {
        FileLifecycleResult::Outstanding(owner) => owner,
        other => panic!("expected pending owner, got {other:?}"),
    };
    let rejection =
        f.io.begin_retained_file_lifecycle_ack(retained)
            .unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    let (_, retained) = rejection.into_parts();
    assert!(f.io.publish_driver_completion(
        driver,
        DriverCompletion {
            irp_id,
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: None,
        }
    ));
    let ack = f.io.begin_retained_file_lifecycle_ack(retained).unwrap();
    assert_eq!(ack.completion().id, irp_id);
    let outcome = f
        .io
        .finish_retained_file_lifecycle_ack(ack.returned(FileLifecycleAckOutcome::Acknowledged))
        .unwrap();
    assert!(matches!(
        outcome,
        FileLifecycleAckResult::Acknowledged { .. }
    ));
    assert!(f.io.irp(irp_id).is_none());
    assert_eq!(
        f.io.file(file_id).unwrap().state,
        FileState::CleanupComplete
    );
}

#[test]
fn completion_before_outer_return_keeps_the_exact_ack_owner() {
    let mut f = Fixture::new();
    f.driver("EarlyCompletion");
    let (_, file_id) = f.file("EarlyCompletion");
    let call = f.begin(file_id);
    let driver = call.projection().driver_id;
    let irp_id = call.irp_id();
    assert!(f.io.publish_driver_completion(
        driver,
        DriverCompletion {
            irp_id,
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: None,
        }
    ));
    let retained = match f
        .io
        .finish_file_lifecycle(call.returned(FileLifecycleOutcome::Returned {
            status: NtStatus::SUCCESS,
            information: 0,
        }))
        .unwrap()
    {
        FileLifecycleResult::Outstanding(owner) => owner,
        other => panic!("expected early completion owner, got {other:?}"),
    };
    assert_eq!(f.io.irp(irp_id).unwrap().state, IrpState::Completed);
    let ack = f.io.begin_retained_file_lifecycle_ack(retained).unwrap();
    assert_eq!(ack.completion().id, irp_id);
    f.io.finish_retained_file_lifecycle_ack(ack.returned(FileLifecycleAckOutcome::Acknowledged))
        .unwrap();
    assert!(f.io.irp(irp_id).is_none());
}

#[test]
fn indeterminate_dispatch_resolves_only_by_genuine_cancelled_completion() {
    let mut f = Fixture::new();
    f.driver("Uncertain");
    let (_, file_id) = f.file("Uncertain");
    let call = f.begin(file_id);
    let driver = call.projection().driver_id;
    let irp_id = call.irp_id();
    let retained = match f
        .io
        .finish_file_lifecycle(call.returned(FileLifecycleOutcome::Indeterminate {
            transport_status: NtStatus::DEVICE_NOT_CONNECTED,
        }))
        .unwrap()
    {
        FileLifecycleResult::Outstanding(owner) => owner,
        other => panic!("expected uncertain owner, got {other:?}"),
    };
    assert!(retained.is_indeterminate());
    assert!(f.io.publish_driver_completion(
        driver,
        DriverCompletion {
            irp_id,
            status: NtStatus::CANCELLED,
            information: 0,
            file_context: None,
        }
    ));
    let ack = f.io.begin_retained_file_lifecycle_ack(retained).unwrap();
    assert_eq!(ack.completion().status, NtStatus::CANCELLED);
    let retained = match f
        .io
        .finish_retained_file_lifecycle_ack(ack.returned(FileLifecycleAckOutcome::Indeterminate {
            transport_status: NtStatus::DEVICE_NOT_CONNECTED,
        }))
        .unwrap()
    {
        FileLifecycleAckResult::Retained(owner) => owner,
        other => panic!("expected uncertain ACK owner, got {other:?}"),
    };
    assert!(retained.acknowledgement_is_uncertain());
    let rejection =
        f.io.begin_retained_file_lifecycle_ack(retained)
            .unwrap_err();
    assert_eq!(rejection.status(), NtStatus::DELETE_PENDING);
    assert!(f.io.irp(irp_id).is_some());
    assert_eq!(f.io.file(file_id).unwrap().state, FileState::CleanupPending);
}
