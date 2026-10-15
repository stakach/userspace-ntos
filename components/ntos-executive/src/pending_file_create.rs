//! Exact retained CREATE output stages, separate from provider completion and handle ownership.

use crate::{driver_launch, ExecNtHandler, PENDING_FILE_IO};
use nt_address_space::copy::MemoryCopyFailure;
use nt_io_manager::{
    PendingCreateOutputAction as Action, PendingCreateOutputObservation as Observation,
    PendingFileIo, PendingFileIoIdentity, PendingFileIoOperation,
};

pub(crate) unsafe fn deliver(
    handler: &mut ExecNtHandler,
    identity: PendingFileIoIdentity,
) -> Result<PendingFileIo, ()> {
    loop {
        let pending = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .get_exact(identity)
            .expect("CREATE output lost its exact owner");
        let PendingFileIoOperation::Create(create) = pending.operation else {
            panic!("CREATE output changed operation kind");
        };
        let action = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .create_output_action_exact(identity, pending.irp_id)
            .expect("CREATE output has no committed result");
        let observation = match action {
            Action::Complete => return Ok(pending),
            Action::Uncertain => return Err(()),
            Action::CommitHandle => {
                let reservation = ExecNtHandler::pending_create_reservation(create);
                match handler.publish_bound_file_handle(reservation) {
                    Ok(handle) => {
                        assert_eq!(handle, create.handle_value);
                        // Record the consumed reservation before any later effect or output.
                        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                            .observe_create_output_exact(
                                identity,
                                pending.irp_id,
                                action,
                                Observation::Succeeded,
                            )
                            .expect("committed CREATE handle lost its delivery owner");
                        if create.lifecycle_reserved {
                            assert!(driver_launch::cancel_hosted_file_lifecycle_reservation(
                                pending
                                    .route
                                    .hosted_file_id()
                                    .expect("CREATE lost its File route"),
                            ));
                        }
                        continue;
                    }
                    // This local operation validates before mutation. Failure denotes lost
                    // authority, not permission to replay or cancel an unrelated reservation.
                    Err(status) => Observation::Uncertain(status),
                }
            }
            Action::Handle | Action::Information | Action::Status => {
                let (address, bytes, length) = match action {
                    Action::Handle => (create.handle_va, create.handle_value.to_le_bytes(), 8),
                    Action::Information => {
                        let Some(address) = pending.iosb_va.checked_add(8) else {
                            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                                .observe_create_output_exact(
                                    identity,
                                    pending.irp_id,
                                    action,
                                    Observation::UserFault(
                                        nt_address_space::STATUS_ACCESS_VIOLATION,
                                    ),
                                )
                                .expect("CREATE overflow lost its output owner");
                            continue;
                        };
                        (address, create.information.to_le_bytes(), 8)
                    }
                    Action::Status => {
                        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                        (pending.iosb_va, u64::from(create.status).to_le_bytes(), 4)
                    }
                    _ => unreachable!(),
                };
                match handler.process_memory_write_checked(
                    pending.pi as usize,
                    address,
                    &bytes[..length],
                ) {
                    Ok(()) => Observation::Succeeded,
                    Err(MemoryCopyFailure::UserFault(status)) => Observation::UserFault(status),
                    // Retry can follow accepted page chunks or post-copy alias cleanup failure;
                    // it does not prove no stores. Preserve this exact prefix without replay.
                    Err(MemoryCopyFailure::Retry(status)) => Observation::Uncertain(status),
                }
            }
        };
        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
            .observe_create_output_exact(identity, pending.irp_id, action, observation)
            .expect("CREATE output settlement lost its exact owner");
    }
}
