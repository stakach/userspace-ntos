//! Retained native CLEANUP/CLOSE owners. The requestor identity survives handle
//! removal and process rundown; only the live system caller executes the driver.

use super::*;
use nt_io_manager::owned_file_lifecycle::{
    FileLifecycleAckOutcome, FileLifecycleAckResult, FileLifecycleAckReturn,
    FileLifecycleOutcome, FileLifecycleResult, FileLifecycleReturn, PreparedFileLifecycle,
    RetainedFileLifecycle,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

enum Payload {
    Prepared(PreparedFileLifecycle),
    Returned(FileLifecycleReturn),
    Retained(RetainedFileLifecycle),
    AckReturned(FileLifecycleAckReturn),
}

struct Row {
    file_id: FileId,
    caller: NativeHandleCaller,
    requestor: NativeThreadProcessReference,
    payload: Option<Payload>,
    retry_after: u64,
    blocked: Option<nt_status::NtStatus>,
}

static mut ROWS: Vec<Row> = Vec::new();

fn rows() -> &'static mut Vec<Row> {
    // Executive work is serialized. No row borrow spans a hosted invocation.
    unsafe { &mut *core::ptr::addr_of_mut!(ROWS) }
}

fn index(file_id: FileId) -> Option<usize> {
    rows().iter().position(|row| row.file_id == file_id)
}

fn release_requestor(index: usize) {
    unsafe {
        crate::with_provider_process_manager(|pm| rows()[index].requestor.release(pm))
    }
    .expect("retained lifecycle requestor must release its exact Ps pair");
    rows().swap_remove(index);
}

/// Reserve the exact original thread before the last handle or thread can go away.
/// On failure ownership of the held reference returns to the caller.
pub(super) fn reserve(
    file_id: FileId,
    caller: NativeHandleCaller,
    requestor: NativeThreadProcessReference,
) -> Result<(), (nt_status::NtStatus, NativeThreadProcessReference)> {
    if file_id.raw() == 0
        || caller.original_thread() != requestor.thread_lifetime()
        || !requestor.is_held()
    {
        return Err((nt_status::NtStatus::INVALID_PARAMETER, requestor));
    }
    if let Err(status) = unsafe {
        crate::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(caller)?;
            requestor.validate(pm)
        })
    } {
        return Err((nt_status::NtStatus(status as i32), requestor));
    }
    if index(file_id).is_some() {
        return Err((nt_status::NtStatus::OBJECT_NAME_COLLISION, requestor));
    }
    if let Err(_) = rows().try_reserve(1) {
        return Err((nt_status::NtStatus::INSUFFICIENT_RESOURCES, requestor));
    }
    rows().push(Row {
        file_id,
        caller,
        requestor,
        payload: None,
        retry_after: 0,
        blocked: None,
    });
    Ok(())
}

/// Undo a reservation only when the manager release was not queued. After
/// preparation, cancellation would discard a canonical IRP and is forbidden.
pub(super) fn cancel(file_id: FileId) -> bool {
    let Some(index) = index(file_id) else { return false };
    if rows()[index].payload.is_some()
        || io_manager_mut()
            .file(file_id)
            .is_some_and(|file| file.close_deferred)
    {
        return false;
    }
    release_requestor(index);
    true
}

fn retain(file_id: FileId, payload: Payload, status: nt_status::NtStatus) {
    let index = index(file_id).expect("lifecycle File owner missing");
    rows()[index].payload = Some(payload);
    rows()[index].blocked = Some(status);
    rows()[index].retry_after = monotonic_time_100ns().saturating_add(1_000_000);
}

fn route_live(projection: &IrpProjection) -> Option<usize> {
    let (index, _) = instance_by_driver_id(projection.driver_id.raw())?;
    let (physical, _, _) = hosted_driver_device_route_by_device_id(projection.device_id.raw())?;
    (physical == index).then_some(index)
}

fn finish_returned(file_id: FileId, returned: FileLifecycleReturn) -> bool {
    match io_manager_mut().finish_file_lifecycle(returned) {
        Ok(FileLifecycleResult::Returned { .. }) => true,
        Ok(FileLifecycleResult::Outstanding(owner)) => {
            rows()[index(file_id).unwrap()].payload = Some(Payload::Retained(owner));
            true
        }
        Ok(FileLifecycleResult::NotEntered { status, prepared }) => {
            // No driver entry occurred. The manager can retry this exact preparation.
            retain(file_id, Payload::Prepared(prepared), status);
            true
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retain(file_id, Payload::Returned(returned), status);
            false
        }
    }
}

fn dispatch_prepared(
    file_id: FileId,
    prepared: PreparedFileLifecycle,
    executor: NativeHandleCaller,
) -> bool {
    let projection = prepared.projection().clone();
    let Some(route) = route_live(&projection) else {
        // This operation has not entered a driver, so it remains retryable.
        retain(
            file_id,
            Payload::Prepared(prepared),
            nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        );
        return false;
    };
    let executor_live = unsafe {
        crate::with_provider_process_manager(|pm| pm.validate_native_handle_caller(executor))
    };
    if executor_live.is_err() {
        retain(
            file_id,
            Payload::Prepared(prepared),
            nt_status::NtStatus::INVALID_HANDLE,
        );
        return false;
    }
    let row = &rows()[index(file_id).expect("lifecycle File owner missing")];
    let requestor_valid = projection.requestor_tid
        == u64::from(row.requestor.thread_lifetime().thread_id())
        && row.caller.original_thread() == row.requestor.thread_lifetime()
        && unsafe {
            crate::with_provider_process_manager(|pm| row.requestor.validate(pm))
        }
        .is_ok();
    if !requestor_valid {
        retain(
            file_id,
            Payload::Prepared(prepared),
            nt_status::NtStatus::INVALID_HANDLE,
        );
        return false;
    }
    let invocation = match io_manager_mut().begin_prepared_file_lifecycle(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, prepared) = rejection.into_parts();
            retain(file_id, Payload::Prepared(prepared), status);
            return false;
        }
    };
    // The projection retains the original requestor TID. The system caller is
    // execution authority only, and does not reauthenticate an exited thread.
    let result = hosted_file_dispatch::execute(route, Some(executor), &projection, &[], &mut []);
    let outcome = match result {
        HostedIrpTransportResult::NotDispatched { status } => {
            FileLifecycleOutcome::NotEntered { status }
        }
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::PENDING,
            ..
        } => FileLifecycleOutcome::Pending,
        HostedIrpTransportResult::Returned {
            status,
            information,
            ..
        } => FileLifecycleOutcome::Returned { status, information },
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            FileLifecycleOutcome::Indeterminate { transport_status }
        }
    };
    finish_returned(file_id, invocation.returned(outcome))
}

fn ack_outcome(result: HostedIrpTransportResult) -> FileLifecycleAckOutcome {
    match result {
        HostedIrpTransportResult::NotDispatched { status } => {
            FileLifecycleAckOutcome::NotEntered { status }
        }
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::SUCCESS,
            information: 0,
            file_context: 0,
        } => FileLifecycleAckOutcome::Acknowledged,
        HostedIrpTransportResult::Returned {
            status,
            information: 0,
            file_context: 0,
        } if status.is_error() => FileLifecycleAckOutcome::Rejected { status },
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            FileLifecycleAckOutcome::Indeterminate { transport_status }
        }
        HostedIrpTransportResult::Returned { .. } => FileLifecycleAckOutcome::Indeterminate {
            transport_status: nt_status::NtStatus::INVALID_PARAMETER,
        },
    }
}

fn finish_ack(file_id: FileId, returned: FileLifecycleAckReturn) -> bool {
    match io_manager_mut().finish_retained_file_lifecycle_ack(returned) {
        Ok(FileLifecycleAckResult::Acknowledged { .. }) => true,
        Ok(FileLifecycleAckResult::Retained(owner)) => {
            let uncertain = owner.acknowledgement_is_uncertain();
            rows()[index(file_id).unwrap()].payload = Some(Payload::Retained(owner));
            if uncertain {
                rows()[index(file_id).unwrap()].blocked = Some(nt_status::NtStatus::DEVICE_BUSY);
            } else {
                rows()[index(file_id).unwrap()].retry_after =
                    monotonic_time_100ns().saturating_add(1_000_000);
            }
            true
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retain(file_id, Payload::AckReturned(returned), status);
            false
        }
    }
}

fn drive_retained(file_id: FileId, owner: RetainedFileLifecycle) -> bool {
    if owner.acknowledgement_is_uncertain() {
        rows()[index(file_id).unwrap()].payload = Some(Payload::Retained(owner));
        return false;
    }
    let ack = match io_manager_mut().begin_retained_file_lifecycle_ack(owner) {
        Ok(ack) => ack,
        Err(rejection) => {
            let (status, owner) = rejection.into_parts();
            rows()[index(file_id).unwrap()].payload = Some(Payload::Retained(owner));
            if status != nt_status::NtStatus::DELETE_PENDING {
                rows()[index(file_id).unwrap()].blocked = Some(status);
            }
            return false;
        }
    };
    let result = match route_live(ack.projection()) {
        Some(route) => hosted_file_dispatch::control(
            route,
            ack.irp_id(),
            FSD_DISPATCH_ACK_COMPLETION,
            0,
            &mut [],
        ),
        None => HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        },
    };
    finish_ack(file_id, ack.returned(ack_outcome(result)))
}

fn drive_payload(file_id: FileId, executor: NativeHandleCaller) -> bool {
    let index = index(file_id).expect("lifecycle File owner missing");
    if rows()[index].retry_after > monotonic_time_100ns() {
        return false;
    }
    let Some(payload) = rows()[index].payload.take() else { return false };
    rows()[index].blocked = None;
    rows()[index].retry_after = 0;
    match payload {
        Payload::Prepared(prepared) => dispatch_prepared(file_id, prepared, executor),
        Payload::Returned(returned) => finish_returned(file_id, returned),
        Payload::Retained(owner) => drive_retained(file_id, owner),
        Payload::AckReturned(returned) => finish_ack(file_id, returned),
    }
}

/// Drive bounded work without keeping an I/O-manager borrow across driver entry.
/// A pending or uncertain effect remains held by its exact File and generation.
pub(super) fn pump(executor: NativeHandleCaller) -> usize {
    let _durable = crate::allocator::enter_durable();
    let mut progress = 0;
    let mut ids = [FileId(0); 32];
    let count = rows().len().min(ids.len());
    for (slot, row) in ids[..count].iter_mut().zip(rows().iter()) {
        *slot = row.file_id;
    }
    for file_id in ids[..count].iter().copied() {
        progress += usize::from(drive_payload(file_id, executor));
    }
    for _ in 0..32 {
        let prepared = match io_manager_mut().prepare_next_queued_peer_file_lifecycle(|file_id| {
            rows()
                .iter()
                .find(|row| row.file_id == file_id && row.payload.is_none())
                .map(|row| row.requestor.thread_lifetime().thread_id() as u64)
        }) {
            Ok(Some(prepared)) => prepared,
            Ok(None) => break,
            Err(_) => break,
        };
        let file_id = prepared.file_id();
        progress += usize::from(dispatch_prepared(file_id, prepared, executor));
    }
    progress + retire()
}

/// Retire only after the canonical File is gone and every outstanding lifecycle
/// IRP has resolved. The manager's generational FileId prevents ABA reuse.
pub(super) fn retire() -> usize {
    let mut retired = 0;
    let mut cursor = 0;
    while cursor < rows().len() {
        if rows()[cursor].payload.is_none()
            && io_manager_mut().file(rows()[cursor].file_id).is_none()
        {
            release_requestor(cursor);
            retired += 1;
        } else {
            cursor += 1;
        }
    }
    retired
}
