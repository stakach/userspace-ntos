//! Stateless File IRP execution and owned dispatch/ACK adapters.
//!
//! Owned callers release manager borrows before invocation. The remaining borrowed backend
//! callers fail-stop on uncertainty until their lifecycle and delivery owners are detached.

use super::*;
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpAcknowledgement, ExternalFileIrpCompletionInvocation,
    ExternalFileIrpCompletionReturn, ExternalFileIrpInvocation, ExternalFileIrpOutcome,
    ExternalFileIrpReturn,
};

pub(super) fn invoke(mut invocation: ExternalFileIrpInvocation) -> ExternalFileIrpReturn {
    let projection = invocation.projection().clone();
    let route = invocation.route();
    let Some((instance_index, _)) = instance_by_driver_id(route.driver_id().raw()) else {
        return invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        });
    };
    if route.driver_id() != projection.driver_id || route.device_id() != projection.device_id {
        return invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        });
    }
    let (input, output) = invocation.buffers_mut().split();
    let result = execute(instance_index, &projection, input, output);
    let outcome = match result {
        HostedIrpTransportResult::NotDispatched { status } => {
            ExternalFileIrpOutcome::NotEntered { status }
        }
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::PENDING,
            ..
        } => ExternalFileIrpOutcome::Pending,
        HostedIrpTransportResult::Returned {
            status,
            information,
            file_context,
        } => ExternalFileIrpOutcome::Returned {
            status,
            information,
            file_context: major::is_create_major(projection.major).then_some(file_context),
        },
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            ExternalFileIrpOutcome::Indeterminate { transport_status }
        }
    };
    invocation.returned(outcome)
}

pub(super) fn acknowledge(
    invocation: ExternalFileIrpCompletionInvocation,
) -> ExternalFileIrpCompletionReturn {
    let Some((instance_index, _)) = instance_by_driver_id(invocation.route().driver_id().raw())
    else {
        return invocation.acknowledged(ExternalFileIrpAcknowledgement::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        });
    };
    let outcome = acknowledgement_result(control(
        instance_index,
        invocation.irp_id(),
        FSD_DISPATCH_ACK_COMPLETION,
        0,
        &mut [],
    ));
    invocation.acknowledged(outcome)
}

fn acknowledgement_result(result: HostedIrpTransportResult) -> ExternalFileIrpAcknowledgement {
    match result {
        HostedIrpTransportResult::NotDispatched { status } => {
            ExternalFileIrpAcknowledgement::NotEntered { status }
        }
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::SUCCESS,
            information: 0,
            file_context: 0,
        } => ExternalFileIrpAcknowledgement::Acknowledged,
        HostedIrpTransportResult::Returned {
            status,
            information: 0,
            file_context: 0,
        } if status.is_error() => ExternalFileIrpAcknowledgement::Rejected { status },
        HostedIrpTransportResult::Returned { .. } => {
            ExternalFileIrpAcknowledgement::Indeterminate {
                transport_status: nt_status::NtStatus::INVALID_PARAMETER,
            }
        }
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            ExternalFileIrpAcknowledgement::Indeterminate { transport_status }
        }
    }
}

pub(super) fn borrowed_acknowledgement_result(
    result: HostedIrpTransportResult,
    irp_id: IrpId,
) -> Result<(), nt_status::NtStatus> {
    match acknowledgement_result(result) {
        ExternalFileIrpAcknowledgement::Acknowledged => Ok(()),
        ExternalFileIrpAcknowledgement::NotEntered { status }
        | ExternalFileIrpAcknowledgement::Rejected { status } => Err(status),
        ExternalFileIrpAcknowledgement::Indeterminate { .. } => {
            panic!(
                "indeterminate borrowed File IRP ACK {:?}: {:?}",
                irp_id, result
            )
        }
    }
}

pub(super) fn borrowed_control_result(
    result: HostedIrpTransportResult,
    irp_id: IrpId,
) -> Result<u64, nt_status::NtStatus> {
    match result {
        HostedIrpTransportResult::NotDispatched { status } => Err(status),
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::SUCCESS,
            information,
            ..
        } => Ok(information),
        HostedIrpTransportResult::Returned { status, .. } if status.is_error() => Err(status),
        HostedIrpTransportResult::Returned { .. }
        | HostedIrpTransportResult::Indeterminate { .. } => {
            // A possibly accepted ACK or cancel cannot be blindly retried by the old pump.
            panic!(
                "indeterminate borrowed File IRP control {:?}: {:?}",
                irp_id, result
            )
        }
    }
}

pub(super) fn control(
    instance_index: usize,
    irp_id: IrpId,
    operation: u64,
    offset: u64,
    output: &mut [u8],
) -> HostedIrpTransportResult {
    if !matches!(
        operation,
        FSD_DISPATCH_ACK_COMPLETION | FSD_DISPATCH_COPY_COMPLETION | FSD_DISPATCH_CANCEL_IRP
    ) || irp_id.raw() == 0
    {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        };
    }
    let storage_instance = hosted_completion_storage_instance(instance_index);
    unsafe {
        dispatch_irp_for_instance_exact(
            storage_instance,
            operation,
            0,
            0,
            irp_id.raw(),
            0,
            offset,
            0,
            0,
            None,
            &[],
            output,
        )
    }
    .unwrap_or(HostedIrpTransportResult::NotDispatched {
        status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
    })
}

pub(super) fn execute(
    instance_index: usize,
    projection: &IrpProjection,
    input: &[u8],
    output: &mut [u8],
) -> HostedIrpTransportResult {
    let request =
        match hosted_irp_dispatch_request(instance_index, projection, input.len(), output.len()) {
            Ok(request) => request,
            Err(status) => return HostedIrpTransportResult::NotDispatched { status },
        };
    let Some((route_instance, route_inst, device_object)) =
        hosted_driver_device_route_by_device_id(projection.device_id.raw())
            .filter(|(index, _, _)| *index == instance_index)
    else {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        };
    };
    if let Some(binding) = hosted_device_binding_by_device_id(projection.device_id.raw())
        .filter(|binding| binding.instance == route_instance)
    {
        if let Some(result) = unsafe {
            dispatch_video_irp_for_binding_exact(
                route_instance,
                route_inst,
                binding,
                projection.major as u64,
                projection.minor as u64,
                projection_fsctl(projection),
                projection.user_data,
                input,
                output,
            )
        } {
            return result;
        }
    }
    unsafe {
        dispatch_irp_for_instance_exact(
            route_instance,
            projection.major as u64,
            projection.minor as u64,
            device_object,
            projection.irp_id.raw(),
            projection.file_id.map(FileId::raw).unwrap_or(0),
            projection_fsctl(projection),
            projection.user_data,
            projection.requestor_tid,
            Some(request),
            input,
            output,
        )
    }
    .unwrap_or(HostedIrpTransportResult::NotDispatched {
        status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
    })
}
