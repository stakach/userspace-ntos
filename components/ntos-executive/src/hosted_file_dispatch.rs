//! Stateless File IRP execution and owned dispatch/ACK adapters.
//!
//! Owned callers release manager borrows before invocation. The remaining borrowed backend
//! callers fail-stop on uncertainty until their lifecycle and delivery owners are detached.

use super::*;
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpAckInvocation, ExternalFileIrpAcknowledgement, ExternalFileIrpCancelInvocation,
    ExternalFileIrpCancelOutcome, ExternalFileIrpCancelReturn, ExternalFileIrpCompletionReturn,
    ExternalFileIrpCopyInvocation, ExternalFileIrpCopyOutcome, ExternalFileIrpCopyReturn,
    ExternalFileIrpInvocation, ExternalFileIrpOutcome, ExternalFileIrpOutputCapture,
    ExternalFileIrpPumpKey,
    ExternalFileIrpReturn,
};

/// Root's completion-storage selector copies the retained Type3InputBuffer before ACK.
pub(super) const FSD_DISPATCH_COPY_MUTABLE_INPUT: u64 = super::FSD_DISPATCH_COPY_MUTABLE_INPUT;

#[must_use = "retain either the manager return or the original invocation and native continuation"]
pub(super) enum InvokeResult {
    Returned(ExternalFileIrpReturn),
    ChildWorkYield {
        invocation: ExternalFileIrpInvocation,
        key: ExternalFileIrpPumpKey,
        continuation: FileDispatchContinuation,
    },
    /// A malformed native epoch cannot be used as authority; both owners still survive.
    UnkeyedChildWorkYield {
        invocation: ExternalFileIrpInvocation,
        continuation: FileDispatchContinuation,
    },
}

#[must_use = "resume the exact native dispatch before finishing this File invocation"]
pub(super) struct FileDispatchContinuation {
    native: FileIrpPumpContinuation,
    instance_index: usize,
}

impl FileDispatchContinuation {
    pub(super) fn epoch(&self) -> u64 { self.native.epoch() }

    pub(super) fn child_work_ready(&self) -> bool { self.native.child_work_ready() }

    pub(super) fn retry_without_new_child(&self) -> bool {
        self.native.retry_without_new_child()
    }

    pub(super) fn record_child_step(
        &mut self,
        step: crate::service_sec_image::NestedChildStep,
    ) -> Result<(), crate::service_sec_image::NestedChildStep> {
        self.native.record_child_step(step)
    }

    /// The caller has already run or retained one exact outer-loop child step. Reborrow the
    /// output from the move-only invocation only for the receive half; no stack slice survives.
    pub(super) unsafe fn resume_after_child(
        self,
        mut invocation: ExternalFileIrpInvocation,
    ) -> Result<InvokeResult, (ExternalFileIrpInvocation, Self)> {
        let Self { native, instance_index } = self;
        let progress = {
            let (_, output) = invocation.buffers_mut().split();
            native.resume_after_child(output)
        };
        match progress {
            Ok(FileIrpResumeProgress::Completed(result)) => {
                let projection = invocation.projection().clone();
                Ok(InvokeResult::Returned(finish_invoke_result(
                    invocation, projection, instance_index,
                    ExternalFileIrpOutputCapture::MethodNeitherInput, result, true,
                )))
            }
            Ok(FileIrpResumeProgress::ChildWorkYield(native)) => {
                let continuation = Self { native, instance_index };
                match ExternalFileIrpPumpKey::new(&invocation, continuation.epoch()) {
                    Some(key) => Ok(InvokeResult::ChildWorkYield {
                        invocation, key, continuation,
                    }),
                    None => Ok(InvokeResult::UnkeyedChildWorkYield {
                        invocation, continuation,
                    }),
                }
            }
            Err(native) => Err((invocation, Self { native, instance_index })),
        }
    }
}

enum FileExecuteProgress {
    Returned(HostedIrpTransportResult),
    ChildWorkYield(FileDispatchContinuation),
}

pub(super) fn invoke(
    mut invocation: ExternalFileIrpInvocation,
    caller: nt_process::native_handle::NativeHandleCaller,
    capture: ExternalFileIrpOutputCapture,
) -> ExternalFileIrpReturn {
    let projection = invocation.projection().clone();
    let route = invocation.route();
    let Some((instance_index, _)) = instance_by_driver_id(route.driver_id().raw()) else {
        print_str(b"[hosted-file] detached invoke missing driver instance\n");
        return invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        });
    };
    if route.driver_id() != projection.driver_id || route.device_id() != projection.device_id {
        return invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        });
    }
    let trace_connect = capture == ExternalFileIrpOutputCapture::MethodNeitherInput;
    if trace_connect {
        trace_port_connect_execute(0, projection.irp_id, projection.device_id);
    }
    let result = {
        let (input, output) = invocation.buffers_mut().split();
        if let IoParameters::Scsi(parameters) = &projection.parameters {
            match nt_io_manager::scsi_srb_wire::encode_scsi_dispatch_input(
                parameters, projection.irp_id, input,
            ) {
                Ok(packet) => execute_with_capture(instance_index, Some(caller), &projection, &packet, output, capture),
                Err(error) => HostedIrpTransportResult::NotDispatched {
                    status: match error {
                        nt_io_manager::scsi_srb_wire::ScsiWireError::NoCapacity =>
                            nt_status::NtStatus::INSUFFICIENT_RESOURCES,
                        _ => nt_status::NtStatus::INVALID_PARAMETER,
                    },
                },
            }
        } else {
            execute_with_capture(instance_index, Some(caller), &projection, input, output, capture)
        }
    };
    finish_invoke_result(invocation, projection, instance_index, capture, result, trace_connect)
}

fn finish_invoke_result(
    mut invocation: ExternalFileIrpInvocation,
    projection: IrpProjection,
    instance_index: usize,
    capture: ExternalFileIrpOutputCapture,
    result: HostedIrpTransportResult,
    trace_connect: bool,
) -> ExternalFileIrpReturn {
    if trace_connect {
        trace_port_connect_execute(1, projection.irp_id, projection.device_id);
    }
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
        } => {
            if capture == ExternalFileIrpOutputCapture::MethodNeitherInput {
                let expected = invocation.input_mut().len() as u64;
                trace_mutable_control_probe(10, invocation.irp_id(), instance_index, expected, None);
                let copied = control(
                    instance_index,
                    invocation.irp_id(),
                    FSD_DISPATCH_COPY_MUTABLE_INPUT,
                    0,
                    invocation.input_mut(),
                );
                trace_mutable_control_probe(11, invocation.irp_id(), instance_index, expected, Some(&copied));
                if !matches!(copied, HostedIrpTransportResult::Returned {
                    status: nt_status::NtStatus::SUCCESS,
                    information,
                    file_context: 0,
                } if information == expected)
                {
                    let transport_status = match copied {
                        HostedIrpTransportResult::NotDispatched { status }
                        | HostedIrpTransportResult::Indeterminate {
                            transport_status: status,
                        }
                        | HostedIrpTransportResult::Returned { status, .. } => status,
                    };
                    return invocation
                        .returned(ExternalFileIrpOutcome::Indeterminate { transport_status });
                }
                // Synchronous completion already released the IRP graph. The sidecar survives
                // until this exact copy is acknowledged through the same terminal selector.
                trace_mutable_control_probe(12, invocation.irp_id(), instance_index, 0, None);
                let ack = control(
                    instance_index,
                    invocation.irp_id(),
                    FSD_DISPATCH_ACK_COMPLETION,
                    0,
                    &mut [],
                );
                trace_mutable_control_probe(13, invocation.irp_id(), instance_index, 0, Some(&ack));
                if !matches!(
                    ack,
                    HostedIrpTransportResult::Returned {
                        status: nt_status::NtStatus::SUCCESS,
                        information: 0,
                        file_context: 0,
                    }
                ) {
                    let transport_status = match ack {
                        HostedIrpTransportResult::NotDispatched { status }
                        | HostedIrpTransportResult::Indeterminate {
                            transport_status: status,
                        }
                        | HostedIrpTransportResult::Returned { status, .. } => status,
                    };
                    return invocation
                        .returned(ExternalFileIrpOutcome::Indeterminate { transport_status });
                }
            }
            ExternalFileIrpOutcome::Returned {
            status,
            information,
            file_context: major::is_create_major(projection.major).then_some(file_context),
            }
        }
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            ExternalFileIrpOutcome::Indeterminate { transport_status }
        }
    };
    if trace_connect {
        trace_port_connect_execute(2, projection.irp_id, projection.device_id);
    }
    let returned = invocation.returned(outcome);
    if trace_connect {
        trace_port_connect_execute(3, projection.irp_id, projection.device_id);
    }
    returned
}

/// Bounded observation of an exact METHOD_NEITHER terminal's copy and ACK handoff.
fn trace_mutable_control_probe(
    stage: u64, irp: IrpId, instance_index: usize, expected: u64,
    result: Option<&HostedIrpTransportResult>,
) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 64 { return; }
    let (kind, status, information) = match result {
        None => (0, 0, 0),
        Some(HostedIrpTransportResult::NotDispatched { status }) =>
            (1, status.raw() as u32 as u64, 0),
        Some(HostedIrpTransportResult::Returned { status, information, .. }) =>
            (2, status.raw() as u32 as u64, *information),
        Some(HostedIrpTransportResult::Indeterminate { transport_status }) =>
            (3, transport_status.raw() as u32 as u64, 0),
    };
    print_str(b"[mutable-control-probe] stage/irp/instance/expected/kind/status/info=");
    print_u64(stage); print_str(b"/");
    print_hex_u64(irp.raw()); print_str(b"/");
    print_u64(instance_index as u64); print_str(b"/");
    print_u64(expected); print_str(b"/");
    print_u64(kind); print_str(b"/");
    print_hex_u64(status); print_str(b"/");
    print_u64(information); print_str(b"\n");
}

/// A port-local CONNECT may yield while its provider waits for nested root work. The original
/// invocation is returned intact; only a genuine native return may reach `finish_invoke_result`.
pub(super) fn invoke_suspend_aware(
    mut invocation: ExternalFileIrpInvocation,
    caller: nt_process::native_handle::NativeHandleCaller,
    capture: ExternalFileIrpOutputCapture,
) -> InvokeResult {
    let projection = invocation.projection().clone();
    let route = invocation.route();
    let Some((instance_index, _)) = instance_by_driver_id(route.driver_id().raw()) else {
        return InvokeResult::Returned(invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        }));
    };
    if route.driver_id() != projection.driver_id || route.device_id() != projection.device_id
        || capture != ExternalFileIrpOutputCapture::MethodNeitherInput
        || projection.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
    {
        return InvokeResult::Returned(invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        }));
    }
    trace_port_connect_execute(0, projection.irp_id, projection.device_id);
    let progress = {
        let (input, output) = invocation.buffers_mut().split();
        execute_port_connect_suspend_aware(
            instance_index, caller, &projection, input, output,
        )
    };
    match progress {
        FileExecuteProgress::Returned(result) => InvokeResult::Returned(
            finish_invoke_result(invocation, projection, instance_index, capture, result, true),
        ),
        FileExecuteProgress::ChildWorkYield(continuation) => {
            let Some(key) = ExternalFileIrpPumpKey::new(&invocation, continuation.epoch()) else {
                return InvokeResult::UnkeyedChildWorkYield { invocation, continuation };
            };
            InvokeResult::ChildWorkYield { invocation, key, continuation }
        }
    }
}

fn trace_port_connect_execute(stage: u64, irp: nt_io_manager::IrpId, device: nt_io_manager::DeviceId) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags)); }
    print_str(b"[port-connect-execute] stage/irp/device=");
    print_u64(stage);
    print_str(b"/");
    print_hex_u64(irp.raw());
    print_str(b"/");
    print_hex_u64(device.raw());
    print_str(b" rsp=");
    print_hex_u64(rsp);
    print_str(b"\n");
}

pub(super) fn acknowledge(
    invocation: ExternalFileIrpAckInvocation,
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

pub(super) fn cancel(invocation: ExternalFileIrpCancelInvocation) -> ExternalFileIrpCancelReturn {
    let Some((instance_index, _)) = instance_by_driver_id(invocation.route().driver_id().raw())
    else {
        return invocation.returned(ExternalFileIrpCancelOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        });
    };
    let result = control(
        instance_index,
        invocation.irp_id(),
        FSD_DISPATCH_CANCEL_IRP,
        0,
        &mut [],
    );
    let outcome = match result {
        HostedIrpTransportResult::NotDispatched { status } => {
            ExternalFileIrpCancelOutcome::NotEntered { status }
        }
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::SUCCESS,
            information: 1,
            file_context: 0,
        } => ExternalFileIrpCancelOutcome::Accepted,
        HostedIrpTransportResult::Returned {
            status,
            information: 0,
            file_context: 0,
        } if status.is_error() => ExternalFileIrpCancelOutcome::Rejected { status },
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            ExternalFileIrpCancelOutcome::Indeterminate { transport_status }
        }
        HostedIrpTransportResult::Returned { .. } => ExternalFileIrpCancelOutcome::Indeterminate {
            transport_status: nt_status::NtStatus::INVALID_PARAMETER,
        },
    };
    invocation.returned(outcome)
}

pub(super) fn copy(mut invocation: ExternalFileIrpCopyInvocation) -> ExternalFileIrpCopyReturn {
    let Some((instance_index, _)) = instance_by_driver_id(invocation.route().driver_id().raw())
    else {
        return invocation.returned(ExternalFileIrpCopyOutcome::NotEntered {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        });
    };
    let irp_id = invocation.irp_id();
    let offset = invocation.offset() as u64;
    let requested_len = invocation.requested_len();
    let result = control(
        instance_index,
        irp_id,
        if invocation.capture_kind() == ExternalFileIrpOutputCapture::MethodNeitherInput {
            FSD_DISPATCH_COPY_MUTABLE_INPUT
        } else {
            FSD_DISPATCH_COPY_COMPLETION
        },
        offset,
        invocation.staging_mut(),
    );
    let outcome = match result {
        HostedIrpTransportResult::NotDispatched { status } => {
            ExternalFileIrpCopyOutcome::NotEntered { status }
        }
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::SUCCESS,
            information,
            file_context: 0,
        } if information <= requested_len as u64 => ExternalFileIrpCopyOutcome::Copied {
            bytes: information as usize,
        },
        HostedIrpTransportResult::Returned {
            status,
            information: 0,
            file_context: 0,
        } if status.is_error() => ExternalFileIrpCopyOutcome::Rejected { status },
        HostedIrpTransportResult::Indeterminate { transport_status } => {
            ExternalFileIrpCopyOutcome::Indeterminate { transport_status }
        }
        HostedIrpTransportResult::Returned { .. } => ExternalFileIrpCopyOutcome::Indeterminate {
            transport_status: nt_status::NtStatus::INVALID_PARAMETER,
        },
    };
    invocation.returned(outcome)
}

pub(super) fn acknowledgement_result(
    result: HostedIrpTransportResult,
) -> ExternalFileIrpAcknowledgement {
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
        FSD_DISPATCH_ACK_COMPLETION
            | FSD_DISPATCH_COPY_COMPLETION
            | FSD_DISPATCH_COPY_MUTABLE_INPUT
            | FSD_DISPATCH_CANCEL_IRP
    ) || irp_id.raw() == 0
    {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        };
    }
    let storage_instance = hosted_completion_storage_instance(instance_index);
    let mutable_probe = matches!(operation,
        FSD_DISPATCH_COPY_MUTABLE_INPUT | FSD_DISPATCH_ACK_COMPLETION);
    let probe_stage = if operation == FSD_DISPATCH_COPY_MUTABLE_INPUT { 20 } else { 22 };
    if mutable_probe {
        trace_mutable_control_probe(
            probe_stage, irp_id, instance_index, storage_instance as u64, None,
        );
    }
    let result = unsafe {
        let caller = crate::initial_system_driver_caller();
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
            Some(caller),
        )
    }
    .unwrap_or(HostedIrpTransportResult::NotDispatched {
        status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
    });
    if mutable_probe {
        trace_mutable_control_probe(
            probe_stage + 1, irp_id, instance_index, storage_instance as u64, Some(&result),
        );
    }
    if operation == FSD_DISPATCH_ACK_COMPLETION
        && matches!(result, HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus::SUCCESS,
            information: 0,
            file_context: 0,
        })
    {
        if let Some(source) = instance(instance_index) {
            if let Some(identity) = hosted_source_create_security::lookup_retained_irp(source, irp_id) {
                hosted_create_subject_registration::finish(
                    source,
                    identity,
                    hosted_create_subject_registration::SourceCreateCompletion::AcknowledgedTerminal,
                );
            }
        }
    }
    result
}

/// Issue a retained PnP ACK to its captured physical completion store. The dependent driver
/// route is deliberately not resolved again: it may now name a different provider publication.
pub(super) fn control_exact_storage(
    storage_instance: usize,
    storage_domain: HostedDomainIdentity,
    irp_id: IrpId,
    operation: u64,
    offset: u64,
    output: &mut [u8],
) -> HostedIrpTransportResult {
    if operation != FSD_DISPATCH_ACK_COMPLETION
        || irp_id.raw() == 0
        || instance(storage_instance).is_none_or(|inst| {
            !inst.ready || instance_domain_identity(inst) != Some(storage_domain)
        })
        || io_manager_mut().hosted_domain_identity(storage_domain.domain_id)
            != Some(storage_domain)
        || unsafe { hosted_provider_dispatch_route_for_instance(storage_instance) }.is_some()
    {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
        };
    }
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
            Some(crate::initial_system_driver_caller()),
        )
    }
    .unwrap_or(HostedIrpTransportResult::NotDispatched {
        status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
    })
}

pub(super) fn execute(
    instance_index: usize,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    projection: &IrpProjection,
    input: &[u8],
    output: &mut [u8],
) -> HostedIrpTransportResult {
    execute_with_capture(instance_index, caller, projection, input, output,
        ExternalFileIrpOutputCapture::Information)
}

fn prepare_dispatch_request(
    instance_index: usize,
    projection: &IrpProjection,
    input_len: usize,
    output_len: usize,
    capture: ExternalFileIrpOutputCapture,
) -> Result<(IrpDispatchRequest, usize, DriverInstance, u64), nt_status::NtStatus> {
    let mut request = hosted_irp_dispatch_request(
        instance_index, projection, input_len, output_len,
    )?;
    if capture == ExternalFileIrpOutputCapture::BufferedDeviceControlCapacity {
        request._reserved0 = nt_io_abi::IRP_DISPATCH_BUFFERED_OUTPUT_CAPACITY;
        if !nt_io_abi::valid_buffered_output_capacity_dispatch(&request) {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
    }
    let Some((route_instance, route_inst, device_object)) =
        hosted_driver_device_route_by_device_id_for_irp(
            projection.device_id.raw(), Some(projection.irp_id),
        ).filter(|(index, _, _)| *index == instance_index)
    else {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    Ok((request, route_instance, route_inst, device_object))
}

fn execute_port_connect_suspend_aware(
    instance_index: usize,
    caller: nt_process::native_handle::NativeHandleCaller,
    projection: &IrpProjection,
    input: &[u8],
    output: &mut [u8],
) -> FileExecuteProgress {
    let (request, route_instance, _, device_object) = match prepare_dispatch_request(
        instance_index, projection, input.len(), output.len(),
        ExternalFileIrpOutputCapture::MethodNeitherInput,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return FileExecuteProgress::Returned(
            HostedIrpTransportResult::NotDispatched { status },
        ),
    };
    let progress = unsafe {
        dispatch_irp_for_instance_exact_suspend_aware(
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
            Some(caller),
        )
    };
    match progress {
        HostedIrpDispatchProgress::Returned(result) => FileExecuteProgress::Returned(
            result.unwrap_or(HostedIrpTransportResult::NotDispatched {
                status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
            }),
        ),
        HostedIrpDispatchProgress::ChildWorkYield(native) => {
            FileExecuteProgress::ChildWorkYield(FileDispatchContinuation {
                native, instance_index,
            })
        }
    }
}

fn execute_with_capture(
    instance_index: usize,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    projection: &IrpProjection,
    input: &[u8],
    output: &mut [u8],
    capture: ExternalFileIrpOutputCapture,
) -> HostedIrpTransportResult {
    let (request, route_instance, route_inst, device_object) =
        match prepare_dispatch_request(
            instance_index, projection, input.len(), output.len(), capture,
        ) {
            Ok(prepared) => prepared,
            Err(status) => return HostedIrpTransportResult::NotDispatched { status },
        };
    let scsi_data = match &projection.parameters {
        IoParameters::Scsi(parameters) if parameters.data_length != 0 => {
            if let Err(status) = unsafe {
                hosted_scsi_dma_reservation::reserve_for_dispatch(
                    &request, parameters.route.provider_pdo,
                    u64::from(parameters.data_length),
                )
            } {
                return HostedIrpTransportResult::NotDispatched { status };
            }
            true
        }
        _ => false,
    };
    let result = unsafe {
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
            caller,
        )
    };
    if scsi_data {
        match result {
            Some(HostedIrpTransportResult::NotDispatched { .. }) => {
                if unsafe { hosted_scsi_dma_reservation::release_after_ack(projection.irp_id.raw()) }
                    .is_err()
                {
                    unsafe { hosted_scsi_dma_reservation::quarantine(projection.irp_id.raw()) };
                }
            }
            None | Some(HostedIrpTransportResult::Indeterminate { .. }) =>
                unsafe { hosted_scsi_dma_reservation::quarantine(projection.irp_id.raw()) },
            Some(HostedIrpTransportResult::Returned { .. }) => {}
        }
    }
    if result.is_none() {
        print_str(b"[hosted-file] exact dispatch unavailable instance/device/irp=");
        print_u64(instance_index as u64);
        print_str(b"/");
        print_hex_u64(projection.device_id.raw());
        print_str(b"/");
        print_hex_u64(projection.irp_id.raw());
        print_str(b"\n");
    }
    let result = result.unwrap_or(HostedIrpTransportResult::NotDispatched {
        status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
    });
    if projection.major == major::IRP_MJ_CREATE
        && matches!(
            result,
            HostedIrpTransportResult::Returned {
                status: nt_status::NtStatus::SUCCESS,
                ..
            }
        )
        && unsafe { hosted_instance_video_port_initialized(route_inst) }
    {
        if let Err(transport_status) =
            unsafe { commit_video_registry_parameters_for_instance(route_inst) }
        {
            // Native CREATE already published its File. A later registry failure cannot undo it.
            register_instance_ready(route_instance, false);
            return HostedIrpTransportResult::Indeterminate { transport_status };
        }
    }
    result
}
