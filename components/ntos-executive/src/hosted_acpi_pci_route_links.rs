// Full-path interrupt-link `_CRS` evaluation and atomic route publication.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciLinkDisposition {
    RetryResources,
    RetryExact(usize),
    EvaluationReady,
    Barrier(nt_status::NtStatus),
}

unsafe fn hosted_acpi_pci_link_query(
    request_index: usize,
) -> Option<&'static nt_pnp::AcpiPciInterruptLinkMethodQuery> {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY)).as_ref()?;
    let HostedAcpiPciRoutePolicy::Links(discovery) = query.policy.as_ref()? else {
        return None;
    };
    discovery.link_queries().get(request_index)
}

fn classify_hosted_acpi_pci_link_result(
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> (
    HostedAcpiPciLinkDisposition,
    Option<Vec<nt_acpi::InterruptResource>>,
) {
    let information = match classify_hosted_acpi_variable_eval_result(
        output_len,
        status,
        information,
        payload,
    ) {
        HostedAcpiVariableEvalDisposition::RetryExact(required) => {
            return (HostedAcpiPciLinkDisposition::RetryExact(required), None);
        }
        HostedAcpiVariableEvalDisposition::Payload(information) => information,
        HostedAcpiVariableEvalDisposition::Barrier(status) => {
            return (HostedAcpiPciLinkDisposition::Barrier(status), None);
        }
    };
    match nt_acpi::parse_interrupt_resource_template(&payload[..information]) {
        Ok(resources) => (
            HostedAcpiPciLinkDisposition::EvaluationReady,
            Some(resources),
        ),
        Err(nt_acpi::PciRoutingError::Allocation) => {
            (HostedAcpiPciLinkDisposition::RetryResources, None)
        }
        Err(_) => (
            HostedAcpiPciLinkDisposition::Barrier(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            None,
        ),
    }
}

unsafe fn apply_hosted_acpi_pci_link_disposition(
    request_index: usize,
    disposition: HostedAcpiPciLinkDisposition,
) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .expect("ACPI PCI route query disappeared while applying link _CRS result");
    if query
        .policy
        .as_ref()
        .is_none_or(|policy| !hosted_acpi_pci_route_policy_current(policy))
    {
        retry_and_clear_hosted_acpi_pci_route_query();
        return;
    }
    query.phase = match disposition {
        HostedAcpiPciLinkDisposition::RetryResources => {
            query.barrier_status = Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            HostedAcpiPciRoutePhase::Barrier
        }
        HostedAcpiPciLinkDisposition::RetryExact(output_len) => {
            HostedAcpiPciRoutePhase::DispatchLink {
                request_index,
                output_len,
            }
        }
        HostedAcpiPciLinkDisposition::EvaluationReady => {
            let Some(resources) = query.pending_resources.take() else {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                query.phase = HostedAcpiPciRoutePhase::Barrier;
                return;
            };
            if query.link_evaluations.len() != request_index {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                HostedAcpiPciRoutePhase::Barrier
            } else {
                query
                    .link_evaluations
                    .push(nt_pnp::AcpiPciInterruptLinkEvaluation {
                        request_index,
                        resources,
                    });
                let request_count = match query.policy.as_ref().unwrap() {
                    HostedAcpiPciRoutePolicy::Links(discovery) => discovery.link_queries().len(),
                    HostedAcpiPciRoutePolicy::Routing(_)
                    | HostedAcpiPciRoutePolicy::Tables(_)
                    | HostedAcpiPciRoutePolicy::Publication(_) => 0,
                };
                if query.link_evaluations.len() == request_count {
                    HostedAcpiPciRoutePhase::PreparePublication
                } else {
                    HostedAcpiPciRoutePhase::DispatchLink {
                        request_index: request_index + 1,
                        output_len: nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN,
                    }
                }
            }
        }
        HostedAcpiPciLinkDisposition::Barrier(status) => {
            query.barrier_status = Some(status);
            HostedAcpiPciRoutePhase::Barrier
        }
    };
}

unsafe fn dispatch_hosted_acpi_pci_link(request_index: usize, output_len: usize) -> bool {
    if !(nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN..=HOSTED_ACPI_ROUTE_MAX_EVAL_BYTES)
        .contains(&output_len)
    {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    let Some(method_query) = hosted_acpi_pci_link_query(request_index) else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let Some(device_id) = hosted_acpi_pci_route_endpoint_device(method_query.endpoint) else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let input = match nt_acpi::eval_method_input_ex(method_query.method_path.as_str()) {
        Ok(input) => input,
        Err(_) => {
            let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap();
            query.phase = HostedAcpiPciRoutePhase::Barrier;
            query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return true;
        }
    };
    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return false;
    }
    output.resize(output_len, 0);
    let result = match io_manager_mut().buffered_device_control_exact_device_payload(
        ClientId(IO_MANAGER_COMPONENT_ID),
        device_id,
        nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX,
        &input,
        &mut output,
    ) {
        Ok(result) => result,
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return false,
        Err(status) => {
            let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap();
            query.phase = HostedAcpiPciRoutePhase::Barrier;
            query.barrier_status = Some(status);
            return true;
        }
    };
    match result {
        ExternalDispatchResult::Completed {
            status,
            information,
            ..
        } => {
            record_hosted_acpi_pci_route_driver_result(status, information);
            let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap();
            query.inline_payload = Some(output);
            query.phase = HostedAcpiPciRoutePhase::DecodeInlineLink {
                request_index,
                output_len,
                status,
                information,
            };
        }
        ExternalDispatchResult::Pending { irp_id } => {
            let identities = io_manager_mut().irp(irp_id).and_then(|irp| {
                let current = irp.current_stack()?;
                matches!(
                    &current.parameters,
                    IoParameters::DeviceControl(parameters)
                        if parameters.ioctl_code == nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX
                            && parameters.input_len as usize
                                == nt_acpi::ACPI_EVAL_INPUT_BUFFER_EX_LEN
                            && parameters.output_len as usize == output_len
                )
                .then_some((irp.origin_driver_id, current.driver_id, current.device_id))
            });
            let (origin_driver_id, completion_driver_id, completion_device_id) =
                identities.unwrap_or((DriverId(0), DriverId(0), nt_io_manager::DeviceId(0)));
            let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap();
            query.irp_id = irp_id;
            query.origin_driver_id = origin_driver_id;
            query.completion_driver_id = completion_driver_id;
            query.completion_device_id = completion_device_id;
            query.phase = HostedAcpiPciRoutePhase::AwaitingLinkCompletion {
                request_index,
                output_len,
            };
        }
    }
    true
}

unsafe fn decode_inline_hosted_acpi_pci_link(
    request_index: usize,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
) -> bool {
    let Some((disposition, resources)) = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .and_then(|query| query.inline_payload.as_deref())
        .map(|payload| {
            classify_hosted_acpi_pci_link_result(output_len, status, information, payload)
        })
    else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    if disposition == HostedAcpiPciLinkDisposition::RetryResources {
        return false;
    }
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    query.inline_payload = None;
    query.pending_resources = resources;
    apply_hosted_acpi_pci_link_disposition(request_index, disposition);
    true
}

unsafe fn advance_hosted_acpi_pci_link_completion(
    request_index: usize,
    output_len: usize,
) -> bool {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .unwrap();
    let Some(completion) = io_manager_mut().completed_irp(query.irp_id) else {
        return false;
    };
    let method_query = hosted_acpi_pci_link_query(request_index);
    let expected_device_id = method_query
        .and_then(|method| hosted_acpi_pci_route_endpoint_device(method.endpoint));
    let request_fingerprint_valid = method_query
        .and_then(|method| nt_acpi::eval_method_input_ex(method.method_path.as_str()).ok())
        .is_some_and(|input| hosted_acpi_route_request_input_is(query.irp_id, &input));
    let request_valid = io_manager_mut().irp(query.irp_id).is_some_and(|irp| {
        irp.current_stack().is_some_and(|stack| {
            stack.driver_id == query.completion_driver_id
                && stack.device_id == query.completion_device_id
                && matches!(
                    &stack.parameters,
                    IoParameters::DeviceControl(parameters)
                        if parameters.ioctl_code == nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX
                            && parameters.input_len as usize
                                == nt_acpi::ACPI_EVAL_INPUT_BUFFER_EX_LEN
                            && parameters.output_len as usize == output_len
                )
        })
    });
    let identity_valid = completion.id == query.irp_id
        && completion.client_id == ClientId(IO_MANAGER_COMPONENT_ID)
        && completion.file_id.is_none()
        && completion.driver_id == query.origin_driver_id
        && Some(completion.device_id) == expected_device_id
        && completion.major == major::IRP_MJ_DEVICE_CONTROL
        && completion.minor == 0
        && completion.completion_driver_id == query.completion_driver_id
        && completion.completion_device_id == query.completion_device_id
        && completion.user_data == 0
        && completion.requestor_tid == 0
        && completion.completion_origin == IrpCompletionOrigin::Driver
        && request_valid
        && request_fingerprint_valid;
    let (status, information) = if identity_valid {
        (completion.status, completion.information)
    } else {
        (nt_status::NtStatus::INVALID_DEVICE_REQUEST, 0)
    };
    record_hosted_acpi_pci_route_driver_result(completion.status, completion.information);
    (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap()
        .phase = HostedAcpiPciRoutePhase::AwaitingLinkCopy {
        request_index,
        output_len,
        status,
        information,
    };
    true
}

unsafe fn copy_hosted_acpi_pci_link_completion(
    request_index: usize,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
) -> bool {
    let irp_id = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .unwrap()
        .irp_id;
    let mut payload = Vec::new();
    if payload.try_reserve_exact(output_len).is_err() {
        return false;
    }
    payload.resize(output_len, 0);
    let (disposition, resources) = match io_manager_mut()
        .copy_completed_buffered_device_control_payload(irp_id, 0, &mut payload)
    {
        Ok(copied) if copied == output_len => classify_hosted_acpi_pci_link_result(
            output_len,
            status,
            information,
            &payload,
        ),
        Ok(_) => (
            HostedAcpiPciLinkDisposition::Barrier(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            None,
        ),
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES)
        | Err(nt_status::NtStatus::DEVICE_NOT_READY) => return false,
        Err(copy_status) => (HostedAcpiPciLinkDisposition::Barrier(copy_status), None),
    };
    if disposition == HostedAcpiPciLinkDisposition::RetryResources {
        return false;
    }
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    query.pending_resources = resources;
    query.phase = HostedAcpiPciRoutePhase::AwaitingLinkAck {
        request_index,
        disposition,
    };
    true
}

unsafe fn acknowledge_hosted_acpi_pci_link(
    request_index: usize,
    disposition: HostedAcpiPciLinkDisposition,
) -> bool {
    let irp_id = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .unwrap()
        .irp_id;
    match io_manager_mut().acknowledge_completed_irp_strict(irp_id) {
        Ok(_) => {
            apply_hosted_acpi_pci_link_disposition(request_index, disposition);
            true
        }
        Err(status) => {
            retain_hosted_acpi_pci_route_indeterminate_irp(irp_id, status);
            true
        }
    }
}

unsafe fn prepare_hosted_acpi_pci_route_publication() -> bool {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    let Some(HostedAcpiPciRoutePolicy::Links(discovery)) = query.policy.take() else {
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let evaluations = core::mem::take(&mut query.link_evaluations);
    match crate::hosted_pci_topology::prepare_hosted_pci_interrupt_route_publication(
        discovery,
        evaluations,
    ) {
        Ok(publication) => {
            query.policy = Some(HostedAcpiPciRoutePolicy::Publication(publication));
            query.phase = HostedAcpiPciRoutePhase::CommitPublication;
            true
        }
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => {
            *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
            crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
            false
        }
        Err(status) => {
            query.phase = HostedAcpiPciRoutePhase::Barrier;
            query.barrier_status = Some(status);
            true
        }
    }
}

unsafe fn commit_hosted_acpi_pci_route_publication() -> bool {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    let Some(HostedAcpiPciRoutePolicy::Publication(publication)) = query.policy.take() else {
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    match crate::hosted_pci_topology::commit_hosted_pci_interrupt_routes(publication) {
        Ok(_) => {
            *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
            true
        }
        Err(status) => {
            query.phase = HostedAcpiPciRoutePhase::Barrier;
            query.barrier_status = Some(status);
            true
        }
    }
}
