// Exact filtered `_CRS` namespace transport for the serialized PCI route reconciler.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciCrsFilterDisposition {
    RetryResources,
    RetryExact(usize),
    SourceReady,
    Barrier(nt_status::NtStatus),
}

unsafe fn hosted_acpi_pci_crs_filter_endpoint(
    endpoint_index: usize,
) -> Option<nt_pnp::AcpiPciProviderEndpoint> {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY)).as_ref()?;
    let HostedAcpiPciRoutePolicy::Tables(tables) = query.policy.as_ref()? else {
        return None;
    };
    tables.link_candidate_endpoints().get(endpoint_index).copied()
}

fn classify_hosted_acpi_pci_crs_filter_result(
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> (
    HostedAcpiPciCrsFilterDisposition,
    Option<nt_acpi::AcpiNamespaceMatches>,
) {
    if status.raw() as u32 == STATUS_BUFFER_OVERFLOW {
        let required = (information == 0)
            .then(|| {
                nt_acpi::namespace_children_overflow_retry_len(
                    payload,
                    output_len,
                    HOSTED_ACPI_NAMESPACE_MAX_BYTES,
                )
                .ok()
            })
            .flatten();
        return (
            required
                .map_or(
                    HostedAcpiPciCrsFilterDisposition::Barrier(
                        nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                    ),
                    HostedAcpiPciCrsFilterDisposition::RetryExact,
                ),
            None,
        );
    }
    if status.raw() != STATUS_SUCCESS {
        return (HostedAcpiPciCrsFilterDisposition::Barrier(status), None);
    }
    let Some(payload) = hosted_acpi_namespace_success_payload(output_len, information, payload)
    else {
        return (
            HostedAcpiPciCrsFilterDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ),
            None,
        );
    };
    match nt_acpi::parse_namespace_matches(payload, HOSTED_ACPI_NAMESPACE_MAX_CHILDREN) {
        Ok(matches) => (
            HostedAcpiPciCrsFilterDisposition::SourceReady,
            Some(matches),
        ),
        Err(nt_acpi::AcpiNamespaceError::Allocation) => {
            (HostedAcpiPciCrsFilterDisposition::RetryResources, None)
        }
        Err(_) => (
            HostedAcpiPciCrsFilterDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ),
            None,
        ),
    }
}

unsafe fn apply_hosted_acpi_pci_crs_filter_disposition(
    endpoint_index: usize,
    disposition: HostedAcpiPciCrsFilterDisposition,
) {
    let endpoint = hosted_acpi_pci_crs_filter_endpoint(endpoint_index);
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .expect("ACPI PCI route query disappeared while applying filtered _CRS result");
    if query
        .policy
        .as_ref()
        .is_none_or(|policy| !hosted_acpi_pci_route_policy_current(policy))
    {
        retry_and_clear_hosted_acpi_pci_route_query();
        return;
    }
    query.phase = match disposition {
        HostedAcpiPciCrsFilterDisposition::RetryResources => {
            query.barrier_status = Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            HostedAcpiPciRoutePhase::Barrier
        }
        HostedAcpiPciCrsFilterDisposition::RetryExact(output_len) => {
            HostedAcpiPciRoutePhase::DispatchCrsFilter {
                endpoint_index,
                output_len,
            }
        }
        HostedAcpiPciCrsFilterDisposition::SourceReady => {
            let Some(endpoint) = endpoint else {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                query.phase = HostedAcpiPciRoutePhase::Barrier;
                return;
            };
            let Some(methods) = query.pending_matches.take() else {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                query.phase = HostedAcpiPciRoutePhase::Barrier;
                return;
            };
            if query.filtered_sources.len() != endpoint_index {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                HostedAcpiPciRoutePhase::Barrier
            } else {
                query
                    .filtered_sources
                    .push(nt_pnp::AcpiPciCrsMethodSource { endpoint, methods });
                let endpoint_count = match query.policy.as_ref().unwrap() {
                    HostedAcpiPciRoutePolicy::Tables(tables) => {
                        tables.link_candidate_endpoints().len()
                    }
                    HostedAcpiPciRoutePolicy::Routing(_)
                    | HostedAcpiPciRoutePolicy::Links(_)
                    | HostedAcpiPciRoutePolicy::Publication(_) => 0,
                };
                if query.filtered_sources.len() == endpoint_count {
                    HostedAcpiPciRoutePhase::PrepareLinkDiscovery
                } else {
                    HostedAcpiPciRoutePhase::DispatchCrsFilter {
                        endpoint_index: endpoint_index + 1,
                        output_len: HOSTED_ACPI_NAMESPACE_HEADER_LEN,
                    }
                }
            }
        }
        HostedAcpiPciCrsFilterDisposition::Barrier(status) => {
            query.barrier_status = Some(status);
            HostedAcpiPciRoutePhase::Barrier
        }
    };
}

unsafe fn dispatch_hosted_acpi_pci_crs_filter(
    endpoint_index: usize,
    output_len: usize,
) -> bool {
    if !(HOSTED_ACPI_NAMESPACE_HEADER_LEN..=HOSTED_ACPI_NAMESPACE_MAX_BYTES)
        .contains(&output_len)
    {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    let Some(endpoint) = hosted_acpi_pci_crs_filter_endpoint(endpoint_index) else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let Some(device_id) = hosted_acpi_pci_route_endpoint_device(endpoint) else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let input = nt_acpi::multilevel_namespace_filter_input(*b"_CRS")
        .expect("fixed filtered _CRS input was invalid");
    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return false;
    }
    output.resize(output_len, 0);
    let result = match io_manager_mut().buffered_device_control_device_payload(
        ClientId(IO_MANAGER_COMPONENT_ID),
        device_id,
        nt_acpi::IOCTL_ACPI_ENUM_CHILDREN,
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
            let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap();
            query.inline_payload = Some(output);
            query.phase = HostedAcpiPciRoutePhase::DecodeInlineCrsFilter {
                endpoint_index,
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
                        if parameters.ioctl_code == nt_acpi::IOCTL_ACPI_ENUM_CHILDREN
                            && parameters.input_len as usize
                                == nt_acpi::ACPI_ENUM_CHILDREN_FILTER_INPUT_LEN
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
            query.phase = HostedAcpiPciRoutePhase::AwaitingCrsFilterCompletion {
                endpoint_index,
                output_len,
            };
        }
    }
    true
}

unsafe fn decode_inline_hosted_acpi_pci_crs_filter(
    endpoint_index: usize,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
) -> bool {
    let Some((disposition, matches)) = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .and_then(|query| query.inline_payload.as_deref())
        .map(|payload| {
            classify_hosted_acpi_pci_crs_filter_result(
                output_len,
                status,
                information,
                payload,
            )
        })
    else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    if disposition == HostedAcpiPciCrsFilterDisposition::RetryResources {
        return false;
    }
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    query.inline_payload = None;
    query.pending_matches = matches;
    apply_hosted_acpi_pci_crs_filter_disposition(endpoint_index, disposition);
    true
}

unsafe fn advance_hosted_acpi_pci_crs_filter_completion(
    endpoint_index: usize,
    output_len: usize,
) -> bool {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .unwrap();
    let Some(completion) = io_manager_mut().completed_irp(query.irp_id) else {
        return false;
    };
    let endpoint = hosted_acpi_pci_crs_filter_endpoint(endpoint_index);
    let expected_device_id = endpoint.and_then(|endpoint| {
        hosted_acpi_pci_route_endpoint_device(endpoint)
    });
    let request_fingerprint_valid = nt_acpi::multilevel_namespace_filter_input(*b"_CRS")
        .ok()
        .is_some_and(|input| hosted_acpi_route_request_input_is(query.irp_id, &input));
    let request_valid = io_manager_mut().irp(query.irp_id).is_some_and(|irp| {
        irp.current_stack().is_some_and(|stack| {
            stack.driver_id == query.completion_driver_id
                && stack.device_id == query.completion_device_id
                && matches!(
                    &stack.parameters,
                    IoParameters::DeviceControl(parameters)
                        if parameters.ioctl_code == nt_acpi::IOCTL_ACPI_ENUM_CHILDREN
                            && parameters.input_len as usize
                                == nt_acpi::ACPI_ENUM_CHILDREN_FILTER_INPUT_LEN
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
    (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap()
        .phase = HostedAcpiPciRoutePhase::AwaitingCrsFilterCopy {
        endpoint_index,
        output_len,
        status,
        information,
    };
    true
}

unsafe fn copy_hosted_acpi_pci_crs_filter_completion(
    endpoint_index: usize,
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
    let (disposition, matches) = match io_manager_mut()
        .copy_completed_buffered_device_control_payload(irp_id, 0, &mut payload)
    {
        Ok(copied) if copied == output_len => classify_hosted_acpi_pci_crs_filter_result(
            output_len,
            status,
            information,
            &payload,
        ),
        Ok(_) => (
            HostedAcpiPciCrsFilterDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ),
            None,
        ),
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES)
        | Err(nt_status::NtStatus::DEVICE_NOT_READY) => return false,
        Err(copy_status) => (
            HostedAcpiPciCrsFilterDisposition::Barrier(copy_status),
            None,
        ),
    };
    if disposition == HostedAcpiPciCrsFilterDisposition::RetryResources {
        return false;
    }
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    query.pending_matches = matches;
    query.phase = HostedAcpiPciRoutePhase::AwaitingCrsFilterAck {
        endpoint_index,
        disposition,
    };
    true
}

unsafe fn acknowledge_hosted_acpi_pci_crs_filter(
    endpoint_index: usize,
    disposition: HostedAcpiPciCrsFilterDisposition,
) -> bool {
    let irp_id = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .unwrap()
        .irp_id;
    match io_manager_mut().acknowledge_completed_irp_strict(irp_id) {
        Ok(_) => {
            apply_hosted_acpi_pci_crs_filter_disposition(endpoint_index, disposition);
            true
        }
        Err(status) => {
            retain_hosted_acpi_pci_route_indeterminate_irp(irp_id, status);
            true
        }
    }
}

unsafe fn prepare_hosted_acpi_pci_interrupt_link_discovery() -> bool {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    let Some(HostedAcpiPciRoutePolicy::Tables(tables)) = query.policy.take() else {
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let filtered_sources = core::mem::take(&mut query.filtered_sources);
    match crate::hosted_pci_topology::prepare_hosted_pci_interrupt_link_discovery(
        tables,
        filtered_sources,
    ) {
        Ok(discovery) => {
            let request_count = discovery.link_queries().len();
            if query
                .link_evaluations
                .try_reserve_exact(request_count)
                .is_err()
            {
                *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
                crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
                return false;
            }
            query.policy = Some(HostedAcpiPciRoutePolicy::Links(discovery));
            query.phase = if request_count == 0 {
                HostedAcpiPciRoutePhase::PreparePublication
            } else {
                HostedAcpiPciRoutePhase::DispatchLink {
                    request_index: 0,
                    output_len: nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN,
                }
            };
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
