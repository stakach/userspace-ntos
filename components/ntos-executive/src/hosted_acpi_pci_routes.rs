// Serialized ACPI PCI interrupt-route reconciliation transport.

const HOSTED_ACPI_ROUTE_MAX_EVAL_BYTES: usize = 12 + 4 + u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciRoutePhase {
    DispatchPrt { query_index: usize, output_len: usize },
    AwaitingPrtCompletion { query_index: usize, output_len: usize },
    AwaitingPrtCopy {
        query_index: usize,
        output_len: usize,
        status: nt_status::NtStatus,
        information: u64,
    },
    AwaitingPrtAck {
        query_index: usize,
        disposition: HostedAcpiPciPrtDisposition,
    },
    AcceptTables,
    TablesAccepted,
    Barrier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciPrtDisposition {
    RetryResources,
    RetryExact(usize),
    TableReady,
    Barrier(nt_status::NtStatus),
}

enum HostedAcpiPciRoutePolicy {
    Routing(nt_pnp::PreparedAcpiPciRoutingDiscovery),
    Tables(nt_pnp::PreparedAcpiPciRoutingTables),
}

struct HostedAcpiPciRouteQuery {
    policy: Option<HostedAcpiPciRoutePolicy>,
    phase: HostedAcpiPciRoutePhase,
    tables: Vec<nt_acpi::PciRoutingTable>,
    pending_table: Option<nt_acpi::PciRoutingTable>,
    irp_id: IrpId,
    origin_driver_id: DriverId,
    completion_driver_id: DriverId,
    completion_device_id: nt_io_manager::DeviceId,
    barrier_status: Option<nt_status::NtStatus>,
}

static mut HOSTED_ACPI_PCI_ROUTE_QUERY: Option<HostedAcpiPciRouteQuery> = None;

fn hosted_acpi_pci_route_policy_current(policy: &HostedAcpiPciRoutePolicy) -> bool {
    unsafe {
        match policy {
            HostedAcpiPciRoutePolicy::Routing(discovery) => {
                crate::hosted_pci_topology::hosted_pci_route_discovery_is_current(discovery)
            }
            HostedAcpiPciRoutePolicy::Tables(tables) => {
                crate::hosted_pci_topology::hosted_pci_routing_tables_are_current(tables)
            }
        }
    }
}

unsafe fn hosted_acpi_pci_route_endpoint_device(
    endpoint: nt_pnp::AcpiPciProviderEndpoint,
) -> Option<nt_io_manager::DeviceId> {
    let domain = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId(endpoint.hosted_domain_id),
        cookie: endpoint.hosted_domain_cookie,
    };
    let device_id = nt_io_manager::DeviceId(endpoint.device_id);
    if io_manager_mut().hosted_device_by_identity(domain, endpoint.pdo_object) != Some(device_id)
        || io_manager_mut()
            .device(device_id)
            .is_none_or(|device| device.delete_pending)
    {
        return None;
    }
    Some(device_id)
}

unsafe fn hosted_acpi_pci_prt_query(
    query_index: usize,
) -> Option<&'static nt_pnp::AcpiPciRoutingMethodQuery> {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY)).as_ref()?;
    let HostedAcpiPciRoutePolicy::Routing(discovery) = query.policy.as_ref()? else {
        return None;
    };
    discovery.queries().get(query_index)
}

fn classify_hosted_acpi_pci_prt_result(
    query: &nt_pnp::AcpiPciRoutingMethodQuery,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> (HostedAcpiPciPrtDisposition, Option<nt_acpi::PciRoutingTable>) {
    if status.raw() as u32 == STATUS_BUFFER_OVERFLOW {
        let required = usize::try_from(information).ok();
        let valid = output_len == nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN
            && payload.len() == output_len
            && required.is_some_and(|required| {
                required > output_len
                    && nt_acpi::eval_output_required_len(
                        payload,
                        HOSTED_ACPI_ROUTE_MAX_EVAL_BYTES,
                    ) == Ok(required)
            });
        return (
            if valid {
                HostedAcpiPciPrtDisposition::RetryExact(required.unwrap())
            } else {
                HostedAcpiPciPrtDisposition::Barrier(
                    nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                )
            },
            None,
        );
    }
    if !status.is_success() {
        return (HostedAcpiPciPrtDisposition::Barrier(status), None);
    }
    let Some(information) = usize::try_from(information).ok() else {
        return (
            HostedAcpiPciPrtDisposition::Barrier(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            None,
        );
    };
    let valid_information = if output_len == nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN {
        (12..=output_len).contains(&information)
    } else {
        information == output_len
    };
    if !valid_information || payload.len() != output_len {
        return (
            HostedAcpiPciPrtDisposition::Barrier(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            None,
        );
    }
    match nt_acpi::parse_pci_routing_table(query.segment, query.bus, &payload[..information]) {
        Ok(table) => (HostedAcpiPciPrtDisposition::TableReady, Some(table)),
        Err(nt_acpi::PciRoutingError::Allocation) => {
            (HostedAcpiPciPrtDisposition::RetryResources, None)
        }
        Err(_) => (
            HostedAcpiPciPrtDisposition::Barrier(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            None,
        ),
    }
}

unsafe fn apply_hosted_acpi_pci_prt_disposition(
    query_index: usize,
    disposition: HostedAcpiPciPrtDisposition,
) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .expect("ACPI PCI route query disappeared while applying _PRT result");
    if query
        .policy
        .as_ref()
        .is_none_or(|policy| !hosted_acpi_pci_route_policy_current(policy))
    {
        *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
        return;
    }
    query.phase = match disposition {
        HostedAcpiPciPrtDisposition::RetryResources => {
            query.barrier_status = Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            HostedAcpiPciRoutePhase::Barrier
        }
        HostedAcpiPciPrtDisposition::RetryExact(output_len) => {
            HostedAcpiPciRoutePhase::DispatchPrt {
                query_index,
                output_len,
            }
        }
        HostedAcpiPciPrtDisposition::TableReady => {
            let Some(table) = query.pending_table.take() else {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                query.phase = HostedAcpiPciRoutePhase::Barrier;
                return;
            };
            if query.tables.len() != query_index {
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                HostedAcpiPciRoutePhase::Barrier
            } else {
                query.tables.push(table);
                let query_count = match query.policy.as_ref().unwrap() {
                    HostedAcpiPciRoutePolicy::Routing(discovery) => discovery.queries().len(),
                    HostedAcpiPciRoutePolicy::Tables(_) => 0,
                };
                if query.tables.len() == query_count {
                    HostedAcpiPciRoutePhase::AcceptTables
                } else {
                    HostedAcpiPciRoutePhase::DispatchPrt {
                        query_index: query_index + 1,
                        output_len: nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN,
                    }
                }
            }
        }
        HostedAcpiPciPrtDisposition::Barrier(status) => {
            query.barrier_status = Some(status);
            HostedAcpiPciRoutePhase::Barrier
        }
    };
}

unsafe fn dispatch_hosted_acpi_pci_prt(query_index: usize, output_len: usize) -> bool {
    if !(nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN..=HOSTED_ACPI_ROUTE_MAX_EVAL_BYTES)
        .contains(&output_len)
    {
        return false;
    }
    let Some(method_query) = hosted_acpi_pci_prt_query(query_index) else {
        return false;
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
    let result = match io_manager_mut().buffered_device_control_device_payload(
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
            let (disposition, table) = classify_hosted_acpi_pci_prt_result(
                method_query,
                output_len,
                status,
                information,
                &output,
            );
            if disposition == HostedAcpiPciPrtDisposition::RetryResources {
                return false;
            }
            (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap()
                .pending_table = table;
            apply_hosted_acpi_pci_prt_disposition(query_index, disposition);
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
            let Some((origin_driver_id, completion_driver_id, completion_device_id)) = identities
            else {
                let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_mut()
                    .unwrap();
                query.phase = HostedAcpiPciRoutePhase::Barrier;
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                return true;
            };
            let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                .as_mut()
                .unwrap();
            query.irp_id = irp_id;
            query.origin_driver_id = origin_driver_id;
            query.completion_driver_id = completion_driver_id;
            query.completion_device_id = completion_device_id;
            query.phase = HostedAcpiPciRoutePhase::AwaitingPrtCompletion {
                query_index,
                output_len,
            };
        }
    }
    true
}

unsafe fn start_hosted_acpi_pci_route_query() -> usize {
    if (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY)).is_some()
        || (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY)).is_some()
        || hosted_pnp_lifecycle_dispatch_active()
    {
        return 0;
    }
    let discovery = match crate::hosted_pci_topology::begin_hosted_pci_route_reconciliation() {
        Ok(Some(discovery)) => discovery,
        Ok(None) | Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return 0,
        Err(status) => panic!("PCI route reconciliation could not begin: {status:?}"),
    };
    let mut tables = Vec::new();
    if tables.try_reserve_exact(discovery.queries().len()).is_err() {
        crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
        return 0;
    }
    let phase = if discovery.queries().is_empty() {
        HostedAcpiPciRoutePhase::AcceptTables
    } else {
        HostedAcpiPciRoutePhase::DispatchPrt {
            query_index: 0,
            output_len: nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN,
        }
    };
    *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = Some(HostedAcpiPciRouteQuery {
        policy: Some(HostedAcpiPciRoutePolicy::Routing(discovery)),
        phase,
        tables,
        pending_table: None,
        irp_id: IrpId(0),
        origin_driver_id: DriverId(0),
        completion_driver_id: DriverId(0),
        completion_device_id: nt_io_manager::DeviceId(0),
        barrier_status: None,
    });
    1usize.saturating_add(drain_hosted_acpi_pci_route_query())
}

unsafe fn drain_hosted_acpi_pci_route_query() -> usize {
    let mut progress = 0usize;
    loop {
        let Some(phase) = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_ref()
            .map(|query| query.phase)
        else {
            return progress;
        };
        let current = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_ref()
            .and_then(|query| query.policy.as_ref())
            .is_some_and(hosted_acpi_pci_route_policy_current);
        if !current
            && !matches!(
                phase,
                HostedAcpiPciRoutePhase::AwaitingPrtCompletion { .. }
                    | HostedAcpiPciRoutePhase::AwaitingPrtCopy { .. }
                    | HostedAcpiPciRoutePhase::AwaitingPrtAck { .. }
            )
        {
            *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
            return progress.saturating_add(1);
        }
        match phase {
            HostedAcpiPciRoutePhase::DispatchPrt {
                query_index,
                output_len,
            } => {
                if !dispatch_hosted_acpi_pci_prt(query_index, output_len) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingPrtCompletion {
                query_index,
                output_len,
            } => {
                let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_ref()
                    .unwrap();
                let expected_device_id = hosted_acpi_pci_prt_query(query_index)
                    .map(|method| nt_io_manager::DeviceId(method.endpoint.device_id));
                let Some(completion) = io_manager_mut().completed_irp(query.irp_id) else {
                    return progress;
                };
                let request_valid = io_manager_mut().irp(query.irp_id).is_some_and(|irp| {
                    irp.current_stack().is_some_and(|stack| {
                        stack.driver_id == query.completion_driver_id
                            && stack.device_id == query.completion_device_id
                            && matches!(
                                &stack.parameters,
                                IoParameters::DeviceControl(parameters)
                                    if parameters.ioctl_code
                                        == nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX
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
                    && request_valid;
                let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_mut()
                    .unwrap();
                if !identity_valid {
                    query.phase = HostedAcpiPciRoutePhase::AwaitingPrtCopy {
                        query_index,
                        output_len,
                        status: nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                        information: 0,
                    };
                } else {
                    query.phase = HostedAcpiPciRoutePhase::AwaitingPrtCopy {
                        query_index,
                        output_len,
                        status: completion.status,
                        information: completion.information,
                    };
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingPrtCopy {
                query_index,
                output_len,
                status,
                information,
            } => {
                let irp_id = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_ref()
                    .unwrap()
                    .irp_id;
                let mut payload = Vec::new();
                if payload.try_reserve_exact(output_len).is_err() {
                    return progress;
                }
                payload.resize(output_len, 0);
                let (disposition, table) = match io_manager_mut()
                    .copy_completed_buffered_device_control_payload(irp_id, 0, &mut payload)
                {
                    Ok(copied) if copied == output_len => hosted_acpi_pci_prt_query(query_index)
                        .map(|method_query| {
                            classify_hosted_acpi_pci_prt_result(
                                method_query,
                                output_len,
                                status,
                                information,
                                &payload,
                            )
                        })
                        .unwrap_or((
                            HostedAcpiPciPrtDisposition::Barrier(
                                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                            ),
                            None,
                        )),
                    Ok(_) => (
                        HostedAcpiPciPrtDisposition::Barrier(
                            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                        ),
                        None,
                    ),
                    Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES)
                    | Err(nt_status::NtStatus::DEVICE_NOT_READY) => return progress,
                    Err(copy_status) => {
                        (HostedAcpiPciPrtDisposition::Barrier(copy_status), None)
                    }
                };
                if disposition == HostedAcpiPciPrtDisposition::RetryResources {
                    return progress;
                }
                let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_mut()
                    .unwrap();
                query.pending_table = table;
                query.phase = HostedAcpiPciRoutePhase::AwaitingPrtAck {
                    query_index,
                    disposition,
                };
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingPrtAck {
                query_index,
                disposition,
            } => {
                let irp_id = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_ref()
                    .unwrap()
                    .irp_id;
                match io_manager_mut().acknowledge_completed_irp_strict(irp_id) {
                    Ok(_) => {
                        apply_hosted_acpi_pci_prt_disposition(query_index, disposition);
                        progress = progress.saturating_add(1);
                    }
                    Err(status) => {
                        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                            .as_mut()
                            .unwrap();
                        query.barrier_status = Some(status);
                        return progress;
                    }
                }
            }
            HostedAcpiPciRoutePhase::AcceptTables => {
                let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_mut()
                    .unwrap();
                let Some(HostedAcpiPciRoutePolicy::Routing(discovery)) = query.policy.take() else {
                    query.phase = HostedAcpiPciRoutePhase::Barrier;
                    query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                    progress = progress.saturating_add(1);
                    continue;
                };
                let tables = core::mem::take(&mut query.tables);
                match crate::hosted_pci_topology::accept_hosted_pci_routing_tables(
                    discovery,
                    tables,
                ) {
                    Ok(tables) => {
                        query.policy = Some(HostedAcpiPciRoutePolicy::Tables(tables));
                        query.phase = HostedAcpiPciRoutePhase::TablesAccepted;
                    }
                    Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => {
                        *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
                        crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
                        return progress;
                    }
                    Err(status) => {
                        query.phase = HostedAcpiPciRoutePhase::Barrier;
                        query.barrier_status = Some(status);
                    }
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::TablesAccepted | HostedAcpiPciRoutePhase::Barrier => {
                return progress;
            }
        }
    }
}
