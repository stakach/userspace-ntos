// Serialized ACPI PCI interrupt-route reconciliation transport.

const HOSTED_ACPI_ROUTE_MAX_EVAL_BYTES: usize = 12 + 4 + u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciRoutePhase {
    DispatchPic,
    DecodeInlinePic {
        status: nt_status::NtStatus,
        information: u64,
    },
    AwaitingPicCompletion,
    AwaitingPicAck {
        status: nt_status::NtStatus,
        information: u64,
    },
    DispatchPrt { query_index: usize, output_len: usize },
    DecodeInlinePrt {
        query_index: usize,
        output_len: usize,
        status: nt_status::NtStatus,
        information: u64,
    },
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
    DispatchCrsFilter { endpoint_index: usize, output_len: usize },
    DecodeInlineCrsFilter {
        endpoint_index: usize,
        output_len: usize,
        status: nt_status::NtStatus,
        information: u64,
    },
    AwaitingCrsFilterCompletion { endpoint_index: usize, output_len: usize },
    AwaitingCrsFilterCopy {
        endpoint_index: usize,
        output_len: usize,
        status: nt_status::NtStatus,
        information: u64,
    },
    AwaitingCrsFilterAck {
        endpoint_index: usize,
        disposition: HostedAcpiPciCrsFilterDisposition,
    },
    PrepareLinkDiscovery,
    DispatchLink { request_index: usize, output_len: usize },
    DecodeInlineLink {
        request_index: usize,
        output_len: usize,
        status: nt_status::NtStatus,
        information: u64,
    },
    AwaitingLinkCompletion { request_index: usize, output_len: usize },
    AwaitingLinkCopy {
        request_index: usize,
        output_len: usize,
        status: nt_status::NtStatus,
        information: u64,
    },
    AwaitingLinkAck {
        request_index: usize,
        disposition: HostedAcpiPciLinkDisposition,
    },
    PreparePublication,
    CommitPublication,
    Barrier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciRouteOperation {
    Begin,
    Pic,
    Prt,
    PrtPdoRelative,
    PrtProviderAbsolute,
    AcceptTables,
    CrsFilter,
    PrepareLinkDiscovery,
    Link,
    PreparePublication,
    CommitPublication,
}

enum HostedAcpiPciRouteInput {
    PdoRelative([u8; nt_acpi::ACPI_EVAL_INPUT_BUFFER_LEN]),
    ProviderAbsolute([u8; nt_acpi::ACPI_EVAL_INPUT_BUFFER_EX_LEN]),
}

impl HostedAcpiPciRouteInput {
    fn ioctl_code(&self) -> u32 {
        match self {
            Self::PdoRelative(_) => nt_acpi::IOCTL_ACPI_EVAL_METHOD,
            Self::ProviderAbsolute(_) => nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::PdoRelative(input) => input,
            Self::ProviderAbsolute(input) => input,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiPciPrtDisposition {
    RetryResources,
    RetryExact(usize),
    TableReady,
    Barrier(nt_status::NtStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedAcpiVariableEvalDisposition {
    RetryExact(usize),
    Payload(usize),
    Barrier(nt_status::NtStatus),
}

enum HostedAcpiPciRoutePolicy {
    Routing(nt_pnp::PreparedAcpiPciRoutingDiscovery),
    Tables(nt_pnp::PreparedAcpiPciRoutingTables),
    Links(nt_pnp::PreparedAcpiPciInterruptLinkDiscovery),
    Publication(nt_pnp::PreparedPciInterruptRoutePublication),
}

struct HostedAcpiPciRouteQuery {
    policy: Option<HostedAcpiPciRoutePolicy>,
    phase: HostedAcpiPciRoutePhase,
    tables: Vec<nt_acpi::PciRoutingTable>,
    pending_table: Option<nt_acpi::PciRoutingTable>,
    filtered_sources: Vec<nt_pnp::AcpiPciCrsMethodSource>,
    pending_matches: Option<nt_acpi::AcpiNamespaceMatches>,
    link_evaluations: Vec<nt_pnp::AcpiPciInterruptLinkEvaluation>,
    pending_resources: Option<Vec<nt_acpi::InterruptResource>>,
    inline_payload: Option<Vec<u8>>,
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    irp_id: IrpId,
    origin_driver_id: DriverId,
    completion_driver_id: DriverId,
    completion_device_id: nt_io_manager::DeviceId,
    last_operation: HostedAcpiPciRouteOperation,
    last_operation_index: usize,
    last_output_len: usize,
    last_driver_result: Option<(nt_status::NtStatus, u64)>,
    barrier_status: Option<nt_status::NtStatus>,
}

static mut HOSTED_ACPI_PCI_ROUTE_QUERY: Option<HostedAcpiPciRouteQuery> = None;

#[derive(Clone, Copy)]
struct HostedAcpiPciRouteIndeterminateIrp {
    irp_id: IrpId,
    status: nt_status::NtStatus,
    origin_driver_id: DriverId,
    completion_driver_id: DriverId,
    completion_device_id: nt_io_manager::DeviceId,
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    failure_count: u8,
    next_retry_deadline: u64,
}

static mut HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS: Option<
    Vec<HostedAcpiPciRouteIndeterminateIrp>,
> = None;

unsafe fn hosted_acpi_route_request_input_is(irp_id: IrpId, input: &[u8]) -> bool {
    io_manager_mut()
        .irp(irp_id)
        .and_then(|irp| irp.request_input_fingerprint())
        == Some(nt_io_manager::request_input_fingerprint(input))
}

unsafe fn reserve_hosted_acpi_pci_route_indeterminate_slot() -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap().try_reserve(1).is_ok()
}

unsafe fn retry_and_clear_hosted_acpi_pci_route_query() {
    *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
    crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
}

unsafe fn record_hosted_acpi_pci_route_operation(
    operation: HostedAcpiPciRouteOperation,
    index: usize,
    output_len: usize,
) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .expect("ACPI PCI route operation lost its query");
    query.last_operation = operation;
    query.last_operation_index = index;
    query.last_output_len = output_len;
    query.last_driver_result = None;
}

unsafe fn record_hosted_acpi_pci_route_driver_result(
    status: nt_status::NtStatus,
    information: u64,
) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .expect("ACPI PCI route completion lost its query");
    query.last_driver_result = Some((status, information));
}

fn print_hosted_acpi_pci_route_operation(operation: HostedAcpiPciRouteOperation) {
    print_str(match operation {
        HostedAcpiPciRouteOperation::Begin => b"begin",
        HostedAcpiPciRouteOperation::Pic => b"_PIC",
        HostedAcpiPciRouteOperation::Prt => b"_PRT",
        HostedAcpiPciRouteOperation::PrtPdoRelative => b"pdo-relative-_PRT",
        HostedAcpiPciRouteOperation::PrtProviderAbsolute => b"absolute-_PRT",
        HostedAcpiPciRouteOperation::AcceptTables => b"accept-tables",
        HostedAcpiPciRouteOperation::CrsFilter => b"_CRS-filter",
        HostedAcpiPciRouteOperation::PrepareLinkDiscovery => b"prepare-links",
        HostedAcpiPciRouteOperation::Link => b"link-_CRS",
        HostedAcpiPciRouteOperation::PreparePublication => b"prepare-publication",
        HostedAcpiPciRouteOperation::CommitPublication => b"commit-publication",
    });
}

fn hosted_acpi_pci_prt_input(
    query: &nt_pnp::AcpiPciRoutingMethodQuery,
) -> Result<HostedAcpiPciRouteInput, nt_acpi::AcpiEvalError> {
    match query.invocation {
        nt_pnp::AcpiPciRoutingMethodInvocation::PdoRelative => nt_acpi::eval_method_input(*b"_PRT")
            .map(HostedAcpiPciRouteInput::PdoRelative),
        nt_pnp::AcpiPciRoutingMethodInvocation::ProviderAbsolute => {
            nt_acpi::eval_method_input_ex(query.method_path.as_str())
                .map(HostedAcpiPciRouteInput::ProviderAbsolute)
        }
    }
}

unsafe fn finish_hosted_acpi_pci_route_barrier(status: nt_status::NtStatus) {
    let Some((
        catalog_generation,
        inventory_generation,
        route_owner_generation,
        last_operation,
        last_operation_index,
        last_output_len,
        last_driver_result,
    )) =
        (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_ref()
            .map(|query| {
                (
                    query.catalog_generation,
                    query.inventory_generation,
                    query.route_owner_generation,
                    query.last_operation,
                    query.last_operation_index,
                    query.last_output_len,
                    query.last_driver_result,
                )
            })
    else {
        return;
    };
    match crate::hosted_pci_topology::block_hosted_pci_route_reconciliation(
        catalog_generation,
        inventory_generation,
        route_owner_generation,
        status,
    ) {
        Ok(true) => {
            print_str(b"[pci-route] blocked catalog/inventory/owner=");
            print_u64(catalog_generation);
            print_str(b"/");
            print_u64(inventory_generation);
            print_str(b"/");
            print_u64(route_owner_generation);
            print_str(b" status=");
            print_hex(status.raw() as u32);
            print_str(b" operation=");
            print_hosted_acpi_pci_route_operation(last_operation);
            print_str(b" index/output=");
            print_u64(last_operation_index as u64);
            print_str(b"/");
            print_u64(last_output_len as u64);
            print_str(b" driver-status/information=");
            if let Some((driver_status, information)) = last_driver_result {
                print_hex(driver_status.raw() as u32);
                print_str(b"/");
                print_u64(information);
            } else {
                print_str(b"none");
            }
            print_str(b"\n");
            *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
        }
        Ok(false) => retry_and_clear_hosted_acpi_pci_route_query(),
        Err(block_status) => panic!("PCI route barrier could not be retained: {block_status:?}"),
    }
}

unsafe fn retain_hosted_acpi_pci_route_indeterminate_irp(
    irp_id: IrpId,
    status: nt_status::NtStatus,
) {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .expect("indeterminate ACPI PCI route IRP lost its transport owner");
    let retained = HostedAcpiPciRouteIndeterminateIrp {
        irp_id,
        status,
        origin_driver_id: query.origin_driver_id,
        completion_driver_id: query.completion_driver_id,
        completion_device_id: query.completion_device_id,
        catalog_generation: query.catalog_generation,
        inventory_generation: query.inventory_generation,
        route_owner_generation: query.route_owner_generation,
        failure_count: 1,
        next_retry_deadline: crate::monotonic_time_100ns(),
    };
    let records = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
        .as_mut()
        .expect("ACPI PCI route indeterminate storage was not reserved");
    assert!(records.len() < records.capacity());
    records.push(retained);
    let _ = crate::service_sec_image::rearm_registered_delay_timer();
    print_str(b"[pci-route] indeterminate irp/status=");
    print_u64(retained.irp_id.raw());
    print_str(b"/");
    print_hex(retained.status.raw() as u32);
    print_str(b" fence=");
    print_u64(retained.catalog_generation);
    print_str(b"/");
    print_u64(retained.inventory_generation);
    print_str(b"/");
    print_u64(retained.route_owner_generation);
    print_str(b"\n");
    finish_hosted_acpi_pci_route_barrier(status);
}

unsafe fn hosted_acpi_pci_route_transport_fences(
    device_id: nt_io_manager::DeviceId,
    driver_id: DriverId,
) -> bool {
    (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
        .as_ref()
        .is_some_and(|records| {
            records.iter().any(|record| {
                record.completion_device_id.raw() == 0
                    || record.origin_driver_id.raw() == 0
                    || record.completion_driver_id.raw() == 0
                    || record.completion_device_id == device_id
                    || record.origin_driver_id == driver_id
                    || record.completion_driver_id == driver_id
            })
        })
}

unsafe fn hosted_acpi_pci_route_transport_is_indeterminate() -> bool {
    (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
        .as_ref()
        .is_some_and(|records| !records.is_empty())
}

pub(crate) fn hosted_acpi_pci_route_recovery_next_deadline() -> Option<u64> {
    unsafe {
        (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
            .as_ref()?
            .iter()
            .map(|record| record.next_retry_deadline)
            .min()
    }
}

pub(crate) unsafe fn hosted_acpi_pci_route_recovery_wake_due(now_100ns: u64) -> u64 {
    let due = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
        .as_ref()
        .and_then(|records| {
            records
                .iter()
                .enumerate()
                .filter(|(_, record)| record.next_retry_deadline <= now_100ns)
                .min_by_key(|(_, record)| record.next_retry_deadline)
                .map(|(index, record)| (index, *record))
        });
    let Some((index, retained)) = due else {
        return 0;
    };
    match io_manager_mut().acknowledge_completed_irp_strict(retained.irp_id) {
        Ok(_) => {
            let records = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
                .as_mut()
                .expect("ACPI PCI route recovery storage disappeared");
            assert_eq!(records[index].irp_id, retained.irp_id);
            records.remove(index);
            print_str(b"[pci-route] recovered completion acknowledgement irp=");
            print_u64(retained.irp_id.raw());
            print_str(b"\n");
            crate::hosted_pci_topology::recover_hosted_pci_route_reconciliation_block(
                retained.catalog_generation,
                retained.inventory_generation,
                retained.route_owner_generation,
            )
            .expect("recovered ACPI PCI route completion lost its topology authority");
        }
        Err(status) => {
            let record = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_INDETERMINATE_IRPS))
                .as_mut()
                .and_then(|records| records.get_mut(index))
                .expect("ACPI PCI route recovery record disappeared");
            assert_eq!(record.irp_id, retained.irp_id);
            record.status = status;
            record.failure_count = record.failure_count.saturating_add(1);
            let delay_100ns = 10_000u64 << u32::from(record.failure_count.min(10));
            record.next_retry_deadline = now_100ns.saturating_add(delay_100ns);
            let _ = crate::service_sec_image::rearm_registered_delay_timer();
        }
    }
    1
}

unsafe fn drain_hosted_acpi_pci_route_indeterminate_irps() -> usize {
    hosted_acpi_pci_route_recovery_wake_due(crate::monotonic_time_100ns()) as usize
}

unsafe fn cancel_stale_hosted_acpi_pci_route_query() -> Result<bool, nt_status::NtStatus> {
    let Some((phase, irp_id)) = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .map(|query| (query.phase, query.irp_id))
    else {
        return Ok(false);
    };
    if !matches!(
        phase,
        HostedAcpiPciRoutePhase::AwaitingPicCompletion
            | HostedAcpiPciRoutePhase::AwaitingPrtCompletion { .. }
            | HostedAcpiPciRoutePhase::AwaitingCrsFilterCompletion { .. }
            | HostedAcpiPciRoutePhase::AwaitingLinkCompletion { .. }
    ) {
        return Ok(false);
    }
    io_manager_mut().cancel_if_pending(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)
}

fn hosted_acpi_pci_route_policy_current(policy: &HostedAcpiPciRoutePolicy) -> bool {
    unsafe {
        match policy {
            HostedAcpiPciRoutePolicy::Routing(discovery) => {
                crate::hosted_pci_topology::hosted_pci_route_discovery_is_current(discovery)
            }
            HostedAcpiPciRoutePolicy::Tables(tables) => {
                crate::hosted_pci_topology::hosted_pci_routing_tables_are_current(tables)
            }
            HostedAcpiPciRoutePolicy::Links(discovery) => {
                crate::hosted_pci_topology::hosted_pci_interrupt_link_discovery_is_current(
                    discovery,
                )
            }
            HostedAcpiPciRoutePolicy::Publication(publication) => {
                crate::hosted_pci_topology::hosted_pci_route_publication_is_current(publication)
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

unsafe fn hosted_acpi_pci_pic_endpoint() -> Option<nt_pnp::AcpiPciProviderEndpoint> {
    let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY)).as_ref()?;
    let HostedAcpiPciRoutePolicy::Routing(discovery) = query.policy.as_ref()? else {
        return None;
    };
    discovery.queries().first().map(|query| query.relation_owner)
}

unsafe fn apply_hosted_acpi_pic_result(
    status: nt_status::NtStatus,
    information: u64,
) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .expect("ACPI PCI route query disappeared while applying _PIC result");
    if query
        .policy
        .as_ref()
        .is_none_or(|policy| !hosted_acpi_pci_route_policy_current(policy))
    {
        retry_and_clear_hosted_acpi_pci_route_query();
        return;
    }
    if status.raw() == STATUS_SUCCESS && information == 0 {
        query.phase = HostedAcpiPciRoutePhase::DispatchPrt {
            query_index: 0,
            output_len: nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN,
        };
    } else {
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(if status.raw() == STATUS_SUCCESS {
            nt_status::NtStatus::INVALID_DEVICE_REQUEST
        } else {
            status
        });
    }
}

unsafe fn dispatch_hosted_acpi_pic() -> bool {
    let Some(endpoint) = hosted_acpi_pci_pic_endpoint() else {
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
    let input = match nt_acpi::eval_method_input_integer_ex("\\_PIC", 1) {
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
    record_hosted_acpi_pci_route_operation(HostedAcpiPciRouteOperation::Pic, 0, 0);
    let mut output = [];
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
            query.phase = HostedAcpiPciRoutePhase::DecodeInlinePic {
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
                            && parameters.input_len as usize == input.len()
                            && parameters.output_len == 0
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
            query.phase = HostedAcpiPciRoutePhase::AwaitingPicCompletion;
        }
    }
    true
}

fn classify_hosted_acpi_variable_eval_result(
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> HostedAcpiVariableEvalDisposition {
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
        return if valid {
            HostedAcpiVariableEvalDisposition::RetryExact(required.unwrap())
        } else {
            HostedAcpiVariableEvalDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            )
        };
    }
    if status.raw() != STATUS_SUCCESS {
        return HostedAcpiVariableEvalDisposition::Barrier(status);
    }
    let Some(information) = usize::try_from(information).ok() else {
        return HostedAcpiVariableEvalDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        );
    };
    let valid_information = if output_len == nt_acpi::ACPI_EVAL_OUTPUT_PROBE_LEN {
        (12..=output_len).contains(&information)
    } else {
        information == output_len
    };
    if !valid_information || payload.len() != output_len {
        HostedAcpiVariableEvalDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        )
    } else {
        HostedAcpiVariableEvalDisposition::Payload(information)
    }
}

fn classify_hosted_acpi_pci_prt_result(
    query: &nt_pnp::AcpiPciRoutingMethodQuery,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> (HostedAcpiPciPrtDisposition, Option<nt_acpi::PciRoutingTable>) {
    let information = match classify_hosted_acpi_variable_eval_result(
        output_len,
        status,
        information,
        payload,
    ) {
        HostedAcpiVariableEvalDisposition::RetryExact(required) => {
            return (HostedAcpiPciPrtDisposition::RetryExact(required), None);
        }
        HostedAcpiVariableEvalDisposition::Payload(information) => information,
        HostedAcpiVariableEvalDisposition::Barrier(status) => {
            return (HostedAcpiPciPrtDisposition::Barrier(status), None);
        }
    };
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
        retry_and_clear_hosted_acpi_pci_route_query();
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
                    HostedAcpiPciRoutePolicy::Tables(_)
                    | HostedAcpiPciRoutePolicy::Links(_)
                    | HostedAcpiPciRoutePolicy::Publication(_) => 0,
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
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    let Some(method_query) = hosted_acpi_pci_prt_query(query_index) else {
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
    let input = match hosted_acpi_pci_prt_input(method_query) {
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
    record_hosted_acpi_pci_route_operation(
        match method_query.invocation {
            nt_pnp::AcpiPciRoutingMethodInvocation::PdoRelative => {
                HostedAcpiPciRouteOperation::PrtPdoRelative
            }
            nt_pnp::AcpiPciRoutingMethodInvocation::ProviderAbsolute => {
                HostedAcpiPciRouteOperation::PrtProviderAbsolute
            }
        },
        query_index,
        output_len,
    );
    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return false;
    }
    output.resize(output_len, 0);
    let result = match io_manager_mut().buffered_device_control_exact_device_payload(
        ClientId(IO_MANAGER_COMPONENT_ID),
        device_id,
        input.ioctl_code(),
        input.as_bytes(),
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
            query.phase = HostedAcpiPciRoutePhase::DecodeInlinePrt {
                query_index,
                output_len,
                status,
                information,
            };
        }
        ExternalDispatchResult::Pending { irp_id } => {
            let ioctl_code = input.ioctl_code();
            let input_len = input.as_bytes().len();
            let identities = io_manager_mut().irp(irp_id).and_then(|irp| {
                let current = irp.current_stack()?;
                matches!(
                    &current.parameters,
                    IoParameters::DeviceControl(parameters)
                        if parameters.ioctl_code == ioctl_code
                            && parameters.input_len as usize == input_len
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
            query.phase = HostedAcpiPciRoutePhase::AwaitingPrtCompletion {
                query_index,
                output_len,
            };
        }
    }
    true
}

unsafe fn decode_inline_hosted_acpi_pci_prt(
    query_index: usize,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
) -> bool {
    let Some((disposition, table)) = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_ref()
        .and_then(|query| query.inline_payload.as_deref())
        .and_then(|payload| {
            hosted_acpi_pci_prt_query(query_index).map(|method_query| {
                classify_hosted_acpi_pci_prt_result(
                    method_query,
                    output_len,
                    status,
                    information,
                    payload,
                )
            })
        })
    else {
        let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
            .as_mut()
            .unwrap();
        query.phase = HostedAcpiPciRoutePhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    if disposition == HostedAcpiPciPrtDisposition::RetryResources {
        return false;
    }
    let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
        .as_mut()
        .unwrap();
    query.inline_payload = None;
    query.pending_table = table;
    apply_hosted_acpi_pci_prt_disposition(query_index, disposition);
    true
}

unsafe fn start_hosted_acpi_pci_route_query() -> usize {
    if (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY)).is_some()
        || (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY)).is_some()
        || hosted_pnp_lifecycle_dispatch_active()
        || hosted_acpi_pci_route_transport_is_indeterminate()
    {
        return 0;
    }
    let discovery = match crate::hosted_pci_topology::begin_hosted_pci_route_reconciliation() {
        Ok(Some(discovery)) => discovery,
        Ok(None) | Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return 0,
        Err(status) => panic!("PCI route reconciliation could not begin: {status:?}"),
    };
    let (catalog_generation, inventory_generation, route_owner_generation) = (
        discovery.catalog_generation(),
        discovery.inventory_generation(),
        discovery.route_owner_generation(),
    );
    let mut tables = Vec::new();
    if tables.try_reserve_exact(discovery.queries().len()).is_err() {
        crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
        return 0;
    }
    if !reserve_hosted_acpi_pci_route_indeterminate_slot() {
        crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
        return 0;
    }
    let phase = if discovery.queries().is_empty() {
        HostedAcpiPciRoutePhase::AcceptTables
    } else {
        HostedAcpiPciRoutePhase::DispatchPic
    };
    *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = Some(HostedAcpiPciRouteQuery {
        policy: Some(HostedAcpiPciRoutePolicy::Routing(discovery)),
        phase,
        tables,
        pending_table: None,
        filtered_sources: Vec::new(),
        pending_matches: None,
        link_evaluations: Vec::new(),
        pending_resources: None,
        inline_payload: None,
        catalog_generation,
        inventory_generation,
        route_owner_generation,
        irp_id: IrpId(0),
        origin_driver_id: DriverId(0),
        completion_driver_id: DriverId(0),
        completion_device_id: nt_io_manager::DeviceId(0),
        last_operation: HostedAcpiPciRouteOperation::Begin,
        last_operation_index: 0,
        last_output_len: 0,
        last_driver_result: None,
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
                HostedAcpiPciRoutePhase::AwaitingPicCompletion
                    | HostedAcpiPciRoutePhase::AwaitingPicAck { .. }
                    | HostedAcpiPciRoutePhase::AwaitingPrtCompletion { .. }
                    | HostedAcpiPciRoutePhase::AwaitingPrtCopy { .. }
                    | HostedAcpiPciRoutePhase::AwaitingPrtAck { .. }
                    | HostedAcpiPciRoutePhase::AwaitingCrsFilterCompletion { .. }
                    | HostedAcpiPciRoutePhase::AwaitingCrsFilterCopy { .. }
                    | HostedAcpiPciRoutePhase::AwaitingCrsFilterAck { .. }
                    | HostedAcpiPciRoutePhase::AwaitingLinkCompletion { .. }
                    | HostedAcpiPciRoutePhase::AwaitingLinkCopy { .. }
                    | HostedAcpiPciRoutePhase::AwaitingLinkAck { .. }
                    | HostedAcpiPciRoutePhase::Barrier
            )
        {
            retry_and_clear_hosted_acpi_pci_route_query();
            return progress.saturating_add(1);
        }
        match phase {
            HostedAcpiPciRoutePhase::DispatchPic => {
                if !dispatch_hosted_acpi_pic() {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::DecodeInlinePic {
                status,
                information,
            } => {
                apply_hosted_acpi_pic_result(status, information);
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingPicCompletion => {
                let query = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_ref()
                    .unwrap();
                let expected_device_id = hosted_acpi_pci_pic_endpoint()
                    .and_then(|endpoint| hosted_acpi_pci_route_endpoint_device(endpoint));
                let input = nt_acpi::eval_method_input_integer_ex("\\_PIC", 1).ok();
                let request_fingerprint_valid = input.as_ref().is_some_and(|input| {
                    hosted_acpi_route_request_input_is(query.irp_id, input)
                });
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
                                            == nt_acpi::ACPI_EVAL_INPUT_BUFFER_SIMPLE_INTEGER_EX_LEN
                                        && parameters.output_len == 0
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
                record_hosted_acpi_pci_route_driver_result(status, information);
                let query = (*core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_mut()
                    .unwrap();
                query.phase = HostedAcpiPciRoutePhase::AwaitingPicAck {
                    status,
                    information,
                };
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingPicAck {
                status,
                information,
            } => {
                let irp_id = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_ref()
                    .unwrap()
                    .irp_id;
                match io_manager_mut().acknowledge_completed_irp_strict(irp_id) {
                    Ok(_) => {
                        apply_hosted_acpi_pic_result(status, information);
                        progress = progress.saturating_add(1);
                    }
                    Err(ack_status) => {
                        retain_hosted_acpi_pci_route_indeterminate_irp(irp_id, ack_status);
                        return progress.saturating_add(1);
                    }
                }
            }
            HostedAcpiPciRoutePhase::DispatchPrt {
                query_index,
                output_len,
            } => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::Prt,
                    query_index,
                    output_len,
                );
                if !dispatch_hosted_acpi_pci_prt(query_index, output_len) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::DecodeInlinePrt {
                query_index,
                output_len,
                status,
                information,
            } => {
                if !decode_inline_hosted_acpi_pci_prt(
                    query_index,
                    output_len,
                    status,
                    information,
                ) {
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
                let method_query = hosted_acpi_pci_prt_query(query_index);
                let expected_device_id = method_query
                    .and_then(|method| hosted_acpi_pci_route_endpoint_device(method.endpoint));
                let input = method_query.and_then(|method| hosted_acpi_pci_prt_input(method).ok());
                let request_fingerprint_valid = input.as_ref().is_some_and(|input| {
                    hosted_acpi_route_request_input_is(query.irp_id, input.as_bytes())
                });
                let expected_ioctl_code = input.as_ref().map(HostedAcpiPciRouteInput::ioctl_code);
                let expected_input_len = input.as_ref().map(|input| input.as_bytes().len());
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
                                    if Some(parameters.ioctl_code) == expected_ioctl_code
                                        && Some(parameters.input_len as usize)
                                            == expected_input_len
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
                let completion_status = completion.status;
                let completion_information = completion.information;
                record_hosted_acpi_pci_route_driver_result(
                    completion_status,
                    completion_information,
                );
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
                        status: completion_status,
                        information: completion_information,
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
                        retain_hosted_acpi_pci_route_indeterminate_irp(irp_id, status);
                        return progress.saturating_add(1);
                    }
                }
            }
            HostedAcpiPciRoutePhase::AcceptTables => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::AcceptTables,
                    0,
                    0,
                );
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
                        let endpoint_count = tables.link_candidate_endpoints().len();
                        if query.filtered_sources.try_reserve_exact(endpoint_count).is_err() {
                            *core::ptr::addr_of_mut!(HOSTED_ACPI_PCI_ROUTE_QUERY) = None;
                            crate::hosted_pci_topology::retry_hosted_pci_route_reconciliation();
                            return progress;
                        }
                        query.policy = Some(HostedAcpiPciRoutePolicy::Tables(tables));
                        query.phase = if endpoint_count == 0 {
                            HostedAcpiPciRoutePhase::PrepareLinkDiscovery
                        } else {
                            HostedAcpiPciRoutePhase::DispatchCrsFilter {
                                endpoint_index: 0,
                                output_len: HOSTED_ACPI_NAMESPACE_HEADER_LEN,
                            }
                        };
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
            HostedAcpiPciRoutePhase::DispatchCrsFilter {
                endpoint_index,
                output_len,
            } => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::CrsFilter,
                    endpoint_index,
                    output_len,
                );
                if !dispatch_hosted_acpi_pci_crs_filter(endpoint_index, output_len) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::DecodeInlineCrsFilter {
                endpoint_index,
                output_len,
                status,
                information,
            } => {
                if !decode_inline_hosted_acpi_pci_crs_filter(
                    endpoint_index,
                    output_len,
                    status,
                    information,
                ) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingCrsFilterCompletion {
                endpoint_index,
                output_len,
            } => {
                if !advance_hosted_acpi_pci_crs_filter_completion(endpoint_index, output_len) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingCrsFilterCopy {
                endpoint_index,
                output_len,
                status,
                information,
            } => {
                if !copy_hosted_acpi_pci_crs_filter_completion(
                    endpoint_index,
                    output_len,
                    status,
                    information,
                ) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingCrsFilterAck {
                endpoint_index,
                disposition,
            } => {
                if !acknowledge_hosted_acpi_pci_crs_filter(endpoint_index, disposition) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::PrepareLinkDiscovery => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::PrepareLinkDiscovery,
                    0,
                    0,
                );
                if !prepare_hosted_acpi_pci_interrupt_link_discovery() {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::DispatchLink {
                request_index,
                output_len,
            } => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::Link,
                    request_index,
                    output_len,
                );
                if !dispatch_hosted_acpi_pci_link(request_index, output_len) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::DecodeInlineLink {
                request_index,
                output_len,
                status,
                information,
            } => {
                if !decode_inline_hosted_acpi_pci_link(
                    request_index,
                    output_len,
                    status,
                    information,
                ) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingLinkCompletion {
                request_index,
                output_len,
            } => {
                if !advance_hosted_acpi_pci_link_completion(request_index, output_len) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingLinkCopy {
                request_index,
                output_len,
                status,
                information,
            } => {
                if !copy_hosted_acpi_pci_link_completion(
                    request_index,
                    output_len,
                    status,
                    information,
                ) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::AwaitingLinkAck {
                request_index,
                disposition,
            } => {
                if !acknowledge_hosted_acpi_pci_link(request_index, disposition) {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::PreparePublication => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::PreparePublication,
                    0,
                    0,
                );
                if !prepare_hosted_acpi_pci_route_publication() {
                    return progress;
                }
                progress = progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::CommitPublication => {
                record_hosted_acpi_pci_route_operation(
                    HostedAcpiPciRouteOperation::CommitPublication,
                    0,
                    0,
                );
                if !commit_hosted_acpi_pci_route_publication() {
                    return progress;
                }
                return progress.saturating_add(1);
            }
            HostedAcpiPciRoutePhase::Barrier => {
                let status = (*core::ptr::addr_of!(HOSTED_ACPI_PCI_ROUTE_QUERY))
                    .as_ref()
                    .and_then(|query| query.barrier_status)
                    .unwrap_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                finish_hosted_acpi_pci_route_barrier(status);
                return progress.saturating_add(1);
            }
        }
    }
}
