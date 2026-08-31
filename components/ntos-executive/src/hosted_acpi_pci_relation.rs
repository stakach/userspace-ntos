// Resumable ACPI PCI namespace discovery for one retained BusRelations transaction.

unsafe fn advance_hosted_acpi_pci_scope_discovery(child_index: usize) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .expect("hosted relation query disappeared while advancing ACPI PCI discovery");
    let complete = query.child_properties.get(child_index).is_some_and(|properties| {
        matches!(
            properties.acpi_pci_scope_discovery,
            HostedAcpiPciScopeDiscoveryState::NotApplicable
                | HostedAcpiPciScopeDiscoveryState::Planned(_)
        )
    });
    if !complete {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return;
    }
    let next_child = child_index.saturating_add(1);
    query.phase = if next_child < query.reported_children.len() {
        HostedDeviceRelationQueryPhase::DispatchAcpiPciNamespaceFilter {
            child_index: next_child,
            method: HostedAcpiPciNamespaceMethod::Address,
            output_len: HOSTED_ACPI_NAMESPACE_HEADER_LEN,
        }
    } else {
        HostedDeviceRelationQueryPhase::AcpiPciScopeMethodsPlanned
    };
}

unsafe fn store_hosted_acpi_pci_namespace_matches(
    child_index: usize,
    method: HostedAcpiPciNamespaceMethod,
    matches: nt_acpi::AcpiNamespaceMatches,
) -> Result<(), nt_status::NtStatus> {
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let properties = query
        .child_properties
        .get_mut(child_index)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    match (&properties.acpi_pci_root, &mut properties.acpi_pci_scope_discovery) {
        (
            HostedAcpiPciRootState::Present(_),
            HostedAcpiPciScopeDiscoveryState::Discovering {
                addresses,
                routing_tables,
            },
        ) => match method {
            HostedAcpiPciNamespaceMethod::Address
                if addresses.is_none() && routing_tables.is_none() =>
            {
                *addresses = Some(matches);
                Ok(())
            }
            HostedAcpiPciNamespaceMethod::RoutingTable
                if addresses.is_some() && routing_tables.is_none() =>
            {
                *routing_tables = Some(matches);
                Ok(())
            }
            HostedAcpiPciNamespaceMethod::Address
            | HostedAcpiPciNamespaceMethod::RoutingTable => {
                Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST)
            }
        },
        _ => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
    }
}

unsafe fn classify_hosted_acpi_pci_namespace_filter_result(
    child_index: usize,
    method: HostedAcpiPciNamespaceMethod,
    output_len: usize,
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> HostedAcpiPciNamespaceDisposition {
    if status.raw() as u32 == STATUS_BUFFER_OVERFLOW {
        return match (information == 0)
            .then(|| {
                nt_acpi::namespace_children_overflow_retry_len(
                    payload,
                    output_len,
                    HOSTED_ACPI_NAMESPACE_MAX_BYTES,
                )
                .ok()
            })
            .flatten()
        {
            Some(required) => HostedAcpiPciNamespaceDisposition::RetryExact(required),
            None => HostedAcpiPciNamespaceDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ),
        };
    }
    if !status.is_success() {
        return HostedAcpiPciNamespaceDisposition::Barrier(status);
    }
    let Some(payload) = hosted_acpi_namespace_success_payload(output_len, information, payload)
    else {
        return HostedAcpiPciNamespaceDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        );
    };
    let matches = match nt_acpi::parse_namespace_matches(
        payload,
        HOSTED_ACPI_NAMESPACE_MAX_CHILDREN,
    ) {
        Ok(matches) => matches,
        Err(nt_acpi::AcpiNamespaceError::Allocation) => {
            return HostedAcpiPciNamespaceDisposition::RetryResources;
        }
        Err(_) => {
            return HostedAcpiPciNamespaceDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            );
        }
    };
    match store_hosted_acpi_pci_namespace_matches(child_index, method, matches) {
        Ok(()) => HostedAcpiPciNamespaceDisposition::Advance,
        Err(status) => HostedAcpiPciNamespaceDisposition::Barrier(status),
    }
}

unsafe fn apply_hosted_acpi_pci_namespace_disposition(
    child_index: usize,
    method: HostedAcpiPciNamespaceMethod,
    disposition: HostedAcpiPciNamespaceDisposition,
) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .expect("hosted relation query disappeared while applying ACPI PCI namespace result");
    query.phase = match disposition {
        HostedAcpiPciNamespaceDisposition::RetryResources => {
            query.phase = HostedDeviceRelationQueryPhase::Barrier;
            query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return;
        }
        HostedAcpiPciNamespaceDisposition::RetryExact(output_len) => {
            HostedDeviceRelationQueryPhase::DispatchAcpiPciNamespaceFilter {
                child_index,
                method,
                output_len,
            }
        }
        HostedAcpiPciNamespaceDisposition::Advance => match method {
            HostedAcpiPciNamespaceMethod::Address => {
                HostedDeviceRelationQueryPhase::DispatchAcpiPciNamespaceFilter {
                    child_index,
                    method: HostedAcpiPciNamespaceMethod::RoutingTable,
                    output_len: HOSTED_ACPI_NAMESPACE_HEADER_LEN,
                }
            }
            HostedAcpiPciNamespaceMethod::RoutingTable => {
                HostedDeviceRelationQueryPhase::PlanAcpiPciScopeMethods { child_index }
            }
        },
        HostedAcpiPciNamespaceDisposition::Barrier(status) => {
            query.barrier_status = Some(status);
            HostedDeviceRelationQueryPhase::Barrier
        }
    };
}

unsafe fn dispatch_hosted_acpi_pci_namespace_filter(
    child_index: usize,
    method: HostedAcpiPciNamespaceMethod,
    output_len: usize,
) -> bool {
    note_hosted_relation_query_operation(
        HostedRelationQueryOperation::AcpiPciNamespace,
        child_index,
        (u64::from(method == HostedAcpiPciNamespaceMethod::RoutingTable) << 32)
            | output_len as u64,
    );
    if !(HOSTED_ACPI_NAMESPACE_HEADER_LEN..=HOSTED_ACPI_NAMESPACE_MAX_BYTES)
        .contains(&output_len)
    {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    }
    let root_state = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .and_then(|query| query.child_properties.get(child_index))
        .map(|properties| &properties.acpi_pci_root);
    match root_state {
        Some(HostedAcpiPciRootState::NotApplicable) => {
            let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
                .as_mut()
                .unwrap();
            let properties = &mut query.child_properties[child_index];
            if method != HostedAcpiPciNamespaceMethod::Address
                || output_len != HOSTED_ACPI_NAMESPACE_HEADER_LEN
                || properties.acpi_pci_scope_discovery
                    != HostedAcpiPciScopeDiscoveryState::Unqueried
            {
                query.phase = HostedDeviceRelationQueryPhase::Barrier;
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                return true;
            }
            properties.acpi_pci_scope_discovery =
                HostedAcpiPciScopeDiscoveryState::NotApplicable;
            advance_hosted_acpi_pci_scope_discovery(child_index);
            return true;
        }
        Some(HostedAcpiPciRootState::Present(_)) => {}
        Some(
            HostedAcpiPciRootState::Unqueried
            | HostedAcpiPciRootState::Evaluating { .. }
            | HostedAcpiPciRootState::Consumed,
        )
        | None => {
            set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
            return true;
        }
    }

    let Some((pdo_device_id, _, _)) = hosted_relation_child_identity(child_index) else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    {
        let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
            .as_mut()
            .unwrap();
        let state = &mut query.child_properties[child_index].acpi_pci_scope_discovery;
        let valid = match method {
            HostedAcpiPciNamespaceMethod::Address => match state {
                HostedAcpiPciScopeDiscoveryState::Unqueried => {
                    *state = HostedAcpiPciScopeDiscoveryState::Discovering {
                        addresses: None,
                        routing_tables: None,
                    };
                    true
                }
                HostedAcpiPciScopeDiscoveryState::Discovering {
                    addresses: None,
                    routing_tables: None,
                } => true,
                _ => false,
            },
            HostedAcpiPciNamespaceMethod::RoutingTable => matches!(
                state,
                HostedAcpiPciScopeDiscoveryState::Discovering {
                    addresses: Some(_),
                    routing_tables: None,
                }
            ),
        };
        if !valid {
            query.phase = HostedDeviceRelationQueryPhase::Barrier;
            query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return true;
        }
    }

    let mut output = Vec::new();
    if output.try_reserve_exact(output_len).is_err() {
        return false;
    }
    output.resize(output_len, 0);
    let input = nt_acpi::multilevel_namespace_filter_input(method.name())
        .expect("fixed ACPI PCI namespace filter was invalid");
    let result = match io_manager_mut().buffered_device_control_device_payload(
        ClientId(IO_MANAGER_COMPONENT_ID),
        pdo_device_id,
        nt_acpi::IOCTL_ACPI_ENUM_CHILDREN,
        &input,
        &mut output,
    ) {
        Ok(result) => result,
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return false,
        Err(status) => {
            set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
                status,
            ));
            return true;
        }
    };
    match result {
        ExternalDispatchResult::Completed {
            status,
            information,
            ..
        } => {
            let disposition = classify_hosted_acpi_pci_namespace_filter_result(
                child_index,
                method,
                output_len,
                status,
                information,
                &output,
            );
            if disposition == HostedAcpiPciNamespaceDisposition::RetryResources {
                return false;
            }
            apply_hosted_acpi_pci_namespace_disposition(child_index, method, disposition);
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
            let Some((origin_driver_id, completion_driver_id, completion_device_id)) = identities
            else {
                set_hosted_relation_query_disposition(
                    HostedDeviceRelationQueryDisposition::Barrier(
                        nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                    ),
                );
                return true;
            };
            let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
                .as_mut()
                .unwrap();
            query.irp_id = irp_id;
            query.origin_driver_id = origin_driver_id;
            query.completion_driver_id = completion_driver_id;
            query.completion_device_id = completion_device_id;
            query.driver_status = None;
            query.phase =
                HostedDeviceRelationQueryPhase::AwaitingAcpiPciNamespaceFilterCompletion {
                    child_index,
                    method,
                    output_len,
                };
        }
    }
    true
}

unsafe fn plan_hosted_acpi_pci_scope_methods(child_index: usize) -> bool {
    let result = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .and_then(|query| query.child_properties.get(child_index))
        .map(|properties| {
            match (
                &properties.acpi_pci_root,
                &properties.acpi_pci_scope_discovery,
            ) {
                (
                    HostedAcpiPciRootState::Present(root),
                    HostedAcpiPciScopeDiscoveryState::Discovering {
                        addresses: Some(addresses),
                        routing_tables: Some(routing_tables),
                    },
                ) => nt_pnp::plan_acpi_pci_scope_methods(
                    &root.path,
                    addresses,
                    routing_tables,
                ),
                _ => Err(nt_pnp::AcpiPciScopeError::InvalidFilteredMethod),
            }
        })
        .unwrap_or(Err(nt_pnp::AcpiPciScopeError::InvalidFilteredMethod));
    let plan = match result {
        Ok(plan) => plan,
        Err(nt_pnp::AcpiPciScopeError::Allocation) => return false,
        Err(_) => {
            set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
            return true;
        }
    };
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .unwrap();
    query.child_properties[child_index].acpi_pci_scope_discovery =
        HostedAcpiPciScopeDiscoveryState::Planned(plan);
    advance_hosted_acpi_pci_scope_discovery(child_index);
    true
}

unsafe fn advance_hosted_acpi_pci_scope_source(child_index: usize) {
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .expect("hosted relation query disappeared while advancing ACPI PCI source assembly");
    let complete = query.child_properties.get(child_index).is_some_and(|properties| {
        matches!(
            properties.acpi_pci_scope_discovery,
            HostedAcpiPciScopeDiscoveryState::NotApplicable
                | HostedAcpiPciScopeDiscoveryState::Complete(_)
        )
    });
    if !complete {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return;
    }
    let next_child = child_index.saturating_add(1);
    query.phase = if next_child < query.reported_children.len() {
        HostedDeviceRelationQueryPhase::BeginAcpiPciAddressMethods {
            child_index: next_child,
        }
    } else {
        HostedDeviceRelationQueryPhase::AcpiPciScopeSourcesReady
    };
}

unsafe fn begin_hosted_acpi_pci_address_methods(child_index: usize) -> bool {
    let state = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .and_then(|query| query.child_properties.get(child_index))
        .map(|properties| &properties.acpi_pci_scope_discovery);
    match state {
        Some(HostedAcpiPciScopeDiscoveryState::NotApplicable) => {
            advance_hosted_acpi_pci_scope_source(child_index);
            return true;
        }
        Some(HostedAcpiPciScopeDiscoveryState::Planned(plan)) => {
            let mut values = Vec::new();
            if values.try_reserve_exact(plan.addresses.len()).is_err() {
                return false;
            }
            let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
                .as_mut()
                .unwrap();
            let state = &mut query.child_properties[child_index].acpi_pci_scope_discovery;
            let HostedAcpiPciScopeDiscoveryState::Planned(plan) = core::mem::replace(
                state,
                HostedAcpiPciScopeDiscoveryState::Unqueried,
            ) else {
                query.phase = HostedDeviceRelationQueryPhase::Barrier;
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                return true;
            };
            let empty = plan.addresses.is_empty();
            *state = HostedAcpiPciScopeDiscoveryState::EvaluatingAddresses { plan, values };
            query.phase = if empty {
                HostedDeviceRelationQueryPhase::CompleteAcpiPciScopeSource { child_index }
            } else {
                HostedDeviceRelationQueryPhase::DispatchAcpiPciAddressMethod {
                    child_index,
                    address_index: 0,
                }
            };
            true
        }
        Some(
            HostedAcpiPciScopeDiscoveryState::Unqueried
            | HostedAcpiPciScopeDiscoveryState::Discovering { .. }
            | HostedAcpiPciScopeDiscoveryState::EvaluatingAddresses { .. }
            | HostedAcpiPciScopeDiscoveryState::Complete(_)
            | HostedAcpiPciScopeDiscoveryState::Staged,
        )
        | None => {
            set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
            true
        }
    }
}

fn classify_hosted_acpi_pci_address_method_result(
    status: nt_status::NtStatus,
    information: u64,
    payload: &[u8],
) -> HostedAcpiPciAddressMethodDisposition {
    if !status.is_success() {
        return HostedAcpiPciAddressMethodDisposition::Barrier(status);
    }
    if information != HOSTED_ACPI_EVAL_INTEGER_LEN as u64
        || payload.len() != HOSTED_ACPI_EVAL_INTEGER_LEN
    {
        return HostedAcpiPciAddressMethodDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        );
    }
    match nt_acpi::parse_integer_evaluation(payload) {
        Ok(value) => HostedAcpiPciAddressMethodDisposition::Value(value),
        Err(_) => HostedAcpiPciAddressMethodDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ),
    }
}

unsafe fn apply_hosted_acpi_pci_address_method_disposition(
    child_index: usize,
    address_index: usize,
    disposition: HostedAcpiPciAddressMethodDisposition,
) {
    let value = match disposition {
        HostedAcpiPciAddressMethodDisposition::Value(value) => value,
        HostedAcpiPciAddressMethodDisposition::Barrier(status) => {
            set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
                status,
            ));
            return;
        }
    };
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .expect("hosted relation query disappeared while accepting ACPI PCI address");
    let Some(properties) = query.child_properties.get_mut(child_index) else {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return;
    };
    let HostedAcpiPciScopeDiscoveryState::EvaluatingAddresses { plan, values } =
        &mut properties.acpi_pci_scope_discovery
    else {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return;
    };
    if address_index != values.len()
        || address_index >= plan.addresses.len()
        || values.capacity() < plan.addresses.len()
    {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return;
    }
    values.push(value);
    let next_index = address_index.saturating_add(1);
    query.phase = if next_index < plan.addresses.len() {
        HostedDeviceRelationQueryPhase::DispatchAcpiPciAddressMethod {
            child_index,
            address_index: next_index,
        }
    } else {
        HostedDeviceRelationQueryPhase::CompleteAcpiPciScopeSource { child_index }
    };
}

unsafe fn dispatch_hosted_acpi_pci_address_method(
    child_index: usize,
    address_index: usize,
) -> bool {
    note_hosted_relation_query_operation(
        HostedRelationQueryOperation::AcpiPciAddress,
        child_index,
        address_index as u64,
    );
    let method_path = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .and_then(|query| query.child_properties.get(child_index))
        .and_then(|properties| match &properties.acpi_pci_scope_discovery {
            HostedAcpiPciScopeDiscoveryState::EvaluatingAddresses { plan, values }
                if values.len() == address_index =>
            {
                plan.addresses.get(address_index)
            }
            _ => None,
        })
        .map(|query| query.method_path.as_str());
    let Some(method_path) = method_path else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let Some((pdo_device_id, _, _)) = hosted_relation_child_identity(child_index) else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let input = match nt_acpi::eval_method_input_ex(method_path) {
        Ok(input) => input,
        Err(_) => {
            set_hosted_relation_query_disposition(
                HostedDeviceRelationQueryDisposition::Barrier(
                    nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                ),
            );
            return true;
        }
    };
    let mut output = [0u8; HOSTED_ACPI_EVAL_INTEGER_LEN];
    let result = match io_manager_mut().buffered_device_control_device_payload(
        ClientId(IO_MANAGER_COMPONENT_ID),
        pdo_device_id,
        nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX,
        &input,
        &mut output,
    ) {
        Ok(result) => result,
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return false,
        Err(status) => {
            set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
                status,
            ));
            return true;
        }
    };
    match result {
        ExternalDispatchResult::Completed {
            status,
            information,
            ..
        } => apply_hosted_acpi_pci_address_method_disposition(
            child_index,
            address_index,
            classify_hosted_acpi_pci_address_method_result(status, information, &output),
        ),
        ExternalDispatchResult::Pending { irp_id } => {
            let identities = io_manager_mut().irp(irp_id).and_then(|irp| {
                let current = irp.current_stack()?;
                matches!(
                    &current.parameters,
                    IoParameters::DeviceControl(parameters)
                        if parameters.ioctl_code == nt_acpi::IOCTL_ACPI_EVAL_METHOD_EX
                            && parameters.input_len as usize
                                == nt_acpi::ACPI_EVAL_INPUT_BUFFER_EX_LEN
                            && parameters.output_len as usize == HOSTED_ACPI_EVAL_INTEGER_LEN
                )
                .then_some((irp.origin_driver_id, current.driver_id, current.device_id))
            });
            let Some((origin_driver_id, completion_driver_id, completion_device_id)) = identities
            else {
                set_hosted_relation_query_disposition(
                    HostedDeviceRelationQueryDisposition::Barrier(
                        nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                    ),
                );
                return true;
            };
            let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
                .as_mut()
                .unwrap();
            query.irp_id = irp_id;
            query.origin_driver_id = origin_driver_id;
            query.completion_driver_id = completion_driver_id;
            query.completion_device_id = completion_device_id;
            query.driver_status = None;
            query.phase = HostedDeviceRelationQueryPhase::AwaitingAcpiPciAddressMethodCompletion {
                child_index,
                address_index,
            };
        }
    }
    true
}

unsafe fn complete_hosted_acpi_pci_scope_source(child_index: usize) -> bool {
    let Some(relation_owner) = hosted_acpi_pci_relation_owner_endpoint() else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let Some((pdo_device_id, domain, pdo_object)) = hosted_relation_child_identity(child_index)
    else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let address_count = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .and_then(|query| query.child_properties.get(child_index))
        .and_then(|properties| match (
            &properties.acpi_pci_root,
            &properties.acpi_pci_scope_discovery,
        ) {
            (
                HostedAcpiPciRootState::Present(_),
                HostedAcpiPciScopeDiscoveryState::EvaluatingAddresses { plan, values },
            ) if plan.addresses.len() == values.len() => Some(values.len()),
            _ => None,
        });
    let Some(address_count) = address_count else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let mut addresses = Vec::new();
    if addresses.try_reserve_exact(address_count).is_err() {
        return false;
    }

    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .unwrap();
    let properties = &mut query.child_properties[child_index];
    let HostedAcpiPciRootState::Present(mut root) = core::mem::replace(
        &mut properties.acpi_pci_root,
        HostedAcpiPciRootState::Consumed,
    ) else {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    let HostedAcpiPciScopeDiscoveryState::EvaluatingAddresses { plan, values } =
        core::mem::replace(
            &mut properties.acpi_pci_scope_discovery,
            HostedAcpiPciScopeDiscoveryState::Unqueried,
        )
    else {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    };
    if plan.addresses.len() != values.len() {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    root.routing_table = plan.root_routing_table;
    for (query, adr) in plan.addresses.into_iter().zip(values) {
        addresses.push(nt_pnp::AcpiPciAddressScopeFact {
            path: query.scope,
            adr: adr as u64,
            routing_table: query.routing_table,
        });
    }
    properties.acpi_pci_scope_discovery = HostedAcpiPciScopeDiscoveryState::Complete(
        nt_pnp::AcpiPciScopeSource {
            relation_owner,
            endpoint: nt_pnp::AcpiPciProviderEndpoint {
                device_id: pdo_device_id.raw(),
                hosted_domain_id: domain.domain_id.raw(),
                hosted_domain_cookie: domain.cookie,
                pdo_object,
            },
            root,
            addresses,
        },
    );
    advance_hosted_acpi_pci_scope_source(child_index);
    true
}

unsafe fn hosted_acpi_pci_relation_owner_endpoint() -> Option<nt_pnp::AcpiPciProviderEndpoint> {
    let query = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY)).as_ref()?;
    let domain = query.relation_domain?;
    let device_id = nt_io_manager::DeviceId(query.claim.pdo_device_id);
    let pdo_object = io_manager_mut().hosted_device_address_by_identity(domain, device_id)?;
    Some(nt_pnp::AcpiPciProviderEndpoint {
        device_id: device_id.raw(),
        hosted_domain_id: domain.domain_id.raw(),
        hosted_domain_cookie: domain.cookie,
        pdo_object,
    })
}

unsafe fn stage_hosted_acpi_pci_scope_sources() -> bool {
    let Some(relation_owner) = hosted_acpi_pci_relation_owner_endpoint() else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let source_count = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .map(|query| {
            query
                .child_properties
                .iter()
                .filter(|properties| {
                    matches!(
                        properties.acpi_pci_scope_discovery,
                        HostedAcpiPciScopeDiscoveryState::Complete(_)
                    )
                })
                .count()
        })
        .unwrap_or(0);
    let relevant = source_count != 0
        || crate::hosted_pci_topology::hosted_acpi_pci_relation_has_sources(relation_owner);
    if !relevant {
        let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
            .as_mut()
            .unwrap();
        if !query.acpi_pci_scope_sources.is_empty()
            || !query.acpi_pci_link_candidates.is_empty()
            || query.acpi_pci_catalog_update.is_some()
            || query.child_properties.iter().any(|properties| {
                properties.acpi_pci_scope_discovery
                    != HostedAcpiPciScopeDiscoveryState::NotApplicable
            })
        {
            query.phase = HostedDeviceRelationQueryPhase::Barrier;
            query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        } else {
            query.phase = HostedDeviceRelationQueryPhase::AcpiPciCatalogPrepared;
        }
        return true;
    }

    let mut sources = Vec::new();
    if sources.try_reserve_exact(source_count).is_err() {
        return false;
    }
    let candidate_count = if source_count == 0 {
        0
    } else {
        (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
            .as_ref()
            .map(|query| {
                query
                    .child_properties
                    .iter()
                    .filter(|properties| {
                        matches!(properties.acpi_namespace, HostedAcpiNamespaceState::Present(_))
                    })
                    .count()
            })
            .unwrap_or(0)
    };
    let mut link_candidates = Vec::new();
    if link_candidates.try_reserve_exact(candidate_count).is_err() {
        return false;
    }
    if source_count != 0 {
        let query = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
            .as_ref()
            .unwrap();
        for properties in &query.child_properties {
            if let HostedAcpiNamespaceState::Present(namespace) = &properties.acpi_namespace {
                let Ok(path) = namespace.self_path().try_clone() else {
                    return false;
                };
                link_candidates.push(nt_pnp::AcpiPciLinkCandidateFact {
                    relation_owner,
                    path,
                });
            }
        }
    }
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .unwrap();
    if !query.acpi_pci_scope_sources.is_empty()
        || !query.acpi_pci_link_candidates.is_empty()
        || query.acpi_pci_catalog_update.is_some()
    {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    for properties in &mut query.child_properties {
        let state = core::mem::replace(
            &mut properties.acpi_pci_scope_discovery,
            HostedAcpiPciScopeDiscoveryState::Unqueried,
        );
        match state {
            HostedAcpiPciScopeDiscoveryState::NotApplicable => {
                properties.acpi_pci_scope_discovery =
                    HostedAcpiPciScopeDiscoveryState::NotApplicable;
            }
            HostedAcpiPciScopeDiscoveryState::Complete(source)
                if source.relation_owner == relation_owner =>
            {
                sources.push(source);
                properties.acpi_pci_scope_discovery = HostedAcpiPciScopeDiscoveryState::Staged;
            }
            _ => {
                query.phase = HostedDeviceRelationQueryPhase::Barrier;
                query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                return true;
            }
        }
    }
    if sources.len() != source_count {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    query.acpi_pci_scope_sources = sources;
    query.acpi_pci_link_candidates = link_candidates;
    query.phase = HostedDeviceRelationQueryPhase::PrepareAcpiPciCatalogUpdate;
    true
}

unsafe fn prepare_hosted_acpi_pci_catalog_update() -> bool {
    let Some(relation_owner) = hosted_acpi_pci_relation_owner_endpoint() else {
        set_hosted_relation_query_disposition(HostedDeviceRelationQueryDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
        return true;
    };
    let sources = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .map(|query| query.acpi_pci_scope_sources.as_slice())
        .unwrap_or(&[]);
    let link_candidates = (*core::ptr::addr_of!(HOSTED_DEVICE_RELATION_QUERY))
        .as_ref()
        .map(|query| query.acpi_pci_link_candidates.as_slice())
        .unwrap_or(&[]);
    let prepared = match crate::hosted_pci_topology::prepare_hosted_acpi_pci_relation_facts(
        relation_owner,
        sources,
        link_candidates,
    ) {
        Ok(prepared) => prepared,
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return false,
        Err(status) => {
            set_hosted_relation_query_disposition(
                HostedDeviceRelationQueryDisposition::Barrier(status),
            );
            return true;
        }
    };
    let query = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_RELATION_QUERY))
        .as_mut()
        .unwrap();
    if query.acpi_pci_catalog_update.is_some() {
        query.phase = HostedDeviceRelationQueryPhase::Barrier;
        query.barrier_status = Some(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return true;
    }
    query.acpi_pci_catalog_update = Some(prepared);
    query.phase = HostedDeviceRelationQueryPhase::AcpiPciCatalogPrepared;
    true
}
