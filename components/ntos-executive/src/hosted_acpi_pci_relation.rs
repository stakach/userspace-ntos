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
        if information != 0 {
            return HostedAcpiPciNamespaceDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            );
        }
        return match nt_acpi::namespace_children_required_len(
            payload,
            HOSTED_ACPI_NAMESPACE_MAX_BYTES,
        ) {
            Ok(required) if required > output_len => {
                HostedAcpiPciNamespaceDisposition::RetryExact(required)
            }
            Ok(_) | Err(_) => HostedAcpiPciNamespaceDisposition::Barrier(
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ),
        };
    }
    if !status.is_success() {
        return HostedAcpiPciNamespaceDisposition::Barrier(status);
    }
    if information != output_len as u64
        || payload.len() != output_len
        || !(HOSTED_ACPI_NAMESPACE_HEADER_LEN..=HOSTED_ACPI_NAMESPACE_MAX_BYTES)
            .contains(&output_len)
    {
        return HostedAcpiPciNamespaceDisposition::Barrier(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        );
    }
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
            HostedAcpiPciRootState::Unqueried | HostedAcpiPciRootState::Evaluating { .. },
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
