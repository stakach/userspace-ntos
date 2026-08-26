use crate::*;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostedPnpStartTrace {
    BootService,
    DemandStart,
    HardwareProof,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpStartOptions {
    pub(crate) trace: HostedPnpStartTrace,
    pub(crate) inject_test_interrupt: bool,
}

impl HostedPnpStartOptions {
    pub(crate) const fn boot_service() -> Self {
        Self {
            trace: HostedPnpStartTrace::BootService,
            inject_test_interrupt: false,
        }
    }

    pub(crate) const fn demand_start() -> Self {
        Self {
            trace: HostedPnpStartTrace::DemandStart,
            inject_test_interrupt: false,
        }
    }

    pub(crate) const fn hardware_proof() -> Self {
        Self {
            trace: HostedPnpStartTrace::HardwareProof,
            inject_test_interrupt: true,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct HostedPnpStartReport {
    pub(crate) driver_ready_for_pnp: bool,
    pub(crate) add_device: bool,
    pub(crate) start_ok: bool,
    pub(crate) resource_granted: bool,
    pub(crate) mmio_mapped: bool,
    pub(crate) interrupt_connected: bool,
    pub(crate) interrupt_delivered: bool,
    pub(crate) interrupt_acknowledged: bool,
    pub(crate) dpc_delivered: bool,
    pub(crate) dma_adapter: bool,
    pub(crate) dma_common: bool,
    pub(crate) dma_packet_descriptors: bool,
    pub(crate) io_port_out32: bool,
    pub(crate) root_started: bool,
    pub(crate) video_route_published: bool,
    pub(crate) attempted: u64,
    pub(crate) add_device_count: u64,
    pub(crate) started: u64,
    pub(crate) resource_granted_count: u64,
    pub(crate) mmio_mapped_count: u64,
    pub(crate) interrupt_connected_count: u64,
    pub(crate) interrupt_delivered_count: u64,
    pub(crate) interrupt_acknowledged_count: u64,
    pub(crate) dpc_delivered_count: u64,
    pub(crate) dma_adapter_count: u64,
    pub(crate) dma_common_count: u64,
    pub(crate) dma_packet_descriptor_count: u64,
    pub(crate) dma_packet_descriptor_common_count: u64,
    pub(crate) dma_packet_descriptor_mapping_count: u64,
    pub(crate) dma_packet_descriptor_completed_mapping_count: u64,
    pub(crate) dma_device_tx_completion_count: u64,
    pub(crate) dma_device_rx_completion_count: u64,
    pub(crate) dma_device_interrupt_cause_count: u64,
    pub(crate) dma_device_model_failure_count: u64,
    pub(crate) dma_tx_window_observation_count: u64,
    pub(crate) dma_tx_window_enabled_count: u64,
    pub(crate) dma_tx_window_ring_ready_count: u64,
    pub(crate) dma_tx_window_posted_count: u64,
    pub(crate) dma_tx_window_idle_count: u64,
    pub(crate) dma_tx_descriptor_candidate_count: u64,
    pub(crate) dma_tx_descriptor_map_candidate_count: u64,
    pub(crate) dma_tx_descriptor_done_seen_count: u64,
    pub(crate) dma_tx_last_candidate_address: u64,
    pub(crate) dma_tx_last_candidate_len: u64,
    pub(crate) dma_tx_last_candidate_status: u64,
    pub(crate) dma_tx_last_head: u64,
    pub(crate) dma_tx_last_tail: u64,
    pub(crate) io_port_out32_count: u64,
    pub(crate) root_started_count: u64,
    pub(crate) video_route_attempted_count: u64,
    pub(crate) video_route_published_count: u64,
    pub(crate) first_error: u32,
}

struct HostedPnpDevnodeStart<'a, H, C> {
    instance_id: &'a str,
    driver_key: Option<&'a str>,
    linkage_export: Option<&'a str>,
    hardware_ids: &'a [H],
    compatible_ids: &'a [C],
}

pub(crate) unsafe fn start_inline_driver_service_devnodes(
    dc: &driver_launch::DriverComponent,
    spec: &InlineDriverLaunchSpec,
    plan: &InlineDriverLaunchPlan,
    options: HostedPnpStartOptions,
) -> HostedPnpStartReport {
    let mut report = HostedPnpStartReport {
        driver_ready_for_pnp: (dc.verdict & V_ENTERED) != 0
            && (dc.add_device != 0
                || driver_launch::hosted_driver_video_port_initialized(dc.driver_id)),
        ..HostedPnpStartReport::default()
    };
    let class_guid = if spec.class_guid_present {
        Some(spec.class_guid.as_str())
    } else {
        None
    };
    for devnode in plan.devnodes_for(spec) {
        let hardware_refs = plan.hardware_ids_for(devnode);
        let compatible_refs = plan.compatible_ids_for(devnode);
        let driver_key = if devnode.driver_key_present {
            Some(devnode.driver_key.as_str())
        } else {
            None
        };
        let linkage_export = if devnode.linkage_export_present {
            Some(devnode.linkage_export.as_str())
        } else {
            None
        };
        start_one_devnode(
            dc,
            spec.service_name.as_str(),
            class_guid,
            HostedPnpDevnodeStart {
                instance_id: devnode.instance_id.as_str(),
                driver_key,
                linkage_export,
                hardware_ids: hardware_refs,
                compatible_ids: compatible_refs,
            },
            options,
            &mut report,
        );
    }
    report
}

pub(crate) unsafe fn start_owned_driver_service_devnodes(
    dc: &driver_launch::DriverComponent,
    spec: &DriverServiceLaunchSpec,
    options: HostedPnpStartOptions,
) -> Result<HostedPnpStartReport, nt_status::NtStatus> {
    let mut report = HostedPnpStartReport {
        driver_ready_for_pnp: (dc.verdict & V_ENTERED) != 0
            && (dc.add_device != 0
                || driver_launch::hosted_driver_video_port_initialized(dc.driver_id)),
        ..HostedPnpStartReport::default()
    };
    let class_guid = spec.class_guid.as_deref();
    for devnode in &spec.devnodes {
        start_one_devnode(
            dc,
            &spec.service_name,
            class_guid,
            HostedPnpDevnodeStart {
                instance_id: &devnode.instance_id,
                driver_key: devnode.driver_key.as_deref(),
                linkage_export: devnode.linkage_export.as_deref(),
                hardware_ids: &devnode.hardware_ids,
                compatible_ids: &devnode.compatible_ids,
            },
            options,
            &mut report,
        );
    }
    if report.first_error != 0 {
        Err(nt_status::NtStatus(report.first_error as i32))
    } else if report.attempted != report.started {
        Err(nt_status::NtStatus::UNSUCCESSFUL)
    } else {
        Ok(report)
    }
}

pub(crate) enum PreparedHostedResourcePlan {
    Pci {
        bus_resources: DevnodePciBusResources,
        window: HostedPnpPciResourceDescriptor,
        lease: nt_pnp_context::ContextLease,
    },
    Root {
        grant: DevnodeRootResourceGrant,
        window: HostedPnpRootResourceDescriptor,
        lease: nt_pnp_context::ContextLease,
    },
    None,
}

impl PreparedHostedResourcePlan {
    unsafe fn release_context_lease(self) -> Result<(), nt_status::NtStatus> {
        let lease = match self {
            Self::Pci { lease, .. } | Self::Root { lease, .. } => lease,
            Self::None => return Ok(()),
        };
        release_hosted_pnp_context_lease(lease.into_identity())
    }
}

unsafe fn release_context_lease_after_error(
    lease: nt_pnp_context::ContextLease,
    status: nt_status::NtStatus,
) -> nt_status::NtStatus {
    release_hosted_pnp_context_lease(lease.into_identity())
        .err()
        .unwrap_or(status)
}

struct PreparedHostedDevnode {
    pdo_description: driver_launch::HostedPdoDescription,
    resource_plan: PreparedHostedResourcePlan,
}

unsafe fn prepare_current_hosted_devnode<H, C>(
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
) -> Result<PreparedHostedDevnode, nt_status::NtStatus>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    let lease = acquire_hosted_pnp_context_lease()?;
    let context = match hosted_pnp_context_description(&lease) {
        Ok(context) => context,
        Err(status) => {
            return Err(release_context_lease_after_error(lease, status));
        }
    };
    if let Some(device) = nt_pnp::find_pci_device_for_devnode(
        &context.pci_devices,
        instance_id,
        hardware_ids,
        compatible_ids,
    ) {
        let window = context
            .pci_windows
            .iter()
            .find(|window| window.matches(device))
            .cloned();
        let Some(window) = window else {
            return Err(release_context_lease_after_error(
                lease,
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
        };
        let firmware_routed = device.irq_pin != 0 && !matches!(device.irq_line, 0 | u8::MAX);
        let boot_interrupt = firmware_routed.then_some(nt_pnp::PciInterruptAssignment {
            bus_level: device.irq_line as u32,
            vector: window.interrupt_vector,
            latched: window.interrupt_latched,
            affinity: 1,
        });
        let Some(bus_resources) = build_devnode_pci_bus_resources(device, boot_interrupt) else {
            return Err(release_context_lease_after_error(
                lease,
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
        };
        let resource_publication = nt_root_bus::PdoResourcePublication {
            raw_boot_resources: nt_root_bus::BusResourceState::Present(
                bus_resources.raw_boot_resources.clone(),
            ),
            resource_requirements: nt_root_bus::BusResourceState::Present(
                bus_resources.resource_requirements.clone(),
            ),
        };
        return Ok(PreparedHostedDevnode {
            pdo_description: driver_launch::HostedPdoDescription {
                bus_information: nt_pnp_manager::PnpBusInformation {
                    bus_type_guid: nt_pnp_manager::GUID_BUS_TYPE_PCI,
                    legacy_bus_type: nt_pnp_manager::INTERFACE_TYPE_PCI_BUS,
                    bus_number: device.bus as u32,
                },
                capabilities: nt_pnp_manager::PdoCapabilities {
                    removable: false,
                    eject_supported: false,
                    surprise_removal_ok: false,
                    address: ((device.dev as u32) << 16) | device.func as u32,
                },
                resource_publication,
                translated_boot_resources: nt_pnp_manager::PropertyBlobState::Present(
                    bus_resources.translated_boot_resources.clone(),
                ),
            },
            resource_plan: PreparedHostedResourcePlan::Pci {
                bus_resources,
                window,
                lease,
            },
        });
    }

    if let Some(profile) =
        root_bus_resource_profile_for_devnode(instance_id, hardware_ids, compatible_ids)
    {
        let window = context
            .root_windows
            .iter()
            .find(|window| window.matches_profile(&profile))
            .cloned();
        let Some(window) = window else {
            return Err(release_context_lease_after_error(
                lease,
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
        };
        let Some(grant) = assign_devnode_root_dma_resources(
            instance_id,
            hardware_ids,
            compatible_ids,
            window.interrupt_vector,
            window.interrupt_latched,
            window.dma_len,
        ) else {
            return Err(release_context_lease_after_error(
                lease,
                nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            ));
        };
        let resource_publication = nt_root_bus::PdoResourcePublication {
            raw_boot_resources: nt_root_bus::BusResourceState::Present(
                grant.raw_boot_resources.clone(),
            ),
            resource_requirements: nt_root_bus::BusResourceState::Present(
                grant.resource_requirements.clone(),
            ),
        };
        return Ok(PreparedHostedDevnode {
            pdo_description: driver_launch::HostedPdoDescription {
                bus_information: nt_pnp_manager::PnpBusInformation {
                    bus_type_guid: nt_pnp_manager::GUID_BUS_TYPE_INTERNAL,
                    legacy_bus_type: nt_pnp_manager::INTERFACE_TYPE_PNP_BUS,
                    bus_number: 0,
                },
                capabilities: nt_pnp_manager::PdoCapabilities {
                    removable: false,
                    eject_supported: false,
                    surprise_removal_ok: false,
                    address: nt_pnp_manager::DEVICE_ADDRESS_UNAVAILABLE,
                },
                resource_publication,
                translated_boot_resources: nt_pnp_manager::PropertyBlobState::Present(
                    grant.translated_boot_resources.clone(),
                ),
            },
            resource_plan: PreparedHostedResourcePlan::Root {
                grant,
                window,
                lease,
            },
        });
    }

    release_hosted_pnp_context_lease(lease.into_identity())?;

    Ok(PreparedHostedDevnode {
        pdo_description: driver_launch::HostedPdoDescription {
            bus_information: nt_pnp_manager::PnpBusInformation {
                bus_type_guid: nt_pnp_manager::GUID_BUS_TYPE_INTERNAL,
                legacy_bus_type: nt_pnp_manager::INTERFACE_TYPE_PNP_BUS,
                bus_number: 0,
            },
            capabilities: nt_pnp_manager::PdoCapabilities {
                removable: false,
                eject_supported: false,
                surprise_removal_ok: false,
                address: nt_pnp_manager::DEVICE_ADDRESS_UNAVAILABLE,
            },
            resource_publication: nt_root_bus::PdoResourcePublication::none(),
            translated_boot_resources: nt_pnp_manager::PropertyBlobState::KnownNone,
        },
        resource_plan: PreparedHostedResourcePlan::None,
    })
}

unsafe fn start_one_devnode<H, C>(
    dc: &driver_launch::DriverComponent,
    service_name: &str,
    class_guid: Option<&str>,
    devnode: HostedPnpDevnodeStart<'_, H, C>,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) where
    H: AsRef<str>,
    C: AsRef<str>,
{
    report.attempted += 1;
    let prepared = match prepare_current_hosted_devnode(
        devnode.instance_id,
        devnode.hardware_ids,
        devnode.compatible_ids,
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            remember_error(report, status);
            print_resource_preparation_failure(
                options.trace,
                service_name,
                devnode.instance_id,
                status,
            );
            return;
        }
    };
    let PreparedHostedDevnode {
        pdo_description,
        resource_plan,
    } = prepared;
    match driver_launch::call_add_device_for_driver(
        dc.driver_id,
        class_guid,
        devnode.driver_key,
        devnode.linkage_export,
        devnode.instance_id,
        devnode.hardware_ids,
        devnode.compatible_ids,
        pdo_description,
    ) {
        Ok(device_id) => {
            report.add_device = true;
            report.add_device_count += 1;
            print_add_device_success(options.trace, service_name, devnode.instance_id, device_id);
            let start_status = match grant_prepared_hosted_devnode_resources(
                device_id,
                resource_plan,
            ) {
                Ok(Some(grant)) => {
                    print_hosted_devnode_grant(
                        service_name.as_bytes(),
                        devnode.instance_id.as_bytes(),
                        &grant,
                    );
                    match driver_launch::commit_hosted_device_resource_assignment(
                        device_id,
                        &grant.raw_resource_list,
                        &grant.translated_resource_list,
                    ) {
                        Ok(()) => {
                            if driver_launch::hosted_device_video_port_initialized(device_id) {
                                match driver_launch::start_hosted_video_device(
                                    device_id,
                                    &grant.raw_resource_list,
                                    &grant.translated_resource_list,
                                    grant.pci_interrupt_line,
                                ) {
                                    Ok(()) => Ok(()),
                                    Err(status) => Err(rollback_pre_dispatch_start(
                                        device_id,
                                        grant.pci_interrupt_line,
                                        status,
                                    )),
                                }
                            } else {
                                canonical_start_status(
                                    device_id,
                                    &grant.raw_resource_list,
                                    &grant.translated_resource_list,
                                    grant.pci_interrupt_line,
                                )
                            }
                        }
                        Err(status) => Err(rollback_pre_dispatch_start(
                            device_id,
                            grant.pci_interrupt_line,
                            status,
                        )),
                    }
                }
                Ok(None) => {
                    match driver_launch::commit_hosted_device_resource_assignment(
                        device_id,
                        &[],
                        &[],
                    ) {
                        Ok(()) => {
                            if driver_launch::hosted_device_video_port_initialized(device_id) {
                                match driver_launch::start_hosted_video_device(
                                    device_id,
                                    &[],
                                    &[],
                                    None,
                                ) {
                                    Ok(()) => Ok(()),
                                    Err(status) => Err(rollback_pre_dispatch_start(
                                        device_id, None, status,
                                    )),
                                }
                            } else {
                                canonical_start_status(device_id, &[], &[], None)
                            }
                        }
                        Err(status) => {
                            Err(rollback_pre_dispatch_start(device_id, None, status))
                        }
                    }
                }
                Err(status) => {
                    let status = rollback_pre_dispatch_start(device_id, None, status);
                    print_resource_grant_failure(
                        options.trace,
                        service_name,
                        devnode.instance_id,
                        status,
                    );
                    Err(status)
                }
            };
            let start_status_raw = match start_status {
                Ok(()) => {
                    report.start_ok = true;
                    report.started += 1;
                    0
                }
                Err(status) => {
                    remember_error(report, status);
                    status.raw() as u32
                }
            };
            print_start_status(
                options.trace,
                service_name,
                devnode.instance_id,
                start_status_raw,
            );
            if options.inject_test_interrupt && start_status_raw == 0 {
                inject_proof_interrupt(
                    device_id,
                    options.trace,
                    service_name,
                    devnode.instance_id,
                    report,
                );
            }
            collect_hardware_evidence(
                device_id,
                options.trace,
                service_name,
                devnode.instance_id,
                start_status_raw,
                report,
            );
            if start_status_raw == 0 {
                try_publish_hosted_video_route(
                    device_id,
                    service_name,
                    devnode.instance_id,
                    report,
                );
            }
        }
        Err(status) => {
            let status = resource_plan
                .release_context_lease()
                .err()
                .unwrap_or(status);
            remember_error(report, status);
            print_add_device_failure(options.trace, service_name, devnode.instance_id, status);
        }
    }
}

unsafe fn canonical_start_status(
    device_id: u64,
    raw_resource_list: &[u8],
    translated_resource_list: &[u8],
    pci_interrupt_line: Option<crate::pnp::PciInterruptLineProgramming>,
) -> Result<(), nt_status::NtStatus> {
    match driver_launch::start_hosted_device_canonical(
        device_id,
        raw_resource_list,
        translated_resource_list,
        pci_interrupt_line,
    ) {
        Ok(driver_launch::HostedPnpStartOutcome::Started) => Ok(()),
        Ok(driver_launch::HostedPnpStartOutcome::Failed(status)) => Err(status),
        Ok(driver_launch::HostedPnpStartOutcome::Pending { .. }) => {
            Err(nt_status::NtStatus::PENDING)
        }
        Ok(driver_launch::HostedPnpStartOutcome::Indeterminate {
            transport_status,
            ..
        }) => Err(transport_status),
        Ok(driver_launch::HostedPnpStartOutcome::RepairRequired {
            driver_status,
            repair_status,
        }) => Err(if driver_status.is_success() {
            repair_status
        } else {
            driver_status
        }),
        Err(failure) if failure.rollback_safe => Err(rollback_pre_dispatch_start(
            device_id,
            pci_interrupt_line,
            failure.status,
        )),
        Err(failure) => Err(failure.status),
    }
}

unsafe fn rollback_pre_dispatch_start(
    device_id: u64,
    pci_interrupt_line: Option<crate::pnp::PciInterruptLineProgramming>,
    original_status: nt_status::NtStatus,
) -> nt_status::NtStatus {
    if let Err(status) = driver_launch::rollback_hosted_device_start(device_id) {
        return status;
    }
    if pci_interrupt_line
        .map(|programming| crate::pnp::restore_pci_interrupt_line(programming))
        .is_some_and(|restored| !restored)
    {
        print_str(b"[driver-launch] PCI InterruptLine rollback failed device_id=");
        print_u64(device_id);
        print_str(b"\n");
        return nt_status::NtStatus::UNSUCCESSFUL;
    }
    original_status
}

unsafe fn grant_prepared_hosted_devnode_resources(
    device_id: u64,
    plan: PreparedHostedResourcePlan,
) -> Result<Option<HostedDevnodeGrant>, nt_status::NtStatus> {
    grant_hosted_devnode_resources(device_id, plan)
}

fn remember_error(report: &mut HostedPnpStartReport, status: nt_status::NtStatus) {
    if report.first_error == 0 {
        report.first_error = status.raw() as u32;
    }
}

fn hosted_display_service_registry_path(service_name: &str) -> Option<Vec<u8>> {
    if service_name.is_empty() || !service_name.as_bytes().iter().all(|byte| byte.is_ascii()) {
        return None;
    }
    let prefix = b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    let suffix = b"\\Device0";
    let len = prefix
        .len()
        .checked_add(service_name.len())?
        .checked_add(suffix.len())?;
    let mut path = Vec::new();
    path.try_reserve_exact(len).ok()?;
    path.extend_from_slice(prefix);
    path.extend_from_slice(service_name.as_bytes());
    path.extend_from_slice(suffix);
    Some(path)
}

unsafe fn try_publish_hosted_video_route(
    device_id: u64,
    service_name: &str,
    instance_id: &str,
    report: &mut HostedPnpStartReport,
) {
    if !driver_launch::hosted_device_video_port_initialized(device_id) {
        return;
    }
    report.video_route_attempted_count += 1;
    let Some(_route) = driver_launch::hosted_video_route_info(device_id) else {
        remember_error(report, nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        print_hosted_video_route_published(service_name, instance_id, device_id, false);
        return;
    };
    let Some(service_registry_path) = hosted_display_service_registry_path(service_name) else {
        remember_error(report, nt_status::NtStatus::INVALID_PARAMETER);
        print_hosted_video_route_published(service_name, instance_id, device_id, false);
        return;
    };
    let published = crate::video_device::publish_hosted_video_device_route(
        &crate::video_device::HostedVideoDeviceRegistration {
            device_id,
            service_registry_path: service_registry_path.as_slice(),
            allocate_projection: crate::win32k_subsystem::pool_alloc_export,
        },
    );
    report.video_route_published |= published;
    if published {
        report.video_route_published_count += 1;
    } else {
        remember_error(report, nt_status::NtStatus::UNSUCCESSFUL);
    }
    print_hosted_video_route_published(service_name, instance_id, device_id, published);
}

unsafe fn inject_proof_interrupt(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    report: &mut HostedPnpStartReport,
) {
    if let Some(evidence) = driver_launch::hosted_hardware_evidence(device_id) {
        if evidence.interrupt_connected()
            && (evidence.mmio_mapped() || evidence.io_port_out32_serviced())
        {
            let ack_window = root_window_for_evidence(device_id, evidence);
            if let Some(ref window) = ack_window {
                core::ptr::write_volatile(
                    (window.mmio_seed_va + ROOT_DMA_PROOF_INTERRUPT_ACK_OFFSET) as *mut u32,
                    0,
                );
                core::ptr::write_volatile(
                    (window.mmio_seed_va + ROOT_DMA_PROOF_INTERRUPT_STATUS_OFFSET) as *mut u32,
                    1,
                );
            }
            match driver_launch::inject_hosted_device_interrupt(device_id) {
                Ok(delivery) => {
                    let ack = ack_window
                        .as_ref()
                        .map(|window| {
                            core::ptr::read_volatile(
                                (window.mmio_seed_va + ROOT_DMA_PROOF_INTERRUPT_ACK_OFFSET)
                                    as *const u32,
                            )
                        })
                        .unwrap_or(0);
                    if ack_window.is_some() {
                        report.interrupt_acknowledged |= ack == 1;
                        if ack == 1 {
                            report.interrupt_acknowledged_count += 1;
                        }
                    }
                    match driver_launch::redrive_hosted_device_tx_interrupt(device_id) {
                        Ok(_) => {}
                        Err(status) => {
                            print_interrupt_delivery_failure(trace, status);
                            remember_error(report, status);
                        }
                    }
                    print_interrupt_delivery(trace, service_name, instance_id, delivery, ack);
                }
                Err(status) => {
                    print_interrupt_delivery_failure(trace, status);
                    remember_error(report, status);
                }
            }
        }
    }
}

unsafe fn root_window_for_evidence(
    device_id: u64,
    evidence: driver_launch::HostedHardwareEvidence,
) -> Option<HostedPnpRootResourceDescriptor> {
    let lease = driver_launch::hosted_pnp_context_lease_for_device(device_id)?;
    hosted_pnp_root_resource_by_identity(
        lease,
        evidence.resource_mmio_phys,
        evidence.dma_common_va,
        evidence.dma_common_logical,
    )
    .ok()?
}

fn collect_hardware_evidence(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    report: &mut HostedPnpStartReport,
) {
    if let Err(status) = unsafe { driver_launch::redrive_hosted_device_tx_interrupt(device_id) } {
        remember_error(report, status);
    }
    if let Some(evidence) = driver_launch::hosted_hardware_evidence(device_id) {
        if evidence.resource_granted() {
            report.resource_granted = true;
            report.resource_granted_count += 1;
            report.mmio_mapped |= evidence.mmio_mapped();
            report.interrupt_connected |= evidence.interrupt_connected();
            report.interrupt_delivered |= evidence.interrupt_delivered();
            report.dpc_delivered |= evidence.dpc_delivered();
            report.dma_adapter |= evidence.dma_adapter_created();
            report.dma_common |= evidence.dma_common_allocated();
            report.dma_packet_descriptors |= evidence.dma_packet_descriptors_observed();
            report.io_port_out32 |= evidence.io_port_out32_serviced();
            report.root_started |= evidence.root_pdo_started;
            if evidence.mmio_mapped() {
                report.mmio_mapped_count += 1;
            }
            if evidence.interrupt_connected() {
                report.interrupt_connected_count += 1;
            }
            if evidence.interrupt_delivered() {
                report.interrupt_delivered_count += 1;
            }
            if evidence.dpc_delivered() {
                report.dpc_delivered_count += 1;
            }
            if evidence.dma_adapter_created() {
                report.dma_adapter_count += 1;
            }
            if evidence.dma_common_allocated() {
                report.dma_common_count += 1;
            }
            if evidence.dma_packet_descriptors_observed() {
                report.dma_packet_descriptor_count += 1;
            }
            report.dma_packet_descriptor_common_count = report
                .dma_packet_descriptor_common_count
                .saturating_add(evidence.dma_descriptor_common_buffers);
            report.dma_packet_descriptor_mapping_count = report
                .dma_packet_descriptor_mapping_count
                .saturating_add(evidence.dma_descriptor_transfer_mappings);
            report.dma_packet_descriptor_completed_mapping_count = report
                .dma_packet_descriptor_completed_mapping_count
                .saturating_add(evidence.dma_descriptor_completed_transfer_mappings);
            report.dma_device_tx_completion_count = report
                .dma_device_tx_completion_count
                .saturating_add(evidence.dma_device_tx_completions);
            report.dma_device_rx_completion_count = report
                .dma_device_rx_completion_count
                .saturating_add(evidence.dma_device_rx_completions);
            report.dma_device_interrupt_cause_count = report
                .dma_device_interrupt_cause_count
                .saturating_add(evidence.dma_device_interrupt_causes);
            report.dma_device_model_failure_count = report
                .dma_device_model_failure_count
                .saturating_add(evidence.dma_device_model_failures);
            report.dma_tx_window_observation_count = report
                .dma_tx_window_observation_count
                .saturating_add(evidence.dma_tx_window_observations);
            report.dma_tx_window_enabled_count = report
                .dma_tx_window_enabled_count
                .saturating_add(evidence.dma_tx_window_enabled);
            report.dma_tx_window_ring_ready_count = report
                .dma_tx_window_ring_ready_count
                .saturating_add(evidence.dma_tx_window_ring_ready);
            report.dma_tx_window_posted_count = report
                .dma_tx_window_posted_count
                .saturating_add(evidence.dma_tx_window_posted);
            report.dma_tx_window_idle_count = report
                .dma_tx_window_idle_count
                .saturating_add(evidence.dma_tx_window_idle);
            report.dma_tx_descriptor_candidate_count = report
                .dma_tx_descriptor_candidate_count
                .saturating_add(evidence.dma_tx_descriptor_candidates);
            report.dma_tx_descriptor_map_candidate_count = report
                .dma_tx_descriptor_map_candidate_count
                .saturating_add(evidence.dma_tx_descriptor_map_candidates);
            report.dma_tx_descriptor_done_seen_count = report
                .dma_tx_descriptor_done_seen_count
                .saturating_add(evidence.dma_tx_descriptor_done_seen);
            if evidence.dma_tx_descriptor_candidates != 0
                || evidence.dma_tx_descriptor_done_seen != 0
            {
                report.dma_tx_last_candidate_address = evidence.dma_tx_last_candidate_address;
                report.dma_tx_last_candidate_len = evidence.dma_tx_last_candidate_len;
                report.dma_tx_last_candidate_status = evidence.dma_tx_last_candidate_status;
            }
            if evidence.dma_tx_window_observations != 0 {
                report.dma_tx_last_head = evidence.dma_tx_last_head;
                report.dma_tx_last_tail = evidence.dma_tx_last_tail;
            }
            if evidence.io_port_out32_serviced() {
                report.io_port_out32_count += 1;
            }
            if evidence.root_pdo_started {
                report.root_started_count += 1;
            }
        }
        print_hardware_evidence(trace, service_name, instance_id, start_status_raw, evidence);
    }
}

fn print_add_device_success(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    device_id: u64,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware AddDevice service="
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand AddDevice service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] AddDevice service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" device_id=");
    print_u64(device_id);
    print_str(b"\n");
}

fn print_add_device_failure(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: nt_status::NtStatus,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware AddDevice failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand AddDevice failed status=0x",
        HostedPnpStartTrace::BootService => b"[driver-launch] AddDevice failed status=0x",
    });
    print_hex(status.raw() as u32);
    print_str(b" service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b"\n");
}

fn print_resource_preparation_failure(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: nt_status::NtStatus,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware bus resource publication failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => {
            b"[driver-launch] demand bus resource publication failed status=0x"
        }
        HostedPnpStartTrace::BootService => {
            b"[driver-launch] bus resource publication failed status=0x"
        }
    });
    print_hex(status.raw() as u32);
    print_str(b" service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b"\n");
}

fn print_hosted_video_route_published(
    service_name: &str,
    instance_id: &str,
    device_id: u64,
    published: bool,
) {
    print_str(b"[video-device] hosted route service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" device_id=");
    print_u64(device_id);
    print_str(b" published=");
    print_u64(published as u64);
    print_str(b"\n");
}

fn print_resource_grant_failure(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: nt_status::NtStatus,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware resource grant failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => {
            b"[driver-launch] demand resource grant failed status=0x"
        }
        HostedPnpStartTrace::BootService => b"[driver-launch] resource grant failed status=0x",
    });
    print_hex(status.raw() as u32);
    print_str(b" service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b"\n");
}

fn print_start_status(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: u32,
) {
    if status == 0 {
        print_str(match trace {
            HostedPnpStartTrace::HardwareProof => {
                b"[driver-launch] generic hardware StartDevice service="
            }
            HostedPnpStartTrace::DemandStart => b"[driver-launch] demand StartDevice service=",
            HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice service=",
        });
    } else {
        print_str(match trace {
            HostedPnpStartTrace::HardwareProof => {
                b"[driver-launch] generic hardware StartDevice failed service="
            }
            HostedPnpStartTrace::DemandStart => {
                b"[driver-launch] demand StartDevice failed service="
            }
            HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice failed service=",
        });
    }
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" status=");
    print_hex(status);
    print_str(b"\n");
}

fn print_interrupt_delivery(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    delivery: driver_launch::HostedInterruptDelivery,
    ack: u32,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware interrupt delivery service="
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand interrupt delivery service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] interrupt delivery service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" id=");
    print_u64(delivery.interrupt_id);
    print_str(b" vector=");
    print_u64(delivery.vector as u64);
    print_str(b" claimed=");
    print_u64(delivery.claimed as u64);
    print_str(b" ack=");
    print_u64(ack as u64);
    print_str(b"\n");
}

fn print_interrupt_delivery_failure(trace: HostedPnpStartTrace, status: nt_status::NtStatus) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware interrupt delivery failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => {
            b"[driver-launch] demand interrupt delivery failed status=0x"
        }
        HostedPnpStartTrace::BootService => b"[driver-launch] interrupt delivery failed status=0x",
    });
    print_hex(status.raw() as u32);
    print_str(b"\n");
}

fn print_hardware_evidence(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    evidence: driver_launch::HostedHardwareEvidence,
) {
    if trace == HostedPnpStartTrace::HardwareProof {
        print_str(b"[driver-launch] generic hardware evidence service=");
        print_str(service_name.as_bytes());
        print_str(b" devnode=");
        print_str(instance_id.as_bytes());
        print_str(b" start=");
        print_hex(start_status_raw);
        print_str(b" mmio=");
        print_u64(evidence.mmio_mapped() as u64);
        print_str(b" irq=");
        print_u64(evidence.interrupt_connected() as u64);
        print_str(b"/");
        print_u64(evidence.interrupt_delivered() as u64);
        print_str(b" dpc=");
        print_u64(evidence.dpc_delivered() as u64);
        print_str(b" dma=");
        print_u64(evidence.dma_adapter_created() as u64);
        print_str(b"/");
        print_u64(evidence.dma_common_allocated() as u64);
        print_str(b" desc=");
        print_u64(evidence.dma_packet_descriptors_observed() as u64);
        print_str(b" txrx=");
        print_u64(evidence.dma_device_tx_completions);
        print_str(b"/");
        print_u64(evidence.dma_device_rx_completions);
        print_str(b" pbrx=");
        print_u64(evidence.dma_device_post_bind_rx_attempts);
        print_str(b"/");
        print_u64(evidence.dma_device_post_bind_rx_deliveries);
        print_str(b"/");
        print_u64(evidence.dma_device_post_bind_rx_failures);
        print_str(b" io=");
        print_u64(evidence.io_port_out32_serviced() as u64);
        print_str(b" video=");
        print_u64(evidence.video_initialized as u64);
        print_str(b"/");
        print_u64(evidence.video_find_adapter_calls);
        print_str(b" root=");
        print_u64(evidence.root_pdo_started as u64);
        print_str(b"\n");
        return;
    }

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"bus");
    print_str(b" start=");
    print_hex(start_status_raw);
    print_str(b" mmio=");
    print_u64(evidence.mmio_mapped() as u64);
    print_str(b" mmio_len=");
    print_u64(evidence.resource_mmio_len);
    print_str(b" mmio_map_len=");
    print_u64(evidence.resource_mmio_map_len);
    print_str(b" root_started=");
    print_u64(evidence.root_pdo_started as u64);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"irq");
    print_str(b" int=");
    print_u64(evidence.interrupt_connected() as u64);
    print_str(b" int_ctx=");
    print_u64((evidence.interrupt_context != 0) as u64);
    print_str(b" int_delivered=");
    print_u64(evidence.interrupt_delivered() as u64);
    print_str(b" int_count=");
    print_u64(evidence.interrupt_deliveries);
    print_str(b" dpc=");
    print_u64(evidence.dpc_delivered() as u64);
    print_str(b" dpc_count=");
    print_u64(evidence.dpc_deliveries);
    print_str(b" dpc_drops=");
    print_u64(evidence.dpc_drops);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"dma");
    print_str(b" dma_adapter=");
    print_u64(evidence.dma_adapter_created() as u64);
    print_str(b" dma_common=");
    print_u64(evidence.dma_common_allocated() as u64);
    print_str(b" dma_len=");
    print_u64(evidence.dma_common_len);
    print_str(b" dma_desc=");
    print_u64(evidence.dma_packet_descriptors_observed() as u64);
    print_str(b" dma_desc_rings=");
    print_u64(evidence.dma_descriptor_rings);
    print_str(b" dma_desc_addr/ok=");
    print_u64(evidence.dma_descriptor_addresses);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_decodable);
    print_str(b" dma_desc_common/map=");
    print_u64(evidence.dma_descriptor_common_buffers);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_transfer_mappings);
    print_str(b" dma_desc_len/done=");
    print_u64(evidence.dma_descriptor_lengths);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_completed);
    print_str(b" dma_desc_done_common/map=");
    print_u64(evidence.dma_descriptor_completed_common_buffers);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_completed_transfer_mappings);
    print_str(b" dma_desc_bad/fail=");
    print_u64(evidence.dma_descriptor_malformed);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_observation_failures);
    print_str(b" dma_dev_tx/rx=");
    print_u64(evidence.dma_device_tx_completions);
    print_str(b"/");
    print_u64(evidence.dma_device_rx_completions);
    print_str(b" dma_dev_cause/fail=");
    print_u64(evidence.dma_device_interrupt_causes);
    print_str(b"/");
    print_u64(evidence.dma_device_model_failures);
    print_str(b" dma_post_bind_rx=");
    print_u64(evidence.dma_device_post_bind_rx_attempts);
    print_str(b"/");
    print_u64(evidence.dma_device_post_bind_rx_deliveries);
    print_str(b"/");
    print_u64(evidence.dma_device_post_bind_rx_failures);
    print_str(b" dma_tx_window=");
    print_u64(evidence.dma_tx_window_observations);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_enabled);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_ring_ready);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_posted);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_idle);
    print_str(b" dma_tx_head/tail=");
    print_u64(evidence.dma_tx_last_head);
    print_str(b"/");
    print_u64(evidence.dma_tx_last_tail);
    print_str(b" dma_tx_candidates/map/done=");
    print_u64(evidence.dma_tx_descriptor_candidates);
    print_str(b"/");
    print_u64(evidence.dma_tx_descriptor_map_candidates);
    print_str(b"/");
    print_u64(evidence.dma_tx_descriptor_done_seen);
    print_str(b" dma_tx_last_desc=0x");
    print_hex(evidence.dma_tx_last_candidate_address as u32);
    print_str(b"/");
    print_u64(evidence.dma_tx_last_candidate_len);
    print_str(b"/0x");
    print_hex(evidence.dma_tx_last_candidate_status as u32);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"io");
    print_str(b" io_out32=");
    print_u64(evidence.io_port_out32_serviced() as u64);
    print_str(b" io_out32_count=");
    print_u64(evidence.io_port_out32_faults);
    print_str(b" io_cap=");
    print_u64(evidence.resource_io_port_cap);
    print_str(b"/");
    print_u64(evidence.resource_io_port_component_cap);
    print_str(b" io_in16=");
    print_u64(evidence.io_port_in16_calls);
    print_str(b"/");
    print_u64(evidence.io_port_in16_failures);
    print_str(b" io_out16=");
    print_u64(evidence.io_port_out16_calls);
    print_str(b"/");
    print_u64(evidence.io_port_out16_failures);
    print_str(b" io16_denied=");
    print_u64(evidence.io_port_in16_denied);
    print_str(b"/");
    print_u64(evidence.io_port_out16_denied);
    print_str(b" io16_last_status=");
    print_u64(evidence.io_port_last_in16_status);
    print_str(b"/");
    print_u64(evidence.io_port_last_out16_status);
    print_str(b" io16_last_port=0x");
    print_hex(evidence.io_port_last_in16_port as u32);
    print_str(b"/0x");
    print_hex(evidence.io_port_last_out16_port as u32);
    print_str(b" io16_last_value=0x");
    print_hex(evidence.io_port_last_in16_value as u32);
    print_str(b"/0x");
    print_hex(evidence.io_port_last_out16_value as u32);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"video");
    print_str(b" video_init=");
    print_u64(evidence.video_initialized as u64);
    print_str(b" video_find=");
    print_u64(evidence.video_find_adapter_calls);
    print_str(b" video_find_status=0x");
    print_hex(evidence.video_find_adapter_status);
    print_str(b" video_again=");
    print_u64(evidence.video_find_adapter_again as u64);
    print_str(b" video_hwinit=");
    print_u64(evidence.video_hw_initialize_calls);
    print_str(b" video_hwinit_ok=");
    print_u64(evidence.video_hw_initialize_ok as u64);
    print_str(b" video_startio=");
    print_u64(evidence.video_hw_start_io_calls);
    print_str(b" video_reg_set=");
    print_u64(evidence.video_registry_set_calls);
    print_str(b"/");
    print_u64(evidence.video_registry_set_bytes);
    print_str(b" video_reg_status=0x");
    print_hex(evidence.video_registry_commit_status as u32);
    print_str(b" video_reg_failures=");
    print_u64(evidence.video_registry_commit_failures);
    print_str(b"\n");
}

fn print_hardware_evidence_prefix(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    group: &[u8],
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => b"[driver-launch] generic hardware evidence service=",
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand hardware evidence service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] hardware evidence service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" group=");
    print_str(group);
}
