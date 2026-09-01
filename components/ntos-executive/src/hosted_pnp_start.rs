use crate::*;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostedPnpStartTrace {
    BootService,
    DemandStart,
    ConfigPnp,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpStartOptions {
    pub(crate) trace: HostedPnpStartTrace,
    reuse_existing_stack: bool,
}

impl HostedPnpStartOptions {
    pub(crate) const fn boot_service() -> Self {
        Self {
            trace: HostedPnpStartTrace::BootService,
            reuse_existing_stack: false,
        }
    }

    pub(crate) const fn demand_start() -> Self {
        Self {
            trace: HostedPnpStartTrace::DemandStart,
            reuse_existing_stack: false,
        }
    }

    pub(crate) const fn config_pnp() -> Self {
        Self {
            trace: HostedPnpStartTrace::ConfigPnp,
            reuse_existing_stack: false,
        }
    }

    pub(crate) const fn rebalance() -> Self {
        Self {
            trace: HostedPnpStartTrace::DemandStart,
            reuse_existing_stack: true,
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
    pub(crate) dpc_delivered: bool,
    pub(crate) dma_adapter: bool,
    pub(crate) dma_common: bool,
    pub(crate) io_port_out32: bool,
    pub(crate) root_started: bool,
    pub(crate) video_route_published: bool,
    pub(crate) attempted: u64,
    pub(crate) terminal: u64,
    pub(crate) add_device_count: u64,
    pub(crate) started: u64,
    pub(crate) failed: u64,
    pub(crate) pending: u64,
    pub(crate) pending_observed: u64,
    pub(crate) indeterminate: u64,
    pub(crate) resource_granted_count: u64,
    pub(crate) mmio_mapped_count: u64,
    pub(crate) interrupt_connected_count: u64,
    pub(crate) interrupt_delivered_count: u64,
    pub(crate) dpc_delivered_count: u64,
    pub(crate) dma_adapter_count: u64,
    pub(crate) dma_common_count: u64,
    pub(crate) io_port_out32_count: u64,
    pub(crate) root_started_count: u64,
    pub(crate) video_route_attempted_count: u64,
    pub(crate) video_route_published_count: u64,
    pub(crate) first_error: u32,
    pub(crate) first_indeterminate: u32,
}

impl HostedPnpStartReport {
    pub(crate) fn merge(&mut self, other: Self) {
        self.driver_ready_for_pnp |= other.driver_ready_for_pnp;
        self.add_device |= other.add_device;
        self.start_ok |= other.start_ok;
        self.resource_granted |= other.resource_granted;
        self.mmio_mapped |= other.mmio_mapped;
        self.interrupt_connected |= other.interrupt_connected;
        self.interrupt_delivered |= other.interrupt_delivered;
        self.dpc_delivered |= other.dpc_delivered;
        self.dma_adapter |= other.dma_adapter;
        self.dma_common |= other.dma_common;
        self.io_port_out32 |= other.io_port_out32;
        self.root_started |= other.root_started;
        self.video_route_published |= other.video_route_published;
        macro_rules! add {
            ($($field:ident),+ $(,)?) => {
                $(self.$field = self.$field.saturating_add(other.$field);)+
            };
        }
        add!(
            attempted,
            terminal,
            add_device_count,
            started,
            failed,
            pending,
            pending_observed,
            indeterminate,
            resource_granted_count,
            mmio_mapped_count,
            interrupt_connected_count,
            interrupt_delivered_count,
            dpc_delivered_count,
            dma_adapter_count,
            dma_common_count,
            io_port_out32_count,
            root_started_count,
            video_route_attempted_count,
            video_route_published_count,
        );
        if self.first_error == 0 {
            self.first_error = other.first_error;
        }
        if self.first_indeterminate == 0 {
            self.first_indeterminate = other.first_indeterminate;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostedPnpStartBatchFailure {
    pub(crate) status: nt_status::NtStatus,
    pub(crate) teardown_blocked: bool,
}

pub(crate) enum OwnedHostedPnpStartProgress {
    AwaitingCompletion,
    Complete(Result<HostedPnpStartReport, HostedPnpStartBatchFailure>),
    OwnershipLost(HostedPnpStartBatchFailure),
}

pub(crate) struct OwnedHostedPnpStartBatch {
    spec: DriverServiceLaunchSpec,
    options: HostedPnpStartOptions,
    coordinator: nt_driver_start::DriverStartBatch,
    report: HostedPnpStartReport,
    pending_device_id: u64,
    pending_filter: Option<PendingHostedPnpFilter>,
    pending_relations_device_id: u64,
    single_start_evidence: SingleStartEvidence,
}

pub(crate) enum SingleStartEvidence {
    Consumed,
    NotDispatched,
    Dispatched {
        irp_id: u64,
    },
    Lifecycle {
        receipt: nt_pnp_manager::StartDeviceLifecycleReceipt,
    },
    OwnershipLost {
        irp_id: u64,
        receipt: Option<nt_pnp_manager::StartDeviceLifecycleReceipt>,
    },
}

struct PendingHostedPnpFilter {
    devnode_index: usize,
    device_id: u64,
    irp_id: u64,
    resource_plan: PreparedHostedResourcePlan,
    ownership_lost: Option<nt_status::NtStatus>,
}

impl OwnedHostedPnpStartBatch {
    pub(crate) fn new(
        dc: &driver_launch::DriverComponent,
        spec: DriverServiceLaunchSpec,
        options: HostedPnpStartOptions,
    ) -> Self {
        Self::new_for_driver(
            dc.driver_id,
            (dc.verdict & V_ENTERED) != 0
                && (dc.add_device != 0
                    || driver_launch::hosted_driver_video_port_initialized(dc.driver_id)),
            spec,
            options,
        )
    }

    pub(crate) fn new_for_driver(
        driver_id: u64,
        driver_ready_for_pnp: bool,
        spec: DriverServiceLaunchSpec,
        options: HostedPnpStartOptions,
    ) -> Self {
        let report = HostedPnpStartReport {
            driver_ready_for_pnp,
            ..HostedPnpStartReport::default()
        };
        let coordinator = nt_driver_start::DriverStartBatch::new(driver_id, spec.devnodes.len());
        Self {
            spec,
            options,
            coordinator,
            report,
            pending_device_id: 0,
            pending_filter: None,
            pending_relations_device_id: 0,
            single_start_evidence: SingleStartEvidence::NotDispatched,
        }
    }

    pub(crate) fn driver_object_path(&self) -> &str {
        &self.spec.driver_object_path
    }

    pub(crate) fn report(&self) -> HostedPnpStartReport {
        self.report
    }

    /// The live StartDevice path owns exactly one devnode. Keep its canonical START receipt across
    /// any later initial-BusRelations wait so the outer syscall can join to the retired IRP.
    pub(crate) fn take_single_start_evidence(&mut self) -> Option<SingleStartEvidence> {
        if self.spec.devnodes.len() == 1 {
            let evidence = core::mem::replace(
                &mut self.single_start_evidence,
                SingleStartEvidence::Consumed,
            );
            assert!(
                !matches!(evidence, SingleStartEvidence::Consumed),
                "single-devnode START evidence was consumed twice"
            );
            Some(evidence)
        } else {
            None
        }
    }

    fn retain_start_receipt(&mut self, receipt: nt_pnp_manager::StartDeviceLifecycleReceipt) {
        if self.spec.devnodes.len() == 1 {
            assert!(unsafe {
                driver_launch::hosted_pnp_start_receipt_matches_instance(
                    &receipt,
                    &self.spec.devnodes[0].instance_id,
                )
            });
            assert!(
                matches!(
                    self.single_start_evidence,
                    SingleStartEvidence::NotDispatched | SingleStartEvidence::Dispatched { .. }
                ),
                "single-devnode START batch produced duplicate lifecycle evidence"
            );
            self.single_start_evidence = SingleStartEvidence::Lifecycle { receipt };
        }
    }

    fn retain_start_dispatch(&mut self, irp_id: u64) {
        if self.spec.devnodes.len() == 1 {
            assert_ne!(irp_id, 0);
            assert!(matches!(
                self.single_start_evidence,
                SingleStartEvidence::NotDispatched
            ));
            self.single_start_evidence = SingleStartEvidence::Dispatched { irp_id };
        }
    }

    fn retain_start_ownership_lost(
        &mut self,
        irp_id: u64,
        receipt: Option<nt_pnp_manager::StartDeviceLifecycleReceipt>,
    ) {
        if self.spec.devnodes.len() == 1 {
            assert_ne!(irp_id, 0);
            if let Some(receipt) = receipt.as_ref() {
                assert_eq!(receipt.dispatch().canonical_irp_id, irp_id);
                assert!(unsafe {
                    driver_launch::hosted_pnp_start_receipt_matches_instance(
                        receipt,
                        &self.spec.devnodes[0].instance_id,
                    )
                });
            }
            assert!(matches!(
                self.single_start_evidence,
                SingleStartEvidence::NotDispatched | SingleStartEvidence::Dispatched { .. }
            ));
            self.single_start_evidence = SingleStartEvidence::OwnershipLost { irp_id, receipt };
        }
    }

    pub(crate) fn needs_completion_redrive(&self) -> bool {
        self.pending_filter
            .as_ref()
            .is_some_and(|pending| pending.ownership_lost.is_none())
            || self.pending_relations_device_id != 0
            || matches!(
                self.coordinator.phase(),
                nt_driver_start::BatchPhase::Ready | nt_driver_start::BatchPhase::Awaiting { .. }
            )
    }

    pub(crate) unsafe fn drive(&mut self) -> OwnedHostedPnpStartProgress {
        self.drive_inner(true)
    }

    /// Resume after the caller has pumped the shared hosted-I/O completion plane once.
    /// Walking several pending batches must not repump that global plane once per row.
    pub(crate) unsafe fn drive_after_completion_pump(&mut self) -> OwnedHostedPnpStartProgress {
        self.drive_inner(false)
    }

    unsafe fn schedule_initial_bus_relations(
        &mut self,
        device_id: u64,
    ) -> OwnedHostedPnpStartProgress {
        assert_ne!(device_id, 0, "successful START lost its canonical device");
        match driver_launch::enqueue_hosted_initial_bus_relations(device_id) {
            Ok(_) => {
                self.pending_relations_device_id = device_id;
                OwnedHostedPnpStartProgress::AwaitingCompletion
            }
            Err(status) => OwnedHostedPnpStartProgress::Complete(Err(HostedPnpStartBatchFailure {
                status,
                teardown_blocked: true,
            })),
        }
    }

    unsafe fn apply_devnode_progress(
        &mut self,
        devnode_index: usize,
        progress: HostedPnpDevnodeProgress,
    ) -> Option<OwnedHostedPnpStartProgress> {
        match progress {
            HostedPnpDevnodeProgress::FilterPending {
                device_id,
                irp_id,
                resource_plan,
            } => {
                assert!(self.pending_filter.is_none());
                self.pending_filter = Some(PendingHostedPnpFilter {
                    devnode_index,
                    device_id,
                    irp_id,
                    resource_plan,
                    ownership_lost: None,
                });
                return Some(OwnedHostedPnpStartProgress::AwaitingCompletion);
            }
            HostedPnpDevnodeProgress::FilterOwnershipLost {
                device_id,
                irp_id,
                resource_plan,
                transport_status,
            } => {
                assert!(self.pending_filter.is_none());
                self.pending_filter = Some(PendingHostedPnpFilter {
                    devnode_index,
                    device_id,
                    irp_id,
                    resource_plan,
                    ownership_lost: Some(transport_status),
                });
                return Some(OwnedHostedPnpStartProgress::OwnershipLost(
                    HostedPnpStartBatchFailure {
                        status: transport_status,
                        teardown_blocked: true,
                    },
                ));
            }
            _ => {}
        }

        let token = self
            .coordinator
            .begin_next()
            .expect("ready START batch rejected completed devnode preparation");
        assert_eq!(token.devnode_index(), devnode_index);
        match progress {
            HostedPnpDevnodeProgress::Terminal {
                device_id,
                status,
                receipt,
            } => {
                self.coordinator
                    .dispatch_terminal(token)
                    .expect("terminal START did not match dispatched devnode");
                if let Some(receipt) = receipt {
                    self.retain_start_receipt(receipt);
                }
                if !status.is_success() {
                    self.coordinator
                        .stop()
                        .expect("terminal START failure could not stop batch");
                } else {
                    return Some(self.schedule_initial_bus_relations(device_id));
                }
                None
            }
            HostedPnpDevnodeProgress::Pending {
                device_id, irp_id, ..
            } => {
                self.retain_start_dispatch(irp_id);
                self.coordinator
                    .dispatch_pending(token, irp_id)
                    .expect("pending START did not match dispatched devnode");
                self.pending_device_id = device_id;
                Some(OwnedHostedPnpStartProgress::AwaitingCompletion)
            }
            HostedPnpDevnodeProgress::OwnershipLost {
                irp_id,
                transport_status,
                receipt,
            } => {
                self.retain_start_ownership_lost(irp_id, receipt);
                self.coordinator
                    .dispatch_pending(token, irp_id)
                    .expect("lost START did not match dispatched devnode");
                self.coordinator
                    .lose_ownership(irp_id, transport_status.raw() as u32)
                    .expect("lost START ownership did not match exact IRP");
                Some(OwnedHostedPnpStartProgress::OwnershipLost(
                    HostedPnpStartBatchFailure {
                        status: transport_status,
                        teardown_blocked: true,
                    },
                ))
            }
            HostedPnpDevnodeProgress::FilterPending { .. }
            | HostedPnpDevnodeProgress::FilterOwnershipLost { .. } => unreachable!(),
        }
    }

    unsafe fn drive_inner(&mut self, pump_before_observe: bool) -> OwnedHostedPnpStartProgress {
        loop {
            if self.pending_relations_device_id != 0 {
                if pump_before_observe {
                    driver_launch::pump_hosted_io_completions();
                }
                match driver_launch::hosted_pnp_enumeration_progress() {
                    driver_launch::HostedPnpEnumerationProgress::Current => {
                        self.pending_relations_device_id = 0;
                    }
                    driver_launch::HostedPnpEnumerationProgress::Pending => {
                        return OwnedHostedPnpStartProgress::AwaitingCompletion;
                    }
                    driver_launch::HostedPnpEnumerationProgress::Blocked(status) => {
                        return OwnedHostedPnpStartProgress::Complete(Err(
                            HostedPnpStartBatchFailure {
                                status,
                                teardown_blocked: true,
                            },
                        ));
                    }
                }
                continue;
            }
            if let Some(pending) = self.pending_filter.as_ref() {
                if let Some(status) = pending.ownership_lost {
                    return OwnedHostedPnpStartProgress::OwnershipLost(
                        HostedPnpStartBatchFailure {
                            status,
                            teardown_blocked: true,
                        },
                    );
                }
                if pump_before_observe {
                    driver_launch::pump_hosted_io_completions();
                }
                let devnode_index = pending.devnode_index;
                let device_id = pending.device_id;
                let irp_id = pending.irp_id;
                let outcome = driver_launch::observe_hosted_filter_resource_requirements(irp_id);
                match outcome {
                    Ok(driver_launch::HostedFilterRequirementsOutcome::Pending { .. }) => {
                        return OwnedHostedPnpStartProgress::AwaitingCompletion;
                    }
                    Ok(driver_launch::HostedFilterRequirementsOutcome::Indeterminate {
                        transport_status,
                        ..
                    })
                    | Err(transport_status) => {
                        self.pending_filter
                            .as_mut()
                            .expect("filter owner disappeared")
                            .ownership_lost = Some(transport_status);
                        return OwnedHostedPnpStartProgress::OwnershipLost(
                            HostedPnpStartBatchFailure {
                                status: transport_status,
                                teardown_blocked: true,
                            },
                        );
                    }
                    Ok(driver_launch::HostedFilterRequirementsOutcome::Failed(status)) => {
                        let pending = self
                            .pending_filter
                            .take()
                            .expect("filter owner disappeared");
                        let devnode = &self.spec.devnodes[devnode_index];
                        let progress = finish_filter_failure(
                            device_id,
                            pending.resource_plan,
                            &self.spec.service_name,
                            &devnode.instance_id,
                            self.options,
                            status,
                            &mut self.report,
                        );
                        if let Some(outcome) = self.apply_devnode_progress(devnode_index, progress)
                        {
                            return outcome;
                        }
                    }
                    Ok(driver_launch::HostedFilterRequirementsOutcome::Filtered {
                        requirements,
                    }) => {
                        let pending = self
                            .pending_filter
                            .take()
                            .expect("filter owner disappeared");
                        let devnode = &self.spec.devnodes[devnode_index];
                        let progress = start_filtered_devnode(
                            device_id,
                            pending.resource_plan,
                            requirements,
                            &self.spec.service_name,
                            &devnode.instance_id,
                            self.options,
                            &mut self.report,
                        );
                        if let Some(outcome) = self.apply_devnode_progress(devnode_index, progress)
                        {
                            return outcome;
                        }
                    }
                }
                continue;
            }
            match self.coordinator.phase() {
                nt_driver_start::BatchPhase::Complete => {
                    return OwnedHostedPnpStartProgress::Complete(finalize_batch(self.report));
                }
                nt_driver_start::BatchPhase::OwnershipLost { status } => {
                    return OwnedHostedPnpStartProgress::OwnershipLost(
                        HostedPnpStartBatchFailure {
                            status: nt_status::NtStatus(status as i32),
                            teardown_blocked: true,
                        },
                    );
                }
                nt_driver_start::BatchPhase::Awaiting {
                    devnode_index,
                    irp_id,
                } => {
                    let devnode = &self.spec.devnodes[devnode_index];
                    match observe_canonical_start(irp_id, false, pump_before_observe) {
                        CanonicalStartDisposition::Terminal {
                            status, receipt, ..
                        } => {
                            assert_eq!(
                                self.report.pending, 1,
                                "START pending count lost ownership"
                            );
                            self.report.pending -= 1;
                            self.coordinator
                                .observe_terminal(irp_id)
                                .expect("exact START terminal observation rejected");
                            let device_id = self.pending_device_id;
                            finish_started_devnode(
                                device_id,
                                &self.spec.service_name,
                                &devnode.instance_id,
                                self.options,
                                status,
                                false,
                                &mut self.report,
                            );
                            if let Some(receipt) = receipt {
                                self.retain_start_receipt(receipt);
                            }
                            self.pending_device_id = 0;
                            if !status.is_success() {
                                self.coordinator
                                    .stop()
                                    .expect("terminal START failure could not stop batch");
                            } else {
                                return self.schedule_initial_bus_relations(device_id);
                            }
                        }
                        CanonicalStartDisposition::OwnershipLost {
                            irp_id,
                            transport_status,
                            receipt,
                            ..
                        } => {
                            assert_eq!(
                                self.report.pending, 1,
                                "START pending count lost ownership"
                            );
                            self.report.pending -= 1;
                            record_start_indeterminate(&mut self.report, transport_status, false);
                            print_start_indeterminate(
                                self.options.trace,
                                &self.spec.service_name,
                                &devnode.instance_id,
                                transport_status,
                            );
                            self.coordinator
                                .lose_ownership(irp_id, transport_status.raw() as u32)
                                .expect("lost START ownership did not match exact IRP");
                            self.retain_start_ownership_lost(irp_id, receipt);
                        }
                        CanonicalStartDisposition::Pending { .. } => {
                            return OwnedHostedPnpStartProgress::AwaitingCompletion;
                        }
                    }
                }
                nt_driver_start::BatchPhase::Ready => {
                    match driver_launch::hosted_pnp_enumeration_progress() {
                        driver_launch::HostedPnpEnumerationProgress::Current => {}
                        driver_launch::HostedPnpEnumerationProgress::Pending => {
                            return OwnedHostedPnpStartProgress::AwaitingCompletion;
                        }
                        driver_launch::HostedPnpEnumerationProgress::Blocked(status) => {
                            return OwnedHostedPnpStartProgress::Complete(Err(
                                HostedPnpStartBatchFailure {
                                    status,
                                    teardown_blocked: true,
                                },
                            ));
                        }
                    }
                    let devnode_index = self.coordinator.next_devnode();
                    let devnode = &self.spec.devnodes[devnode_index];
                    let progress = start_one_devnode(
                        self.coordinator.driver_id(),
                        &self.spec.service_name,
                        self.spec.class_guid.as_deref(),
                        HostedPnpDevnodeStart {
                            instance_id: &devnode.instance_id,
                            driver_key: devnode.driver_key.as_deref(),
                            linkage_export: devnode.linkage_export.as_deref(),
                            hardware_ids: &devnode.hardware_ids,
                            compatible_ids: &devnode.compatible_ids,
                        },
                        self.options,
                        &mut self.report,
                    );
                    if let Some(outcome) = self.apply_devnode_progress(devnode_index, progress) {
                        return outcome;
                    }
                }
                nt_driver_start::BatchPhase::Dispatching { .. } => {
                    panic!("START batch escaped while a devnode dispatch was active");
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedPnpRebalanceStage {
    QueryStop,
    AwaitingLifecycle {
        minor: nt_pnp_manager::PnpMinor,
        irp_id: u64,
        failure_status: Option<nt_status::NtStatus>,
    },
    Stop,
    CancelStop {
        failure_status: nt_status::NtStatus,
    },
    Restart,
    Complete,
    OwnershipLost,
}

pub(crate) enum OwnedHostedPnpRebalanceProgress {
    AwaitingCompletion,
    Complete(Result<HostedPnpStartReport, HostedPnpStartBatchFailure>),
    OwnershipLost(HostedPnpStartBatchFailure),
}

/// Own QUERY_STOP/STOP/CANCEL_STOP and restart of one existing canonical FDO stack.
pub(crate) struct OwnedHostedPnpRebalance {
    device_id: u64,
    stage: HostedPnpRebalanceStage,
    restart: OwnedHostedPnpStartBatch,
    terminal: Option<Result<HostedPnpStartReport, HostedPnpStartBatchFailure>>,
    ownership_failure: Option<HostedPnpStartBatchFailure>,
}

impl OwnedHostedPnpRebalance {
    pub(crate) fn new(
        device_id: u64,
        driver_id: u64,
        driver_ready_for_pnp: bool,
        spec: DriverServiceLaunchSpec,
    ) -> Self {
        Self {
            device_id,
            stage: HostedPnpRebalanceStage::QueryStop,
            restart: OwnedHostedPnpStartBatch::new_for_driver(
                driver_id,
                driver_ready_for_pnp,
                spec,
                HostedPnpStartOptions::rebalance(),
            ),
            terminal: None,
            ownership_failure: None,
        }
    }

    pub(crate) fn needs_completion_redrive(&self) -> bool {
        matches!(
            self.stage,
            HostedPnpRebalanceStage::AwaitingLifecycle { .. } | HostedPnpRebalanceStage::Restart
        ) && (matches!(
            self.stage,
            HostedPnpRebalanceStage::AwaitingLifecycle { .. }
        ) || self.restart.needs_completion_redrive())
    }

    pub(crate) unsafe fn drive(&mut self) -> OwnedHostedPnpRebalanceProgress {
        self.drive_inner(true)
    }

    pub(crate) unsafe fn drive_after_completion_pump(&mut self) -> OwnedHostedPnpRebalanceProgress {
        self.drive_inner(false)
    }

    fn fail_terminal(&mut self, failure: HostedPnpStartBatchFailure) {
        self.terminal = Some(Err(failure));
        self.stage = HostedPnpRebalanceStage::Complete;
    }

    fn lose_ownership(&mut self, status: nt_status::NtStatus) {
        self.ownership_failure = Some(HostedPnpStartBatchFailure {
            status,
            teardown_blocked: true,
        });
        self.stage = HostedPnpRebalanceStage::OwnershipLost;
    }

    unsafe fn dispatch_lifecycle(
        &mut self,
        minor: nt_pnp_manager::PnpMinor,
        failure_status: Option<nt_status::NtStatus>,
    ) -> Option<OwnedHostedPnpRebalanceProgress> {
        match driver_launch::dispatch_hosted_pnp_lifecycle_canonical(self.device_id, minor) {
            Ok(driver_launch::HostedPnpLifecycleOutcome::Complete { driver_status }) => {
                self.finish_lifecycle(minor, driver_status, failure_status);
                None
            }
            Ok(driver_launch::HostedPnpLifecycleOutcome::Pending { irp_id })
            | Ok(driver_launch::HostedPnpLifecycleOutcome::RepairRequired { irp_id, .. }) => {
                self.stage = HostedPnpRebalanceStage::AwaitingLifecycle {
                    minor,
                    irp_id,
                    failure_status,
                };
                Some(OwnedHostedPnpRebalanceProgress::AwaitingCompletion)
            }
            Ok(driver_launch::HostedPnpLifecycleOutcome::Indeterminate {
                transport_status,
                ..
            }) => {
                self.lose_ownership(transport_status);
                Some(OwnedHostedPnpRebalanceProgress::OwnershipLost(
                    self.ownership_failure
                        .expect("rebalance barrier disappeared"),
                ))
            }
            Err(status) => {
                if minor == nt_pnp_manager::PnpMinor::StopDevice {
                    self.stage = HostedPnpRebalanceStage::CancelStop {
                        failure_status: status,
                    };
                    None
                } else if minor == nt_pnp_manager::PnpMinor::CancelStopDevice {
                    self.lose_ownership(failure_status.unwrap_or(status));
                    Some(OwnedHostedPnpRebalanceProgress::OwnershipLost(
                        self.ownership_failure
                            .expect("rebalance barrier disappeared"),
                    ))
                } else {
                    self.fail_terminal(HostedPnpStartBatchFailure {
                        status: failure_status.unwrap_or(status),
                        teardown_blocked: false,
                    });
                    None
                }
            }
        }
    }

    fn finish_lifecycle(
        &mut self,
        minor: nt_pnp_manager::PnpMinor,
        driver_status: nt_status::NtStatus,
        failure_status: Option<nt_status::NtStatus>,
    ) {
        match minor {
            nt_pnp_manager::PnpMinor::QueryStopDevice if driver_status.is_success() => {
                self.stage = HostedPnpRebalanceStage::Stop;
            }
            nt_pnp_manager::PnpMinor::QueryStopDevice => {
                self.stage = HostedPnpRebalanceStage::CancelStop {
                    failure_status: driver_status,
                };
            }
            nt_pnp_manager::PnpMinor::StopDevice => {
                self.stage = HostedPnpRebalanceStage::Restart;
            }
            nt_pnp_manager::PnpMinor::CancelStopDevice => {
                self.fail_terminal(HostedPnpStartBatchFailure {
                    status: failure_status.unwrap_or(driver_status),
                    teardown_blocked: false,
                });
            }
            _ => self.lose_ownership(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
        }
    }

    unsafe fn drive_inner(&mut self, pump_before_observe: bool) -> OwnedHostedPnpRebalanceProgress {
        loop {
            match self.stage {
                HostedPnpRebalanceStage::QueryStop => {
                    if let Some(progress) =
                        self.dispatch_lifecycle(nt_pnp_manager::PnpMinor::QueryStopDevice, None)
                    {
                        return progress;
                    }
                }
                HostedPnpRebalanceStage::Stop => {
                    if let Some(progress) =
                        self.dispatch_lifecycle(nt_pnp_manager::PnpMinor::StopDevice, None)
                    {
                        return progress;
                    }
                }
                HostedPnpRebalanceStage::CancelStop { failure_status } => {
                    if let Some(progress) = self.dispatch_lifecycle(
                        nt_pnp_manager::PnpMinor::CancelStopDevice,
                        Some(failure_status),
                    ) {
                        return progress;
                    }
                }
                HostedPnpRebalanceStage::AwaitingLifecycle {
                    minor,
                    irp_id,
                    failure_status,
                } => {
                    if pump_before_observe {
                        driver_launch::pump_hosted_io_completions();
                    }
                    match driver_launch::observe_hosted_pnp_lifecycle(irp_id, minor) {
                        Ok(driver_launch::HostedPnpLifecycleObservation::AwaitingCompletion) => {
                            return OwnedHostedPnpRebalanceProgress::AwaitingCompletion;
                        }
                        Ok(driver_launch::HostedPnpLifecycleObservation::Terminal {
                            driver_status,
                        }) => {
                            self.finish_lifecycle(minor, driver_status, failure_status);
                        }
                        Ok(driver_launch::HostedPnpLifecycleObservation::Indeterminate {
                            transport_status,
                        })
                        | Err(transport_status) => {
                            self.lose_ownership(transport_status);
                        }
                    }
                }
                HostedPnpRebalanceStage::Restart => {
                    let progress = if pump_before_observe {
                        self.restart.drive()
                    } else {
                        self.restart.drive_after_completion_pump()
                    };
                    match progress {
                        OwnedHostedPnpStartProgress::AwaitingCompletion => {
                            return OwnedHostedPnpRebalanceProgress::AwaitingCompletion;
                        }
                        OwnedHostedPnpStartProgress::Complete(result) => {
                            self.terminal = Some(result);
                            self.stage = HostedPnpRebalanceStage::Complete;
                        }
                        OwnedHostedPnpStartProgress::OwnershipLost(failure) => {
                            self.ownership_failure = Some(failure);
                            self.stage = HostedPnpRebalanceStage::OwnershipLost;
                        }
                    }
                }
                HostedPnpRebalanceStage::Complete => {
                    return OwnedHostedPnpRebalanceProgress::Complete(
                        self.terminal
                            .expect("terminal rebalance has no retained result"),
                    );
                }
                HostedPnpRebalanceStage::OwnershipLost => {
                    return OwnedHostedPnpRebalanceProgress::OwnershipLost(
                        self.ownership_failure
                            .expect("indeterminate rebalance has no retained barrier"),
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedPnpRemovalKind {
    Orderly,
    Surprise,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedPnpRemovalStage {
    QueryRemove,
    SurpriseRemove,
    AwaitingLifecycle {
        minor: nt_pnp_manager::PnpMinor,
        irp_id: u64,
        failure_status: Option<nt_status::NtStatus>,
    },
    Remove,
    CancelRemove {
        failure_status: nt_status::NtStatus,
    },
    Complete,
    OwnershipLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostedPnpRemovalFailure {
    pub(crate) status: nt_status::NtStatus,
    pub(crate) teardown_blocked: bool,
}

pub(crate) enum OwnedHostedPnpRemovalProgress {
    AwaitingCompletion,
    Complete(Result<(), HostedPnpRemovalFailure>),
    OwnershipLost(HostedPnpRemovalFailure),
}

/// Own an orderly QUERY_REMOVE/CANCEL_REMOVE/REMOVE sequence or a bus-loss
/// SURPRISE_REMOVE/REMOVE sequence for one exact canonical function stack.
pub(crate) struct OwnedHostedPnpRemoval {
    device_id: u64,
    kind: HostedPnpRemovalKind,
    stage: HostedPnpRemovalStage,
    terminal: Option<Result<(), HostedPnpRemovalFailure>>,
    ownership_failure: Option<HostedPnpRemovalFailure>,
}

impl OwnedHostedPnpRemoval {
    pub(crate) fn new(device_id: u64, kind: HostedPnpRemovalKind) -> Self {
        Self {
            device_id,
            kind,
            stage: match kind {
                HostedPnpRemovalKind::Orderly => HostedPnpRemovalStage::QueryRemove,
                HostedPnpRemovalKind::Surprise => HostedPnpRemovalStage::SurpriseRemove,
            },
            terminal: None,
            ownership_failure: None,
        }
    }

    pub(crate) fn needs_completion_redrive(&self) -> bool {
        matches!(self.stage, HostedPnpRemovalStage::AwaitingLifecycle { .. })
    }

    pub(crate) unsafe fn drive(&mut self) -> OwnedHostedPnpRemovalProgress {
        self.drive_inner(true)
    }

    pub(crate) unsafe fn drive_after_completion_pump(&mut self) -> OwnedHostedPnpRemovalProgress {
        self.drive_inner(false)
    }

    fn fail_terminal(&mut self, status: nt_status::NtStatus) {
        self.terminal = Some(Err(HostedPnpRemovalFailure {
            status,
            teardown_blocked: false,
        }));
        self.stage = HostedPnpRemovalStage::Complete;
    }

    fn lose_ownership(&mut self, status: nt_status::NtStatus) {
        self.ownership_failure = Some(HostedPnpRemovalFailure {
            status,
            teardown_blocked: true,
        });
        self.stage = HostedPnpRemovalStage::OwnershipLost;
    }

    unsafe fn dispatch_lifecycle(
        &mut self,
        minor: nt_pnp_manager::PnpMinor,
        failure_status: Option<nt_status::NtStatus>,
    ) -> Option<OwnedHostedPnpRemovalProgress> {
        match driver_launch::dispatch_hosted_pnp_lifecycle_canonical(self.device_id, minor) {
            Ok(driver_launch::HostedPnpLifecycleOutcome::Complete { driver_status }) => {
                self.finish_lifecycle(minor, driver_status, failure_status);
                None
            }
            Ok(driver_launch::HostedPnpLifecycleOutcome::Pending { irp_id })
            | Ok(driver_launch::HostedPnpLifecycleOutcome::RepairRequired { irp_id, .. }) => {
                self.stage = HostedPnpRemovalStage::AwaitingLifecycle {
                    minor,
                    irp_id,
                    failure_status,
                };
                Some(OwnedHostedPnpRemovalProgress::AwaitingCompletion)
            }
            Ok(driver_launch::HostedPnpLifecycleOutcome::Indeterminate {
                transport_status,
                ..
            }) => {
                self.lose_ownership(transport_status);
                Some(OwnedHostedPnpRemovalProgress::OwnershipLost(
                    self.ownership_failure
                        .expect("removal ownership barrier disappeared"),
                ))
            }
            Err(status) => {
                if minor == nt_pnp_manager::PnpMinor::RemoveDevice
                    && self.kind == HostedPnpRemovalKind::Orderly
                {
                    self.stage = HostedPnpRemovalStage::CancelRemove {
                        failure_status: failure_status.unwrap_or(status),
                    };
                    None
                } else if minor == nt_pnp_manager::PnpMinor::CancelRemoveDevice
                    || minor == nt_pnp_manager::PnpMinor::RemoveDevice
                        && self.kind == HostedPnpRemovalKind::Surprise
                {
                    self.lose_ownership(failure_status.unwrap_or(status));
                    Some(OwnedHostedPnpRemovalProgress::OwnershipLost(
                        self.ownership_failure
                            .expect("removal ownership barrier disappeared"),
                    ))
                } else {
                    self.fail_terminal(failure_status.unwrap_or(status));
                    None
                }
            }
        }
    }

    fn finish_lifecycle(
        &mut self,
        minor: nt_pnp_manager::PnpMinor,
        driver_status: nt_status::NtStatus,
        failure_status: Option<nt_status::NtStatus>,
    ) {
        match minor {
            nt_pnp_manager::PnpMinor::QueryRemoveDevice if driver_status.is_success() => {
                self.stage = HostedPnpRemovalStage::Remove;
            }
            nt_pnp_manager::PnpMinor::QueryRemoveDevice => {
                self.stage = HostedPnpRemovalStage::CancelRemove {
                    failure_status: nt_status::NtStatus(0x8000_0028u32 as i32),
                };
            }
            nt_pnp_manager::PnpMinor::CancelRemoveDevice => {
                self.fail_terminal(failure_status.unwrap_or(driver_status));
            }
            nt_pnp_manager::PnpMinor::SurpriseRemoval => {
                self.stage = HostedPnpRemovalStage::Remove;
            }
            nt_pnp_manager::PnpMinor::RemoveDevice => {
                self.terminal = Some(Ok(()));
                self.stage = HostedPnpRemovalStage::Complete;
            }
            _ => self.lose_ownership(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
        }
    }

    unsafe fn drive_inner(&mut self, pump_before_observe: bool) -> OwnedHostedPnpRemovalProgress {
        loop {
            match self.stage {
                HostedPnpRemovalStage::QueryRemove => {
                    if let Some(progress) =
                        self.dispatch_lifecycle(nt_pnp_manager::PnpMinor::QueryRemoveDevice, None)
                    {
                        return progress;
                    }
                }
                HostedPnpRemovalStage::SurpriseRemove => {
                    if let Some(progress) =
                        self.dispatch_lifecycle(nt_pnp_manager::PnpMinor::SurpriseRemoval, None)
                    {
                        return progress;
                    }
                }
                HostedPnpRemovalStage::Remove => {
                    if let Some(progress) =
                        self.dispatch_lifecycle(nt_pnp_manager::PnpMinor::RemoveDevice, None)
                    {
                        return progress;
                    }
                }
                HostedPnpRemovalStage::CancelRemove { failure_status } => {
                    if let Some(progress) = self.dispatch_lifecycle(
                        nt_pnp_manager::PnpMinor::CancelRemoveDevice,
                        Some(failure_status),
                    ) {
                        return progress;
                    }
                }
                HostedPnpRemovalStage::AwaitingLifecycle {
                    minor,
                    irp_id,
                    failure_status,
                } => {
                    if pump_before_observe {
                        driver_launch::pump_hosted_io_completions();
                    }
                    match driver_launch::observe_hosted_pnp_lifecycle(irp_id, minor) {
                        Ok(driver_launch::HostedPnpLifecycleObservation::AwaitingCompletion) => {
                            return OwnedHostedPnpRemovalProgress::AwaitingCompletion;
                        }
                        Ok(driver_launch::HostedPnpLifecycleObservation::Terminal {
                            driver_status,
                        }) => self.finish_lifecycle(minor, driver_status, failure_status),
                        Ok(driver_launch::HostedPnpLifecycleObservation::Indeterminate {
                            transport_status,
                        })
                        | Err(transport_status) => self.lose_ownership(transport_status),
                    }
                }
                HostedPnpRemovalStage::Complete => {
                    return OwnedHostedPnpRemovalProgress::Complete(
                        self.terminal
                            .expect("terminal removal has no retained result"),
                    );
                }
                HostedPnpRemovalStage::OwnershipLost => {
                    return OwnedHostedPnpRemovalProgress::OwnershipLost(
                        self.ownership_failure
                            .expect("indeterminate removal has no retained barrier"),
                    );
                }
            }
        }
    }
}

struct HostedPnpDevnodeStart<'a, H, C> {
    instance_id: &'a str,
    driver_key: Option<&'a str>,
    linkage_export: Option<&'a str>,
    hardware_ids: &'a [H],
    compatible_ids: &'a [C],
}

fn finalize_batch(
    report: HostedPnpStartReport,
) -> Result<HostedPnpStartReport, HostedPnpStartBatchFailure> {
    if report.indeterminate != 0 {
        Err(HostedPnpStartBatchFailure {
            status: nt_status::NtStatus(report.first_indeterminate as i32),
            teardown_blocked: true,
        })
    } else if report.pending != 0 {
        Err(HostedPnpStartBatchFailure {
            status: nt_status::NtStatus::PENDING,
            teardown_blocked: true,
        })
    } else if report.first_error != 0 {
        Err(HostedPnpStartBatchFailure {
            status: nt_status::NtStatus(report.first_error as i32),
            teardown_blocked: report.add_device_count != 0,
        })
    } else if report.terminal != report.attempted || report.started != report.attempted {
        Err(HostedPnpStartBatchFailure {
            status: nt_status::NtStatus::UNSUCCESSFUL,
            teardown_blocked: report.add_device_count != 0,
        })
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
    Platform {
        grant: DevnodeRootResourceGrant,
        window: HostedPnpPlatformResourceDescriptor,
        lease: nt_pnp_context::ContextLease,
    },
    None,
}

impl PreparedHostedResourcePlan {
    fn native_property_blobs(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        match self {
            Self::Pci { bus_resources, .. } => (
                Some(&bus_resources.raw_boot_resources),
                Some(&bus_resources.resource_requirements),
            ),
            Self::Platform { grant, .. } => (
                Some(&grant.raw_boot_resources),
                Some(&grant.resource_requirements),
            ),
            Self::None => (None, None),
        }
    }

    unsafe fn release_context_lease(self) -> Result<(), nt_status::NtStatus> {
        let lease = match self {
            Self::Pci { lease, .. } | Self::Platform { lease, .. } => lease,
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
        let Some(bus_resources) = build_devnode_pci_bus_resources(device, None) else {
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

    if let Some(window) = context
        .platform_windows
        .iter()
        .find(|window| window.matches_devnode(instance_id, hardware_ids, compatible_ids))
        .cloned()
    {
        let mut platform_memory = Vec::new();
        platform_memory
            .try_reserve_exact(window.memory.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        for resource in &window.memory {
            platform_memory.push(nt_pnp::PlatformMemoryResource {
                start: resource.phys,
                length: u32::try_from(resource.len)
                    .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?,
                writable: resource.writable,
            });
        }
        let mut platform_ports = Vec::new();
        platform_ports
            .try_reserve_exact(window.ports.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        for resource in &window.ports {
            platform_ports.push(nt_pnp::PlatformPortResource {
                start: resource.base,
                length: resource.len,
            });
        }
        let profile = nt_pnp::PlatformResourceProfile {
            memory: platform_memory,
            ports: platform_ports,
            interrupt: nt_pnp::PlatformInterruptResource {
                level: window.interrupt_vector,
                vector: window.interrupt_vector,
                affinity: 1,
                latched: window.interrupt_latched,
                shared: window.interrupt_shared,
            },
        };
        let grant = build_devnode_platform_resources(&profile)
            .map_err(hosted_resource_requirements_status)?;
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
            resource_plan: PreparedHostedResourcePlan::Platform {
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

enum HostedPnpDevnodeProgress {
    Terminal {
        device_id: u64,
        status: nt_status::NtStatus,
        receipt: Option<nt_pnp_manager::StartDeviceLifecycleReceipt>,
    },
    Pending {
        device_id: u64,
        irp_id: u64,
    },
    OwnershipLost {
        irp_id: u64,
        transport_status: nt_status::NtStatus,
        receipt: Option<nt_pnp_manager::StartDeviceLifecycleReceipt>,
    },
    FilterPending {
        device_id: u64,
        irp_id: u64,
        resource_plan: PreparedHostedResourcePlan,
    },
    FilterOwnershipLost {
        device_id: u64,
        irp_id: u64,
        resource_plan: PreparedHostedResourcePlan,
        transport_status: nt_status::NtStatus,
    },
}

unsafe fn start_one_devnode<H, C>(
    driver_id: u64,
    service_name: &str,
    class_guid: Option<&str>,
    devnode: HostedPnpDevnodeStart<'_, H, C>,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) -> HostedPnpDevnodeProgress
where
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
            record_terminal_start_failure(report, status);
            print_resource_preparation_failure(
                options.trace,
                service_name,
                devnode.instance_id,
                status,
            );
            return HostedPnpDevnodeProgress::Terminal {
                device_id: 0,
                status,
                receipt: None,
            };
        }
    };
    let PreparedHostedDevnode {
        pdo_description,
        resource_plan,
    } = prepared;
    let bus_pdo = driver_launch::hosted_bus_reported_device_id(devnode.instance_id);
    if let Some(pdo_device_id) = bus_pdo {
        let (raw_boot_resources, resource_requirements) = resource_plan.native_property_blobs();
        if let Err(status) = driver_launch::validate_hosted_bus_pdo_resource_properties(
            devnode.instance_id,
            pdo_device_id,
            raw_boot_resources,
            resource_requirements,
        ) {
            let status = resource_plan
                .release_context_lease()
                .err()
                .unwrap_or(status);
            record_terminal_start_failure(report, status);
            print_resource_preparation_failure(
                options.trace,
                service_name,
                devnode.instance_id,
                status,
            );
            return HostedPnpDevnodeProgress::Terminal {
                device_id: 0,
                status,
                receipt: None,
            };
        }
    }
    let add_device = if options.reuse_existing_stack {
        driver_launch::hosted_function_device_id_for_instance(devnode.instance_id, driver_id)
    } else {
        match bus_pdo {
            Some(pdo_device_id) => driver_launch::call_add_device_for_bus_pdo(
                driver_id,
                class_guid,
                devnode.driver_key,
                devnode.linkage_export,
                devnode.instance_id,
                pdo_device_id,
            ),
            None => driver_launch::call_add_device_for_driver(
                driver_id,
                class_guid,
                devnode.driver_key,
                devnode.linkage_export,
                devnode.instance_id,
                devnode.hardware_ids,
                devnode.compatible_ids,
                pdo_description,
            ),
        }
    };
    match add_device {
        Ok(device_id) => {
            if !options.reuse_existing_stack {
                report.add_device = true;
                report.add_device_count += 1;
                print_add_device_success(
                    options.trace,
                    service_name,
                    devnode.instance_id,
                    device_id,
                );
            }
            let filter_outcome = match resource_plan.native_property_blobs().1 {
                Some(requirements) => driver_launch::filter_hosted_device_resource_requirements(
                    device_id,
                    requirements,
                ),
                None => {
                    driver_launch::commit_hosted_no_resource_requirements(device_id).map(|()| {
                        driver_launch::HostedFilterRequirementsOutcome::Filtered {
                            requirements: Vec::new(),
                        }
                    })
                }
            };
            match filter_outcome {
                Ok(driver_launch::HostedFilterRequirementsOutcome::Filtered { requirements }) => {
                    start_filtered_devnode(
                        device_id,
                        resource_plan,
                        requirements,
                        service_name,
                        devnode.instance_id,
                        options,
                        report,
                    )
                }
                Ok(driver_launch::HostedFilterRequirementsOutcome::Failed(status))
                | Err(status) => finish_filter_failure(
                    device_id,
                    resource_plan,
                    service_name,
                    devnode.instance_id,
                    options,
                    status,
                    report,
                ),
                Ok(driver_launch::HostedFilterRequirementsOutcome::Pending { irp_id }) => {
                    HostedPnpDevnodeProgress::FilterPending {
                        device_id,
                        irp_id,
                        resource_plan,
                    }
                }
                Ok(driver_launch::HostedFilterRequirementsOutcome::Indeterminate {
                    irp_id,
                    transport_status,
                }) => HostedPnpDevnodeProgress::FilterOwnershipLost {
                    device_id,
                    irp_id,
                    resource_plan,
                    transport_status,
                },
            }
        }
        Err(status) => {
            let status = resource_plan
                .release_context_lease()
                .err()
                .unwrap_or(status);
            record_terminal_start_failure(report, status);
            print_add_device_failure(options.trace, service_name, devnode.instance_id, status);
            HostedPnpDevnodeProgress::Terminal {
                device_id: 0,
                status,
                receipt: None,
            }
        }
    }
}

unsafe fn finish_filter_failure(
    device_id: u64,
    resource_plan: PreparedHostedResourcePlan,
    service_name: &str,
    instance_id: &str,
    options: HostedPnpStartOptions,
    status: nt_status::NtStatus,
    report: &mut HostedPnpStartReport,
) -> HostedPnpDevnodeProgress {
    let status = driver_launch::rollback_hosted_device_start(device_id)
        .err()
        .unwrap_or(status);
    let status = resource_plan
        .release_context_lease()
        .err()
        .unwrap_or(status);
    record_terminal_start_failure(report, status);
    print_resource_grant_failure(options.trace, service_name, instance_id, status);
    HostedPnpDevnodeProgress::Terminal {
        device_id: 0,
        status,
        receipt: None,
    }
}

unsafe fn start_filtered_devnode(
    device_id: u64,
    resource_plan: PreparedHostedResourcePlan,
    filtered_resource_requirements: Vec<u8>,
    service_name: &str,
    instance_id: &str,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) -> HostedPnpDevnodeProgress {
    let start_status = match grant_prepared_hosted_devnode_resources(
        device_id,
        resource_plan,
        filtered_resource_requirements,
    ) {
        Ok(Some(grant)) => {
            print_hosted_devnode_grant(service_name.as_bytes(), instance_id.as_bytes(), &grant);
            match driver_launch::commit_hosted_device_resource_assignment(
                device_id,
                &grant.raw_resource_list,
                &grant.translated_resource_list,
            ) {
                Ok(()) => canonical_start_status(
                    device_id,
                    &grant.raw_resource_list,
                    &grant.translated_resource_list,
                ),
                Err(status) => CanonicalStartDisposition::Terminal {
                    status: rollback_pre_dispatch_start(device_id, status),
                    waited: false,
                    receipt: None,
                },
            }
        }
        Ok(None) => {
            match driver_launch::commit_hosted_device_resource_assignment(device_id, &[], &[]) {
                Ok(()) => canonical_start_status(device_id, &[], &[]),
                Err(status) => CanonicalStartDisposition::Terminal {
                    status: rollback_pre_dispatch_start(device_id, status),
                    waited: false,
                    receipt: None,
                },
            }
        }
        Err(status) => {
            let status = rollback_pre_dispatch_start(device_id, status);
            print_resource_grant_failure(options.trace, service_name, instance_id, status);
            CanonicalStartDisposition::Terminal {
                status,
                waited: false,
                receipt: None,
            }
        }
    };
    match start_status {
        CanonicalStartDisposition::Terminal {
            status,
            waited,
            receipt,
        } => {
            finish_started_devnode(
                device_id,
                service_name,
                instance_id,
                options,
                status,
                waited,
                report,
            );
            HostedPnpDevnodeProgress::Terminal {
                device_id: status.is_success().then_some(device_id).unwrap_or(0),
                status,
                receipt,
            }
        }
        CanonicalStartDisposition::OwnershipLost {
            irp_id,
            transport_status,
            receipt,
            observed_driver_pending,
        } => {
            record_start_indeterminate(report, transport_status, observed_driver_pending);
            print_start_indeterminate(options.trace, service_name, instance_id, transport_status);
            HostedPnpDevnodeProgress::OwnershipLost {
                irp_id,
                transport_status,
                receipt,
            }
        }
        CanonicalStartDisposition::Pending {
            irp_id,
            driver_pending,
        } => {
            report.pending += 1;
            report.pending_observed += driver_pending as u64;
            print_start_pending(options.trace, service_name, instance_id);
            HostedPnpDevnodeProgress::Pending { device_id, irp_id }
        }
    }
}

enum CanonicalStartDisposition {
    Terminal {
        status: nt_status::NtStatus,
        waited: bool,
        receipt: Option<nt_pnp_manager::StartDeviceLifecycleReceipt>,
    },
    Pending {
        irp_id: u64,
        driver_pending: bool,
    },
    OwnershipLost {
        irp_id: u64,
        transport_status: nt_status::NtStatus,
        observed_driver_pending: bool,
        receipt: Option<nt_pnp_manager::StartDeviceLifecycleReceipt>,
    },
}

unsafe fn canonical_start_status(
    device_id: u64,
    raw_resource_list: &[u8],
    translated_resource_list: &[u8],
) -> CanonicalStartDisposition {
    match driver_launch::start_hosted_device_canonical(
        device_id,
        raw_resource_list,
        translated_resource_list,
    ) {
        Ok(driver_launch::HostedPnpStartOutcome::Started { receipt }) => {
            CanonicalStartDisposition::Terminal {
                status: nt_status::NtStatus::SUCCESS,
                waited: false,
                receipt: Some(receipt),
            }
        }
        Ok(driver_launch::HostedPnpStartOutcome::Failed { status, receipt }) => {
            CanonicalStartDisposition::Terminal {
                status,
                waited: false,
                receipt: Some(receipt),
            }
        }
        Ok(driver_launch::HostedPnpStartOutcome::Pending { irp_id }) => {
            observe_canonical_start(irp_id, true, true)
        }
        Ok(driver_launch::HostedPnpStartOutcome::Indeterminate {
            irp_id,
            transport_status,
        }) => CanonicalStartDisposition::OwnershipLost {
            irp_id,
            transport_status,
            observed_driver_pending: false,
            receipt: None,
        },
        Ok(driver_launch::HostedPnpStartOutcome::RepairRequired { irp_id, .. }) => {
            observe_canonical_start(irp_id, false, true)
        }
        Err(failure) if failure.rollback_safe => CanonicalStartDisposition::Terminal {
            status: rollback_pre_dispatch_start(device_id, failure.status),
            waited: false,
            receipt: None,
        },
        Err(failure) => CanonicalStartDisposition::Terminal {
            status: failure.status,
            waited: false,
            receipt: None,
        },
    }
}

unsafe fn observe_canonical_start(
    irp_id: u64,
    driver_pending: bool,
    pump_before_observe: bool,
) -> CanonicalStartDisposition {
    if pump_before_observe {
        driver_launch::pump_hosted_io_completions();
    }
    match driver_launch::observe_hosted_pnp_start(irp_id) {
        Ok(driver_launch::HostedPnpStartObservation::Terminal {
            driver_status,
            receipt,
        }) => CanonicalStartDisposition::Terminal {
            status: driver_status,
            waited: driver_pending,
            receipt: Some(receipt),
        },
        Ok(driver_launch::HostedPnpStartObservation::Indeterminate {
            transport_status,
            receipt,
        }) => CanonicalStartDisposition::OwnershipLost {
            irp_id,
            transport_status,
            observed_driver_pending: driver_pending,
            receipt,
        },
        Ok(driver_launch::HostedPnpStartObservation::AwaitingCompletion) => {
            CanonicalStartDisposition::Pending {
                irp_id,
                driver_pending,
            }
        }
        Err(transport_status) => CanonicalStartDisposition::OwnershipLost {
            irp_id,
            transport_status,
            observed_driver_pending: driver_pending,
            receipt: None,
        },
    }
}

unsafe fn rollback_pre_dispatch_start(
    device_id: u64,
    original_status: nt_status::NtStatus,
) -> nt_status::NtStatus {
    if let Err(status) = driver_launch::rollback_hosted_device_start(device_id) {
        return status;
    }
    original_status
}

unsafe fn grant_prepared_hosted_devnode_resources(
    device_id: u64,
    plan: PreparedHostedResourcePlan,
    filtered_resource_requirements: Vec<u8>,
) -> Result<Option<HostedDevnodeGrant>, nt_status::NtStatus> {
    grant_hosted_devnode_resources(device_id, plan, filtered_resource_requirements)
}

fn remember_error(report: &mut HostedPnpStartReport, status: nt_status::NtStatus) {
    if report.first_error == 0 {
        report.first_error = status.raw() as u32;
    }
}

fn record_terminal_start_failure(report: &mut HostedPnpStartReport, status: nt_status::NtStatus) {
    report.terminal += 1;
    report.failed += 1;
    remember_error(report, status);
}

fn record_start_indeterminate(
    report: &mut HostedPnpStartReport,
    transport_status: nt_status::NtStatus,
    observed_driver_pending: bool,
) {
    report.pending_observed += observed_driver_pending as u64;
    report.indeterminate += 1;
    if report.first_indeterminate == 0 {
        report.first_indeterminate = transport_status.raw() as u32;
    }
}

unsafe fn finish_started_devnode(
    device_id: u64,
    service_name: &str,
    instance_id: &str,
    options: HostedPnpStartOptions,
    status: nt_status::NtStatus,
    observed_driver_pending: bool,
    report: &mut HostedPnpStartReport,
) {
    report.terminal += 1;
    report.pending_observed += observed_driver_pending as u64;
    if status.is_success() {
        report.start_ok = true;
        report.started += 1;
    } else {
        report.failed += 1;
        remember_error(report, status);
    }
    let status_raw = status.raw() as u32;
    print_start_status(options.trace, service_name, instance_id, status_raw);
    collect_hardware_evidence(
        device_id,
        options.trace,
        service_name,
        instance_id,
        status_raw,
        report,
    );
    if status.is_success() {
        try_publish_hosted_video_route(device_id, service_name, instance_id, report);
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

fn collect_hardware_evidence(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    report: &mut HostedPnpStartReport,
) {
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
        HostedPnpStartTrace::ConfigPnp => b"[driver-launch] config PnP AddDevice service=",
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
        HostedPnpStartTrace::ConfigPnp => b"[driver-launch] config PnP AddDevice failed status=0x",
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
        HostedPnpStartTrace::ConfigPnp => {
            b"[driver-launch] config PnP bus resource publication failed status=0x"
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
        HostedPnpStartTrace::ConfigPnp => {
            b"[driver-launch] config PnP resource grant failed status=0x"
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
            HostedPnpStartTrace::ConfigPnp => b"[driver-launch] config PnP StartDevice service=",
            HostedPnpStartTrace::DemandStart => b"[driver-launch] demand StartDevice service=",
            HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice service=",
        });
    } else {
        print_str(match trace {
            HostedPnpStartTrace::ConfigPnp => {
                b"[driver-launch] config PnP StartDevice failed service="
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

fn print_start_indeterminate(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    transport_status: nt_status::NtStatus,
) {
    print_str(match trace {
        HostedPnpStartTrace::ConfigPnp => {
            b"[driver-launch] config PnP StartDevice indeterminate service="
        }
        HostedPnpStartTrace::DemandStart => {
            b"[driver-launch] demand StartDevice indeterminate service="
        }
        HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice indeterminate service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" transport_status=");
    print_hex(transport_status.raw() as u32);
    print_str(b"\n");
}

fn print_start_pending(trace: HostedPnpStartTrace, service_name: &str, instance_id: &str) {
    print_str(match trace {
        HostedPnpStartTrace::ConfigPnp => {
            b"[driver-launch] config PnP StartDevice pending service="
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand StartDevice pending service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice pending service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b"\n");
}

fn print_hardware_evidence(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    evidence: driver_launch::HostedHardwareEvidence,
) {
    if trace == HostedPnpStartTrace::ConfigPnp {
        print_str(b"[driver-launch] config PnP evidence service=");
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
        HostedPnpStartTrace::ConfigPnp => b"[driver-launch] config PnP evidence service=",
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand hardware evidence service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] hardware evidence service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" group=");
    print_str(group);
}
