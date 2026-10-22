use crate::*;
use alloc::vec::Vec;

static ACTIVE_HOSTED_START_BATCH_DRIVES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

struct ActiveHostedStartBatchDrive;

impl ActiveHostedStartBatchDrive {
    fn enter() -> Self {
        ACTIVE_HOSTED_START_BATCH_DRIVES.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        Self
    }
}

impl Drop for ActiveHostedStartBatchDrive {
    fn drop(&mut self) {
        assert_ne!(
            ACTIVE_HOSTED_START_BATCH_DRIVES.fetch_sub(1, core::sync::atomic::Ordering::AcqRel),
            0,
        );
    }
}

pub(crate) fn hosted_start_batch_drive_active() -> bool {
    ACTIVE_HOSTED_START_BATCH_DRIVES.load(core::sync::atomic::Ordering::Acquire) != 0
}

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
    pending_filter_admission: Option<PendingHostedFilterAdmission>,
    pending_filter: Option<PendingHostedPnpFilter>,
    pending_grant_admission: Option<PendingHostedGrantAdmission>,
    pending_relations: Option<driver_launch::HostedPnpRelationRefresh>,
    pending_bus_relation_devnode: Option<usize>,
    bootstrap_required_bus_pdos: Vec<usize>,
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

struct PendingHostedFilterAdmission {
    devnode_index: usize,
    device_id: u64,
    resource_plan: PreparedHostedResourcePlan,
}

/// FILTER is terminal, but the accepted controller is not yet available for a physical grant.
/// Keep the same FDO and checked requirements until the controller owner admits START.
struct PendingHostedGrantAdmission {
    devnode_index: usize,
    device_id: u64,
    resource_plan: PreparedHostedResourcePlan,
    filtered_requirements: Vec<u8>,
    blocked_status: Option<nt_status::NtStatus>,
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
            pending_filter_admission: None,
            pending_filter: None,
            pending_grant_admission: None,
            pending_relations: None,
            pending_bus_relation_devnode: None,
            bootstrap_required_bus_pdos: Vec::new(),
            single_start_evidence: SingleStartEvidence::NotDispatched,
        }
    }

    /// An earlier registry-selected enumerator is still starting. Its relation, rather than this
    /// batch's registry instance string, must supply the exact child PDO before dispatch.
    pub(crate) fn require_bootstrap_bus_pdos(&mut self, devnodes: Vec<usize>) {
        assert!(self.coordinator.phase() == nt_driver_start::BatchPhase::Ready);
        assert!(devnodes.iter().all(|index| *index < self.spec.devnodes.len()));
        self.bootstrap_required_bus_pdos = devnodes;
    }

    pub(crate) fn service_name(&self) -> &str {
        &self.spec.service_name
    }

    /// A predecessor lost exact ownership before this batch entered native AddDevice/START.
    pub(crate) fn fail_unentered_bootstrap_barrier(
        &mut self,
        status: nt_status::NtStatus,
    ) -> OwnedHostedPnpStartProgress {
        assert!(self.coordinator.phase() == nt_driver_start::BatchPhase::Ready);
        self.coordinator.stop().expect("unentered boot START could not stop");
        if self.report.first_error == 0 {
            self.report.first_error = status.raw() as u32;
        }
        OwnedHostedPnpStartProgress::Complete(Err(HostedPnpStartBatchFailure {
            status,
            teardown_blocked: false,
        }))
    }

    pub(crate) fn driver_object_path(&self) -> &str {
        &self.spec.driver_object_path
    }

    pub(crate) unsafe fn owns_current_bus_child(
        &self,
        instance_id: &str,
        child_pdo: u64,
    ) -> bool {
        self.spec.devnodes.iter().enumerate().any(|(index, devnode)| {
            devnode.instance_id.eq_ignore_ascii_case(instance_id)
                && driver_launch::hosted_bus_reported_device_id(instance_id) == Some(child_pdo)
                && [
                    self.pending_filter.as_ref().map(|pending| (pending.devnode_index, pending.device_id)),
                    self.pending_filter_admission.as_ref().map(|pending| (pending.devnode_index, pending.device_id)),
                    self.pending_grant_admission.as_ref().map(|pending| (pending.devnode_index, pending.device_id)),
                ].into_iter().flatten().all(|(pending_index, device_id)| {
                    pending_index != index
                        || driver_launch::hosted_function_device_id_for_instance(
                            instance_id,
                            self.coordinator.driver_id(),
                        ) == Ok(device_id)
                })
        })
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

    unsafe fn retire_reserved_critical_start(
        &self,
        devnode_index: usize,
        status: nt_status::NtStatus,
        receipt: &nt_pnp_manager::StartDeviceLifecycleReceipt,
    ) {
        if self.options.trace != HostedPnpStartTrace::ConfigPnp {
            return;
        }
        let instance_id = &self.spec.devnodes[devnode_index].instance_id;
        driver_launch::retire_hosted_critical_child_from_config_start(
            instance_id,
            self.coordinator.driver_id(),
            status,
            receipt,
        )
        .expect("exact config START terminal could not retire its reserved critical child");
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
        self.pending_filter_admission.is_some()
            || self.pending_grant_admission.as_ref().is_some_and(|pending| pending.blocked_status.is_none())
            || self.pending_filter
            .as_ref()
            .is_some_and(|pending| pending.ownership_lost.is_none())
            || self.pending_relations.is_some()
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
            Ok(refresh) => {
                self.pending_relations = Some(refresh);
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
            HostedPnpDevnodeProgress::BusRelationPending { require_accepted_bus_pdo } => {
                if require_accepted_bus_pdo {
                    self.pending_bus_relation_devnode = Some(devnode_index);
                }
                return Some(OwnedHostedPnpStartProgress::AwaitingCompletion);
            }
            HostedPnpDevnodeProgress::ResourceAdmissionPending => {
                return Some(OwnedHostedPnpStartProgress::AwaitingCompletion);
            }
            HostedPnpDevnodeProgress::FilterAdmissionPending { device_id, resource_plan } => {
                assert!(self.pending_filter_admission.is_none());
                self.pending_filter_admission = Some(PendingHostedFilterAdmission {
                    devnode_index,
                    device_id,
                    resource_plan,
                });
                return Some(OwnedHostedPnpStartProgress::AwaitingCompletion);
            }
            HostedPnpDevnodeProgress::GrantAdmissionPending {
                device_id, resource_plan, filtered_requirements,
            } => {
                assert!(self.pending_grant_admission.is_none());
                self.pending_grant_admission = Some(PendingHostedGrantAdmission {
                    devnode_index,
                    device_id,
                    resource_plan,
                    filtered_requirements,
                    blocked_status: None,
                });
                return Some(OwnedHostedPnpStartProgress::AwaitingCompletion);
            }
            HostedPnpDevnodeProgress::GrantAdmissionBlocked {
                device_id, resource_plan, filtered_requirements, status,
            } => {
                assert!(self.pending_grant_admission.is_none());
                self.pending_grant_admission = Some(PendingHostedGrantAdmission {
                    devnode_index,
                    device_id,
                    resource_plan,
                    filtered_requirements,
                    blocked_status: Some(status),
                });
                return Some(OwnedHostedPnpStartProgress::OwnershipLost(
                    HostedPnpStartBatchFailure { status, teardown_blocked: true },
                ));
            }
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

        if self.pending_bus_relation_devnode == Some(devnode_index) {
            self.pending_bus_relation_devnode = None;
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
                    self.retire_reserved_critical_start(devnode_index, status, &receipt);
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
            HostedPnpDevnodeProgress::BusRelationPending { .. }
            | HostedPnpDevnodeProgress::FilterAdmissionPending { .. }
            | HostedPnpDevnodeProgress::FilterPending { .. }
            | HostedPnpDevnodeProgress::FilterOwnershipLost { .. }
            | HostedPnpDevnodeProgress::GrantAdmissionPending { .. }
            | HostedPnpDevnodeProgress::GrantAdmissionBlocked { .. }
            | HostedPnpDevnodeProgress::ResourceAdmissionPending => unreachable!(),
        }
    }

    unsafe fn drive_inner(&mut self, pump_before_observe: bool) -> OwnedHostedPnpStartProgress {
        let _active_drive = ActiveHostedStartBatchDrive::enter();
        loop {
            if let Some(refresh) = self.pending_relations {
                if pump_before_observe {
                    driver_launch::pump_hosted_io_completions();
                }
                match driver_launch::hosted_pnp_relation_progress(refresh) {
                    driver_launch::HostedPnpRelationProgress::Current => {
                        self.pending_relations = None;
                    }
                    driver_launch::HostedPnpRelationProgress::Pending => {
                        return OwnedHostedPnpStartProgress::AwaitingCompletion;
                    }
                    driver_launch::HostedPnpRelationProgress::Blocked(status) => {
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
            if let Some(pending) = self.pending_filter_admission.take() {
                let devnode_index = pending.devnode_index;
                let devnode = &self.spec.devnodes[devnode_index];
                let progress = filter_attached_devnode(
                    pending.device_id,
                    pending.resource_plan,
                    &self.spec.service_name,
                    &devnode.instance_id,
                    self.options,
                    &mut self.report,
                );
                if let Some(outcome) = self.apply_devnode_progress(devnode_index, progress) {
                    return outcome;
                }
                continue;
            }
            if let Some(status) = self.pending_grant_admission.as_ref().and_then(|pending| pending.blocked_status) {
                return OwnedHostedPnpStartProgress::OwnershipLost(
                    HostedPnpStartBatchFailure { status, teardown_blocked: true },
                );
            }
            if let Some(pending) = self.pending_grant_admission.take() {
                let devnode_index = pending.devnode_index;
                let devnode = &self.spec.devnodes[devnode_index];
                let progress = start_filtered_devnode(
                    pending.device_id,
                    pending.resource_plan,
                    pending.filtered_requirements,
                    &self.spec.service_name,
                    &devnode.instance_id,
                    self.options,
                    &mut self.report,
                );
                if let Some(outcome) = self.apply_devnode_progress(devnode_index, progress) {
                    return outcome;
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
                    Ok(driver_launch::HostedFilterRequirementsOutcome::AdmissionPending) => {
                        panic!("entered FILTER IRP reverted to pre-dispatch admission");
                    }
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
                                self.retire_reserved_critical_start(devnode_index, status, &receipt);
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
                        self.pending_bus_relation_devnode == Some(devnode_index)
                            || self.bootstrap_required_bus_pdos.contains(&devnode_index),
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
    BusReportedBusNumber {
        resources: nt_pnp_manager::BusReportedBusNumberStart,
    },
    BusOwnedRoot {
        resources: driver_launch::HostedBusOwnedRootResources,
    },
    Pci {
        bus_resources: DevnodePciBusResources,
        accepted_properties: Option<(Vec<u8>, Vec<u8>)>,
        window: HostedPnpPciResourceDescriptor,
        lease: nt_pnp_context::ContextLease,
    },
    PciNoResources {
        provider: nt_pnp_manager::AcceptedPdoProviderAuthority,
        child: nt_pnp_manager::DevnodeIdentity,
        device: nt_pnp::PciDevice,
    },
    Platform {
        grant: DevnodeRootResourceGrant,
        window: HostedPnpPlatformResourceDescriptor,
        lease: nt_pnp_context::ContextLease,
    },
    AcpiChild {
        resources: driver_launch::HostedAcceptedAcpiChildResources,
        ports: Vec<nt_cm_resources::PortDescriptor>,
        interrupt: nt_cm_resources::InterruptDescriptor,
        lease: nt_pnp_context::ContextLease,
    },
    AcpiChildNoResources {
        provider: nt_pnp_manager::AcceptedPdoProviderAuthority,
        child: nt_pnp_manager::DevnodeIdentity,
    },
    None,
}

impl PreparedHostedResourcePlan {
    fn grant_admission(&self) -> crate::boot_storage_dma_handoff::ControllerGrantAdmission {
        match self {
            Self::Pci { bus_resources, window, lease, .. } => {
                crate::boot_storage_dma_handoff::admit_hosted_pci_controller_grant(
                    lease.identity(), &bus_resources.device, window,
                )
            }
            Self::BusReportedBusNumber { .. } | Self::BusOwnedRoot { .. }
            | Self::PciNoResources { .. } | Self::Platform { .. }
            | Self::AcpiChild { .. } | Self::AcpiChildNoResources { .. }
            | Self::None => crate::boot_storage_dma_handoff::ControllerGrantAdmission::Current,
        }
    }

    fn native_property_blobs(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        match self {
            Self::BusReportedBusNumber { resources } => (Some(&resources.raw_resources), None),
            Self::BusOwnedRoot { resources } => (
                Some(&resources.snapshot.raw_resources),
                Some(&resources.snapshot.resource_requirements),
            ),
            Self::Pci { bus_resources, accepted_properties, .. } => accepted_properties
                .as_ref()
                .map(|(raw, requirements)| (Some(raw.as_slice()), Some(requirements.as_slice())))
                .unwrap_or((
                    Some(&bus_resources.raw_boot_resources),
                    Some(&bus_resources.resource_requirements),
                )),
            Self::Platform { grant, .. } => (
                Some(&grant.raw_boot_resources),
                Some(&grant.resource_requirements),
            ),
            Self::AcpiChild { resources, .. } => (
                Some(&resources.raw_resources),
                Some(&resources.resource_requirements),
            ),
            Self::PciNoResources { .. } | Self::AcpiChildNoResources { .. } | Self::None => (None, None),
        }
    }

    unsafe fn release_context_lease(self) -> Result<(), nt_status::NtStatus> {
        let lease = match self {
            Self::Pci { lease, .. } | Self::Platform { lease, .. }
            | Self::AcpiChild { lease, .. } => lease,
            Self::BusReportedBusNumber { .. } | Self::BusOwnedRoot { .. }
            | Self::PciNoResources { .. } | Self::AcpiChildNoResources { .. }
            | Self::None => return Ok(()),
        };
        release_hosted_pnp_context_lease(lease.into_identity())
    }

    unsafe fn interrupt_route_admission(
        &self,
    ) -> crate::hosted_pci_topology::HostedPciInterruptRouteAdmission {
        match self {
            Self::Pci { bus_resources, .. } => {
                crate::hosted_pci_topology::hosted_pci_interrupt_route_admission(
                    &bus_resources.device,
                )
            }
            Self::BusReportedBusNumber { .. } | Self::BusOwnedRoot { .. }
            | Self::Platform { .. }
            | Self::AcpiChild { .. } | Self::PciNoResources { .. }
            | Self::AcpiChildNoResources { .. }
            | Self::None => {
                crate::hosted_pci_topology::HostedPciInterruptRouteAdmission::Current
            }
        }
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
    pdo_description: Option<driver_launch::HostedPdoDescription>,
    resource_plan: PreparedHostedResourcePlan,
}

fn acpi_child_reported_interrupt(
    raw: &[u8],
) -> Result<nt_pnp::PlatformInterruptResource, nt_status::NtStatus> {
    let invalid = nt_status::NtStatus::INVALID_DEVICE_REQUEST;
    if nt_cm_resources::validate_cm_resource_list_extent(raw).map_err(|_| invalid)? != raw.len()
        || u32::from_le_bytes(raw.get(0..4).ok_or(invalid)?.try_into().unwrap()) != 1
    {
        return Err(invalid);
    }
    let count = u32::from_le_bytes(raw.get(16..20).ok_or(invalid)?.try_into().unwrap()) as usize;
    let mut interrupt = None;
    for index in 0..count {
        let offset = 20usize.checked_add(index.checked_mul(nt_cm_resources::PARTIAL_DESCRIPTOR_SIZE)
            .ok_or(invalid)?).ok_or(invalid)?;
        let descriptor = raw.get(offset..offset + nt_cm_resources::PARTIAL_DESCRIPTOR_SIZE)
            .ok_or(invalid)?;
        if descriptor[0] == nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT {
            if interrupt.is_some() { return Err(invalid); }
            let level = u32::from_le_bytes(descriptor[4..8].try_into().unwrap());
            let flags = u16::from_le_bytes(descriptor[2..4].try_into().unwrap());
            if level == 0 || !matches!(flags,
                nt_cm_resources::CM_RESOURCE_INTERRUPT_LATCHED
                    | nt_cm_resources::CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE)
            {
                return Err(invalid);
            }
            interrupt = Some(nt_pnp::PlatformInterruptResource {
                level,
                vector: level,
                affinity: 1,
                latched: flags == nt_cm_resources::CM_RESOURCE_INTERRUPT_LATCHED,
                shared: descriptor[1] == nt_cm_resources::CM_RESOURCE_SHARE_SHARED,
            });
        }
    }
    interrupt.ok_or(invalid)
}

unsafe fn prepare_current_hosted_devnode<H, C>(
    bus_pdo: Option<u64>,
    require_accepted_bus_pdo: bool,
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
) -> Result<PreparedHostedDevnode, nt_status::NtStatus>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    if require_accepted_bus_pdo && bus_pdo.is_none() {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    if let Some(pdo_device_id) = bus_pdo {
        let bus_number = driver_launch::prepare_hosted_bus_pdo_bus_number_start(
            instance_id, pdo_device_id,
        )?;

        if let Some(resources) = bus_number {
            return Ok(PreparedHostedDevnode {
                pdo_description: None,
                resource_plan: PreparedHostedResourcePlan::BusReportedBusNumber { resources },
            });
        }
    }

    let lease = acquire_hosted_pnp_context_lease()?;
    if let Some(pdo) = bus_pdo {
        match driver_launch::hosted_accepted_bus_owned_root_resources(instance_id, pdo) {
            Ok(Some(resources)) => {
                release_hosted_pnp_context_lease(lease.into_identity())?;
                return Ok(PreparedHostedDevnode {
                    pdo_description: None,
                    resource_plan: PreparedHostedResourcePlan::BusOwnedRoot { resources },
                });
            }
            Ok(None) => {}
            Err(status) => {
                driver_launch::trace_hosted_bus_resource_refusal(
                    b"bus-owned-root", instance_id, pdo, status,
                );
                return Err(release_context_lease_after_error(lease, status));
            }
        }
        let accepted = match driver_launch::hosted_accepted_acpi_child_resources(instance_id, pdo) {
            Ok(accepted) => accepted,
            Err(status) => {
                driver_launch::trace_hosted_bus_resource_refusal(
                    b"accepted-acpi", instance_id, pdo, status,
                );
                return Err(release_context_lease_after_error(lease, status));
            }
        };

        if let Some(driver_launch::AcceptedAcpiChildResources::NoResources { provider, child }) = accepted {
            release_hosted_pnp_context_lease(lease.into_identity())?;
            return Ok(PreparedHostedDevnode {
                pdo_description: None,
                resource_plan: PreparedHostedResourcePlan::AcpiChildNoResources { provider, child },
            });
        }

        if let Some(driver_launch::AcceptedAcpiChildResources::Present(resources)) = accepted {
            let admitted = (|| {
                let interrupt = acpi_child_reported_interrupt(&resources.raw_resources)?;

                let admitted = nt_pnp::admit_bus_reported_platform_resources(
                    &resources.raw_resources,
                    &resources.resource_requirements,
                    &[nt_pnp::PlatformPortResource { start: 0, length: u16::MAX as u32 + 1 }],
                    interrupt,
                ).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;

                let (gsi, _) = crate::resolve_hosted_legacy_irq(
                    admitted.raw_interrupt.level,
                    admitted.raw_interrupt.flags != nt_cm_resources::CM_RESOURCE_INTERRUPT_LATCHED,
                )?;

                if crate::resolve_platform_ioapic_gsi(gsi).is_none() {
                    return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                }

                Ok::<_, nt_status::NtStatus>((admitted.ports, admitted.raw_interrupt))
            })();
            let (ports, interrupt) = match admitted {
                Ok(admitted) => admitted,
                Err(status) => {
                    driver_launch::trace_hosted_bus_resource_refusal(
                        b"acpi-resource-admission", instance_id, pdo, status,
                    );
                    return Err(release_context_lease_after_error(lease, status));
                }
            };
            return Ok(PreparedHostedDevnode {
                pdo_description: None,
                resource_plan: PreparedHostedResourcePlan::AcpiChild {
                    resources, ports, interrupt, lease,
                },
            });
        }
    }
    let context = match hosted_pnp_context_description(&lease) {
        Ok(context) => context,
        Err(status) => {
            return Err(release_context_lease_after_error(lease, status));
        }
    };
    let accepted_pci_pdo = bus_pdo.filter(|_| nt_pnp::parse_pci_id_pattern(instance_id).is_some());
    let pci_device = if let Some(pdo) = accepted_pci_pdo {
        let (bus_number, address) = match driver_launch::hosted_accepted_pci_location(instance_id, pdo) {
            Ok(location) => location,
            Err(status) => return Err(release_context_lease_after_error(lease, status)),
        };
        nt_pnp::find_pci_device_for_accepted_pdo(
            &context.pci_devices,
            instance_id,
            hardware_ids,
            bus_number,
            address,
        )
    } else {
        nt_pnp::find_pci_device_for_devnode(
            &context.pci_devices,
            instance_id,
            hardware_ids,
            compatible_ids,
        )
    };

    if accepted_pci_pdo.is_some() && pci_device.is_none() {
        return Err(release_context_lease_after_error(
            lease,
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ));
    }

    if let Some(device) = pci_device {
        let accepted_properties = match bus_pdo {
            Some(pdo) => match driver_launch::hosted_accepted_pci_resource_properties(
                instance_id, pdo, device,
            ) {
                Ok(driver_launch::AcceptedPciResourceProperties::NoResources { provider, child }) => {
                    let device = device.clone();
                    release_hosted_pnp_context_lease(lease.into_identity())?;
                    return Ok(PreparedHostedDevnode {
                        pdo_description: None,
                        resource_plan: PreparedHostedResourcePlan::PciNoResources {
                            provider, child, device,
                        },
                    });
                }
                Ok(driver_launch::AcceptedPciResourceProperties::Present { raw, requirements }) => {
                    Some((raw, requirements))
                }
                Err(status) => return Err(release_context_lease_after_error(lease, status)),
            },
            None => None,
        };
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
            pdo_description: Some(driver_launch::HostedPdoDescription {
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
            }),
            resource_plan: PreparedHostedResourcePlan::Pci {
                bus_resources,
                accepted_properties,
                window,
                lease,
            },
        });
    }

    let platform_window = context
        .platform_windows
        .iter()
        .find(|window| window.matches_devnode(instance_id, hardware_ids, compatible_ids))
        .cloned();

    if let Some(window) = platform_window {
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
            pdo_description: Some(driver_launch::HostedPdoDescription {
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
            }),
            resource_plan: PreparedHostedResourcePlan::Platform {
                grant,
                window,
                lease,
            },
        });
    }

    release_hosted_pnp_context_lease(lease.into_identity())?;



    Ok(PreparedHostedDevnode {
        pdo_description: Some(driver_launch::HostedPdoDescription {
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
        }),
        resource_plan: PreparedHostedResourcePlan::None,
    })
}

enum HostedPnpDevnodeProgress {
    BusRelationPending { require_accepted_bus_pdo: bool },
    ResourceAdmissionPending,
    FilterAdmissionPending {
        device_id: u64,
        resource_plan: PreparedHostedResourcePlan,
    },
    GrantAdmissionPending {
        device_id: u64,
        resource_plan: PreparedHostedResourcePlan,
        filtered_requirements: Vec<u8>,
    },
    GrantAdmissionBlocked {
        device_id: u64,
        resource_plan: PreparedHostedResourcePlan,
        filtered_requirements: Vec<u8>,
        status: nt_status::NtStatus,
    },
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

unsafe fn resolve_upper_filter_drivers(
    instance_id: &str,
) -> Result<(u64, Vec<u64>), nt_status::NtStatus> {
    let plan = config_manager_query_upper_filter_launch_plan(instance_id)
        .map_err(nt_status::NtStatus)?;
    let Some(plan) = plan else {
        if config_manager_query_upper_filter_launch_plan(instance_id)
            .map_err(nt_status::NtStatus)?
            .is_some()
        {
            return Err(nt_status::NtStatus::DEVICE_NOT_READY);
        }
        return Ok((0, Vec::new()));
    };
    let mut driver_ids = Vec::new();
    driver_ids
        .try_reserve_exact(plan.bindings.len())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;

    for binding in &plan.bindings {
        let driver_id = if let Some((driver_id, _)) =
            driver_launch::loaded_driver_pnp_start_context(&binding.driver_object_path)
        {
            driver_id
        } else {
            if driver_launch::driver_id_by_name(&binding.driver_object_path).is_some() {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            // DriverEntry is an irreversible native effect. Check the entire ordered policy and
            // every resolved service again before entering it, then fence the result afterward.
            if config_manager_query_upper_filter_launch_plan(instance_id)
                .map_err(nt_status::NtStatus)?
                .as_ref()
                != Some(&plan)
            {
                return Err(nt_status::NtStatus::DEVICE_NOT_READY);
            }
            let image_path = registry_ascii_path(&binding.image_path)
                .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
            let fs = crate::fs_loader::exec_fs().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
            let loaded = driver_launch::load_driver(
                &fs,
                &image_path,
                driver_launch::DriverClass::Device,
                &binding.driver_object_path,
                initial_system_driver_caller(),
            )?;
            if config_manager_query_upper_filter_launch_plan(instance_id)
                .map_err(nt_status::NtStatus)?
                .as_ref()
                != Some(&plan)
            {
                return Err(nt_status::NtStatus::DEVICE_NOT_READY);
            }
            if driver_launch::loaded_driver_pnp_start_context(&binding.driver_object_path)
                .map(|context| context.0)
                != Some(loaded.driver_id)
            {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            loaded.driver_id
        };
        if driver_launch::driver_add_device(driver_id) == 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        driver_ids.push(driver_id);
    }
    if config_manager_query_upper_filter_launch_plan(instance_id)
        .map_err(nt_status::NtStatus)?
        .as_ref()
        != Some(&plan)
    {
        return Err(nt_status::NtStatus::DEVICE_NOT_READY);
    }
    for (binding, driver_id) in plan.bindings.iter().zip(&driver_ids) {
        print_str(b"[pnp-upper-filter] devnode=");
        print_str(instance_id.as_bytes());
        print_str(b" generation=");
        print_u64(plan.mount_generation);
        print_str(b" service=");
        print_str(binding.service_name.as_bytes());
        print_str(b" driver-id=");
        print_u64(*driver_id);
        print_str(b" object=");
        print_str(binding.driver_object_path.as_bytes());
        print_str(b"\n");
    }
    Ok((plan.mount_generation, driver_ids))
}

unsafe fn start_one_devnode<H, C>(
    driver_id: u64,
    service_name: &str,
    class_guid: Option<&str>,
    devnode: HostedPnpDevnodeStart<'_, H, C>,
    require_accepted_bus_pdo: bool,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) -> HostedPnpDevnodeProgress
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    let bus_pdo = driver_launch::hosted_bus_reported_device_id(devnode.instance_id);
    let relation_pending = bus_pdo.is_none() && driver_launch::hosted_bus_relation_pending();

    if bus_pdo.is_none() && relation_pending {
        return HostedPnpDevnodeProgress::BusRelationPending { require_accepted_bus_pdo };
    }
    let prepared = match prepare_current_hosted_devnode(
        bus_pdo,
        require_accepted_bus_pdo,
        devnode.instance_id,
        devnode.hardware_ids,
        devnode.compatible_ids,
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            driver_launch::trace_hosted_bus_resource_refusal(
                b"prepare", devnode.instance_id, bus_pdo.unwrap_or(0), status,
            );
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
    match resource_plan.interrupt_route_admission() {
        crate::hosted_pci_topology::HostedPciInterruptRouteAdmission::Current => {}
        crate::hosted_pci_topology::HostedPciInterruptRouteAdmission::Pending => {
            return match resource_plan.release_context_lease() {
                Ok(()) => HostedPnpDevnodeProgress::ResourceAdmissionPending,
                Err(status) => {
                    report.attempted += 1;
                    record_terminal_start_failure(report, status);
                    print_resource_preparation_failure(
                        options.trace,
                        service_name,
                        devnode.instance_id,
                        status,
                    );
                    HostedPnpDevnodeProgress::Terminal {
                        device_id: 0,
                        status,
                        receipt: None,
                    }
                }
            };
        }
        crate::hosted_pci_topology::HostedPciInterruptRouteAdmission::Blocked(status) => {
            let status = resource_plan
                .release_context_lease()
                .err()
                .unwrap_or(status);
            driver_launch::trace_hosted_bus_resource_refusal(
                b"interrupt-route", devnode.instance_id, bus_pdo.unwrap_or(0), status,
            );
            report.attempted += 1;
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
            driver_launch::trace_hosted_bus_resource_refusal(
                b"property-match", devnode.instance_id, pdo_device_id, status,
            );
            report.attempted += 1;
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
    let existing_stack = bus_pdo.and_then(|_| {
        driver_launch::hosted_function_device_id_for_instance(devnode.instance_id, driver_id).ok()
    });
    if !options.reuse_existing_stack && existing_stack.is_none() {
        if let Some(pdo_device_id) = bus_pdo {
            match driver_launch::hosted_bus_pdo_attach_admission(
                devnode.instance_id,
                pdo_device_id,
            ) {
                Ok(()) => {}
                Err(nt_status::NtStatus::DEVICE_BUSY) => {
                    return match resource_plan.release_context_lease() {
                        Ok(()) => HostedPnpDevnodeProgress::ResourceAdmissionPending,
                        Err(status) => {
                            report.attempted += 1;
                            record_terminal_start_failure(report, status);
                            print_resource_preparation_failure(
                                options.trace,
                                service_name,
                                devnode.instance_id,
                                status,
                            );
                            HostedPnpDevnodeProgress::Terminal {
                                device_id: 0,
                                status,
                                receipt: None,
                            }
                        }
                    };
                }
                Err(status) => {
                    let status = resource_plan
                        .release_context_lease()
                        .err()
                        .unwrap_or(status);
                    report.attempted += 1;
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
        }
    }
    report.attempted += 1;
    let reused_stack = options.reuse_existing_stack || existing_stack.is_some();
    let add_device = if options.reuse_existing_stack {
        driver_launch::hosted_function_device_id_for_instance(devnode.instance_id, driver_id)
    } else if let Some(device_id) = existing_stack {
        Ok(device_id)
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
            None => match pdo_description {
                Some(pdo_description) => driver_launch::call_add_device_for_driver(
                    driver_id,
                    class_guid,
                    devnode.driver_key,
                    devnode.linkage_export,
                    devnode.instance_id,
                    devnode.hardware_ids,
                    devnode.compatible_ids,
                    pdo_description,
                ),
                None => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            },
        }
    };
    match add_device {
        Ok(device_id) => {
            if !reused_stack {
                report.add_device = true;
                report.add_device_count += 1;
                print_add_device_success(
                    options.trace,
                    service_name,
                    devnode.instance_id,
                    device_id,
                );
            }
            let (filter_generation, upper_filter_driver_ids) = match resolve_upper_filter_drivers(devnode.instance_id) {
                Ok(plan) => plan,
                Err(status) => {
                    print_str(b"[pnp-upper-filter] resolve failed status=0x");
                    print_hex(status.raw() as u32);
                    print_str(b" devnode=");
                    print_str(devnode.instance_id.as_bytes());
                    print_str(b"\n");
                    return finish_filter_failure(
                        device_id,
                        resource_plan,
                        service_name,
                        devnode.instance_id,
                        options,
                        status,
                        report,
                    );
                }
            };
            if let Err(status) = driver_launch::attach_hosted_class_upper_filters(
                devnode.instance_id,
                device_id,
                filter_generation,
                &upper_filter_driver_ids,
            ) {
                print_str(b"[pnp-upper-filter] AddDevice failed status=0x");
                print_hex(status.raw() as u32);
                print_str(b" devnode=");
                print_str(devnode.instance_id.as_bytes());
                print_str(b"\n");
                return finish_filter_failure(
                    device_id,
                    resource_plan,
                    service_name,
                    devnode.instance_id,
                    options,
                    status,
                    report,
                );
            }
            filter_attached_devnode(
                device_id,
                resource_plan,
                service_name,
                devnode.instance_id,
                options,
                report,
            )
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

/// Continue FILTER for the already attached stack. AdmissionPending retains this exact FDO and
/// context lease; a later drive retries only FILTER, never native AddDevice or upper filters.
unsafe fn filter_attached_devnode(
    device_id: u64,
    resource_plan: PreparedHostedResourcePlan,
    service_name: &str,
    instance_id: &str,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) -> HostedPnpDevnodeProgress {
    if driver_launch::hosted_filter_resource_admission_pending() {
        return HostedPnpDevnodeProgress::FilterAdmissionPending { device_id, resource_plan };
    }
    if let PreparedHostedResourcePlan::AcpiChildNoResources { provider, child } = &resource_plan {
        if let Err(status) = driver_launch::validate_hosted_accepted_acpi_no_resources(
            instance_id, device_id, *provider, *child,
        ) {
            return finish_filter_failure(
                device_id, resource_plan, service_name, instance_id, options, status, report,
            );
        }
    }
    if let PreparedHostedResourcePlan::PciNoResources { provider, child, device } = &resource_plan {
        if let Err(status) = driver_launch::validate_hosted_accepted_pci_no_resources(
            instance_id, device_id, *provider, *child, device,
        ) {
            return finish_filter_failure(
                device_id, resource_plan, service_name, instance_id, options, status, report,
            );
        }
    }
    let filter_outcome = match resource_plan.native_property_blobs().1 {
        Some(requirements) => driver_launch::filter_hosted_device_resource_requirements(
            device_id,
            requirements,
        ),
        None => driver_launch::commit_hosted_no_resource_requirements(device_id).map(|()| {
            driver_launch::HostedFilterRequirementsOutcome::Filtered {
                requirements: Vec::new(),
            }
        }),
    };
    match filter_outcome {
        Ok(driver_launch::HostedFilterRequirementsOutcome::AdmissionPending) => {
            HostedPnpDevnodeProgress::FilterAdmissionPending { device_id, resource_plan }
        }
        Ok(driver_launch::HostedFilterRequirementsOutcome::Filtered { requirements }) => {
            start_filtered_devnode(
                device_id,
                resource_plan,
                requirements,
                service_name,
                instance_id,
                options,
                report,
            )
        }
        Ok(driver_launch::HostedFilterRequirementsOutcome::Failed(status)) | Err(status) => {
            finish_filter_failure(
                device_id,
                resource_plan,
                service_name,
                instance_id,
                options,
                status,
                report,
            )
        }
        Ok(driver_launch::HostedFilterRequirementsOutcome::Pending { irp_id }) => {
            HostedPnpDevnodeProgress::FilterPending { device_id, irp_id, resource_plan }
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

unsafe fn finish_filter_failure(
    device_id: u64,
    resource_plan: PreparedHostedResourcePlan,
    service_name: &str,
    instance_id: &str,
    options: HostedPnpStartOptions,
    status: nt_status::NtStatus,
    report: &mut HostedPnpStartReport,
) -> HostedPnpDevnodeProgress {
    let original_status = status;
    let rollback_status = driver_launch::rollback_hosted_device_start(device_id).err();
    let status = rollback_status.unwrap_or(status);
    let lease_status = resource_plan.release_context_lease().err();
    let status = lease_status.unwrap_or(status);
    static FILTER_FAILURE_DIAGNOSTIC_COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if FILTER_FAILURE_DIAGNOSTIC_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 8 {
        print_str(b"[hosted-filter-failure] device/original/rollback/lease/final=");
        print_u64(device_id);
        for diagnostic_status in [
            Some(original_status), rollback_status, lease_status, Some(status),
        ] {
            print_str(b"/0x");
            print_hex(diagnostic_status.unwrap_or(nt_status::NtStatus::SUCCESS).raw() as u32);
        }
        print_str(b" devnode=");
        print_str(instance_id.as_bytes());
        print_str(b"\n");
    }
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
    match resource_plan.grant_admission() {
        crate::boot_storage_dma_handoff::ControllerGrantAdmission::Current => {}
        crate::boot_storage_dma_handoff::ControllerGrantAdmission::Pending => {
            return HostedPnpDevnodeProgress::GrantAdmissionPending {
                device_id,
                resource_plan,
                filtered_requirements: filtered_resource_requirements,
            };
        }
        crate::boot_storage_dma_handoff::ControllerGrantAdmission::Blocked(status) => {
            return HostedPnpDevnodeProgress::GrantAdmissionBlocked {
                device_id,
                resource_plan,
                filtered_requirements: filtered_resource_requirements,
                status,
            };
        }
    }
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
                Err(status) => {
                    trace_canonical_start_failure(b"assignment", device_id, status);
                    CanonicalStartDisposition::Terminal {
                        status: rollback_pre_dispatch_start(device_id, status),
                        waited: false,
                        receipt: None,
                    }
                }
            }
        }
        Ok(None) => {
            match driver_launch::commit_hosted_device_resource_assignment(device_id, &[], &[]) {
                Ok(()) => canonical_start_status(device_id, &[], &[]),
                Err(status) => {
                    trace_canonical_start_failure(b"empty-assignment", device_id, status);
                    CanonicalStartDisposition::Terminal {
                        status: rollback_pre_dispatch_start(device_id, status),
                        waited: false,
                        receipt: None,
                    }
                }
            }
        }
        Err(status) => {
            trace_canonical_start_failure(b"grant", device_id, status);
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
            trace_canonical_start_failure(b"driver-returned", device_id, status);
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
        Err(failure) if failure.rollback_safe => {
            trace_canonical_start_failure(b"pre-dispatch", device_id, failure.status);
            CanonicalStartDisposition::Terminal {
                status: rollback_pre_dispatch_start(device_id, failure.status),
                waited: false,
                receipt: None,
            }
        }
        Err(failure) => {
            trace_canonical_start_failure(b"unretired-owner", device_id, failure.status);
            CanonicalStartDisposition::Terminal {
                status: failure.status,
                waited: false,
                receipt: None,
            }
        }
    }
}

fn trace_canonical_start_failure(stage: &[u8], device_id: u64, status: nt_status::NtStatus) {
    print_str(b"[canonical-start-failure] stage=");
    print_str(stage);
    print_str(b" device=");
    print_u64(device_id);
    print_str(b" status=0x");
    print_hex(status.raw() as u32);
    print_str(b"\n");
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
        Ok(driver_launch::HostedPnpStartObservation::NotEntered { status, device_id }) => {
            CanonicalStartDisposition::Terminal {
                status: rollback_pre_dispatch_start(device_id, status),
                waited: driver_pending,
                receipt: None,
            }
        }
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
        trace_canonical_start_failure(b"rollback", device_id, status);
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
        driver_launch::fence_hosted_acpi_child_interrupt_for_device(device_id)
            .expect("failed START could not fence its accepted ACPI child IRQ claim");
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
    if crate::current_win32k_provider_domain().is_none() {
        return;
    }
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
            allocate_projection: crate::win32k_subsystem::allocate_root_provider_pool_allocation,
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
