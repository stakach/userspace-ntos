//! Durable native AddDevice pump and rollback transaction.

use super::*;

/// AddDevice may publish registry identity on a primary page and dispatch on a provider page.
/// Keep one exclusive retained row covering both in the canonical transfer lease table.
/// It has no active bank selector, so AddDevice callbacks cannot mistake it for an IRP bank.
static NEXT_ADD_DEVICE_BANK_ID: AtomicU64 = AtomicU64::new(1);

unsafe fn reserve_add_device_bank(
    shared_va: u64,
    secondary_shared_va: Option<u64>,
    instance_index: usize,
) -> Result<SuspendedActiveHostedIrpTransfer, nt_status::NtStatus> {
    let id = NEXT_ADD_DEVICE_BANK_ID.fetch_update(
        Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
    ).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let transfers = active_hosted_irp_transfers_mut();
    let reservation = transfers.reserve()
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let Some(source_domain) = instance(instance_index).and_then(instance_domain_identity) else {
        let _ = transfers.cancel_reservation(reservation);
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    };
    let Some(banks) = hosted_irp_banks::HostedIrpBanks::new(&[], &[]) else {
        let _ = transfers.cancel_reservation(reservation);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    let secondary_shared_va = secondary_shared_va.filter(|secondary| *secondary != shared_va);
    let transfer = ActiveHostedIrpTransfer {
        shared_va, secondary_shared_va, transfer_id: id,
        source_instance: instance_index, source_domain: Some(source_domain),
        requestor_thread: None, create_subject: None, source_registered: false,
        file_create: None, banks,
        input_cursor: BankedTransferCursor::new(0),
        output_seed_cursor: BankedTransferCursor::new(0),
        output_cursor: BankedTransferCursor::new(0),
        bank_ticks: 0, measure_bank: false, diagnostic_file_rpc: false,
    };
    let ticket = match transfers.retain_exclusive_by(
        reservation, (shared_va, id, instance_index), transfer,
        |held| held.shared_va == shared_va
            || held.secondary_shared_va == Some(shared_va)
            || secondary_shared_va.is_some_and(|secondary|
                held.shared_va == secondary || held.secondary_shared_va == Some(secondary)),
    ) {
        Ok(ticket) => ticket,
        Err((error, _transfer)) => {
            let _ = transfers.cancel_reservation(reservation);
            return Err(if error == nt_user_host::durable_context_lease::DurableContextLeaseError::ConflictingRetained {
                nt_status::NtStatus::DEVICE_BUSY
            } else {
                nt_status::NtStatus::INSUFFICIENT_RESOURCES
            });
        }
    };
    Ok(SuspendedActiveHostedIrpTransfer { ticket })
}

pub(super) unsafe fn retire_add_device_bank(
    ticket: SuspendedActiveHostedIrpTransfer,
) -> Result<(), (nt_status::NtStatus, SuspendedActiveHostedIrpTransfer)> {
    active_hosted_irp_transfers_mut().retire(ticket.ticket)
        .map(|_| ())
        .map_err(|_| (nt_status::NtStatus::INVALID_HANDLE, ticket))
}

pub(super) struct AddDeviceBanks {
    ticket: Option<SuspendedActiveHostedIrpTransfer>,
}

impl AddDeviceBanks {
    /// Retain the exact class dispatch page before either native upper-filter phase enters.
    /// The caller keeps this owner through child work, terminal validation, and rollback.
    pub(super) unsafe fn claim(
        shared_va: u64,
        instance_index: usize,
    ) -> Result<Self, nt_status::NtStatus> {
        reserve_add_device_bank(shared_va, None, instance_index)
            .map(|ticket| Self { ticket: Some(ticket) })
    }

    /// Rollback may continue after the caller's stack unwinds. Give that durable owner the
    /// same exact page ticket before native AddDevice enters, so a deferred drain cannot race
    /// with another claimant of the class dispatch page.
    pub(super) unsafe fn transfer_to_rollback(
        &mut self,
        reservation: &hosted_add_device_rollback::Reservation,
    ) -> Result<(), nt_status::NtStatus> {
        let Some(ticket) = self.ticket.take() else {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        };
        match hosted_add_device_rollback::attach_bank_ticket(reservation, ticket) {
            Ok(()) => Ok(()),
            Err(ticket) => {
                self.ticket = Some(ticket);
                Err(nt_status::NtStatus::INVALID_HANDLE)
            }
        }
    }

    pub(super) unsafe fn retire(&mut self) -> Result<(), nt_status::NtStatus> {
        if let Some(ticket) = self.ticket.take() {
            if let Err((status, ticket)) = retire_add_device_bank(ticket) {
                self.ticket = Some(ticket);
                return Err(status);
            }
        }
        Ok(())
    }

    pub(super) fn held(&self) -> bool { self.ticket.is_some() }
}

/// The native AddDevice request has one dispatch page and one physical Reply. A yielded pump
/// owns the Reply here; its caller keeps this with both leased pages and rollback transaction.
pub(super) struct AddDevicePumpContinuation {
    pump: Option<component_scheduler::HostedPumpRestore>,
    child_step: Option<crate::service_sec_image::NestedChildStep>,
    instance_index: usize,
    shared_va: u64,
    driver_object: u64,
    pdo_object: u64,
    projection: bool,
}

impl AddDevicePumpContinuation {
    pub(super) fn physical_identity(&self) -> Option<component_scheduler::ChildWorkPhysicalIdentity> {
        self.pump.as_ref()?.child_work_identity()
    }
}

/// Enter CREATE_PDO_PROJECTION once while the AddDevice transaction owns the shared-page
/// lease. A yielded projection carries the same physical Reply and one-use child receipt as
/// the later AddDevice dispatch; its caller may not send another ReplyRequest on resume.
pub(super) unsafe fn dispatch_pdo_projection_progress(
    projection_instance: usize,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> AddDevicePumpProgress {
    let (ch, sh) = match prepare_device_projection_control_for_instance(
        projection_instance, 0, FSD_DISPATCH_CREATE_PDO_PROJECTION, 0, 0, false, None,
    ) {
        Ok(ready) => ready,
        Err(status) => return AddDevicePumpProgress::ProjectionCompleted(Err(status)),
    };
    let pump = component_scheduler::hosted_component_pump_with_caller_add_device_child_work(&ch, caller);
    AddDevicePumpContinuation {
        pump: Some(pump), child_step: None, instance_index: projection_instance,
        shared_va: sh, driver_object: 0, pdo_object: 0, projection: true,
    }.into_progress()
}

pub(super) enum AddDevicePumpProgress {
    Completed(Result<AddDeviceDispatchResult, nt_status::NtStatus>),
    ProjectionCompleted(Result<u64, nt_status::NtStatus>),
    ChildWorkYield(AddDevicePumpContinuation),
    RetainedRefusal(AddDevicePumpContinuation),
}

impl AddDevicePumpContinuation {
    pub(super) fn child_work_ready(&self) -> bool {
        self.child_step.is_none()
            && matches!(self.pump, Some(component_scheduler::HostedPumpRestore::ChildWorkReady { .. }))
    }

    pub(super) fn retry_without_new_child(&self) -> bool {
        self.child_step.is_some()
            || matches!(self.pump, Some(component_scheduler::HostedPumpRestore::ChildWorkPending(ref pending))
                if pending.retryable())
            || matches!(self.pump,
                Some(component_scheduler::HostedPumpRestore::Retained { retryable: true, .. }))
    }

    pub(super) fn record_child_step(
        &mut self,
        step: crate::service_sec_image::NestedChildStep,
    ) -> Result<(), crate::service_sec_image::NestedChildStep> {
        if !self.child_work_ready() { return Err(step); }
        self.child_step = Some(step);
        Ok(())
    }

    pub(super) unsafe fn resume(mut self) -> AddDevicePumpProgress {
        let Some(pump) = self.pump.take() else {
            return AddDevicePumpProgress::RetainedRefusal(self);
        };
        let next = match pump {
            component_scheduler::HostedPumpRestore::ChildWorkReady { .. } => {
                let Some(step) = self.child_step.take() else {
                    self.pump = Some(pump);
                    return AddDevicePumpProgress::RetainedRefusal(self);
                };
                match component_scheduler::resume_child_work(pump, step) {
                    Ok(next) => next,
                    Err((pump, step)) => {
                        self.pump = Some(pump);
                        self.child_step = Some(step);
                        return AddDevicePumpProgress::RetainedRefusal(self);
                    }
                }
            }
            component_scheduler::HostedPumpRestore::ChildWorkPending(pending)
                if pending.retryable() =>
                    component_scheduler::retry_child_work(
                        component_scheduler::HostedPumpRestore::ChildWorkPending(pending)),
            component_scheduler::HostedPumpRestore::Retained {
                result, key, ticket, retryable: true,
            } => component_scheduler::retry_retained_add_device_restore(
                component_scheduler::HostedPumpRestore::Retained {
                    result, key, ticket, retryable: true,
                }),
            other => other,
        };
        self.pump = Some(next);
        let detail = match self.pump.as_ref() {
            Some(component_scheduler::HostedPumpRestore::Restored(result)) =>
                1 | (u64::from(result.completed) << 8),
            Some(component_scheduler::HostedPumpRestore::ChildWorkReady { .. }) => 2,
            Some(component_scheduler::HostedPumpRestore::ChildWorkPending(pending)) =>
                3 | (u64::from(pending.retryable()) << 8),
            Some(component_scheduler::HostedPumpRestore::Retained { retryable, .. }) =>
                4 | (u64::from(*retryable) << 8),
            Some(component_scheduler::HostedPumpRestore::ChildWorkQuarantined { .. }) => 5,
            Some(component_scheduler::HostedPumpRestore::Unattributed(_)) => 6,
            None => 0,
        };
        trace_add_device_resume_gate(20, detail);
        self.into_progress()
    }

    unsafe fn into_progress(mut self) -> AddDevicePumpProgress {
        match self.pump.as_ref() {
            Some(component_scheduler::HostedPumpRestore::ChildWorkReady { .. }) =>
                AddDevicePumpProgress::ChildWorkYield(self),
            Some(component_scheduler::HostedPumpRestore::Restored(_)) => {
                if !matches!(self.pump.as_ref(),
                    Some(component_scheduler::HostedPumpRestore::Restored(result)) if result.completed)
                {
                    trace_add_device_resume_gate(21, 0);
                    return AddDevicePumpProgress::RetainedRefusal(self);
                }
                let Some(component_scheduler::HostedPumpRestore::Restored(pr)) = self.pump.take()
                else { unreachable!("checked AddDevice restored pump") };
                trace_add_device_access_violation(&pr);
                let status = nt_status::NtStatus(pr.status);
                let fdo_object = read_volatile((self.shared_va + SH_REQ_INFO) as *const u64);
                if self.projection {
                    let projection = status.to_result().and_then(|()| {
                        if fdo_object == 0 {
                            Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST)
                        } else {
                            Ok(fdo_object)
                        }
                    });
                    return AddDevicePumpProgress::ProjectionCompleted(projection);
                }
                let previous_device_head = read_volatile((self.shared_va + SH_REQ_OUTLEN) as *const u64);
                if status.is_success() && fdo_object == 0 {
                    return AddDevicePumpProgress::Completed(
                        Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST));
                }
                AddDevicePumpProgress::Completed(Ok(AddDeviceDispatchResult {
                    status, driver_object: self.driver_object, pdo_object: self.pdo_object,
                    fdo_object, previous_device_head,
                }))
            }
            _ => AddDevicePumpProgress::RetainedRefusal(self),
        }
    }
}

/// Enter a class-local lower-alias projection through the same move-only child-work pump as
/// AddDevice. The caller owns the exact attachment claim and shared-bank lease across a yield.
pub(super) unsafe fn dispatch_class_lower_alias_progress(
    class_instance: usize,
    prepared: hosted_upper_filter_projection::PreparedUpperFilterProjection,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> AddDevicePumpProgress {
    let (ch, sh) = match prepare_device_projection_control_for_instance(
        class_instance, 0, FSD_DISPATCH_CLASS_LOWER_ALIAS,
        prepared.pdo_object, 0, false, Some(prepared),
    ) {
        Ok(ready) => ready,
        Err(status) => return AddDevicePumpProgress::ProjectionCompleted(Err(status)),
    };
    let pump = component_scheduler::hosted_component_pump_with_caller_add_device_child_work(
        &ch, caller,
    );
    AddDevicePumpContinuation {
        pump: Some(pump), child_step: None, instance_index: class_instance,
        shared_va: sh, driver_object: 0, pdo_object: prepared.pdo_object,
        projection: true,
    }.into_progress()
}

pub(super) unsafe fn dispatch_add_device_for_instance_progress(
    index: usize,
    inst: DriverInstance,
    pdo_object: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> AddDevicePumpProgress {
    let prepare = (|| -> Result<_, nt_status::NtStatus> {
        if inst.driver_object == 0 || pdo_object == 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let (pump_index, pump_inst, driver_object, add_device, major, minor) =
            if let Some(route) = hosted_provider_dispatch_route_for_instance(index) {
                if !route.add_device_ready() { return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST); }
                let provider = instance(route.provider_instance)
                    .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
                (route.provider_instance, provider, route.provider_driver_object,
                    route.provider_add_device, FSD_DISPATCH_ADD_DEVICE, 0)
            } else if inst.add_device != 0 {
                (index, inst, inst.driver_object, inst.add_device, FSD_DISPATCH_ADD_DEVICE, 0)
            } else if hosted_instance_video_port_initialized(inst) {
                let number = allocate_hosted_video_object_number()
                    .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
                (index, inst, inst.driver_object, 0, FSD_DISPATCH_VIDEO_ADD_DEVICE, number as u64)
            } else {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            };
        if pump_inst.fault_ep == 0 || pump_inst.pml4 == 0 || pump_inst.reply_cap == 0 {
            return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        }
        let exec_code_va = ExecVaWindow::try_for_instance(pump_index)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?.code_va;
        let sh = pump_inst.exec_shared_va;
        write_volatile((sh + SH_DRVOBJ) as *mut u64, driver_object);
        if major != FSD_DISPATCH_VIDEO_ADD_DEVICE {
            write_volatile((sh + SH_ADD_DEVICE) as *mut u64, add_device);
        }
        write_volatile((sh + SH_REQ_MAJOR) as *mut u64, major);
        write_volatile((sh + SH_REQ_MINOR) as *mut u64, minor);
        write_volatile((sh + SH_REQ_FSCTL) as *mut u64, 0);
        write_volatile((sh + SH_REQ_INLEN) as *mut u64, 0);
        write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, 0);
        write_volatile((sh + SH_REQ_FILEID) as *mut u64, pdo_object);
        write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
        write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);
        write_volatile((sh + SH_ACTIVE_DEVICE_OBJECT) as *mut u64, 0);
        clear_shared_path_len_at(sh, SH_DEVICE_NAME_LEN);
        let ch = crate::spawn_hosts::PumpChannel {
            initial_root_dispatch: None, fault_ep: pump_inst.fault_ep, pml4: pump_inst.pml4,
            physical_domain: instance_domain_identity(pump_inst),
            ingress_route: hosted_ingress_sources::primary_route(pump_index),
            code_va: 0, image_frames: 0,
            exec_code_va,
            root_image_rights: 3, root_image_map_owner: pump_inst.map_cap_bank.owner,
            shared_va: sh, dispatch_label: FSD_DISPATCH_LABEL, demand_cap: 256,
            trace_faults: false, initial: crate::spawn_hosts::InitialAction::ReplyRequest,
            tcb: pump_inst.tcb, reply_cap: pump_inst.reply_cap, child_work_capable: false,
            client_pi: 0, client_generation: 0, logical_caller: None, kernel_caller: None,
            caps: crate::spawn_hosts::HostCaps {
                dispatch_server: true, kind: crate::spawn_hosts::ReqKind::Irp,
                io_port_faults: major == FSD_DISPATCH_VIDEO_ADD_DEVICE
                    && shared_has_port_resources(sh),
                ..crate::spawn_hosts::HostCaps::default()
            },
        };
        Ok((ch, pump_index, sh, driver_object))
    })();
    let (ch, pump_index, sh, driver_object) = match prepare {
        Ok(ready) => ready,
        Err(status) => return AddDevicePumpProgress::Completed(Err(status)),
    };
    let pump = component_scheduler::hosted_component_pump_with_caller_add_device_child_work(&ch, caller);
    AddDevicePumpContinuation {
        pump: Some(pump), child_step: None,
        instance_index: pump_index, shared_va: sh, driver_object, pdo_object,
        projection: false,
    }.into_progress()
}

/// Typed AddDevice entry for a root-bus PDO. The caller retains a yielded transaction in its
/// PnP batch; it must not treat a parked physical parent as an NTSTATUS return.
pub(crate) unsafe fn call_add_device_for_driver_progress<H, C>(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
    pdo_description: HostedPdoDescription,
) -> HostedAddDeviceProgress
where H: AsRef<str>, C: AsRef<str>,
{
    let bus_information = pdo_description.bus_information.clone();
    let pdo_address = pdo_description.capabilities.address;
    let setup = (|| -> Result<u64, nt_status::NtStatus> {
        let pdo_device_id = ensure_hosted_root_pdo(
            instance_path, hardware_ids, compatible_ids, pdo_description.resource_publication,
        )?;
        let pdo_device = nt_io_manager::DeviceId(pdo_device_id);
        let raw_boot_resources = hosted_root_bus_mut()
            .query_resources(pdo_device)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)
            .and_then(pnp_property_blob_from_bus_query)?;
        let resource_requirements = hosted_root_bus_mut()
            .query_resource_requirements(pdo_device)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)
            .and_then(pnp_property_blob_from_bus_query)?;
        let pdo_properties = nt_pnp_manager::PdoProperties::enumerated(
            pdo_description.bus_information, pdo_description.capabilities,
            raw_boot_resources, pdo_description.translated_boot_resources,
            resource_requirements,
        );
        hosted_pnp_manager_mut()
            .register_enumerated_pdo(instance_path, pdo_device_id, pdo_properties)
            .map_err(hosted_pnp_status)?;
        Ok(pdo_device_id)
    })();
    let pdo_device_id = match setup {
        Ok(pdo) => pdo,
        Err(status) => return HostedAddDeviceProgress::Completed(Err(status)),
    };
    call_add_device_for_existing_pdo_progress(
        driver_id, class_guid, driver_key, linkage_export, instance_path,
        pdo_device_id, Some(bus_information), pdo_address,
    )
}

pub(crate) unsafe fn call_add_device_for_bus_pdo_progress(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    pdo_device_id: u64,
) -> HostedAddDeviceProgress {
    if hosted_bus_reported_device_id(instance_path) != Some(pdo_device_id) {
        return HostedAddDeviceProgress::Completed(Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST));
    }
    let devnode_id = match hosted_pnp_manager_mut().devnode_for_pdo(pdo_device_id) {
        Some(id) => id,
        None => return HostedAddDeviceProgress::Completed(Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST)),
    };
    if !hosted_pnp_manager_mut().instance_id(devnode_id)
        .is_some_and(|value| value.eq_ignore_ascii_case(instance_path))
    {
        return HostedAddDeviceProgress::Completed(Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST));
    }
    let (bus_information, pdo_address) = match hosted_pnp_manager_mut()
        .enumerated_pdo_properties(pdo_device_id)
    {
        Some(properties) => (
            properties.bus_information.clone(),
            properties.capabilities.as_ref()
                .map(|capabilities| capabilities.address)
                .unwrap_or(nt_pnp_manager::DEVICE_ADDRESS_UNAVAILABLE),
        ),
        None => return HostedAddDeviceProgress::Completed(Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST)),
    };
    call_add_device_for_existing_pdo_progress(
        driver_id, class_guid, driver_key, linkage_export, instance_path,
        pdo_device_id, bus_information, pdo_address,
    )
}

/// Everything prepared for one real AddDevice entry. The rollback reservation remains the
/// authoritative owner of PDO, registry, power and projection effects until final settlement.
struct AddDeviceTransaction {
    rollback: Option<hosted_add_device_rollback::Reservation>,
    banks: AddDeviceBanks,
    registry_identity: HostedDriverRegistryIdentity,
    registry_identity_id: HostedRegistryIdentityId,
    provider_add_device_shared: Option<u64>,
    projection_inst: DriverInstance,
    projection_domain: HostedDomainIdentity,
    projection_instance: usize,
    index: usize,
    inst: DriverInstance,
    driver_id: u64,
    pdo_device_id: u64,
    pdo_object: u64,
    bus_information: Option<nt_pnp_manager::PnpBusInformation>,
    pdo_address: u32,
    bank_owned_by_rollback: bool,
}

enum AddDeviceFinishProgress {
    Completed(Result<u64, nt_status::NtStatus>),
    RetainedCommit(hosted_add_device_rollback::Reservation, u64, usize),
}

enum AddDevicePreparation {
    Ready(AddDeviceTransaction),
    Rejected(nt_status::NtStatus),
    Retained(AddDeviceTransaction, nt_status::NtStatus),
}

struct AddDeviceRetainedOwners {
    transaction: Option<AddDeviceTransaction>,
    pump: Option<AddDevicePumpContinuation>,
    terminal: Option<Result<AddDeviceDispatchResult, nt_status::NtStatus>>,
    projection_terminal: Option<Result<u64, nt_status::NtStatus>>,
    commit_retry: Option<(hosted_add_device_rollback::Reservation, u64, usize)>,
}

static NEXT_ADD_DEVICE_CONTINUATION_EPOCH: AtomicU64 = AtomicU64::new(1);

/// The retained key names the AddDevice transaction and, when a child is parked, the exact
/// physical source first authenticated by the scheduler. The move-only pump reauthenticates
/// the live route, dispatch and Reply on each subsequent receive and restore.
#[derive(Clone, Copy, Eq, PartialEq)]
struct AddDeviceRetainedKey {
    epoch: u64,
    driver_id: u64,
    pdo_object: u64,
    registry_identity_id: HostedRegistryIdentityId,
    primary_shared_va: u64,
    provider_shared_va: Option<u64>,
    physical: Option<component_scheduler::ChildWorkPhysicalIdentity>,
}

impl AddDeviceRetainedKey {
    fn new(transaction: &AddDeviceTransaction, epoch: u64,
        physical: Option<component_scheduler::ChildWorkPhysicalIdentity>) -> Self
    {
        Self {
            epoch, driver_id: transaction.driver_id, pdo_object: transaction.pdo_object,
            registry_identity_id: transaction.registry_identity_id,
            primary_shared_va: transaction.inst.exec_shared_va,
            provider_shared_va: transaction.provider_add_device_shared,
            physical,
        }
    }
}

#[must_use = "retain AddDevice rollback, Reply and shared bank until genuine completion"]
pub(crate) struct HostedAddDeviceContinuation {
    retained: nt_component_suspension::RetainedChildDispatch<
        AddDeviceRetainedKey, AddDeviceRetainedOwners,
        crate::service_sec_image::NestedChildStep,
    >,
    preentry_error: Option<nt_status::NtStatus>,
    preentry_block: bool,
    undeposited_terminal: Option<Result<AddDeviceDispatchResult, nt_status::NtStatus>>,
    undeposited_projection_terminal: Option<Result<u64, nt_status::NtStatus>>,
}

#[must_use = "an AddDevice yield or refusal still owns its physical transaction"]
pub(crate) enum HostedAddDeviceProgress {
    Completed(Result<u64, nt_status::NtStatus>),
    ChildWorkYield(HostedAddDeviceContinuation),
    RetainedRefusal(HostedAddDeviceContinuation),
}

/// Capped location probe for the retained AddDevice child restore. Stage 1 records
/// child-ready/retry bits; 2 entered the native pump; 3/4/5/6 are completed,
/// projection, yielded, and refused. Stages 10..18 identify pre-pump refusals.
pub(super) unsafe fn trace_add_device_resume_gate(stage: u64, detail: u64) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if !hosted_connect_live::pending_reply_published()
        || COUNT.fetch_add(1, Ordering::Relaxed) >= 32 { return; }
    print_str(b"[add-device-resume-gate] stage/detail=");
    print_u64(stage); print_str(b"/"); print_u64(detail); print_str(b"\n");
}

impl HostedAddDeviceContinuation {
    fn retain(transaction: AddDeviceTransaction, pump: AddDevicePumpContinuation, epoch: u64)
        -> Self
    {
        let key = AddDeviceRetainedKey::new(&transaction, epoch, pump.physical_identity());
        let mut retained = nt_component_suspension::RetainedChildDispatch::retain(
            key, AddDeviceRetainedOwners {
                transaction: Some(transaction), pump: Some(pump), terminal: None,
                projection_terminal: None,
                commit_retry: None,
            },
        );
        let _ = retained.park_for_child(key);
        Self { retained, preentry_error: None, preentry_block: false,
            undeposited_terminal: None,
            undeposited_projection_terminal: None }
    }

    fn retain_preentry(transaction: AddDeviceTransaction, status: nt_status::NtStatus,
        epoch: u64, block: bool)
        -> Self
    {
        let key = AddDeviceRetainedKey::new(&transaction, epoch, None);
        Self {
            retained: nt_component_suspension::RetainedChildDispatch::retain(
                key, AddDeviceRetainedOwners {
                    transaction: Some(transaction), pump: None, terminal: None,
                    projection_terminal: None,
                    commit_retry: None,
                },
            ),
            preentry_error: Some(status), preentry_block: block,
            undeposited_terminal: None,
            undeposited_projection_terminal: None,
        }
    }

    fn retain_terminal(
        transaction: AddDeviceTransaction,
        terminal: Result<AddDeviceDispatchResult, nt_status::NtStatus>,
        epoch: u64,
    ) -> Self {
        let key = AddDeviceRetainedKey::new(&transaction, epoch, None);
        let mut retained = nt_component_suspension::RetainedChildDispatch::retain(
            key, AddDeviceRetainedOwners {
                transaction: Some(transaction), pump: None, terminal: Some(terminal),
                projection_terminal: None,
                commit_retry: None,
            },
        );
        let _ = retained.park_for_child(key);
        Self { retained, preentry_error: None, preentry_block: false,
            undeposited_terminal: None,
            undeposited_projection_terminal: None }
    }

    fn retain_commit(key: AddDeviceRetainedKey,
        reservation: hosted_add_device_rollback::Reservation, device_id: u64, index: usize)
        -> Self
    {
        Self {
            retained: nt_component_suspension::RetainedChildDispatch::retain(
                key, AddDeviceRetainedOwners {
                    transaction: None, pump: None, terminal: None,
                    projection_terminal: None,
                    commit_retry: Some((reservation, device_id, index)),
                },
            ),
            preentry_error: None, preentry_block: false,
            undeposited_terminal: None,
            undeposited_projection_terminal: None,
        }
    }

    pub(crate) fn child_work_ready(&self) -> bool {
        self.retained.key().physical.is_some()
            && self.retained.owners(self.retained.key()).ok()
            .and_then(|owners| owners.pump.as_ref())
            .is_some_and(AddDevicePumpContinuation::child_work_ready)
    }

    pub(crate) fn retry_without_new_child(&self) -> bool {
        if self.preentry_error.is_some() { return true; }
        if self.undeposited_terminal.is_some() { return true; }
        if self.undeposited_projection_terminal.is_some() { return true; }
        self.retained.owners(self.retained.key()).ok()
            .is_some_and(|owners| owners.terminal.is_some()
                || owners.projection_terminal.is_some()
                || owners.commit_retry.is_some()
                || owners.pump.as_ref()
                    .is_some_and(AddDevicePumpContinuation::retry_without_new_child))
    }

    unsafe fn settle_terminal(mut self) -> HostedAddDeviceProgress {
        use nt_component_suspension::RetainedChildDispatchPhase;
        let key = self.retained.key();
        if let Some(result) = self.undeposited_terminal.take() {
            match self.retained.owners_mut(key) {
                Ok(owners) => owners.terminal = Some(result),
                Err(_) => {
                    self.undeposited_terminal = Some(result);
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
            }
        }
        if self.retained.phase() == RetainedChildDispatchPhase::Parked
            && self.retained.begin_restore_without_child(key).is_err()
        {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if self.retained.phase() == RetainedChildDispatchPhase::Restoring
            && self.retained.acknowledge_restore(key).is_err()
        {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if self.retained.phase() != RetainedChildDispatchPhase::Restored {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        let Some(transaction) = self.retained.owners_mut(key).ok()
            .and_then(|owners| owners.transaction.as_mut()) else {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        };
        // The typed bank is owned by rollback through all shared-page cleanup. A ticket
        // still present here means attachment failed; it cannot be released before finish.
        if transaction.banks.held() {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if !self.retained.owners(key).ok().is_some_and(|owners|
            owners.transaction.is_some() && owners.terminal.is_some())
        {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        let (mut owners, ()) = match self.retained.finish_terminal(key, ()) {
            Ok(complete) => complete,
            Err(_) => return HostedAddDeviceProgress::RetainedRefusal(self),
        };
        let (Some(transaction), Some(terminal)) =
            (owners.transaction.take(), owners.terminal.take())
        else { return HostedAddDeviceProgress::RetainedRefusal(self); };
        match transaction.finish(terminal) {
            AddDeviceFinishProgress::Completed(result) => HostedAddDeviceProgress::Completed(result),
            AddDeviceFinishProgress::RetainedCommit(reservation, device_id, index) =>
                HostedAddDeviceProgress::RetainedRefusal(
                    Self::retain_commit(key, reservation, device_id, index)),
        }
    }

    unsafe fn settle_projection(mut self) -> HostedAddDeviceProgress {
        use nt_component_suspension::RetainedChildDispatchPhase;
        let key = self.retained.key();
        if let Some(result) = self.undeposited_projection_terminal.take() {
            match self.retained.owners_mut(key) {
                Ok(owners) => owners.projection_terminal = Some(result),
                Err(_) => {
                    self.undeposited_projection_terminal = Some(result);
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
            }
        }
        if self.retained.phase() == RetainedChildDispatchPhase::Parked
            && self.retained.begin_restore_without_child(key).is_err()
        {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if self.retained.phase() == RetainedChildDispatchPhase::Restoring
            && self.retained.acknowledge_restore(key).is_err()
        {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if self.retained.phase() != RetainedChildDispatchPhase::Restored {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if !self.retained.owners(key).ok().is_some_and(|owners|
            owners.transaction.is_some() && owners.projection_terminal.is_some())
        {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        let (mut owners, ()) = match self.retained.finish_terminal(key, ()) {
            Ok(finished) => finished,
            Err(_) => return HostedAddDeviceProgress::RetainedRefusal(self),
        };
        let (Some(transaction), Some(result)) =
            (owners.transaction.take(), owners.projection_terminal.take())
        else { return HostedAddDeviceProgress::RetainedRefusal(self); };
        continue_typed_after_projection(transaction, result, key.epoch, true)
    }

    pub(crate) fn record_child_step(
        &mut self,
        step: crate::service_sec_image::NestedChildStep,
    ) -> Result<(), crate::service_sec_image::NestedChildStep> {
        if !self.child_work_ready() { return Err(step); }
        self.retained.record_child_step(self.retained.key(), step)
            .map_err(|(_, step)| step)
    }

    pub(crate) unsafe fn resume(mut self) -> HostedAddDeviceProgress {
        let key = self.retained.key();
        if let Ok(owners) = self.retained.owners_mut(key) {
            if let Some((reservation, device_id, index)) = owners.commit_retry.take() {
                return match hosted_add_device_rollback::commit_banked(reservation) {
                    Ok(()) => {
                        register_instance_ready(index, true);
                        HostedAddDeviceProgress::Completed(Ok(device_id))
                    }
                    Err(reservation) => {
                        owners.commit_retry = Some((reservation, device_id, index));
                        HostedAddDeviceProgress::RetainedRefusal(self)
                    }
                };
            }
        }
        if let Some(status) = self.preentry_error {
            let Ok(owners) = self.retained.owners_mut(key) else {
                return HostedAddDeviceProgress::RetainedRefusal(self);
            };
            let Some(transaction) = owners.transaction.as_mut() else {
                return HostedAddDeviceProgress::RetainedRefusal(self);
            };
            if transaction.banks.retire().is_err() {
                return HostedAddDeviceProgress::RetainedRefusal(self);
            }
            let mut transaction = owners.transaction.take().unwrap();
            if let Some(rollback) = transaction.rollback.take() {
                if self.preentry_block {
                    hosted_add_device_rollback::block(rollback, status);
                } else {
                    hosted_add_device_rollback::abort(rollback);
                }
            }
            write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
                INVALID_HOSTED_REGISTRY_IDENTITY_ID);
            return HostedAddDeviceProgress::Completed(Err(status));
        }
        if self.undeposited_terminal.is_some()
            || self.retained.owners(key).ok().is_some_and(|owners| owners.terminal.is_some())
        {
            return self.settle_terminal();
        }
        if self.undeposited_projection_terminal.is_some()
            || self.retained.owners(key).ok()
                .is_some_and(|owners| owners.projection_terminal.is_some())
        {
            return self.settle_projection();
        }
        let child_ready = self.child_work_ready();
        let retry = self.retry_without_new_child();
        trace_add_device_resume_gate(1, u64::from(child_ready) | (u64::from(retry) << 1));
        if !child_ready && !retry {
            trace_add_device_resume_gate(10, 0);
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if child_ready && !retry {
            if self.retained.begin_restore(key).is_err() {
                trace_add_device_resume_gate(11, 0);
                return HostedAddDeviceProgress::RetainedRefusal(self);
            }
            let step = match self.retained.take_child_step_for_native_restore(key) {
                Ok(step) => step,
                Err(_) => {
                    trace_add_device_resume_gate(12, 0);
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
            };
            let owner = match self.retained.owners_mut(key) {
                Ok(owner) => owner,
                Err(_) => {
                    trace_add_device_resume_gate(13, 0);
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
            };
            let Some(pump) = owner.pump.as_mut() else {
                trace_add_device_resume_gate(14, 0);
                return HostedAddDeviceProgress::RetainedRefusal(self);
            };
            if let Err(step) = pump.record_child_step(step) {
                // The physical owner refused before entry. Keep the sealed receipt in the
                // native bundle; this row remains fenced and cannot select another child.
                pump.child_step = Some(step);
                trace_add_device_resume_gate(15, 0);
                return HostedAddDeviceProgress::RetainedRefusal(self);
            }
        } else {
            let begun = if self.retained.phase()
                == nt_component_suspension::RetainedChildDispatchPhase::RestoreRetry
            {
                self.retained.begin_restore(key)
            } else {
                self.retained.begin_restore_without_child(key)
            };
            if begun.is_err() {
                trace_add_device_resume_gate(16, 0);
                return HostedAddDeviceProgress::RetainedRefusal(self);
            }
        }
        let pump = match self.retained.owners_mut(key) {
            Ok(owners) => owners.pump.take(),
            Err(_) => None,
        };
        let Some(pump) = pump else {
            trace_add_device_resume_gate(17, 0);
            return HostedAddDeviceProgress::RetainedRefusal(self);
        };
        trace_add_device_resume_gate(2, 0);
        let progress = pump.resume();
        match progress {
            AddDevicePumpProgress::Completed(result) => {
                trace_add_device_resume_gate(3, 0);
                if let Ok(owners) = self.retained.owners_mut(key) {
                    owners.terminal = Some(result);
                    self.settle_terminal()
                } else {
                    self.undeposited_terminal = Some(result);
                    HostedAddDeviceProgress::RetainedRefusal(self)
                }
            }
            AddDevicePumpProgress::ProjectionCompleted(result) => {
                trace_add_device_resume_gate(4, 0);
                if let Ok(owners) = self.retained.owners_mut(key) {
                    owners.projection_terminal = Some(result);
                    self.settle_projection()
                } else {
                    self.undeposited_projection_terminal = Some(result);
                    HostedAddDeviceProgress::RetainedRefusal(self)
                }
            }
            AddDevicePumpProgress::ChildWorkYield(pump) => {
                trace_add_device_resume_gate(5, 0);
                let mut next_key = key;
                next_key.physical = pump.physical_identity();
                if let Ok(owners) = self.retained.owners_mut(key) { owners.pump = Some(pump); }
                if next_key.physical.is_none()
                    || self.retained.repark_after_native_yield_with_key(key, next_key).is_err()
                {
                    trace_add_device_resume_gate(18, 0);
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
                HostedAddDeviceProgress::ChildWorkYield(self)
            }
            AddDevicePumpProgress::RetainedRefusal(pump) => {
                let retryable = pump.retry_without_new_child();
                trace_add_device_resume_gate(6, u64::from(retryable));
                if let Ok(owners) = self.retained.owners_mut(key) { owners.pump = Some(pump); }
                if retryable {
                    let _ = self.retained.refuse_restore_no_effects(key);
                }
                HostedAddDeviceProgress::RetainedRefusal(self)
            }
        }
    }
}

impl AddDeviceTransaction {
    unsafe fn finish(mut self, dispatch: Result<AddDeviceDispatchResult, nt_status::NtStatus>)
        -> AddDeviceFinishProgress
    {
        let dispatch = match dispatch {
            Ok(dispatch) => dispatch,
            Err(status) => {
                write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
                    INVALID_HOSTED_REGISTRY_IDENTITY_ID);
                hosted_add_device_rollback::block(self.rollback.take().unwrap(), status);
                return AddDeviceFinishProgress::Completed(Err(status));
            }
        };
        hosted_add_device_rollback::completed_dispatch(self.rollback.as_ref().unwrap(), &dispatch);
        write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
            INVALID_HOSTED_REGISTRY_IDENTITY_ID);
        let result = (|| -> Result<u64, nt_status::NtStatus> {
            dispatch.status.to_result()?;
            if dispatch.pdo_object != self.pdo_object {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            let device_id = io_manager_mut()
                .hosted_device_by_identity(self.projection_domain, dispatch.fdo_object)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
            let canonical_name_matches = io_manager_mut().device(device_id).is_some_and(|device| {
                device.name.as_ref().is_none_or(|name| {
                    !self.registry_identity.has_linkage_export()
                        || nt_path_ascii(name).is_some_and(|name| {
                            name.eq_ignore_ascii_case(self.registry_identity.export_name.as_bytes())
                        })
                })
            });
            if !canonical_name_matches {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            validate_and_sync_hosted_device_projection(
                self.projection_inst, self.projection_domain, dispatch.fdo_object, device_id,
                DriverId(self.driver_id), dispatch.driver_object,
            )?;
            match io_manager_mut().device(device_id).and_then(|device| device.attached_to) {
                Some(lower) if lower == nt_io_manager::DeviceId(self.pdo_device_id) => {}
                None | Some(_) => return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
            }
            hosted_pnp_manager_mut()
                .commit_device_stack(self.pdo_device_id, device_id.raw(), self.driver_id)
                .map_err(hosted_pnp_status)?;
            hosted_add_device_rollback::committed_stack(self.rollback.as_ref().unwrap(), device_id);
            if !driver_instances().is_some_and(|table| self.index < table.len() && table[self.index].used) {
                return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
            }
            let registration = hosted_device_pointer_registration(
                self.projection_domain, dispatch.fdo_object, device_id,
            )?;
            if !hosted_add_device_rollback::owns_created_registration(
                self.rollback.as_ref().unwrap(), registration,
            ) {
                return Err(nt_status::NtStatus::INVALID_HANDLE);
            }
            register_hosted_device_binding(
                self.driver_id, device_id.raw(), self.pdo_device_id, self.index,
                self.projection_instance, self.projection_domain, dispatch.fdo_object,
                registration, self.pdo_object, self.registry_identity_id,
                self.bus_information.as_ref(), self.pdo_address,
            )?;
            Ok(device_id.raw())
        })();
        match result {
            Ok(device_id) => {
                if let Some(shared) = self.provider_add_device_shared {
                    clear_shared_registry_identity_at(shared);
                }
                let reservation = self.rollback.take().unwrap();
                if self.bank_owned_by_rollback {
                    match hosted_add_device_rollback::commit_banked(reservation) {
                        Ok(()) => {
                            register_instance_ready(self.index, true);
                            AddDeviceFinishProgress::Completed(Ok(device_id))
                        }
                        Err(reservation) => AddDeviceFinishProgress::RetainedCommit(
                            reservation, device_id, self.index),
                    }
                } else {
                    hosted_add_device_rollback::commit(reservation);
                    register_instance_ready(self.index, true);
                    AddDeviceFinishProgress::Completed(Ok(device_id))
                }
            }
            Err(status) => {
                hosted_add_device_rollback::abort(self.rollback.take().unwrap());
                AddDeviceFinishProgress::Completed(Err(status))
            }
        }
    }
}

#[path = "hosted_add_device_continuation/preparation.rs"]
mod preparation;
use preparation::{
    call_add_device_for_existing_pdo_progress, continue_typed_after_projection,
};
pub(super) use preparation::call_add_device_for_existing_pdo;
