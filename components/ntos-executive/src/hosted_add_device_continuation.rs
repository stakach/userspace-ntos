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

unsafe fn retire_add_device_bank(
    ticket: SuspendedActiveHostedIrpTransfer,
) -> Result<(), (nt_status::NtStatus, SuspendedActiveHostedIrpTransfer)> {
    active_hosted_irp_transfers_mut().retire(ticket.ticket)
        .map(|_| ())
        .map_err(|_| (nt_status::NtStatus::INVALID_HANDLE, ticket))
}

struct AddDeviceBanks {
    ticket: Option<SuspendedActiveHostedIrpTransfer>,
}

impl AddDeviceBanks {
    unsafe fn retire(&mut self) -> Result<(), nt_status::NtStatus> {
        if let Some(ticket) = self.ticket.take() {
            if let Err((status, ticket)) = retire_add_device_bank(ticket) {
                self.ticket = Some(ticket);
                return Err(status);
            }
        }
        Ok(())
    }

    fn held(&self) -> bool { self.ticket.is_some() }
}

/// The native AddDevice request has one dispatch page and one physical Reply. A yielded pump
/// owns the Reply here; its caller keeps this with both leased pages and rollback transaction.
struct AddDevicePumpContinuation {
    pump: Option<component_scheduler::HostedPumpRestore>,
    child_step: Option<crate::service_sec_image::NestedChildStep>,
    instance_index: usize,
    shared_va: u64,
    driver_object: u64,
    pdo_object: u64,
    projection: bool,
}

impl AddDevicePumpContinuation {
    fn physical_identity(&self) -> Option<component_scheduler::ChildWorkPhysicalIdentity> {
        self.pump.as_ref()?.child_work_identity()
    }
}

/// Enter CREATE_PDO_PROJECTION once while the AddDevice transaction owns the shared-page
/// lease. A yielded projection carries the same physical Reply and one-use child receipt as
/// the later AddDevice dispatch; its caller may not send another ReplyRequest on resume.
unsafe fn dispatch_pdo_projection_progress(
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

enum AddDevicePumpProgress {
    Completed(Result<AddDeviceDispatchResult, nt_status::NtStatus>),
    ProjectionCompleted(Result<u64, nt_status::NtStatus>),
    ChildWorkYield(AddDevicePumpContinuation),
    RetainedRefusal(AddDevicePumpContinuation),
}

impl AddDevicePumpContinuation {
    fn child_work_ready(&self) -> bool {
        self.child_step.is_none()
            && matches!(self.pump, Some(component_scheduler::HostedPumpRestore::ChildWorkReady { .. }))
    }

    fn retry_without_new_child(&self) -> bool {
        self.child_step.is_some()
            || matches!(self.pump, Some(component_scheduler::HostedPumpRestore::ChildWorkPending(ref pending))
                if pending.retryable())
    }

    fn record_child_step(
        &mut self,
        step: crate::service_sec_image::NestedChildStep,
    ) -> Result<(), crate::service_sec_image::NestedChildStep> {
        if !self.child_work_ready() { return Err(step); }
        self.child_step = Some(step);
        Ok(())
    }

    unsafe fn resume(mut self) -> AddDevicePumpProgress {
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
            other => other,
        };
        self.pump = Some(next);
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

unsafe fn dispatch_add_device_for_instance_progress(
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
}

#[must_use = "an AddDevice yield or refusal still owns its physical transaction"]
pub(crate) enum HostedAddDeviceProgress {
    Completed(Result<u64, nt_status::NtStatus>),
    ChildWorkYield(HostedAddDeviceContinuation),
    RetainedRefusal(HostedAddDeviceContinuation),
}

impl HostedAddDeviceContinuation {
    fn retain(transaction: AddDeviceTransaction, pump: AddDevicePumpContinuation, epoch: u64)
        -> Self
    {
        let key = AddDeviceRetainedKey::new(&transaction, epoch, pump.physical_identity());
        let mut retained = nt_component_suspension::RetainedChildDispatch::retain(
            key, AddDeviceRetainedOwners {
                transaction: Some(transaction), pump: Some(pump), terminal: None,
            },
        );
        let _ = retained.park_for_child(key);
        Self { retained, preentry_error: None, preentry_block: false }
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
                },
            ),
            preentry_error: Some(status), preentry_block: block,
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
            },
        );
        let _ = retained.park_for_child(key);
        Self { retained, preentry_error: None, preentry_block: false }
    }

    pub(crate) fn child_work_ready(&self) -> bool {
        self.retained.key().physical.is_some()
            && self.retained.owners(self.retained.key()).ok()
            .and_then(|owners| owners.pump.as_ref())
            .is_some_and(AddDevicePumpContinuation::child_work_ready)
    }

    pub(crate) fn retry_without_new_child(&self) -> bool {
        if self.preentry_error.is_some() { return true; }
        self.retained.owners(self.retained.key()).ok()
            .is_some_and(|owners| owners.terminal.is_some()
                || owners.pump.as_ref()
                    .is_some_and(AddDevicePumpContinuation::retry_without_new_child))
    }

    unsafe fn settle_terminal(mut self) -> HostedAddDeviceProgress {
        use nt_component_suspension::RetainedChildDispatchPhase;
        let key = self.retained.key();
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
        if transaction.banks.retire().is_err() {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        let (mut owners, ()) = match self.retained.finish_terminal(key, ()) {
            Ok(complete) => complete,
            Err(_) => return HostedAddDeviceProgress::RetainedRefusal(self),
        };
        let (Some(transaction), Some(terminal)) =
            (owners.transaction.take(), owners.terminal.take())
        else { return HostedAddDeviceProgress::RetainedRefusal(self); };
        HostedAddDeviceProgress::Completed(transaction.finish(terminal))
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
        if self.retained.owners(key).ok().is_some_and(|owners| owners.terminal.is_some()) {
            return self.settle_terminal();
        }
        let child_ready = self.child_work_ready();
        let retry = self.retry_without_new_child();
        if !child_ready && !retry {
            return HostedAddDeviceProgress::RetainedRefusal(self);
        }
        if child_ready && !retry {
            if self.retained.begin_restore(key).is_err() {
                return HostedAddDeviceProgress::RetainedRefusal(self);
            }
            let step = match self.retained.take_child_step_for_native_restore(key) {
                Ok(step) => step,
                Err(_) => return HostedAddDeviceProgress::RetainedRefusal(self),
            };
            let owner = match self.retained.owners_mut(key) {
                Ok(owner) => owner,
                Err(_) => return HostedAddDeviceProgress::RetainedRefusal(self),
            };
            let Some(pump) = owner.pump.as_mut() else {
                return HostedAddDeviceProgress::RetainedRefusal(self);
            };
            if let Err(step) = pump.record_child_step(step) {
                // The physical owner refused before entry. Keep the sealed receipt in the
                // native bundle; this row remains fenced and cannot select another child.
                pump.child_step = Some(step);
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
                return HostedAddDeviceProgress::RetainedRefusal(self);
            }
        }
        let pump = match self.retained.owners_mut(key) {
            Ok(owners) => owners.pump.take(),
            Err(_) => None,
        };
        let Some(pump) = pump else { return HostedAddDeviceProgress::RetainedRefusal(self); };
        let progress = pump.resume();
        match progress {
            AddDevicePumpProgress::Completed(result) => {
                if let Ok(owners) = self.retained.owners_mut(key) {
                    owners.terminal = Some(result);
                }
                self.settle_terminal()
            }
            AddDevicePumpProgress::ProjectionCompleted(result) => {
                use nt_component_suspension::RetainedChildDispatchPhase;
                if self.retained.phase() == RetainedChildDispatchPhase::Restoring
                    && self.retained.acknowledge_restore(key).is_err()
                {
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
                let (mut owners, ()) = match self.retained.finish_terminal(key, ()) {
                    Ok(finished) => finished,
                    Err(_) => return HostedAddDeviceProgress::RetainedRefusal(self),
                };
                let Some(transaction) = owners.transaction.take() else {
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                };
                continue_typed_after_projection(transaction, result, key.epoch, true)
            }
            AddDevicePumpProgress::ChildWorkYield(pump) => {
                let mut next_key = key;
                next_key.physical = pump.physical_identity();
                if let Ok(owners) = self.retained.owners_mut(key) { owners.pump = Some(pump); }
                if next_key.physical.is_none()
                    || self.retained.repark_after_native_yield_with_key(key, next_key).is_err()
                {
                    return HostedAddDeviceProgress::RetainedRefusal(self);
                }
                HostedAddDeviceProgress::ChildWorkYield(self)
            }
            AddDevicePumpProgress::RetainedRefusal(pump) => {
                let retryable = pump.retry_without_new_child();
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
        -> Result<u64, nt_status::NtStatus>
    {
        let dispatch = match dispatch {
            Ok(dispatch) => dispatch,
            Err(status) => {
                write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
                    INVALID_HOSTED_REGISTRY_IDENTITY_ID);
                hosted_add_device_rollback::block(self.rollback.take().unwrap(), status);
                return Err(status);
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
            register_instance_ready(self.index, true);
            Ok(device_id.raw())
        })();
        match result {
            Ok(device_id) => {
                hosted_add_device_rollback::commit(self.rollback.take().unwrap());
                if let Some(shared) = self.provider_add_device_shared {
                    clear_shared_registry_identity_at(shared);
                }
                Ok(device_id)
            }
            Err(status) => {
                hosted_add_device_rollback::abort(self.rollback.take().unwrap());
                Err(status)
            }
        }
    }
}

unsafe fn reject_typed_preentry(
    mut transaction: AddDeviceTransaction, status: nt_status::NtStatus,
    epoch: u64, block: bool,
) -> HostedAddDeviceProgress {
    if transaction.banks.retire().is_err() {
        return HostedAddDeviceProgress::RetainedRefusal(
            HostedAddDeviceContinuation::retain_preentry(transaction, status, epoch, block));
    }
    if let Some(rollback) = transaction.rollback.take() {
        if block {
            hosted_add_device_rollback::block(rollback, status);
        } else {
            hosted_add_device_rollback::abort(rollback);
        }
    }
    write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
        INVALID_HOSTED_REGISTRY_IDENTITY_ID);
    HostedAddDeviceProgress::Completed(Err(status))
}

#[allow(clippy::too_many_arguments)]
unsafe fn start_typed_add_device(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    pdo_device_id: u64,
    bus_information: Option<nt_pnp_manager::PnpBusInformation>,
    pdo_address: u32,
    epoch: u64,
) -> HostedAddDeviceProgress {
    let prepared = (|| -> Result<AddDeviceTransaction, nt_status::NtStatus> {
        let pdo_device = nt_io_manager::DeviceId(pdo_device_id);
        let (index, inst) = instance_by_driver_id(driver_id)
            .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
        if inst.faulted { return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED); }
        let provider_route = hosted_provider_dispatch_route_for_instance(index);
        let projection_instance = provider_route.map(|route| route.provider_instance)
            .unwrap_or(index);
        let projection_inst = instance(projection_instance)
            .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        if projection_inst.faulted {
            return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        }
        if projection_inst.hosted_domain_id == 0 || projection_inst.hosted_domain_cookie == 0 {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let projection_domain = HostedDomainIdentity {
            domain_id: nt_io_manager::HostedDomainId(projection_inst.hosted_domain_id),
            cookie: projection_inst.hosted_domain_cookie,
        };
        if io_manager_mut().hosted_domain_identity(projection_domain.domain_id)
            != Some(projection_domain)
        {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        if !io_manager_mut().device(pdo_device)
            .is_some_and(|device| device.top_of_stack == pdo_device && !device.delete_pending)
        {
            return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
        }
        let registry_identity = build_hosted_registry_identity(
            class_guid, driver_key, linkage_export, instance_path,
        )?;
        let rollback = hosted_add_device_rollback::reserve(
            projection_instance, projection_domain, pdo_device_id, driver_id,
        )?;
        let registry_identity_id = match allocate_hosted_registry_identity(registry_identity) {
            Ok(id) => id,
            Err(status) => {
                hosted_add_device_rollback::abort(rollback);
                return Err(status);
            }
        };
        let provider_add_device_shared = provider_route.and_then(|route| {
            instance(route.provider_instance).map(|provider| provider.exec_shared_va)
        });
        // One claim covers projection and AddDevice, including a distinct provider page.
        let bank = match reserve_add_device_bank(
            inst.exec_shared_va, provider_add_device_shared, index,
        ) {
            Ok(bank) => bank,
            Err(status) => {
                hosted_add_device_rollback::abort(rollback);
                return Err(status);
            }
        };
        Ok(AddDeviceTransaction {
            rollback: Some(rollback), banks: AddDeviceBanks { ticket: Some(bank) },
            registry_identity, registry_identity_id, provider_add_device_shared,
            projection_inst, projection_domain, projection_instance, index, inst, driver_id,
            pdo_device_id, pdo_object: 0, bus_information, pdo_address,
        })
    })();
    let transaction = match prepared {
        Ok(transaction) => transaction,
        Err(status) => return HostedAddDeviceProgress::Completed(Err(status)),
    };
    let existing = io_manager_mut().hosted_device_address_by_identity(
        transaction.projection_domain, nt_io_manager::DeviceId(pdo_device_id),
    );
    if let Some(pdo_object) = existing {
        return continue_typed_after_projection(transaction, Ok(pdo_object), epoch, false);
    }
    match dispatch_pdo_projection_progress(
        transaction.projection_instance, crate::initial_system_driver_caller(),
    ) {
        AddDevicePumpProgress::ProjectionCompleted(projected) =>
            continue_typed_after_projection(transaction, projected, epoch, true),
        AddDevicePumpProgress::ChildWorkYield(pump) => {
            let owner = HostedAddDeviceContinuation::retain(transaction, pump, epoch);
            if owner.child_work_ready() {
                HostedAddDeviceProgress::ChildWorkYield(owner)
            } else {
                HostedAddDeviceProgress::RetainedRefusal(owner)
            }
        }
        AddDevicePumpProgress::RetainedRefusal(pump) =>
            HostedAddDeviceProgress::RetainedRefusal(
                HostedAddDeviceContinuation::retain(transaction, pump, epoch)),
        AddDevicePumpProgress::Completed(_) =>
            reject_typed_preentry(
                transaction, nt_status::NtStatus::INVALID_DEVICE_REQUEST, epoch, true),
    }
}

/// Continue only after an authenticated projection terminal, or a pre-existing PDO identity.
/// All later shared writes and the AddDevice entry use the same retained dual-page lease.
unsafe fn continue_typed_after_projection(
    mut transaction: AddDeviceTransaction,
    projected: Result<u64, nt_status::NtStatus>,
    epoch: u64,
    created: bool,
) -> HostedAddDeviceProgress {
    let pdo_object = match projected {
        Ok(pdo_object) if pdo_object != 0 => pdo_object,
        Ok(_) => return reject_typed_preentry(
            transaction, nt_status::NtStatus::INVALID_DEVICE_REQUEST, epoch, true),
        Err(status) => return reject_typed_preentry(transaction, status, epoch, true),
    };
    transaction.pdo_object = pdo_object;
    let pdo_device = nt_io_manager::DeviceId(transaction.pdo_device_id);
    if created {
        hosted_add_device_rollback::set_pdo(
            transaction.rollback.as_ref().unwrap(), pdo_object, true, None,
        );
        let registration = match register_unlinked_hosted_device_projection(
            transaction.projection_inst, transaction.projection_domain,
            pdo_object, pdo_device,
        ) {
            Ok(registration) => registration,
            Err(error) => {
                if let Some(registration) = error.accepted_registration() {
                    hosted_add_device_rollback::set_pdo(
                        transaction.rollback.as_ref().unwrap(), pdo_object, true,
                        Some(registration),
                    );
                }
                return reject_typed_preentry(
                    transaction, error.status, epoch, !error.cleanup_unbound
                        && error.accepted_registration().is_none(),
                );
            }
        };
        hosted_add_device_rollback::set_pdo(
            transaction.rollback.as_ref().unwrap(), pdo_object, true, Some(registration),
        );
    } else {
        let binding_live = hosted_device_bindings().is_some_and(|bindings| {
            bindings.iter().any(|binding| {
                binding.used && binding.projection_domain == transaction.projection_domain
                    && binding.pdo_device_id == transaction.pdo_device_id
                    && binding.pdo_object == pdo_object
            })
        });
        if binding_live {
            return reject_typed_preentry(
                transaction, nt_status::NtStatus::OBJECT_NAME_COLLISION, epoch, false);
        }
        let registration = match hosted_device_pointer_registration(
            transaction.projection_domain, pdo_object, pdo_device,
        ) {
            Ok(registration) => registration,
            Err(status) => return reject_typed_preentry(transaction, status, epoch, false),
        };
        hosted_add_device_rollback::set_pdo(
            transaction.rollback.as_ref().unwrap(), pdo_object, false, Some(registration),
        );
    }
    hosted_add_device_rollback::record_registry(
        transaction.rollback.as_ref().unwrap(), transaction.registry_identity_id,
        transaction.inst.exec_shared_va, transaction.provider_add_device_shared,
    );
    let setup = (|| -> Result<(), nt_status::NtStatus> {
        publish_shared_registry_identity_at(
            transaction.inst.exec_shared_va, &transaction.registry_identity,
        )?;
        if let Some(shared) = transaction.provider_add_device_shared {
            publish_shared_registry_identity_at(shared, &transaction.registry_identity)?;
        }
        write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
            transaction.registry_identity_id);
        crate::power_manager::prepare_device(transaction.pdo_device_id)?;
        hosted_add_device_rollback::record_power(transaction.rollback.as_ref().unwrap());
        hosted_add_device_rollback::begin_dispatch(transaction.rollback.as_ref().unwrap());
        Ok(())
    })();
    if let Err(status) = setup {
        return reject_typed_preentry(transaction, status, epoch, false);
    }
    match dispatch_add_device_for_instance_progress(
        transaction.index, transaction.inst, transaction.pdo_object,
        crate::initial_system_driver_caller(),
    ) {
        AddDevicePumpProgress::Completed(dispatch) =>
            HostedAddDeviceContinuation::retain_terminal(transaction, dispatch, epoch)
                .settle_terminal(),
        AddDevicePumpProgress::ChildWorkYield(pump) => {
            let owner = HostedAddDeviceContinuation::retain(transaction, pump, epoch);
            if owner.child_work_ready() {
                HostedAddDeviceProgress::ChildWorkYield(owner)
            } else {
                HostedAddDeviceProgress::RetainedRefusal(owner)
            }
        }
        AddDevicePumpProgress::RetainedRefusal(pump) =>
            HostedAddDeviceProgress::RetainedRefusal(
                HostedAddDeviceContinuation::retain(transaction, pump, epoch)),
        AddDevicePumpProgress::ProjectionCompleted(_) =>
            reject_typed_preentry(
                transaction, nt_status::NtStatus::INVALID_DEVICE_REQUEST, epoch, true),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_add_device_transaction(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    pdo_device_id: u64,
    bus_information: Option<nt_pnp_manager::PnpBusInformation>,
    pdo_address: u32,
    lease_bank: bool,
) -> AddDevicePreparation {
    let _durable = crate::allocator::enter_durable();
    let mut retained_tx = None;
    let prepare = (|| -> Result<AddDeviceTransaction, nt_status::NtStatus> {
    let caller = crate::initial_system_driver_caller();
    let pdo_device = nt_io_manager::DeviceId(pdo_device_id);
    let (index, inst) =
        instance_by_driver_id(driver_id).ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    if inst.faulted { return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED); }
    let provider_route = hosted_provider_dispatch_route_for_instance(index);
    let projection_instance = provider_route.map(|route| route.provider_instance).unwrap_or(index);
    let projection_inst = instance(projection_instance)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if projection_inst.faulted { return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED); }
    if projection_inst.hosted_domain_id == 0 || projection_inst.hosted_domain_cookie == 0 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let registry_identity =
        build_hosted_registry_identity(class_guid, driver_key, linkage_export, instance_path)?;
    let projection_domain = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId(projection_inst.hosted_domain_id),
        cookie: projection_inst.hosted_domain_cookie,
    };
    if io_manager_mut().hosted_domain_identity(projection_domain.domain_id)
        != Some(projection_domain)
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if !io_manager_mut().device(pdo_device)
        .is_some_and(|device| device.top_of_stack == pdo_device && !device.delete_pending)
    {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    let mut rollback = Some(hosted_add_device_rollback::reserve(
        projection_instance, projection_domain, pdo_device_id, driver_id,
    )?);
    let result = (|| -> Result<AddDeviceTransaction, nt_status::NtStatus> {
        let pdo_object = match io_manager_mut()
            .hosted_device_address_by_identity(projection_domain, pdo_device)
        {
            Some(pdo_object) => {
                let binding_live = hosted_device_bindings().is_some_and(|bindings| {
                    bindings.iter().any(|binding| {
                        binding.used && binding.projection_domain == projection_domain
                            && binding.pdo_device_id == pdo_device_id
                            && binding.pdo_object == pdo_object
                    })
                });
                if binding_live {
                    hosted_add_device_rollback::commit(rollback.take().unwrap());
                    return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
                }
                let registration = match hosted_device_pointer_registration(
                    projection_domain, pdo_object, pdo_device,
                ) {
                    Ok(registration) => registration,
                    Err(status) => {
                        hosted_add_device_rollback::commit(rollback.take().unwrap());
                        return Err(status);
                    }
                };
                hosted_add_device_rollback::set_pdo(
                    rollback.as_ref().unwrap(), pdo_object, false, Some(registration),
                );
                pdo_object
            }
            None => {
                let pdo_object = match create_hosted_pdo_projection(projection_instance, caller) {
                    Ok(pdo) => pdo,
                    Err(status) => {
                        hosted_add_device_rollback::block(rollback.take().unwrap(), status);
                        return Err(status);
                    }
                };
                hosted_add_device_rollback::set_pdo(
                    rollback.as_ref().unwrap(), pdo_object, true, None,
                );
                let registration = match register_unlinked_hosted_device_projection(
                    projection_inst, projection_domain, pdo_object, pdo_device,
                ) {
                    Ok(registration) => registration,
                    Err(error) => {
                        if let Some(registration) = error.accepted_registration() {
                            hosted_add_device_rollback::set_pdo(
                                rollback.as_ref().unwrap(), pdo_object, true, Some(registration),
                            );
                            hosted_add_device_rollback::abort(rollback.take().unwrap());
                        } else if error.cleanup_unbound {
                            hosted_add_device_rollback::abort(rollback.take().unwrap());
                        } else {
                            hosted_add_device_rollback::block(rollback.take().unwrap(), error.status);
                        }
                        return Err(error.status);
                    }
                };
                hosted_add_device_rollback::set_pdo(
                    rollback.as_ref().unwrap(), pdo_object, true, Some(registration),
                );
                pdo_object
            }
        };
        let provider_add_device_shared = provider_route.and_then(|route| {
            instance(route.provider_instance).map(|provider| provider.exec_shared_va)
        });
        let registry_identity_id = allocate_hosted_registry_identity(registry_identity)?;
        let bank = if lease_bank {
            Some(reserve_add_device_bank(
                inst.exec_shared_va, provider_add_device_shared, index,
            )?)
        } else { None };
        retained_tx = Some(AddDeviceTransaction {
            rollback: rollback.take(), banks: AddDeviceBanks { ticket: bank },
            registry_identity, registry_identity_id, provider_add_device_shared,
            projection_inst, projection_domain, projection_instance, index, inst, driver_id,
            pdo_device_id, pdo_object, bus_information, pdo_address,
        });
        let transaction = retained_tx.as_ref().unwrap();
        hosted_add_device_rollback::record_registry(
            transaction.rollback.as_ref().unwrap(), registry_identity_id, inst.exec_shared_va,
            provider_add_device_shared,
        );
        publish_shared_registry_identity_at(inst.exec_shared_va, &registry_identity)?;
        if let Some(shared) = provider_add_device_shared {
            publish_shared_registry_identity_at(shared, &registry_identity)?;
        }
        write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
            registry_identity_id);
        crate::power_manager::prepare_device(pdo_device_id)?;
        hosted_add_device_rollback::record_power(transaction.rollback.as_ref().unwrap());
        hosted_add_device_rollback::begin_dispatch(transaction.rollback.as_ref().unwrap());
        Ok(retained_tx.take().unwrap())
    })();
    if result.is_err() {
        write_volatile(core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
            INVALID_HOSTED_REGISTRY_IDENTITY_ID);
        if let Some(rollback) = rollback.take() {
            hosted_add_device_rollback::abort(rollback);
        }
    }
    result
    })();
    match prepare {
        Ok(transaction) => AddDevicePreparation::Ready(transaction),
        Err(status) => {
            if let Some(mut transaction) = retained_tx.take() {
                if transaction.banks.retire().is_err() {
                    return AddDevicePreparation::Retained(transaction, status);
                }
                if let Some(rollback) = transaction.rollback.take() {
                    hosted_add_device_rollback::abort(rollback);
                }
            }
            AddDevicePreparation::Rejected(status)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn call_add_device_for_existing_pdo(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    pdo_device_id: u64,
    bus_information: Option<nt_pnp_manager::PnpBusInformation>,
    pdo_address: u32,
) -> Result<u64, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let transaction = match prepare_add_device_transaction(
        driver_id, class_guid, driver_key, linkage_export, instance_path,
        pdo_device_id, bus_information, pdo_address, false,
    ) {
        AddDevicePreparation::Ready(transaction) => transaction,
        AddDevicePreparation::Rejected(status) => return Err(status),
        AddDevicePreparation::Retained(_, _) =>
            unreachable!("unleased legacy AddDevice cannot retain a bank"),
    };
    let dispatch = dispatch_add_device_for_instance(
        transaction.index, transaction.inst, transaction.pdo_object,
        crate::initial_system_driver_caller(),
    );
    transaction.finish(dispatch)
}

#[allow(clippy::too_many_arguments)]
unsafe fn call_add_device_for_existing_pdo_progress(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    pdo_device_id: u64,
    bus_information: Option<nt_pnp_manager::PnpBusInformation>,
    pdo_address: u32,
) -> HostedAddDeviceProgress {
    let _durable = crate::allocator::enter_durable();
    // Exhaustion is checked before any PDO or native effect, so no move-only owner can be lost.
    let epoch = match NEXT_ADD_DEVICE_CONTINUATION_EPOCH.fetch_update(
        Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
    ) {
        Ok(epoch) => epoch,
        Err(_) => return HostedAddDeviceProgress::Completed(
            Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES)),
    };
    start_typed_add_device(
        driver_id, class_guid, driver_key, linkage_export, instance_path,
        pdo_device_id, bus_information, pdo_address, epoch,
    )
}
