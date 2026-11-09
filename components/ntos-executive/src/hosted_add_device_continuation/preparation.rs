//! AddDevice preparation, PDO projection and registry publication.

use super::*;

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
        let bank_ticket = hosted_add_device_rollback::attach_bank_ticket(&rollback, bank).err();
        // If attachment refused, retain the unbound ticket for exact retirement. No registry
        // identity has been allocated or published at this point.
        let registry_identity_id = if bank_ticket.is_some() {
            INVALID_HOSTED_REGISTRY_IDENTITY_ID
        } else {
            match allocate_hosted_registry_identity(registry_identity) {
                Ok(id) => id,
                Err(status) => {
                    hosted_add_device_rollback::abort(rollback);
                    return Err(status);
                }
            }
        };
        if registry_identity_id != INVALID_HOSTED_REGISTRY_IDENTITY_ID {
            hosted_add_device_rollback::record_registry(
                &rollback, registry_identity_id, inst.exec_shared_va,
                provider_add_device_shared,
            );
        }
        Ok(AddDeviceTransaction {
            rollback: Some(rollback), banks: AddDeviceBanks { ticket: bank_ticket },
            registry_identity, registry_identity_id, provider_add_device_shared,
            projection_inst, projection_domain, projection_instance, index, inst, driver_id,
            pdo_device_id, pdo_object: 0, bus_information, pdo_address,
            bank_owned_by_rollback: true,
        })
    })();
    let transaction = match prepared {
        Ok(transaction) => transaction,
        Err(status) => return HostedAddDeviceProgress::Completed(Err(status)),
    };
    if transaction.banks.held() {
        return HostedAddDeviceProgress::RetainedRefusal(
            HostedAddDeviceContinuation::retain_preentry(
                transaction, nt_status::NtStatus::INVALID_HANDLE, epoch, false));
    }
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
pub(super) unsafe fn continue_typed_after_projection(
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
            bank_owned_by_rollback: false,
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
pub(in crate::driver_launch) unsafe fn call_add_device_for_existing_pdo(
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
    match transaction.finish(dispatch) {
        AddDeviceFinishProgress::Completed(result) => result,
        AddDeviceFinishProgress::RetainedCommit(_, _, _) =>
            Err(nt_status::NtStatus::DEVICE_BUSY),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn call_add_device_for_existing_pdo_progress(
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
