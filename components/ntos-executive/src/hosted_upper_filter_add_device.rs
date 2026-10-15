//! Ordered class UpperFilter AddDevice dispatch over retained foreign stack projections.

use super::*;

static mut LEDGER: nt_pnp_manager::UpperFilterAttachmentLedger =
    nt_pnp_manager::UpperFilterAttachmentLedger::new();

fn ledger() -> &'static mut nt_pnp_manager::UpperFilterAttachmentLedger {
    unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) }
}

fn ledger_status(error: nt_pnp_manager::UpperFilterAttachmentError) -> nt_status::NtStatus {
    match error {
        nt_pnp_manager::UpperFilterAttachmentError::InsufficientResources => {
            nt_status::NtStatus::INSUFFICIENT_RESOURCES
        }
        _ => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
    }
}

/// Attach the ordered registry-selected class drivers to an existing function stack. Every claim
/// is retained before allocating a class-local alias; after any native effect, no retry is made.
pub(super) unsafe fn attach_ordered(
    instance_path: &str,
    pdo_id: u64,
    function_id: u64,
    mount_generation: u64,
    ordered_drivers: &[u64],
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    if ordered_drivers.is_empty() {
        return Ok(());
    }
    let key = ledger()
        .reserve(
            hosted_pnp_manager_mut(),
            mount_generation,
            pdo_id,
            function_id,
            ordered_drivers,
        )
        .map_err(ledger_status)?;
    loop {
        let Some(claim) = ledger()
            .claim_next(hosted_pnp_manager_mut(), key)
            .map_err(ledger_status)?
        else {
            return Ok(());
        };
        // Conservative entry fence: prepare itself allocates foreign component memory. Any
        // failure after this point remains retained even if AddDevice was never called.
        ledger()
            .mark_entered(hosted_pnp_manager_mut(), claim)
            .map_err(ledger_status)?;
        if let Err(status) = attach_one(instance_path, claim) {
            let _ = ledger().mark_uncertain(hosted_pnp_manager_mut(), claim);
            return Err(status);
        }
    }
}

unsafe fn attach_one(
    instance_path: &str,
    claim: nt_pnp_manager::UpperFilterAttachmentClaim,
) -> Result<(), nt_status::NtStatus> {
    let projection = hosted_upper_filter_projection::prepare(instance_path, claim)?;
    let owner_id = projection.owner_id;
    let result = attach_prepared(owner_id, claim);
    if result.is_err() {
        hosted_upper_filter_projection::block_uncertain(owner_id);
    }
    result
}

unsafe fn attach_prepared(
    owner_id: u64,
    claim: nt_pnp_manager::UpperFilterAttachmentClaim,
) -> Result<(), nt_status::NtStatus> {
    let caller = crate::initial_system_driver_caller();
    let (index, inst) = instance_by_driver_id(claim.driver_id())
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let route = hosted_provider_dispatch_route_for_instance(index);
    let class_instance = route.map_or(index, |route| route.provider_instance);
    let class_inst = instance(class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let prepared = hosted_upper_filter_projection::begin_local_chain(owner_id)?;
    if instance_domain_identity(class_inst) != Some(prepared.class_domain) {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    let observed_pdo = dispatch_device_projection_control_for_instance(
        class_instance,
        0,
        FSD_DISPATCH_CLASS_LOWER_ALIAS,
        prepared.pdo_object,
        0,
        false,
        Some(prepared),
        caller,
    )?;
    hosted_upper_filter_projection::complete_local_chain(owner_id, observed_pdo)?;
    let mut rollback = Some(hosted_add_device_rollback::reserve(
        class_instance,
        prepared.class_domain,
        claim.key().child().pdo_object_id(),
        claim.driver_id(),
    )?);
    hosted_add_device_rollback::set_pdo(
        rollback.as_ref().unwrap(),
        prepared.pdo_object,
        false,
        Some(prepared.pdo_registration),
    );
    let mut transferred = false;
    let result = (|| -> Result<(), nt_status::NtStatus> {
        hosted_add_device_rollback::begin_dispatch(rollback.as_ref().unwrap());
        hosted_upper_filter_projection::begin_add_device(owner_id)?;
        let dispatch =
            match dispatch_add_device_for_instance(index, inst, prepared.pdo_object, caller) {
                Ok(dispatch) => dispatch,
                Err(status) => {
                    hosted_add_device_rollback::block(rollback.take().unwrap(), status);
                    return Err(status);
                }
            };
        hosted_add_device_rollback::completed_dispatch(rollback.as_ref().unwrap(), &dispatch);
        dispatch.status.to_result()?;
        if dispatch.pdo_object != prepared.pdo_object
            || dispatch.fdo_object != prepared.lower_object
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let pdo = nt_io_manager::DeviceId(claim.key().child().pdo_object_id());
        let fdo = io_manager_mut()
            .top_of_device_stack(pdo)
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        if fdo.raw() == claim.lower_device()
            || !io_manager_mut().device(fdo).is_some_and(|device| {
                device.driver_id == DriverId(claim.driver_id())
                    && device.attached_to == Some(nt_io_manager::DeviceId(claim.lower_device()))
            })
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let fdo_address = io_manager_mut()
            .hosted_device_address_by_identity(prepared.class_domain, fdo)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let registration =
            hosted_device_pointer_registration(prepared.class_domain, fdo_address, fdo)?;
        if !hosted_add_device_rollback::owns_created_registration(
            rollback.as_ref().unwrap(),
            registration,
        ) {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        validate_and_sync_hosted_device_projection(
            class_inst,
            prepared.class_domain,
            fdo_address,
            fdo,
            DriverId(claim.driver_id()),
            dispatch.driver_object,
        )?;
        hosted_upper_filter_projection::complete_add_device(owner_id, registration)?;
        transferred = true;
        ledger()
            .complete(
                hosted_pnp_manager_mut(),
                claim,
                fdo.raw(),
                claim.lower_device(),
            )
            .map_err(ledger_status)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            hosted_add_device_rollback::commit(rollback.take().unwrap());
            Ok(())
        }
        Err(status) => {
            if let Some(rollback) = rollback.take() {
                if transferred {
                    hosted_add_device_rollback::commit(rollback);
                } else {
                    hosted_add_device_rollback::abort(rollback);
                }
            }
            Err(status)
        }
    }
}
