//! Boot driver reinitialization callbacks retained until the boot DriverEntry phase completes.

use super::*;
use nt_io_manager::driver_reinitialization::DriverReinitializationError;

const BOOTREINIT_REGISTERED: u32 = 0x20;
static DRAIN_ACTIVE: AtomicBool = AtomicBool::new(false);
/// The boot callback whose dispatch a drain turn left running (#420).
static mut PENDING: Option<hosted_driver_reinitialization::PendingReinit> = None;

pub(super) fn boot_drain_active() -> bool {
    DRAIN_ACTIVE.load(Ordering::Acquire)
}

struct DrainGuard;
impl Drop for DrainGuard {
    fn drop(&mut self) { DRAIN_ACTIVE.store(false, Ordering::Release); }
}

pub(super) extern "win64" fn register(driver_object: u64, routine: u64, context: u64) {
    hosted_driver_reinitialization::register_with_op(driver_object, routine, context,
        HOSTED_DEVICE_OP_REGISTER_BOOT_DRIVER_REINIT, BOOTREINIT_REGISTERED);
}

pub(super) fn service_register(
    ch: &crate::spawn_hosts::PumpChannel,
    driver_object: u64,
    routine: u64,
    context: u64,
    active_reply_cap: u64,
) -> i32 {
    let identity = match hosted_driver_reinitialization::validated_registration(
        ch, driver_object, routine, context, active_reply_cap,
    ) {
        Ok(identity) => identity,
        Err(status) => return status,
    };
    match hosted_driver_reinitialization::queue().register_boot(identity) {
        Ok(_) => STATUS_SUCCESS,
        Err(DriverReinitializationError::Exhausted) => STATUS_INSUFFICIENT_RESOURCES,
        Err(DriverReinitializationError::WrongPhase) => STATUS_INVALID_DEVICE_REQUEST,
        Err(_) => STATUS_INVALID_PARAMETER,
    }
}

pub(super) unsafe fn component_dispatch() -> (i32, u64) {
    hosted_driver_reinitialization::component_dispatch_with_flag(BOOTREINIT_REGISTERED)
}

/// This phase follows all boot-start DriverEntry launches, matching the NT I/O manager's
/// one-shot boot reinit drain. An uncertain callback remains Executing and blocks replay.
pub(crate) unsafe fn run_pending_boot_callbacks() -> Result<usize, nt_status::NtStatus> {
    if DRAIN_ACTIVE.swap(true, Ordering::AcqRel) { return Ok(0); }
    let _guard = DrainGuard;
    hosted_driver_reinitialization::queue().open_boot_phase()
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let mut completed = 0usize;
    if let Some(pending) = (&mut *core::ptr::addr_of_mut!(PENDING)).take() {
        match pending.resume()? {
            hosted_driver_reinitialization::ReinitStep::Acknowledged => completed += 1,
            hosted_driver_reinitialization::ReinitStep::Pending(pending) => {
                *core::ptr::addr_of_mut!(PENDING) = Some(pending);
                return Ok(0);
            }
        }
    }
    while let Some(ticket) = hosted_driver_reinitialization::queue().begin_next_boot_ready(|identity| {
        instance_by_driver_id(identity.driver_id).is_some_and(|(_, inst)| {
            inst.driver_object == identity.driver_object
                && instance_domain_identity(inst).is_some_and(|domain| {
                    domain.domain_id.raw() == identity.domain_id
                        && domain.cookie == identity.domain_cookie
                })
        })
    }) {
        let (index, inst) = instance_by_driver_id(ticket.identity.driver_id)
            .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
        if domain.domain_id.raw() != ticket.identity.domain_id
            || domain.cookie != ticket.identity.domain_cookie
            || inst.driver_object != ticket.identity.driver_object
        { return Err(nt_status::NtStatus::ACCESS_DENIED); }
        match hosted_driver_reinitialization::dispatch_ticket(
            index, ticket, FSD_DISPATCH_BOOT_DRIVER_REINIT)?
        {
            hosted_driver_reinitialization::ReinitStep::Acknowledged => completed += 1,
            hosted_driver_reinitialization::ReinitStep::Pending(pending) => {
                // The callback stays Executing; the next drain turn continues its pump.
                *core::ptr::addr_of_mut!(PENDING) = Some(pending);
                return Ok(completed);
            }
        }
    }
    Ok(completed)
}
