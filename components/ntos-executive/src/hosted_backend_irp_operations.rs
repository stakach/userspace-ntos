//! The `HostedDriverBackend` trait's own native operations on an IRP (#420).
//!
//! The I/O Manager lends the trait a buffer and expects an answer before it returns. When the
//! native pump behind a dispatch, cancel, copy or ACK stops unfinished where the root cannot
//! wait, the operation is kept in `hosted_backend_pumps` with an owned output, and the trait
//! answers its honest pending outcome:
//! - a dispatch answers that the IRP is pending. When the pump returns, its genuine result is
//!   published as the pending IRP's ordinary completion (`IoManager::complete_returned_irp`).
//! - a cancel, copy or ACK answers `STATUS_PENDING`, which the I/O Manager and its consumers
//!   retry. The next identical call collects the result instead of issuing it again.
//!
//! Each IRP has at most one operation running against its native storage
//! (`nt_hosted_runtime::IrpOperations`). An operation whose native effect is uncertain is
//! quarantined: nothing is issued against that IRP again.

use super::*;
use hosted_backend_pumps::{BackendCollected, BackendDispatch};
use nt_hosted_runtime::{BackendTicket, IrpOperationAdmission, IrpOperationKey, IrpOperations};
use nt_io_manager::{ReturnedIrp, ReturnedIrpRejection};

/// A dispatch's key operation: no control selector uses it.
const DISPATCH: u64 = 0;

enum Kept {
    /// A cancel, copy or ACK; the next identical call collects it.
    Control(BackendTicket),
    /// An IRP dispatch; its return is published as the IRP's completion.
    Dispatch { ticket: BackendTicket, driver_id: DriverId, create: bool },
    /// A collected dispatch return the I/O Manager could not take yet.
    Held { driver_id: DriverId, returned: ReturnedIrp },
}

static mut OPERATIONS: IrpOperations<Kept> = IrpOperations::new();

fn operations() -> &'static mut IrpOperations<Kept> {
    unsafe { &mut *core::ptr::addr_of_mut!(OPERATIONS) }
}

/// What a trait dispatch gives the I/O Manager.
pub(super) enum TraitDispatch {
    /// Certainly not entered.
    NotDispatched(nt_status::NtStatus),
    /// The driver's own return, in place; its output is already in the lent buffer.
    Returned { status: nt_status::NtStatus, information: u64, file_context: u64 },
    /// The driver has not returned yet; its return will be published as the IRP's completion.
    Pending,
    /// Entered, with no trustworthy return: the IRP's native storage is quarantined.
    Quarantined { transport_status: nt_status::NtStatus },
}

/// Dispatch `irp` through `issue` (#420). An unfinished pump is kept and the IRP is pending.
/// `None` from `issue` is the exact dispatch's own "the instance is not available".
pub(super) fn dispatch(
    instance: usize,
    irp: &IrpProjection,
    issue: impl FnOnce() -> Option<BackendDispatch>,
) -> TraitDispatch {
    let key = IrpOperationKey {
        instance, irp: irp.irp_id.raw(), operation: DISPATCH, offset: 0, len: 0,
    };
    match operations().admit(key) {
        IrpOperationAdmission::Issue => {}
        IrpOperationAdmission::Collect(kept) => {
            // A dispatch is issued once per IRP: an identical key is the I/O Manager
            // dispatching it again, which nothing here may do.
            let _ = operations().still_running(key, kept);
            return TraitDispatch::NotDispatched(nt_status::NtStatus::DEVICE_BUSY);
        }
        IrpOperationAdmission::Busy =>
            return TraitDispatch::NotDispatched(nt_status::NtStatus::DEVICE_BUSY),
    }
    if operations().reserve().is_err() {
        return TraitDispatch::NotDispatched(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    match issue() {
        None => TraitDispatch::NotDispatched(nt_status::NtStatus::DEVICE_NOT_CONNECTED),
        Some(BackendDispatch::Returned(HostedIrpTransportResult::NotDispatched { status })) =>
            TraitDispatch::NotDispatched(status),
        Some(BackendDispatch::Returned(HostedIrpTransportResult::Returned {
            status, information, file_context,
        })) => TraitDispatch::Returned { status, information, file_context },
        Some(BackendDispatch::Returned(HostedIrpTransportResult::Indeterminate {
            transport_status,
        })) => {
            operations().quarantine_issued(key);
            trace(b"quarantined", key);
            TraitDispatch::Quarantined { transport_status }
        }
        Some(BackendDispatch::Pending(ticket)) => {
            operations().keep(key, Kept::Dispatch {
                ticket,
                driver_id: irp.driver_id,
                create: major::is_create_major(irp.major),
            });
            trace(b"dispatch-pending", key);
            TraitDispatch::Pending
        }
    }
}

/// Issue the completion-storage control `operation`, or collect the identical one already
/// running (#420). `Ok` is a certain result; `Err(PENDING)` means it is still running, another
/// operation owns the IRP, or the IRP is quarantined. `certain` decides which returns are
/// trustworthy; any other return quarantines the IRP.
pub(super) fn control(
    instance: usize,
    irp_id: IrpId,
    operation: u64,
    offset: u64,
    output: &mut [u8],
    certain: impl Fn(&HostedIrpTransportResult) -> bool,
) -> Result<HostedIrpTransportResult, nt_status::NtStatus> {
    let key = IrpOperationKey { instance, irp: irp_id.raw(), operation, offset, len: output.len() };
    let result = match operations().admit(key) {
        IrpOperationAdmission::Busy => return Err(nt_status::NtStatus::PENDING),
        IrpOperationAdmission::Collect(Kept::Control(ticket)) =>
            match hosted_backend_pumps::collect(ticket) {
                BackendCollected::Pending(ticket) => {
                    let _ = operations().still_running(key, Kept::Control(ticket));
                    return Err(nt_status::NtStatus::PENDING);
                }
                BackendCollected::Collected(result, held) => {
                    let count = held.len().min(output.len());
                    output[..count].copy_from_slice(&held[..count]);
                    if certain(&result) {
                        operations().settled(key);
                        trace(b"collected", key);
                        return Ok(result);
                    }
                    operations().quarantine(key);
                    trace(b"quarantined", key);
                    return Err(nt_status::NtStatus::PENDING);
                }
            },
        IrpOperationAdmission::Collect(kept) => {
            // Dispatch keys never equal a control key.
            let _ = operations().still_running(key, kept);
            return Err(nt_status::NtStatus::PENDING);
        }
        IrpOperationAdmission::Issue => {
            if operations().reserve().is_err() {
                return Ok(HostedIrpTransportResult::NotDispatched {
                    status: nt_status::NtStatus::INSUFFICIENT_RESOURCES,
                });
            }
            match hosted_file_dispatch::control_kept(instance, irp_id, operation, offset, output) {
                BackendDispatch::Returned(result) => result,
                BackendDispatch::Pending(ticket) => {
                    operations().keep(key, Kept::Control(ticket));
                    trace(b"control-pending", key);
                    return Err(nt_status::NtStatus::PENDING);
                }
            }
        }
    };
    if certain(&result) {
        return Ok(result);
    }
    operations().quarantine_issued(key);
    trace(b"quarantined", key);
    Err(nt_status::NtStatus::PENDING)
}

/// Publish each kept dispatch whose pump has returned as its pending IRP's ordinary
/// completion, exactly once. Runs where no I/O Manager borrow is held.
pub(super) fn publish_returned() -> usize {
    fn ready(_: &IrpOperationKey, kept: &Kept) -> bool {
        match kept {
            Kept::Dispatch { ticket, .. } => hosted_backend_pumps::collectable(ticket),
            Kept::Held { .. } => true,
            Kept::Control(_) => false,
        }
    }
    let count = operations().ready(ready).count();
    let mut keys = Vec::new();
    if count == 0 || keys.try_reserve_exact(count).is_err() { return 0; }
    keys.extend(operations().ready(ready));
    let mut published = 0;
    for key in keys {
        let Some(kept) = operations().take(key) else { continue };
        let (driver_id, returned) = match kept {
            Kept::Held { driver_id, returned } => (driver_id, returned),
            Kept::Dispatch { ticket, driver_id, create } => match hosted_backend_pumps::collect(ticket) {
                BackendCollected::Pending(ticket) => {
                    let _ = operations().still_running(key, Kept::Dispatch { ticket, driver_id, create });
                    continue;
                }
                BackendCollected::Collected(result, output) => match result {
                    HostedIrpTransportResult::Returned {
                        status: nt_status::NtStatus::PENDING, ..
                    } => {
                        // The driver pended the IRP itself: its completion arrives from the
                        // backend as any pending IRP's does.
                        operations().settled(key);
                        trace(b"native-pending", key);
                        continue;
                    }
                    HostedIrpTransportResult::Returned { status, information, file_context } =>
                        (driver_id, ReturnedIrp {
                            irp_id: IrpId(key.irp),
                            status,
                            information,
                            file_context: create.then_some(file_context),
                            output,
                        }),
                    // An entered pump has no no-entry return, and an uncertain one has no
                    // trustworthy terminal: the IRP stays pending and its storage quarantined.
                    HostedIrpTransportResult::NotDispatched { .. }
                    | HostedIrpTransportResult::Indeterminate { .. } => {
                        operations().quarantine(key);
                        trace(b"quarantined", key);
                        continue;
                    }
                },
            },
            Kept::Control(ticket) => {
                let _ = operations().still_running(key, Kept::Control(ticket));
                continue;
            }
        };
        match io_manager_mut().complete_returned_irp(driver_id, returned) {
            Ok(()) => {
                operations().settled(key);
                trace(b"published", key);
                published += 1;
            }
            Err(ReturnedIrpRejection { status, returned }) => {
                // The I/O Manager has not recorded the dispatch's pending answer yet, or had
                // no room: hold the return for the next pass. Any other refusal means the IRP
                // has another terminal; the return is kept, never published elsewhere.
                let not_yet = io_manager_mut().irp(returned.irp_id)
                    .is_some_and(|irp| irp.state == nt_io_manager::IrpState::Dispatched);
                if not_yet || status == nt_status::NtStatus::INSUFFICIENT_RESOURCES {
                    let _ = operations().still_running(key, Kept::Held { driver_id, returned });
                } else {
                    operations().quarantine(key);
                    trace(b"refused", key);
                }
            }
        }
    }
    published
}

fn trace(stage: &[u8], key: IrpOperationKey) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 32 && !n.is_power_of_two() { return; }
    print_str(b"[backend-irp-op] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" irp=");
    print_hex_u64(key.irp);
    print_str(b" op=");
    print_hex_u64(key.operation);
    print_str(b"\n");
}
