//! `ObfDereferenceObject` from a DPC on a hosted IRQ lane (IRQL == DISPATCH_LEVEL).
//!
//! The lane's root exchange admits only typed arena services, so a DPC publishes one
//! `DeferredDereference` per call. Root drops exactly one reference using the same ledger core as
//! the primary channel for that object kind. As with NT's ObpDeferObjectDeletion, no final
//! deletion runs inside the DPC service:
//!
//! - Device: the caller reference is split from the registration anchor; it never deletes.
//! - File: a retiring projection stays in its row until `hosted_consumer_file_objects::redrive`
//!   retires it from PASSIVE_LEVEL service-loop maintenance. The canonical File close is already
//!   queued by the I/O Manager's deferred close.
//! - Event: the last reference is owned by the Event ledger's lane queue and retires on its
//!   PASSIVE_LEVEL service-loop drain after the lane acknowledged the exact service.
//! - Ps handle and Ps lookup leases: a count drop with no deletion effect.
//! - Dynamic object: a final release marks the registry row ready; the dynamic delete worker
//!   delivers DeleteProcedure at PASSIVE_LEVEL.

use super::*;
use nt_hosted_runtime::HostedDereferenceObjectKind as Kind;

/// The root service whose ledger owns each driver-local classification.
pub(super) const fn service_id(kind: Kind) -> u64 {
    match kind {
        Kind::Device => FSD_SERVICE_DEVICE_LABEL,
        Kind::File => FSD_SERVICE_FILE_LABEL,
        Kind::Event => FSD_SERVICE_EVENT_REFERENCE_LABEL,
        Kind::Object => FSD_SERVICE_DYNAMIC_OBJECT_DEREFERENCE_LABEL,
    }
}

/// Drop one reference for the lane's authenticated instance. Returns `(status, count)`, where
/// `count` is the value the primary path's ObfDereferenceObject returns for that kind.
pub(super) unsafe fn dereference_for(
    index: usize,
    inst: DriverInstance,
    lane: nt_hosted_runtime::HostedIrqLaneIdentity,
    service: nt_hosted_runtime::HostedIrqArenaToken,
    object: u64,
    kind: Kind,
) -> (i32, u64) {
    let _durable = crate::allocator::enter_durable();
    let Some(domain) = instance_domain_identity(inst) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    match kind {
        Kind::Device => {
            hosted_device_pointer_mutation_for(inst, HOSTED_DEVICE_OP_DEREFERENCE_POINTER, object)
        }
        Kind::File => {
            (hosted_consumer_file_objects::dereference_pointer_deferred(domain, object), 0)
        }
        Kind::Event => {
            hosted_driver_event_reference::lane_dereference(index, inst, object, lane, service)
        }
        Kind::Object => {
            // The primary path's order: typed Ps handle leases, Ps lookup leases, then dynamic
            // objects. A body none of them owns has no reference to drop here.
            let status = hosted_driver_ps_handle_reference::release_for(inst, domain, object);
            if !hosted_driver_ps_handle_reference::unowned(status) {
                return (status, 0);
            }
            let (status, references) =
                hosted_driver_process_identity::release_for(inst, domain, object);
            if !hosted_driver_process_identity::unowned(status) {
                return (status, references);
            }
            match hosted_driver_dynamic_delete::release_reference_for(index, inst, object) {
                (STATUS_INVALID_HANDLE, _) => (STATUS_SUCCESS, 0),
                released => released,
            }
        }
    }
}
