//! Exact outer-to-nested FILTER proof bridge at a function FDO's accepted PDO edge.
//!
//! The bus provider has already executed for the original PDO-origin request.
//! Publication here precedes lower FDO entry, so its nested raw call can consume
//! only that original one-use proof. No provider IRP is dispatched from this module.

use super::*;
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, source_irp_ledger::SourceIrpAllocation,
    HostedDevicePointerRegistration,
};
use nt_pnp_manager::AcceptedPdoFilterEdge;

struct Row {
    edge: AcceptedPdoFilterEdge,
    source: Option<(usize, u64, SourceIrpTicket, SourceIrpAllocation)>,
}

static mut ROWS: Vec<Row> = Vec::new();

pub(super) unsafe fn publish(
    outer_irp: IrpId,
    nested_irp: IrpId,
    fdo: HostedDevicePointerRegistration,
    class_source: SourceIrpTicket,
    client: ClientId,
    requestor_tid: u64,
) -> bool {
    if (&*core::ptr::addr_of!(ROWS))
        .iter()
        .any(|row| row.edge.nested_irp() == nested_irp)
    {
        return false;
    }
    let Some(binding) = hosted_device_binding_by_device_id(fdo.device_id().raw()) else {
        return false;
    };
    if binding.projection_domain != fdo.domain()
        || binding.device_id != fdo.device_id().raw()
        || io_manager_mut()
            .device(fdo.device_id())
            .and_then(|device| device.attached_to)
            .is_none_or(|pdo| pdo.raw() != binding.pdo_device_id)
    {
        return false;
    }
    let Some(pdo) =
        io_manager_mut().hosted_device_pointer_registration(fdo.domain(), binding.pdo_object)
    else {
        return false;
    };
    if pdo.device_id().raw() != binding.pdo_device_id
        || !hosted_filter_requirements_transactions_mut()
            .iter()
            .any(|transaction| {
                transaction.irp_id == outer_irp
                    && transaction.binding.pdo_device_id == binding.pdo_device_id
                    && transaction.phase == HostedFilterRequirementsPhase::AwaitingCompletion
                    && transaction.video_provider_proof.is_some()
            })
    {
        return false;
    }
    let Ok(edge) = AcceptedPdoFilterEdge::capture(
        hosted_pnp_manager_mut(),
        hosted_bus_relations(),
        hosted_accepted_pdo_provider_catalog(),
        io_manager_mut(),
        outer_irp,
        nested_irp,
        fdo,
        pdo,
        class_source,
        client,
        requestor_tid,
    ) else {
        return false;
    };
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if rows.try_reserve(1).is_err() {
        return false;
    }
    rows.push(Row { edge, source: None });
    true
}

/// A provider that never entered its native PDO edge leaves no source pin.
pub(super) unsafe fn retire_unentered(nested_irp: IrpId) {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if let Some(index) = rows
        .iter()
        .position(|row| row.edge.nested_irp() == nested_irp && row.source.is_none())
    {
        rows.swap_remove(index);
    }
}

pub(super) unsafe fn consume(
    ch: &crate::spawn_hosts::PumpChannel,
    pdo_object: u64,
    raw_irp: u64,
    caller_badge: u64,
    reply_cap: u64,
) -> (i32, bool) {
    let refused = (nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw(), false);
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return refused;
    }
    let Ok((instance_index, inst, pdo)) = authenticated_hosted_pdo(ch, pdo_object, reply_cap)
    else {
        return refused;
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return refused;
    };
    let Some(active) = (*core::ptr::addr_of!(ACTIVE_HOSTED_IRP_TRANSFERS))
        .as_ref()
        .and_then(|rows| rows.last())
        .copied()
    else {
        return refused;
    };
    if active.shared_va != ch.shared_va
        || active.source_instance != instance_index
        || !hosted_source_irp_ledger::active_caller_projection_matches(
            instance_index,
            active.transfer_id,
            raw_irp,
            nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
        )
    {
        return refused;
    }
    let nested_irp = IrpId(active.transfer_id);
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let Some(row) = rows
        .iter_mut()
        .find(|row| row.edge.nested_irp() == nested_irp && row.source.is_none())
    else {
        return refused;
    };
    let identity = row.edge.original_identity();
    if identity.pdo != pdo
        || io_manager_mut()
            .hosted_device_pointer_registration(domain, pdo_object)
            .is_none_or(|registration| registration.device_id() != pdo)
    {
        return refused;
    }
    let Some((ticket, allocation)) = hosted_source_irp_ledger::pin(instance_index, domain, raw_irp)
    else {
        return refused;
    };
    let result = (|| {
        row.edge
            .bind_nested_source(nested_irp, ticket)
            .map_err(|_| ())?;
        let transaction = hosted_filter_requirements_transactions_mut()
            .iter_mut()
            .find(|transaction| {
                transaction.irp_id == identity.outer_irp
                    && transaction.binding.pdo_device_id == pdo.raw()
                    && transaction.phase == HostedFilterRequirementsPhase::AwaitingCompletion
            })
            .ok_or(())?;
        let proof = transaction.video_provider_proof.as_mut().ok_or(())?;
        row.edge
            .consume_proof(
                hosted_pnp_manager_mut(),
                hosted_bus_relations(),
                hosted_accepted_pdo_provider_catalog(),
                io_manager_mut(),
                nested_irp,
                ticket,
                proof,
            )
            .map_err(|_| ())
    })();
    match result {
        Ok(status) => {
            row.source = Some((instance_index, raw_irp, ticket, allocation));
            (status.raw(), true)
        }
        Err(()) => {
            let _ = hosted_source_irp_ledger::unpin(ticket);
            refused
        }
    }
}

/// Operation 4 (inline terminal) or 5 (held completion) is permitted only
/// after the native completion stack has reached the exact caller terminal.
pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    raw_irp: u64,
) -> (i32, bool) {
    let refused = (nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw(), false);
    let Some((instance_index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return refused;
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return refused;
    };
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let Some(index) = rows.iter().position(|row| {
        row.source
            .is_some_and(|(source_instance, source_address, _, _)| {
                source_instance == instance_index && source_address == raw_irp
            })
    }) else {
        return refused;
    };
    let (_, _, ticket, allocation) = rows[index].source.unwrap();
    if ticket.domain != domain {
        return refused;
    }
    if !hosted_source_irp_ledger::matches(instance_index, allocation, ticket) {
        return refused;
    }
    if !hosted_source_irp_ledger::caller_terminal_ready(ticket, allocation) {
        return refused;
    }
    if !hosted_source_irp_ledger::release_pending_terminal(ticket, allocation) {
        return refused;
    }
    rows.swap_remove(index);
    (STATUS_SUCCESS, false)
}
