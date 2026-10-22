//! The original FILTER IRP's direct function-FDO to accepted-PDO lower edge.
//!
//! Publication precedes FDO entry. The exact source allocation stays pinned
//! until the native completion terminal acknowledges it.

use super::*;
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, source_irp_ledger::SourceIrpAllocation,
};
use nt_pnp_manager::AcceptedPdoDirectFilterEdge;

struct Row {
    edge: AcceptedPdoDirectFilterEdge,
    projection_instance: usize,
    source: Option<(usize, u64, SourceIrpTicket, SourceIrpAllocation)>,
}

static mut ROWS: Vec<Row> = Vec::new();

pub(super) unsafe fn publish(outer_irp: IrpId) -> bool {
    if (&*core::ptr::addr_of!(ROWS)).iter().any(|row| {
        row.edge.original_identity().outer_irp == outer_irp
    }) {
        return false;
    }
    let Some(transaction) = hosted_filter_requirements_transactions_mut().iter().find(|row| {
        row.irp_id == outer_irp
            && row.phase == HostedFilterRequirementsPhase::AwaitingCompletion
            && row.video_provider_proof.is_some()
    }) else {
        return false;
    };
    let binding = transaction.binding;
    let Some(fdo) = io_manager_mut().hosted_device_pointer_registration(
        binding.projection_domain, binding.device_object,
    ) else { return false; };
    let Some(pdo) = io_manager_mut().hosted_device_pointer_registration(
        binding.projection_domain, binding.pdo_object,
    ) else { return false; };
    if fdo.device_id().raw() != binding.device_id
        || pdo.device_id().raw() != binding.pdo_device_id
        || hosted_device_binding_by_device_id(binding.device_id) != Some(binding)
    {
        return false;
    }
    let Ok(edge) = AcceptedPdoDirectFilterEdge::capture(
        hosted_pnp_manager_mut(), hosted_bus_relations(),
        hosted_accepted_pdo_provider_catalog(), io_manager_mut(),
        outer_irp, fdo, pdo, ClientId(IO_MANAGER_COMPONENT_ID), 0,
    ) else { return false; };
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if rows.try_reserve(1).is_err() { return false; }
    rows.push(Row { edge, projection_instance: binding.projection_instance, source: None });
    true
}

pub(super) unsafe fn retire_unentered(outer_irp: IrpId) {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if let Some(index) = rows.iter().position(|row| {
        row.edge.original_identity().outer_irp == outer_irp && row.source.is_none()
    }) {
        rows.swap_remove(index);
    }
}

/// `None` means this transfer belongs to the separate nested-FDO edge.
pub(super) unsafe fn consume(
    ch: &crate::spawn_hosts::PumpChannel,
    pdo_object: u64,
    raw_irp: u64,
    caller_badge: u64,
    reply_cap: u64,
) -> Option<(i32, bool)> {
    let refused = (nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw(), false);
    let Some(active) = (*core::ptr::addr_of!(ACTIVE_HOSTED_IRP_TRANSFERS))
        .as_ref().and_then(|rows| rows.last()).copied()
    else { return None; };
    let outer_irp = IrpId(active.transfer_id);
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let Some(row) = rows.iter_mut().find(|row| {
        row.edge.original_identity().outer_irp == outer_irp
    }) else { return None; };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(refused);
    }
    let Ok((instance_index, inst, pdo)) = authenticated_hosted_pdo(ch, pdo_object, reply_cap)
    else { return Some(refused); };
    let Some(domain) = instance_domain_identity(inst) else { return Some(refused); };
    if row.source.is_some()
        || row.projection_instance != instance_index
        || active.shared_va != ch.shared_va
        || active.source_instance != instance_index
        || !hosted_source_irp_ledger::active_caller_projection_matches(
            instance_index, active.transfer_id, raw_irp,
            nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
        )
        || row.edge.original_identity().pdo != pdo
        || io_manager_mut().hosted_device_pointer_registration(domain, pdo_object)
            .is_none_or(|registration| registration.device_id() != pdo)
    {
        return Some(refused);
    }
    let Some((ticket, allocation)) = hosted_source_irp_ledger::pin(
        instance_index, domain, raw_irp,
    ) else { return Some(refused); };
    let result = (|| {
        row.edge.bind_source(outer_irp, ticket).map_err(|_| ())?;
        let transaction = hosted_filter_requirements_transactions_mut().iter_mut().find(|tx| {
            tx.irp_id == outer_irp
                && tx.binding.pdo_device_id == pdo.raw()
                && tx.phase == HostedFilterRequirementsPhase::AwaitingCompletion
        }).ok_or(())?;
        let proof = transaction.video_provider_proof.as_mut().ok_or(())?;
        row.edge.consume_proof(
            hosted_pnp_manager_mut(), hosted_bus_relations(),
            hosted_accepted_pdo_provider_catalog(), io_manager_mut(),
            outer_irp, ticket, proof,
        ).map_err(|_| ())
    })();
    Some(match result {
        Ok(status) => {
            row.source = Some((instance_index, raw_irp, ticket, allocation));
            (status.raw(), true)
        }
        Err(()) => {
            let _ = hosted_source_irp_ledger::unpin(ticket);
            refused
        }
    })
}

/// `None` lets the nested edge examine its own source allocation.
pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    raw_irp: u64,
) -> Option<(i32, bool)> {
    let Some((instance_index, inst)) = instance_for_pump_channel(ch, reply_cap)
    else { return None; };
    let Some(domain) = instance_domain_identity(inst) else { return None; };
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let Some(index) = rows.iter().position(|row| {
        row.source.is_some_and(|(source_instance, address, _, _)| {
            source_instance == instance_index && address == raw_irp
        })
    }) else { return None; };
    let (_, _, ticket, allocation) = rows[index].source.unwrap();
    let refused = (nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw(), false);
    if ticket.domain != domain
        || !hosted_source_irp_ledger::matches(instance_index, allocation, ticket)
        || !hosted_source_irp_ledger::caller_terminal_ready(ticket, allocation)
        || !hosted_source_irp_ledger::release_pending_terminal(ticket, allocation)
    {
        return Some(refused);
    }
    rows.swap_remove(index);
    Some((STATUS_SUCCESS, false))
}
