//! Exact source stack ownership for METHOD_NEITHER CONNECT_DATA.
//!
//! The received route, dispatch and Reply identify the executing physical thread. A lease pins
//! that thread's actual mapped stack aliases before any source bytes are read. An indeterminate
//! provider effect leaves the pin in place so neither the mapping nor its generation is reused.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime::{
    self, PhysicalDomain, PhysicalSourceKind,
};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::retained_connect_forward::{
    ConnectForwardIdentity, ConnectForwardPhase, ConnectStackRange, RetainedConnectForward,
};
use nt_io_manager::source_irp_ledger::SourceIrpForwardIdentity;
use nt_io_manager::scsi_source_retention::{scsi_stack_reply_admits, ScsiStackAccess};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceStackLeaseId(usize);

#[derive(Clone, Copy)]
enum StackOwner {
    Primary {
        instance: usize,
        domain: HostedDomainIdentity,
        tcb: u64,
        pml4: u64,
    },
    Worker {
        construction: usize,
    },
}

struct StackLease {
    owner: StackOwner,
    source: StackLeaseSource,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    range: ConnectStackRange,
    snapshot: [u8; 0x58],
    exec_va: u64,
    pinned: bool,
    indeterminate: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum StackLeaseSource {
    Connect(ConnectForwardIdentity),
    Scsi(SourceIrpForwardIdentity),
}

static mut LEASES: Vec<StackLease> = Vec::new();

fn checked_stack_range(base: u64, bytes: u64, pointer: u64, length: u64) -> Option<u64> {
    (base != 0
        && bytes >= length
        && pointer != 0
        && pointer & 7 == 0
        && base.checked_add(bytes).is_some_and(|end| {
            pointer >= base && pointer.checked_add(length).is_some_and(|last| last <= end)
        }))
    .then_some(pointer - base)
}

unsafe fn resolve_stack(
    instance: usize,
    inst: DriverInstance,
    physical: runtime::PhysicalSource,
    domain: HostedDomainIdentity,
    route: PeerRoute,
    reply: u64,
    pointer: u64,
    length: u64,
) -> Option<(StackOwner, ConnectStackRange, u64)> {
    let (owner, range, exec_va) = match physical.kind {
        PhysicalSourceKind::Primary => {
            let thread = (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_TABLES))
                .as_ref()?
                .get(instance)?
                .get(inst.main_thread_id)?;
            if thread.tcb != physical.tcb
                || thread.exit_status.is_some()
                || inst.tcb != physical.tcb
                || inst.stack_frame_base == 0
                || inst.stack_frame_count != FSD_STACK_FRAMES
                || inst.exec_stack_va == 0
                || domain.cookie == 0
            {
                return None;
            }
            let offset = checked_stack_range(FSD_STACK_VADDR, FSD_STACK_BYTES, pointer, length)?;
            let exec_va = inst.exec_stack_va.checked_add(offset)?;
            (
                StackOwner::Primary {
                    instance,
                    domain,
                    tcb: physical.tcb,
                    pml4: physical.pml4,
                },
                ConnectStackRange {
                    domain,
                    thread: inst.main_thread_id,
                    base: FSD_STACK_VADDR,
                    bytes: FSD_STACK_BYTES,
                    generation: domain.cookie,
                },
                exec_va,
            )
        }
        PhysicalSourceKind::SystemThread { handle } => {
            let mut matching = (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES))
                .as_ref()?
                .iter()
                .copied()
                .filter(|row| {
                    row.instance == instance
                        && row.domain == domain
                        && row.handle == handle
                        && row.tcb == physical.tcb
                        && row.pml4 == physical.pml4
                        && row.ingress_route == Some(route)
                        && row.reply_cap == reply
                });
            let worker = matching.next()?;
            if matching.next().is_some() || !hosted_thread_resources::stack_live(worker) {
                return None;
            }
            let thread = (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_TABLES))
                .as_ref()?
                .get(instance)?
                .get(handle)?;
            if thread.tcb != physical.tcb || thread.exit_status.is_some() {
                return None;
            }
            let component_base = hosted_worker_component_base_for_slot(worker.component_slot)?;
            let bytes = FSD_WORKER_STACK_FRAMES.checked_mul(0x1000)?;
            let offset = checked_stack_range(component_base, bytes, pointer, length)?;
            let exec_va =
                hosted_worker_exec_base_for_alias(worker.exec_alias_slot)?.checked_add(offset)?;
            let generation = (worker.construction as u64).checked_add(1)?;
            (
                StackOwner::Worker {
                    construction: worker.construction,
                },
                ConnectStackRange {
                    domain,
                    thread: handle,
                    base: component_base,
                    bytes,
                    generation,
                },
                exec_va,
            )
        }
        // IRQ and completion workers have separate ingress and stack contracts.
        _ => return None,
    };

    Some((owner, range, exec_va))
}

/// Capture only while this exact physical source is executing its current admitted dispatch.
/// The returned id must be retained beside the CONNECT forward until terminal reconciliation.
pub(crate) unsafe fn capture(
    channel: &crate::spawn_hosts::PumpChannel,
    reply: u64,
    source_identity: ConnectForwardIdentity,
    pointer: u64,
) -> Option<(SourceStackLeaseId, ConnectStackRange, [u8; 16])> {
    let route = runtime::channel_route(channel).ok()??;
    let physical = runtime::physical_source(route).ok()?;
    let dispatch = runtime::dispatch(route).ok()?;
    if reply == 0
        || runtime::current_reply(route).ok()? != reply
        || physical.tcb != channel.tcb
        || physical.pml4 != channel.pml4
        || !hosted_ingress_sources::verify(physical)
    {
        return None;
    }
    let PhysicalDomain::Hosted(domain) = physical.domain else {
        return None;
    };
    let (instance, inst) = instance_for_pump_channel(channel, reply)?;
    if instance_domain_identity(inst) != Some(domain)
        || source_identity.source.allocation().domain != domain
        || inst.pml4 != physical.pml4
    {
        return None;
    }

    let (owner, range, exec_va) = resolve_stack(instance, inst, physical, domain, route, reply, pointer, 16)?;
    let _durable = crate::allocator::enter_durable();
    let leases = &mut *core::ptr::addr_of_mut!(LEASES);
    leases.try_reserve(1).ok()?;
    let id = SourceStackLeaseId(leases.len());
    // The pin is published before the first read. Retirement checks it before any unmap.
    leases.push(StackLease {
        owner,
        source: StackLeaseSource::Connect(source_identity),
        route,
        dispatch,
        reply,
        range,
        snapshot: [0; 0x58],
        exec_va,
        pinned: true,
        indeterminate: false,
    });
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = core::ptr::read_volatile((exec_va + index as u64) as *const u8);
    }
    leases[id.0].snapshot[..16].copy_from_slice(&bytes);
    // A changed dispatch or Reply makes the result uncertain; the pin remains owned.
    if runtime::dispatch(route).ok()? != dispatch
        || runtime::current_reply(route).ok()? != reply
        || runtime::physical_source(route).ok()? != physical
    {
        leases[id.0].indeterminate = true;
        return None;
    }
    Some((id, range, bytes))
}

/// Pin a class driver's stack-local legacy SRB while its synchronous lower-device call is
/// outstanding. The source address never leaves this domain; the provider gets a copy.
pub(crate) unsafe fn capture_scsi(
    channel: &crate::spawn_hosts::PumpChannel,
    reply: u64,
    source_identity: SourceIrpForwardIdentity,
    pointer: u64,
) -> Option<(SourceStackLeaseId, ConnectStackRange, [u8; 0x58])> {
    let route = runtime::channel_route(channel).ok()??;
    let physical = runtime::physical_source(route).ok()?;
    let dispatch = runtime::dispatch(route).ok()?;
    if reply == 0
        || runtime::current_reply(route).ok()? != reply
        || physical.tcb != channel.tcb
        || physical.pml4 != channel.pml4
        || !hosted_ingress_sources::verify(physical)
    { return None; }
    let PhysicalDomain::Hosted(domain) = physical.domain else { return None; };
    let (instance, inst) = instance_for_pump_channel(channel, reply)?;
    if instance_domain_identity(inst) != Some(domain)
        || source_identity.allocation().domain != domain
        || inst.pml4 != physical.pml4
    { return None; }
    let (owner, range, exec_va) = resolve_stack(
        instance, inst, physical, domain, route, reply, pointer, 0x58,
    )?;
    let _durable = crate::allocator::enter_durable();
    let leases = &mut *core::ptr::addr_of_mut!(LEASES);
    leases.try_reserve(1).ok()?;
    let id = SourceStackLeaseId(leases.len());
    leases.push(StackLease {
        owner,
        source: StackLeaseSource::Scsi(source_identity),
        route,
        dispatch,
        reply,
        range,
        snapshot: [0; 0x58],
        exec_va,
        pinned: true,
        indeterminate: false,
    });
    let mut bytes = [0u8; 0x58];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = core::ptr::read_volatile((exec_va + index as u64) as *const u8);
    }
    leases[id.0].snapshot = bytes;
    if runtime::dispatch(route).ok()? != dispatch
        || runtime::current_reply(route).ok()? != reply
        || runtime::physical_source(route).ok()? != physical
    {
        leases[id.0].indeterminate = true;
        return None;
    }
    Some((id, range, bytes))
}

pub(crate) unsafe fn scsi_matches(
    id: SourceStackLeaseId,
    source: SourceIrpForwardIdentity,
    range: ConnectStackRange,
    pointer: u64,
) -> bool {
    let Some(row) = (&*core::ptr::addr_of!(LEASES)).get(id.0) else { return false; };
    row.pinned && !row.indeterminate
        && row.source == StackLeaseSource::Scsi(source)
        && row.range == range
        && checked_stack_range(range.base, range.bytes, pointer, 0x58).is_some()
        && scsi_stack_reply_admits(
            ScsiStackAccess::RetainedThroughAck,
            runtime::dispatch(row.route).ok() == Some(row.dispatch)
                && runtime::current_reply(row.route).ok() == Some(row.reply),
        )
        && runtime::physical_source(row.route).ok().is_some_and(|physical| {
            physical.domain == PhysicalDomain::Hosted(range.domain)
                && match row.owner {
                    StackOwner::Primary { instance: instance_index, domain, tcb, pml4 } =>
                        physical.tcb == tcb && physical.pml4 == pml4
                            && instance(instance_index).is_some_and(|inst| {
                                instance_domain_identity(inst) == Some(domain)
                                    && inst.tcb == tcb
                                    && inst.pml4 == pml4
                                    && inst.main_thread_id == range.thread
                                    && inst.exec_stack_va != 0
                                    && inst.stack_frame_count == FSD_STACK_FRAMES
                            }),
                    StackOwner::Worker { construction } =>
                        (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES))
                            .as_ref().is_some_and(|rows| rows.iter().copied().any(|worker| {
                                worker.construction == construction
                                    && worker.handle == range.thread
                                    && worker.ingress_route == Some(row.route)
                                    && worker.tcb == physical.tcb
                                    && worker.pml4 == physical.pml4
                                    && hosted_thread_resources::stack_live(worker)
                            })),
                }
        })
}

pub(crate) unsafe fn write_scsi(
    id: SourceStackLeaseId,
    source: SourceIrpForwardIdentity,
    range: ConnectStackRange,
    pointer: u64,
    completed: &[u8; 0x58],
) -> bool {
    if !scsi_can_write(id, source, range, pointer) { return false; }
    let row = &mut (&mut *core::ptr::addr_of_mut!(LEASES))[id.0];
    for (index, byte) in completed.iter().enumerate() {
        core::ptr::write_volatile((row.exec_va + index as u64) as *mut u8, *byte);
    }
    row.snapshot = *completed;
    true
}

pub(crate) unsafe fn scsi_can_write(
    id: SourceStackLeaseId,
    source: SourceIrpForwardIdentity,
    range: ConnectStackRange,
    pointer: u64,
) -> bool {
    if !scsi_matches(id, source, range, pointer) { return false; }
    let row = &mut (&mut *core::ptr::addr_of_mut!(LEASES))[id.0];
    let original_reply_current = runtime::dispatch(row.route).ok() == Some(row.dispatch)
        && runtime::current_reply(row.route).ok() == Some(row.reply);
    if !scsi_stack_reply_admits(
        ScsiStackAccess::SourceCopyback, original_reply_current,
    ) { return false; }
    let unchanged = row.snapshot.iter().enumerate().all(|(index, original)| {
        core::ptr::read_volatile((row.exec_va + index as u64) as *const u8) == *original
    });
    if !unchanged { row.indeterminate = true; }
    unchanged
}

pub(crate) unsafe fn release_scsi(
    id: SourceStackLeaseId, source: SourceIrpForwardIdentity,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LEASES)).get_mut(id.0) else { return false; };
    if !row.pinned || row.indeterminate || row.source != StackLeaseSource::Scsi(source) {
        return false;
    }
    row.pinned = false;
    true
}

/// Only a consumed terminal of the same retained forward can release the physical stack pin.
/// The forward's native caller completes its source IRP before consuming that terminal.
pub(crate) unsafe fn release_terminal(
    id: SourceStackLeaseId,
    forward: &RetainedConnectForward,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LEASES)).get_mut(id.0) else {
        return false;
    };
    if !row.pinned
        || row.indeterminate
        || row.source != StackLeaseSource::Connect(forward.identity())
        || forward.phase() != ConnectForwardPhase::TerminalConsumed
    {
        return false;
    }
    row.pinned = false;
    true
}

/// A prepared forward has not entered the provider; cancelling this exact forward permits the
/// stack pin to be released before dispatch. The target and source pins are retired separately.
pub(crate) unsafe fn release_unentered(
    id: SourceStackLeaseId,
    forward: &RetainedConnectForward,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LEASES)).get_mut(id.0) else { return false; };
    if !row.pinned || row.indeterminate || row.source != StackLeaseSource::Connect(forward.identity())
        || forward.phase() != ConnectForwardPhase::Prepared
    { return false; }
    row.pinned = false;
    true
}

/// A real indeterminate dispatch is recorded once. Its stack stays pinned permanently because
/// neither Reply acknowledgement nor a later address match proves provider completion.
pub(crate) unsafe fn retain_indeterminate(
    id: SourceStackLeaseId,
    forward: &RetainedConnectForward,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LEASES)).get_mut(id.0) else {
        return false;
    };
    if !row.pinned
        || row.source != StackLeaseSource::Connect(forward.identity())
        || !matches!(forward.phase(), ConnectForwardPhase::Indeterminate(_))
    {
        return false;
    }
    row.indeterminate = true;
    true
}

pub(super) unsafe fn blocks_worker_retirement(construction: usize) -> bool {
    (&*core::ptr::addr_of!(LEASES)).iter().any(|row| {
        row.pinned
            && matches!(row.owner, StackOwner::Worker { construction: retained }
            if retained == construction)
    })
}

pub(super) unsafe fn blocks_primary_retirement(
    instance: usize,
    domain: HostedDomainIdentity,
    tcb: u64,
    pml4: u64,
) -> bool {
    (&*core::ptr::addr_of!(LEASES)).iter().any(|row| {
        row.pinned
            && matches!(row.owner, StackOwner::Primary {
            instance: retained, domain: identity, tcb: thread, pml4: space,
        } if retained == instance && identity == domain && thread == tcb && space == pml4)
    })
}
