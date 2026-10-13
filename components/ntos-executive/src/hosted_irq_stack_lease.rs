//! Retained IRQ-worker stack lease for a port ClassService consumed-count output.
//!
//! A DPC passes a four-byte stack local to the callback thunk. The source worker is parked at
//! its arena service request while root drives the class callback. This owner pins the exact
//! worker stack mapping through the callback's terminal acknowledgement; an uncertain dispatch
//! or copyback retains the mapping and prevents TCB/stack retirement.

use super::*;
use nt_hosted_runtime::{
    HostedIrqArenaToken, HostedIrqGrantIdentity, HostedIrqLaneDirection, HostedIrqLaneIdentity,
    HostedIrqServiceCommand, HostedIrqServiceKind, HOSTED_IRQ_ARENA_DEPTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IrqStackLeaseId {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IrqStackRange {
    pub(super) domain: HostedDomainIdentity,
    pub(super) lane: HostedIrqLaneIdentity,
    pub(super) base: u64,
    pub(super) bytes: u64,
    pub(super) generation: u64,
}

impl IrqStackRange {
    pub(super) fn contains(self, domain: HostedDomainIdentity, pointer: u64, bytes: u64) -> bool {
        self.domain == domain
            && self.generation == self.lane.lane_generation
            && self.base != 0
            && pointer != 0
            && bytes != 0
            && self.base.checked_add(self.bytes).is_some_and(|end| {
                pointer >= self.base && pointer.checked_add(bytes).is_some_and(|last| last <= end)
            })
    }
}

struct Lease {
    instance: usize,
    lane: HostedIrqLaneIdentity,
    token: HostedIrqArenaToken,
    command: HostedIrqServiceCommand,
    tcb: u64,
    pml4: u64,
    exec_arena_va: u64,
    pointer: u64,
    exec_pointer: u64,
    range: IrqStackRange,
    pinned: bool,
    write_started: bool,
    uncertain: bool,
}

struct Slot {
    generation: u64,
    lease: Option<Lease>,
}

static mut LEASES: Vec<Slot> = Vec::new();

fn leases() -> &'static mut Vec<Slot> {
    unsafe { &mut *core::ptr::addr_of_mut!(LEASES) }
}

fn lease(id: IrqStackLeaseId) -> Option<&'static mut Lease> {
    let slot = leases().get_mut(id.slot)?;
    if slot.generation != id.generation {
        return None;
    }
    slot.lease.as_mut()
}

fn current_lane(
    instance_index: usize,
    identity: HostedIrqLaneIdentity,
) -> Option<&'static HostedIrqLaneRuntime> {
    unsafe { hosted_irq_lanes()? }.iter().find(|row| {
        row.projection_instance == instance_index
            && row.identity == identity
            && row.domain.domain_id.raw() == identity.domain_id
            && row.domain.cookie == identity.domain_cookie
            && row.state == HostedIrqLaneState::Ready
            && row.ingress_entered
            && !row.ingress_retired
            && row.tcb_resumed
            && row.tcb != 0
            && row.pml4 != 0
            && row.exec_arena_va != 0
            && row.reply_cap != 0
            && row.stack.iter().all(|leaf| leaf.mapped && leaf.exec_mapped)
            && instance(instance_index).is_some_and(|inst| {
                inst.pml4 == row.pml4 && instance_domain_identity(inst) == Some(row.domain)
            })
    })
}

fn matches_active(row: &Lease) -> bool {
    if row.token.depth as usize >= HOSTED_IRQ_ARENA_DEPTH {
        return false;
    }
    let Some(lane) = current_lane(row.instance, row.lane) else {
        return false;
    };
    if lane.tcb != row.tcb || lane.pml4 != row.pml4 || lane.exec_arena_va != row.exec_arena_va {
        return false;
    }
    let arena = unsafe { &*(lane.exec_arena_va as *const nt_hosted_runtime::HostedIrqArena) };
    arena
        .control
        .active_transaction(row.lane, row.token.transaction)
        .is_ok()
        && arena.service[row.token.depth as usize].root_running_command(
            &arena.control,
            row.lane,
            row.token,
        ) == Ok(row.command)
}

/// Capture only after the broker has accepted this exact service token with
/// `arena.service[depth].root_begin` and parked it in the active call frame. This function
/// independently checks lane generation, stack mappings, transaction and pointer bounds, then
/// records the pin before reading or writing any stack byte.
pub(super) unsafe fn capture(
    instance_index: usize,
    identity: HostedIrqLaneIdentity,
    token: HostedIrqArenaToken,
    command: HostedIrqServiceCommand,
    pointer: u64,
) -> Result<(IrqStackLeaseId, IrqStackRange), nt_status::NtStatus> {
    if token.direction != HostedIrqLaneDirection::Service
        || token.lane_generation != identity.lane_generation
        || token.transaction == 0
        || token.sequence == 0
        || token.depth as usize >= HOSTED_IRQ_ARENA_DEPTH
        || command.kind != HostedIrqServiceKind::ClassServiceRequest
        || command.grant.owner_domain_id != identity.domain_id
        || command.grant.owner_domain_cookie != identity.domain_cookie
        || command.grant.grant_id == 0
        || command.grant.grant_generation == 0
        || command.arguments[3] != pointer
        || pointer & 3 != 0
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let lane =
        current_lane(instance_index, identity).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let arena = &*(lane.exec_arena_va as *const nt_hosted_runtime::HostedIrqArena);
    arena
        .control
        .active_transaction(identity, token.transaction)
        .map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
    if arena.service[token.depth as usize].root_running_command(&arena.control, identity, token)
        != Ok(command)
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let component_base = hosted_worker_component_base_for_slot(FSD_IRQ_LANE_COMPONENT_SLOT)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let stack_bytes = FSD_WORKER_STACK_FRAMES
        .checked_mul(0x1000)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let offset = pointer
        .checked_sub(component_base)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    if offset.checked_add(4).is_none_or(|last| last > stack_bytes) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let exec_base = lane
        .exec_arena_va
        .checked_sub(FSD_IRQ_LANE_ARENA_OFFSET)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let exec_pointer = exec_base
        .checked_add(offset)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let domain = lane.domain;
    let range = IrqStackRange {
        domain,
        lane: identity,
        base: component_base,
        bytes: stack_bytes,
        generation: identity.lane_generation,
    };
    let _durable = crate::allocator::enter_durable();
    if leases()
        .iter()
        .filter_map(|slot| slot.lease.as_ref())
        .any(|row| row.pinned && row.lane == identity && row.pointer == pointer)
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let reusable = leases().iter().enumerate().find_map(|(index, slot)| {
        (slot.lease.is_none() && slot.generation < u64::MAX).then_some((index, slot.generation + 1))
    });
    if reusable.is_none() {
        leases()
            .try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    }
    let (index, generation) = reusable.unwrap_or((leases().len(), 1));
    let id = IrqStackLeaseId {
        slot: index,
        generation,
    };
    let retained = Lease {
        instance: instance_index,
        lane: identity,
        token,
        command,
        tcb: lane.tcb,
        pml4: lane.pml4,
        exec_arena_va: lane.exec_arena_va,
        pointer,
        exec_pointer,
        range,
        pinned: true,
        write_started: false,
        uncertain: false,
    };
    if index == leases().len() {
        leases().push(Slot {
            generation,
            lease: Some(retained),
        });
    } else {
        leases()[index] = Slot {
            generation,
            lease: Some(retained),
        };
    }
    if !matches_active(lease(id).unwrap()) {
        lease(id).unwrap().uncertain = true;
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    Ok((id, range))
}

/// Write exactly once while the originating service remains parked. Mark the effect first so a
/// lost or uncertain acknowledgement cannot cause a second write against reused stack storage.
pub(super) unsafe fn write_consumed(
    id: IrqStackLeaseId,
    identity: HostedIrqLaneIdentity,
    token: HostedIrqArenaToken,
    grant: HostedIrqGrantIdentity,
    count: u32,
) -> Result<(), nt_status::NtStatus> {
    let row = lease(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !row.pinned
        || row.uncertain
        || row.write_started
        || row.lane != identity
        || row.token != token
        || row.command.grant != grant
        || !matches_active(row)
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    row.write_started = true;
    core::ptr::write_volatile(row.exec_pointer as *mut u32, count);
    if !matches_active(row) {
        row.uncertain = true;
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    Ok(())
}

/// The broker calls this only after the class callback has acknowledged its terminal, the
/// consumed-count write completed, and the source worker service Reply was acknowledged.
pub(super) fn release_after_ack(
    id: IrqStackLeaseId,
    identity: HostedIrqLaneIdentity,
    token: HostedIrqArenaToken,
    grant: HostedIrqGrantIdentity,
    acknowledgement: nt_io_manager::CompletionAcknowledgement,
) -> bool {
    {
        let Some(row) = lease(id) else {
            return false;
        };
        if acknowledgement != nt_io_manager::CompletionAcknowledgement::Acknowledged
            || !row.pinned
            || row.uncertain
            || !row.write_started
            || row.lane != identity
            || row.token != token
            || row.command.grant != grant
        {
            return false;
        }
    }
    leases()[id.slot].lease = None;
    true
}

/// A rejected callback that never entered class code or wrote the output can relinquish its
/// stack pin while the same service remains parked. A failed check leaves ownership intact.
pub(super) fn abort_unentered(
    id: IrqStackLeaseId,
    identity: HostedIrqLaneIdentity,
    token: HostedIrqArenaToken,
    grant: HostedIrqGrantIdentity,
) -> bool {
    {
        let Some(row) = lease(id) else {
            return false;
        };
        if !row.pinned
            || row.uncertain
            || row.write_started
            || row.lane != identity
            || row.token != token
            || row.command.grant != grant
            || !matches_active(row)
        {
            return false;
        }
    }
    leases()[id.slot].lease = None;
    true
}

pub(super) fn retain_indeterminate(id: IrqStackLeaseId) -> bool {
    let Some(row) = lease(id) else {
        return false;
    };
    if !row.pinned {
        return false;
    }
    row.uncertain = true;
    true
}

pub(super) fn blocks_lane_retirement(identity: HostedIrqLaneIdentity) -> bool {
    leases()
        .iter()
        .filter_map(|slot| slot.lease.as_ref())
        .any(|row| row.pinned && row.lane == identity)
}

pub(super) fn range(id: IrqStackLeaseId) -> Option<IrqStackRange> {
    lease(id).filter(|row| row.pinned).map(|row| row.range)
}
